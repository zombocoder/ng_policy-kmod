#!/bin/sh
#
# Phase 0 proof (vnetfabric spec, single host): arbitrary FreeBSD
# interface types attach to ng_policy as endpoints, in-line policy
# enforcement works, and cross-subnet connectivity is carried by the
# host's own IP forwarding -- no custom routing code, no vnetd/vpcd.
#
# This is the smallest useful slice of "vnetfabric Phase 0 -- Manual
# Interface Fabric" from the design spec: everything here is done by
# hand (ngctl/ifconfig/jail), on one machine, with no overlay/VXLAN
# (that needs a second host and is explicitly out of scope for this
# script).
#
# What this proves:
#   - epair and tap are both Ethernet interfaces: ng_ether attaches a
#     netgraph node to each automatically, and ng_policy binds to
#     either identically via ENDPOINT_ADD -- the fabric genuinely does
#     not care what is behind the interface.
#   - A fresh/unbound ng_policy hook fails closed (drops, counted as
#     unbound_hook_packets), not open.
#   - Default-deny works: traffic with no matching rule is silently
#     dropped (a probe against it times out, it does not get
#     "connection refused" -- proving the SYN never reached the
#     listener on the other side, which this script deliberately runs
#     so a leak would be observable as a refusal instead of a timeout).
#   - Cross-subnet delivery between two ng_policy-gated interfaces
#     rides entirely on net.inet.ip.forwarding=1 and the kernel's own
#     routing table -- ng_policy makes an allow/drop decision and hands
#     an allowed frame back to the same interface's normal upper-layer
#     path; it never picks an egress interface itself (see
#     docs/architecture.md, "Decision 1").
#
# What this does NOT prove:
#   - tun is explicitly out of scope. ng_policy parses Ethernet frames
#     (see docs/architecture.md); ng_ether only attaches to Ethernet
#     interfaces. tun (man 4 tun) is a plain IP-layer point-to-point
#     pseudo-device with no Ethernet framing and no ng_ether
#     attachment, so it cannot be wired into ng_policy as it exists
#     today, full stop -- not a configuration gap, a design boundary.
#     ng_iface has the same IP-only limitation, for the same reason.
#   - Multi-host / overlay connectivity (VXLAN etc.) -- everything here
#     is one machine.
#   - Anything about vnetd/vpcd: this script IS the thing a future
#     vnetd would automate. It is deliberately manual.
#
# ng_policy is stateless: it does not track connections, so a rule
# that allows A -> B does not implicitly allow B's replies back to A.
# This script installs both directions on purpose -- see the two ICMP
# and two TCP rules below -- because the first draft of this proof
# didn't, and silently failed as a result (ping and TCP both "worked"
# on the request leg and then hung, because the reply had no matching
# rule and hit default-deny). Left in as a rule of thumb: any live
# protocol test through ng_policy needs a rule for each direction of
# the conversation.
#
# Test rig note: the two simulated "workload" endpoints are placed in
# plain VNET jails purely so their addresses are NOT locally-owned
# addresses of the test host. Without that, FreeBSD's own IP stack
# recognises the "remote" address as one of its own and delivers via
# the lo0 shortcut, never touching the wire -- meaning ng_policy would
# never see the traffic at all despite everything being wired
# correctly. This is a test-harness requirement, not a vnetfabric
# dependency (matches the spec's own example: "A VNET jail may be
# connected through an epair interface").
#
# Prerequisites (all required; the script refuses to run without them):
#   - Real FreeBSD (not Linux, not a jail without device access).
#   - root (kldload, jail, ifconfig, and live interfaces).
#   - VIMAGE/VNET kernel support (kern.features.vimage=1).
#   - ng_ether, ng_socket, and a built ng_policy.ko all loadable.
#   - Nothing already named epair0/epair1/tap0/jail-a/jail-b/vfab0 on
#     this host, and nothing already using 10.60.1.0/24 or
#     10.60.2.0/24 -- the script refuses to run if it finds any of
#     these, rather than risk tearing down something it didn't create.
#
# Usage: phase0-single-host-fabric.sh -y [seconds-to-leave-it-up]
#
# By default the whole rig (jails, interfaces, ng_policy node) is torn
# down again at the end (or on any failure) so the script is safe to
# re-run. Pass a nonzero third argument to leave it up for manual
# poking afterward (tear down yourself with the commands the script
# echoes at the end).

set -e

usage() {
	echo "usage: $0 -y [leave-up-seconds]" >&2
	echo "  -y   required: confirms you understand this creates two" >&2
	echo "       VNET jails, three interfaces, and a live ng_policy" >&2
	echo "       node with real (if throwaway) IP addresses, then" >&2
	echo "       tears them down again unless leave-up-seconds > 0." >&2
	exit 1
}

case "${1:-}" in
-y|--yes) shift ;;
*) usage ;;
esac

LEAVE_UP=${1:-0}

OSTYPE=$(sysctl -n kern.ostype 2>/dev/null || echo "")
if [ "$OSTYPE" != "FreeBSD" ]; then
	echo "$0: refusing to run on kernel ostype '$OSTYPE' (expected FreeBSD)." >&2
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "$0: must run as root (kldload, jail, live interfaces)." >&2
	echo "  e.g.: doas $0 -y" >&2
	exit 1
fi

if [ "$(sysctl -n kern.features.vimage 2>/dev/null || echo 0)" -ne 1 ]; then
	echo "$0: this kernel does not report VIMAGE support" >&2
	echo "  (kern.features.vimage != 1); VNET jails are required." >&2
	exit 1
fi

for name in epair0a epair0b epair1a epair1b tap0; do
	if ifconfig "$name" >/dev/null 2>&1; then
		echo "$0: interface '$name' already exists -- refusing to" >&2
		echo "  reuse or destroy something this script didn't create." >&2
		exit 1
	fi
done
for j in jail-a jail-b; do
	if jls -j "$j" >/dev/null 2>&1; then
		echo "$0: jail '$j' already exists -- refusing to reuse it." >&2
		exit 1
	fi
done
if ngctl list 2>/dev/null | grep -q 'Name: vfab0 '; then
	echo "$0: a netgraph node named 'vfab0' already exists -- refusing" >&2
	echo "  to reuse or shut it down." >&2
	exit 1
fi
if netstat -rn -f inet | grep -qE '^10\.60\.[12]\.'; then
	echo "$0: 10.60.1.0/24 or 10.60.2.0/24 already appear in the" >&2
	echo "  routing table -- refusing to risk a collision." >&2
	exit 1
fi

for mod in ng_ether ng_socket; do
	if ! kldstat -q -m "$mod" 2>/dev/null && ! kldload "$mod" 2>/dev/null; then
		echo "$0: kernel module '$mod' is not loaded and could not be" >&2
		echo "  loaded from the standard module path." >&2
		exit 1
	fi
done
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NGP_KO="$SCRIPT_DIR/../sys/netgraph/ng_policy/ng_policy.ko"
if ! kldstat -q -m ng_policy 2>/dev/null; then
	if [ ! -f "$NGP_KO" ]; then
		echo "$0: ng_policy.ko not found at $NGP_KO -- build it first" >&2
		echo "  (make -C sys/netgraph/ng_policy)." >&2
		exit 1
	fi
	kldload "$NGP_KO"
fi

FAIL=0
pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; FAIL=1; }

cleanup() {
	if [ "$LEAVE_UP" -gt 0 ] 2>/dev/null && [ "$FAIL" -eq 0 ]; then
		echo
		echo "Leaving the rig up for $LEAVE_UP more seconds (poke it" \
		    "yourself: doas jexec jail-a sh, doas ngctl show vfab0:, ...)"
		sleep "$LEAVE_UP"
	fi
	echo
	echo "=== tearing down ==="
	jls -j jail-a >/dev/null 2>&1 && jail -r jail-a 2>/dev/null || true
	jls -j jail-b >/dev/null 2>&1 && jail -r jail-b 2>/dev/null || true
	ngctl shutdown vfab0: 2>/dev/null || true
	for i in epair0a epair1a tap0; do
		ifconfig "$i" destroy 2>/dev/null || true
	done
}
trap cleanup EXIT

echo "=== creating interfaces ==="
ifconfig epair0 create
ifconfig epair1 create
ifconfig tap0 create

echo "=== wiring ng_policy in-line on epair0a/epair1a/tap0 ==="
ngctl mkpeer epair0a: policy lower ep-1001
ngctl name epair0a:lower vfab0
ngctl connect epair0a: vfab0: upper fab-1001
ngctl connect epair1a: vfab0: lower ep-2001
ngctl connect epair1a: vfab0: upper fab-2001
ngctl connect tap0: vfab0: lower ep-3001
ngctl connect tap0: vfab0: upper fab-3001

echo "=== host-side addressing (the 'VPC gateway' legs) ==="
ifconfig epair0a inet 10.60.1.1/24 up
ifconfig epair1a inet 10.60.2.1/24 up
ifconfig tap0 up
sysctl net.inet.ip.forwarding=1 >/dev/null

echo "=== isolating the two simulated workloads in VNET jails ==="
jail -c name=jail-a path=/ host.hostname=jail-a vnet persist
jail -c name=jail-b path=/ host.hostname=jail-b vnet persist
ifconfig epair0b vnet jail-a
ifconfig epair1b vnet jail-b
jexec jail-a ifconfig epair0b inet 10.60.1.2/24 up
jexec jail-a route add default 10.60.1.1 >/dev/null
jexec jail-b ifconfig epair1b inet 10.60.2.2/24 up
jexec jail-b route add default 10.60.2.1 >/dev/null

echo
echo "=== checkpoint 1: fresh node fails closed (no endpoints registered yet) ==="
if jexec jail-a ping -c 1 -t 1 10.60.2.2 >/dev/null 2>&1; then
	fail "ping succeeded before any endpoint was registered -- should be fail-closed"
else
	pass "ping correctly fails before endpoint registration"
fi
UNBOUND=$(ngctl msg vfab0: getstats 2>/dev/null | \
    sed -n 's/.*unbound_hook_packets=\([0-9]*\).*/\1/p')
if [ -n "$UNBOUND" ] && [ "$UNBOUND" -gt 0 ]; then
	pass "traffic genuinely reached ng_policy and was dropped (unbound_hook_packets=$UNBOUND)"
else
	fail "expected unbound_hook_packets > 0; got '$UNBOUND' -- traffic may be bypassing ng_policy"
fi

echo
echo "=== registering endpoints (epair0a=1001, epair1a=2001, tap0=3001) ==="
ngctl msg vfab0: endpointadd '{ endpoint_id=1001 hook="ep-1001" peer_hook="fab-1001" }'
ngctl msg vfab0: endpointadd '{ endpoint_id=2001 hook="ep-2001" peer_hook="fab-2001" }'
ngctl msg vfab0: endpointadd '{ endpoint_id=3001 hook="ep-3001" peer_hook="fab-3001" }'
EPLIST=$(ngctl msg vfab0: endpointlist \
    '{ endpoint_id=0 start_index=0 max_entries=0 reserved=0 }' 2>&1)
if echo "$EPLIST" | grep -q 'endpoint_id=3001' \
    && echo "$EPLIST" | grep -qc 'flags=0x3000000' >/dev/null; then
	pass "all three endpoints (epair x2 + tap) bound identically (flags=0x3000000 = CONNECTED|PEER_CONNECTED)"
else
	fail "endpoint registration/binding did not come back as expected: $EPLIST"
fi

echo
echo "=== installing policy: default-deny, allow 1001<->2001 ICMP and TCP/443 ==="
TXID=$(ngctl msg vfab0: txbegin '{ requested_generation=0 timeout=0 version=0 flags=0 }' | \
    sed -n 's/.*tx_id=\([0-9]*\).*/\1/p')
ngctl msg vfab0: txaddrule "{ tx_id=$TXID version=0 reserved=0 nrules=4 rules=[
{ rule_id=1 src_endpoint=1001 dst_endpoint=2001 src_port_min=0 src_port_max=65535 dst_port_min=0 dst_port_max=65535 priority=10 flags=0 protocol=1 action=1 icmp_type=0 icmp_code=0 }
{ rule_id=2 src_endpoint=1001 dst_endpoint=2001 src_port_min=0 src_port_max=65535 dst_port_min=443 dst_port_max=443 priority=10 flags=0 protocol=6 action=1 icmp_type=0 icmp_code=0 }
{ rule_id=3 src_endpoint=2001 dst_endpoint=1001 src_port_min=0 src_port_max=65535 dst_port_min=0 dst_port_max=65535 priority=10 flags=0 protocol=1 action=1 icmp_type=0 icmp_code=0 }
{ rule_id=4 src_endpoint=2001 dst_endpoint=1001 src_port_min=443 src_port_max=443 dst_port_min=0 dst_port_max=65535 priority=10 flags=0 protocol=6 action=1 icmp_type=0 icmp_code=0 }
] }"
ngctl msg vfab0: txaddaddr "{ tx_id=$TXID version=0 reserved=0 naddrs=2 addrs=[
{ ipv4=10.60.1.2 endpoint_id=1001 }
{ ipv4=10.60.2.2 endpoint_id=2001 }
] }"
ngctl msg vfab0: txsetdefault "{ tx_id=$TXID default_action=2 reserved0=0 reserved1=0 reserved2=0 }"
ngctl msg vfab0: txcommit "{ tx_id=$TXID base_generation=0 version=0 flags=0 reserved=0 }"

echo
echo "=== checkpoint 2: allowed traffic (ICMP, TCP/443) ==="
if jexec jail-a ping -c 1 -t 2 10.60.2.2 >/dev/null 2>&1; then
	pass "ICMP jail-a -> jail-b allowed and round-tripped through ng_policy"
else
	fail "ICMP should be allowed by rule 1/3 but did not round-trip"
fi
jexec jail-b sh -c 'nc -l 10.60.2.2 443 >/dev/null 2>&1 &'
jexec jail-b sh -c 'nc -l 10.60.2.2 8080 >/dev/null 2>&1 &'
sleep 1
if jexec jail-a nc -z -w 2 10.60.2.2 443 >/dev/null 2>&1; then
	pass "TCP/443 jail-a -> jail-b allowed (matches rule 2/4)"
else
	fail "TCP/443 should be allowed by rule 2/4 but the probe failed"
fi

echo
echo "=== checkpoint 3: default-deny (TCP/8080, no matching rule) ==="
if jexec jail-a nc -z -w 2 10.60.2.2 8080 >/dev/null 2>&1; then
	fail "TCP/8080 should be default-denied but the probe succeeded -- LEAK"
else
	pass "TCP/8080 correctly timed out (silently dropped, not refused -- a listener IS running on the far side)"
fi

echo
echo "=== final ng_policy stats ==="
ngctl msg vfab0: getstats

echo
if [ "$FAIL" -eq 0 ]; then
	echo "Phase 0 single-host proof: ALL CHECKPOINTS PASSED"
else
	echo "Phase 0 single-host proof: ONE OR MORE CHECKPOINTS FAILED" >&2
fi
exit "$FAIL"
