#!/bin/sh
#
# Dataplane throughput probe: ng_policy in line, generating load with
# ng_source and reading the node's own packet counters.
#
# This is NOT a two-NIC "bare ng_bridge vs. ng_policy in line" wire
# comparison -- it does not forward real line-rate traffic between two
# physical ports.  It wires an ng_source node to a single live
# interface's ng_ether hook, injects ng_policy's endpoint hook with a
# synthetic frame replayed as fast as the source node and the host's
# mbuf allocator allow, and reports how many packets ng_policy itself
# counted.  That measures the node's own per-packet processing rate,
# which is the number this project's dataplane actually needs, but it
# is not a claim about NIC line rate, driver TX rate, or anything
# downstream of the (deliberately unconnected) far hook.  A genuine
# wire-rate comparison against ng_bridge would need two physical or
# virtual interfaces, an external packet generator (or a second host)
# driving one of them at a known rate, and ng_policy/ng_bridge bridging
# to the other -- that setup is out of scope for this script and was
# not built or run here.
#
# Prerequisites (all required; the script refuses to run without them):
#   - Real FreeBSD (not Linux, not a jail without device access).
#   - root (this loads kernel modules and drives a live interface).
#   - One interface, given as $1, that is safe to flood: ng_source
#     will push frames through it as fast as it can for $2 seconds.
#     Do not point this at an interface carrying production traffic --
#     it competes with, and can starve, whatever else uses that link.
#   - ng_ether, ng_source and ng_policy.ko all buildable/loadable on
#     this kernel (kldload -n probes each one below and refuses to
#     continue if any is missing).
#   - Explicit confirmation via -y/--yes, precisely because this can
#     disrupt a shared interface; there is no safe default here to
#     silently pick.
#
# This script was written but not run: the sandbox this project was
# developed in has no real or virtual interface safe to flood, so
# "line-rate pps" has NOT been measured for ng_policy anywhere in this
# repository's history so far.  docs/performance.md says so plainly.
#
# Usage: bench-dataplane.sh -y <interface> [seconds]

set -e

usage() {
	echo "usage: $0 -y <interface> [seconds]" >&2
	echo "  -y / --yes   required: confirms you understand this floods" >&2
	echo "               <interface> with synthetic traffic for the" >&2
	echo "               duration given (default 10s)." >&2
	exit 1
}

CONFIRMED=0
case "${1:-}" in
-y|--yes)
	CONFIRMED=1
	shift
	;;
esac

IF=${1:-}
SECS=${2:-10}

if [ "$CONFIRMED" -ne 1 ] || [ -z "$IF" ]; then
	usage
fi

OSTYPE=$(sysctl -n kern.ostype 2>/dev/null || echo "")
if [ "$OSTYPE" != "FreeBSD" ]; then
	# sysctl(kern.ostype) is used rather than uname -s: some sandboxed
	# or compat-layered shells present a spoofed uname(3) sysname
	# (observed: "Linux" from uname -s on a genuine FreeBSD kernel,
	# confirmed by kldstat/sysctl on the same host) while sysctl still
	# answers the real kernel directly.
	echo "bench-dataplane.sh: this drives real FreeBSD netgraph nodes" >&2
	echo "  (ngctl, kldload, ng_source) -- refusing to run on kernel" >&2
	echo "  ostype '$OSTYPE' (expected FreeBSD)." >&2
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "bench-dataplane.sh: must run as root (kldload + live interface)." >&2
	echo "  e.g.: doas $0 -y $IF $SECS" >&2
	exit 1
fi

if ! ifconfig "$IF" >/dev/null 2>&1; then
	echo "bench-dataplane.sh: interface '$IF' does not exist -- refusing" >&2
	echo "  to guess.  Run 'ifconfig -l' to list real interface names." >&2
	exit 1
fi

case "$IF" in
lo*)
	echo "bench-dataplane.sh: '$IF' looks like a loopback interface." >&2
	echo "  ng_source needs a real (or real-enough) link; loopback" >&2
	echo "  traffic through ng_ether does not exercise the same path" >&2
	echo "  as an actual NIC.  Refusing." >&2
	exit 1
	;;
esac

for mod in ng_ether ng_source; do
	if ! kldload -n "$mod" 2>/dev/null && ! kldstat -q -m "$mod" 2>/dev/null; then
		echo "bench-dataplane.sh: kernel module '$mod' is not loaded" >&2
		echo "  and could not be loaded from the standard module path." >&2
		exit 1
	fi
done

# ng_policy.ko is an out-of-tree module, not installed into the
# standard /boot/modules search path, so it is loaded by explicit path
# relative to this script -- the same path the project's own workflow
# uses (see AGENTS.md / task briefs: "doas kldload
# .../sys/netgraph/ng_policy/ng_policy.ko").  A bare "kldload -n
# ng_policy" here would just fail with "module not found" and be more
# confusing than useful.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NGP_KO="$SCRIPT_DIR/../sys/netgraph/ng_policy/ng_policy.ko"
if ! kldstat -q -m ng_policy 2>/dev/null; then
	if [ ! -f "$NGP_KO" ]; then
		echo "bench-dataplane.sh: ng_policy is not loaded and" >&2
		echo "  $NGP_KO does not exist -- build it first:" >&2
		echo "  make -C $SCRIPT_DIR/../src" >&2
		exit 1
	fi
	if ! kldload -n "$NGP_KO" 2>/dev/null; then
		echo "bench-dataplane.sh: kldload of $NGP_KO failed." >&2
		exit 1
	fi
fi

cleanup() { ngctl shutdown bench: 2>/dev/null || true; }
trap cleanup EXIT

# ng_policy in line: source -> policy(ep) -> policy(fab) -> discard.
# The far hook (fab-1001) is deliberately left unconnected: this probe
# measures ng_policy's own accounting, not a second hop.
ngctl -f - <<EOF
mkpeer policy ctl ctl0
name .:ctl bench
msg bench: endpointadd { endpoint_id=1001 hook="ep-1001" peer_hook="fab-1001" }
mkpeer bench:ep-1001 source active ep-1001
EOF

echo "generating for ${SECS}s on $IF ..."
ngctl msg bench:ep-1001 setiface "\"$IF\""
ngctl msg bench:ep-1001 start 0
sleep "$SECS"
ngctl msg bench:ep-1001 stop

ngctl msg bench: getstats
echo
echo "divide packets_total by $SECS for pps; repeat with"
echo "  ngctl msg bench: setmode { mode=0 }   # DISABLED, for the baseline"
echo "to see how much of the per-packet cost is ng_policy_match() itself"
echo "versus the fixed cost of entering/leaving the node."
