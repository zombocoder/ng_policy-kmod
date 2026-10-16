# Phase 0: single-host interface fabric proof

Runbook: [`tools/phase0-single-host-fabric.sh`](../tools/phase0-single-host-fabric.sh)

Automated equivalent:
[`tests/integration/fabric_test.go`](../tests/integration/fabric_test.go) and
[`tests/integration/rig.go`](../tests/integration/rig.go) — the same machine
and the same checkpoints, built by `vnetd` from a config file instead of by
hand from `ngctl`, plus the two agent properties only a real kernel can
settle (a converged pass writes nothing; a cold start converges). Run it
with:

```sh
doas env GOTOOLCHAIN=local /usr/local/go126/bin/go test -tags integration ./tests/integration/ -count=1 -v
```

The script stays. It is the thing the suite is checked against, it needs no
Go toolchain, and it is what somebody reaches for when the question is "does
`ng_policy` work on this machine at all" rather than "does `vnetd` reproduce
it". Both are run before this document is changed.

## What this is

The `vnetfabric` design spec (§68, "Development Phases") calls for a
manual, no-code "Phase 0" before any control-plane software is
written: prove that arbitrary FreeBSD interfaces can be wired into a
policy-enforced fabric using nothing but stock FreeBSD primitives
(`ngctl`, `ifconfig`, `jail`), with the core design principle — "the
fabric manages network interfaces, not workloads" (spec §5) — actually
holding up against a real kernel, not just asserted in a document.

This is the single-host slice of that phase: one machine, no overlay,
no second node. It exists to answer one question before any userland
`vnetd`/`vpcd` code gets written: **given `ng_policy` as it exists
today, does the "interface first" model actually work end to end?**

Cross-host connectivity (VXLAN, a real Phase 0 with two machines) is
explicitly out of scope here and untested by this script.

## What it proves

Run `doas tools/phase0-single-host-fabric.sh -y` and it will, on a real
FreeBSD host with `ng_policy.ko` built:

1. Create three interfaces of two different Ethernet-capable kinds
   (`epair0`/`epair1`, `tap0`) and confirm `ng_ether` auto-attaches a
   netgraph node to each — no `ng_policy`-specific code needed for
   that part.
2. Wire `ng_policy` fully in-line on all three (`lower`→endpoint hook,
   `upper`→fabric hook), and confirm a **fresh, unbound hook fails
   closed**: traffic is dropped and counted (`unbound_hook_packets`),
   not silently passed through.
3. Register all three as `ng_policy` endpoints and confirm `epair` and
   `tap` bind **identically** at the control layer
   (`ENDPOINT_LIST` reports `CONNECTED|PEER_CONNECTED` for both) —
   direct evidence for spec §5's "the system must not care what is
   behind those interfaces."
4. Install a default-deny policy generation (spec §25/§54) with
   explicit `ALLOW` rules for ICMP and TCP/443 between two endpoints,
   and confirm:
   - allowed traffic (ping, a TCP/443 probe) gets through;
   - traffic with no matching rule (TCP/8080) is **silently dropped**,
     verified by probing a port with a live listener behind it and
     observing a timeout rather than a refusal — a refusal would mean
     the policy leaked the connection through to the listener.
5. All of this while cross-subnet delivery between the two live
   endpoints rides entirely on `net.inet.ip.forwarding=1` and the
   host's own routing table — no routing code was written for this,
   matching spec §33 ("the first implementation should avoid
   inventing a new routing protocol") and §7 (L3-first).

## What it does not prove

- **`tun` is out of scope, by design, not by gap.** `ng_policy` parses
  Ethernet frames (`docs/architecture.md`); `ng_ether` only attaches to
  Ethernet-type interfaces. `tun(4)` is an IP-only point-to-point
  pseudo-device with no Ethernet framing at all — it never gets an
  `ng_ether` node, so there is no hook to wire `ng_policy` into in the
  first place. `ng_iface` has the identical limitation (its `inet`
  hook carries raw IP packets, not Ethernet frames). This is a real
  boundary of `ng_policy` as it exists today, not a missing feature of
  this script.
- Multi-host / overlay connectivity. Everything here is one machine.
- Anything a future `vnetd` would do. This script *is* what a `vnetd`
  reconciliation loop would eventually automate — it's deliberately
  manual, per the spec's own Phase 0 description.

## Findings that will matter for `vnetd` (Phase 2)

Two things came up while building this that are genuinely relevant to
implementing the real node agent later, not just artifacts of the test
rig:

1. **`ng_policy` is stateless.** A rule allowing endpoint A to reach
   endpoint B does not implicitly allow B's replies back to A — each
   direction of a conversation needs its own rule. The first draft of
   this proof only had A→B rules; ICMP echo requests and TCP SYNs went
   through fine and then hung forever, because the *reply* traffic
   (B→A) had no matching rule and hit default-deny. A control plane
   compiling policy from a symmetric-looking intent ("frontend can
   talk to api on 443") must compile **two** rules, not one — this is
   a real compiler-design constraint on the future `vpcd`/`vnetd`
   policy-compilation step (spec §23), not just a scripting mistake to
   avoid.
2. **Same-host address collisions are a real hazard.** The first
   version of this test put both simulated endpoint addresses directly
   on the host (no jails). It "worked" — the ping succeeded — but
   `ng_policy`'s own counters showed zero packets processed. FreeBSD's
   IP stack recognises any address configured on any of its own
   interfaces and delivers to it via the `lo0` shortcut, bypassing the
   wire (and therefore bypassing `ng_policy`) entirely, regardless of
   which interface the routing table would otherwise have chosen. The
   fix — isolating each simulated endpoint in its own VNET jail — is
   also exactly the real-world deployment shape the spec describes
   (§1.1: "A VNET jail may be connected through an `epair` interface"),
   so this wasn't a detour; it's the same requirement a real multi-jail
   deployment already has for a different reason (workload isolation
   rather than avoiding a kernel shortcut). Worth remembering for
   `vnetd`: a node agent that ever needs to originate or receive real
   test traffic on behalf of an endpoint it manages will hit the same
   shortcut unless that endpoint's address genuinely lives in a
   separate network stack.

## Running it

```sh
doas tools/phase0-single-host-fabric.sh -y
```

Tears everything down again automatically (safe to re-run — it
refuses to start if it finds a leftover `epair0a`, `jail-a`, `vfab0`,
etc. from a previous run that didn't clean up). Pass a positive second
argument to leave the rig up for manual poking afterward:

```sh
doas tools/phase0-single-host-fabric.sh -y 300   # leave up 5 minutes
```

Both runs during development completed with `ALL CHECKPOINTS PASSED`
and left the host in its original state (`ifconfig -l` back to just
the physical interfaces + `lo0`, `jls` empty, no leftover `ngctl`
policy nodes).
