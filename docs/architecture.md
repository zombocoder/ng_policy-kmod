# Architecture

> A FreeBSD Netgraph kernel node for fast, stateless, identity-aware
> network policy enforcement using precompiled endpoint-based rules and
> atomic policy generations.

This document describes the node model: what `ng_policy` is inside the
kernel, why it is shaped the way it is, where its authority ends, and
what it deliberately does not know. For the wire format see
[`control-api.md`](control-api.md); for how a packet is decided see
[`packet-path.md`](packet-path.md); for the rule semantics see
[`policy-model.md`](policy-model.md).

## One node, one policy, many endpoints

A single `ng_policy` node (Netgraph type `"policy"`) owns three things:
an endpoint table, the currently active policy generation (an
immutable snapshot — rules, address map, default action, counters),
and a set of per-node and per-endpoint counters. There is no per-hook
or per-endpoint copy of the policy: every endpoint attached to the node
is evaluated against the same snapshot. Running multiple independent
policies means running multiple `ng_policy` nodes.

The node is created with `mkpeer` / `ngctl` like any other Netgraph
node type, and holds no state outside what the constructor allocates
(`src/ng_policy.c:ng_policy_constructor`) — no
files, no external database, no persistence across a reload. Everything
the node knows was told to it over its control socket since the last
`kldload`.

## Decision 1 — an endpoint is a pair of hooks

The central structural decision, carried through every other document,
is that an **endpoint is not a hook — it is two hooks**, registered
together by `NGM_POLICY_ENDPOINT_ADD` (`ng_policy_endpoint_add`, see
[`control-api.md`](control-api.md)):

- `hook` — the **workload side**. A packet arriving here was sent by
  this endpoint.
- `peer_hook` — the **fabric side** (an overlay, `ng_bridge`, a
  tunnel — whatever userland topology connects endpoints together). A
  packet arriving here is destined for this endpoint.

```
   workload                        fabric (ng_bridge, overlay, ...)
      |                                    |
   ep-1001 ---------.          .-------- fab-1001
                     v          ^
                 +----------------+
                 |    ng_policy    |
                 +----------------+
                     ^          v
   ep-2001 ---------'          '-------- fab-2001
      |                                    |
   workload                        fabric
```

An allowed packet is always forwarded to the **other hook of the same
endpoint** — `ep-1001`'s traffic that is allowed leaves on `fab-1001`,
and vice versa. The node never chooses an egress hook by looking up a
destination endpoint and picking *that* endpoint's hook; egress is
always "the peer of the hook this packet is bound to." Topology — which
fabric hook eventually reaches which physical or virtual destination —
is entirely userland's responsibility, established by whatever
connects to `peer_hook`.

**This is why the kernel makes no forwarding decision.** `ng_policy` is
a policy gate, not a switch: given a packet and the endpoint the
ingress hook fixes, it decides ALLOW or DROP and, if ALLOW, hands the
packet to the one pre-wired egress hook for that endpoint pair. It
never consults a routing table, never picks among multiple candidate
egress hooks, and never learns topology from traffic. Rejected
alternatives and their cost were recorded in the design spec (§2),
which is not part of this repository: a single shared "fabric" hook
would force the kernel to select an egress endpoint from the address
map, which *is* switching; one node per endpoint would duplicate the
snapshot and address map per endpoint.

**Binding is lazy and symmetric.** A hook may be connected before or
after its endpoint is registered with `ENDPOINT_ADD` — both orders
bind correctly (`ng_policy_hook_attach` binds a new hook against every
registered endpoint; `ng_policy_ep_add`'s `ngp_rebind_hooks` binds a
new endpoint against every existing unbound hook). Disconnecting a hook
clears only the binding — the endpoint and its counters survive — so a
later reconnect rebinds. See
[`endpoint-model.md`](endpoint-model.md) for the exact mechanics,
including what happens when two endpoints claim the same hook name.

**Hook naming is advisory.** `ep-<id>` / `fab-<id>` is the recommended
convention (`NG_POLICY_HOOK_EP_FMT` / `NG_POLICY_HOOK_FAB_FMT` in
`ng_policy.h`) but hook names carry no authority of their own — the
numeric `endpoint_id` assigned by `ENDPOINT_ADD` is the only identity
the node recognises. Nothing stops a deployment from naming hooks
however its topology tooling prefers.

## Boundary against userland

`ng_policy` is one component of a larger control plane, not the whole
of it:

```
   +------------------------------+          +------------------------+
   |   userland policy compiler    |          |  kernel fast path       |
   |   (not part of this repo)     |          |  ng_policy.ko           |
   |                                |          |                        |
   |  intent (tenants, labels,     |  control  |  endpoint table        |
   |  VPCs, security groups, ...)  | -socket-> |  policy snapshot       |
   |        |                      |  ASCII or |  address map           |
   |        v                      |  binary   |  counters              |
   |  endpoint IDs + IPv4 rules    |  NGM_POLICY_*                      |
   |  (ng_policy_rule /            |           |  match + forward       |
   |   ng_policy_addr)             |           |  (this document)       |
   +------------------------------+          +------------------------+
```

Everything left of the control socket — deciding *what* a rule should
say, translating tenant intent into `src_endpoint`/`dst_endpoint`
numbers, assigning endpoint IDs, deciding when to roll a new
generation — is a userland concern outside this repository. `ng_policy`
receives compiled rules and addresses, validates and stores them, and
enforces them at line rate. It compiles nothing and infers nothing.

## What the kernel does not know

By design, and enforced by the fact that no such field exists anywhere
in `ng_policy_msg.h`, `ng_policy_var.h`, or the matcher
(`ng_policy_policy.c:ngp_rule_matches`), the kernel node has no concept
of:

- tenant
- VPC
- subnet
- jail
- VM
- label
- application
- environment
- cluster

A rule's only vocabulary is `src_endpoint`, `dst_endpoint`, `protocol`,
port ranges, `icmp_type`/`icmp_code`, `priority`, `flags`, and
`action`. An endpoint's only identity is a 32-bit `endpoint_id` chosen
by userland (`design spec §1`: "The kernel module knows only: endpoint
ID, address, protocol, port, ICMP type/code, action, generation"). Any
notion of "this endpoint belongs to tenant X" or "this address is in
VPC Y" is encoded — if at all — by userland's *choice* of endpoint ID
and by which rules it compiles, never interpreted by the kernel. This
is what keeps the module small enough to fuzz and reason about
exhaustively, and it is a hard boundary: adding jail- or VM-awareness
to `ng_policy` itself would be a different module.

## Source layout

```
src/
  ng_policy.h           public constants: node type, actions, modes, reserved IDs
  ng_policy_msg.h        public control ABI: cookie, commands, structures, ng_parse types
  ng_policy_var.h        internal structures shared across the .c files (not installed)
  ng_policy.c             type registration, constructor/destructor, hooks,
                         message dispatch, rcvdata, ngp_decide
  ng_policy_packet.c      Ethernet / IPv4 / TCP / UDP / ICMP parsing to flat metadata
  ng_policy_policy.c      rule storage, matching, generations, transactions,
                         atomic snapshot replacement
  ng_policy_endpoint.c    endpoint table, hook binding, address map
  ng_policy_stats.c       counters: allocation, aggregation, reset
  Makefile
```

Each translation unit has a narrow, testable contract (design spec
§11): the parser takes an `mbuf` and returns flat metadata, knowing
nothing about policy; the matcher takes metadata and a snapshot,
knowing nothing about mbufs or hooks; the endpoint table knows nothing
about packets. `ng_policy_var.h` exists specifically so these internal
structures do not have to leak into the public, installed
`ng_policy.h`/`ng_policy_msg.h` headers.

## Node lifecycle

- **Constructor** (`ng_policy_constructor`): allocates `priv`, an empty
  endpoint hash table, and an *empty* snapshot at generation 0 with
  `default_action = DROP` — the node is fail-closed from the instant it
  exists (see the warning at the top of
  [`ngctl-examples.md`](ngctl-examples.md)).
- **`newhook`**: allocates a small per-hook private structure and
  attempts to bind it against every registered endpoint.
- **`disconnect`**: unbinds the hook (endpoint state survives),
  frees the hook private through the net epoch, and — standard
  Netgraph behaviour — calls `ng_rmnode_self()` once the node has zero
  hooks. A control-only session (e.g. a bare `ngctl -f -` script that
  never wires a persistent data hook) therefore tears its own node
  down the moment the connecting process exits; see the note in
  [`ngctl-examples.md`](ngctl-examples.md).
- **`shutdown`**: marks the node as shutting down, force-reaps every
  open transaction, flushes every endpoint, publishes a `NULL` policy
  pointer and defers the last snapshot's free through the net epoch,
  frees the endpoint hash and the counters, and finally frees `priv`
  itself. Nothing is leaked across repeated create/destroy —
  `tests/ngp_stress.sh` and `vmstat -m` are the proof (see
  [`development.md`](development.md)).

For the concurrency model underneath all of this — why the swap in
`TX_COMMIT` is safe, and what the net epoch is actually protecting —
see [`concurrency.md`](concurrency.md).
