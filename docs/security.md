# Security

Every control message `ng_policy` accepts is untrusted input from the
moment it enters `ng_policy_rcvmsg()`. This document covers the
validation performed, the threat list the requirements name, the
privilege model, the one deliberate residual gap and why it stays
open, and — separately, because it is the more important point — what
the test suite, fuzzer, and stress suite actually establish about
memory safety versus what they only make *likely*.

## Threat list and how each is addressed

| Threat | Where it is addressed |
|---|---|
| Malformed message sizes | `NGP_ARGLEN()`/explicit `arglen` checks before any field is read, for every fixed-size command; the batched commands (`TX_ADD_RULE`/`TX_ADD_ADDR`) recompute the exact expected size from the caller-supplied count and compare with `!=`, not `<` |
| Integer overflow | `nrules`/`naddrs` are checked against `(UINT32_MAX - sizeof(header)) / sizeof(entry)` before the multiply that computes the expected message size; transaction growth (`ngp_tx_grow()`) checks `need > hardmax` before any allocation math |
| Duplicate IDs | Duplicate `rule_id` and duplicate address entries both fail the whole commit (`ngp_tx_validate_dups()`); duplicate endpoint IDs are rejected `EEXIST` unless `F_REPLACE` is set |
| Invalid ranges | Port ranges (`min <= max`), action/mode enum validity, protocol byte range (implicit — any `uint8_t` is representable), reserved endpoint IDs used where forbidden — all in `ngp_tx_validate_refs()` and the per-command checks in `ng_policy.c` |
| Excessive allocation | `ng_policy_max_endpoints`/`max_rules`/`max_addrs`/`max_tx`/`max_tx_bytes`, all `ENOSPC` on the limit, all sysctl-configurable and covered by `test_endpoint_limit`/`test_rule_limit`/`test_transaction_limit` |
| Transaction abuse | `tx->committing` blocks any mutation of a transaction that is mid-commit (`EBUSY`); a periodic callout reaps expired transactions (`tx_timeouts`); optimistic concurrency (`base_generation`) rejects a stale commit before it can silently clobber a newer one |
| Stale references | `ESTALE` on a commit whose `base_generation` no longer matches the active generation, and independently on a transaction whose own target generation has already been passed |
| Races | See [`concurrency.md`](concurrency.md) — every control message is a Netgraph writer, so control operations are already serialised per node; the net epoch protects deferred reclamation against genuinely concurrent packet traffic |
| Use-after-free / double-free | Every free of a shared object (`ep`, `hookpriv`, `snapshot`) that a packet could still be holding a pointer to goes through `NET_EPOCH_CALL()`; `ng_policy_snapshot_free()` guards `rule_pkts`/`rule_bytes` independently so a partially-built snapshot never double-frees or NULL-derefs an array that failed to allocate |
| mbuf parsing errors | See "Parser bounds safety" below — every field read in `ng_policy_parse()` is checked against `m_pkthdr.len` first, with no `m_pullup` and no assumption of header contiguity |

Authorisation is left entirely to the existing Netgraph control-socket
privilege boundary — `ng_policy` implements no authentication or
authorisation of its own. Anyone who can open a Netgraph control socket
to this node can reconfigure it arbitrarily, including installing a
permit-everything policy or deleting every endpoint; that privilege
boundary (who may open such a socket) is a FreeBSD-wide concern outside
this module's scope.

## The array-length clamp is deliberately absent

**This will be tempting to "fix" a second time — do not, without first
reading this section and the comment above
`ng_policy_rule_ary_len()` in `ng_policy.c`.** The `getLength` callback
for every variable-length array in this ABI (`rules[]` in
`TX_ADD_RULE`, `addrs[]` in `TX_ADD_ADDR`, `entries[]` in the three
windowed responses) reports the element count straight from the
caller-supplied count field (`nrules`, `naddrs`, `returned`) with no
upper bound derived from the surrounding buffer's actual size.

The reason is not oversight — `ng_parse`'s `getLength` callback
contract cannot express the fix. The same callback runs in **both**
directions of ASCII conversion, and `start`/`buf` mean different things
in each:

- `NGM_BINARY2ASCII` (printing a real, already-received
  `struct ng_mesg`): `start` points at that message's real `data[]`,
  and `header.arglen` genuinely bounds how much of it exists.
- `NGM_ASCII2BINARY` (parsing a hand-typed `ngctl` command, e.g.
  `txaddrule { nrules=3 rules=[...] }`): `start`/`buf` point into an
  **output buffer under construction** — there is no real `struct
  ng_mesg` behind it yet, and the header being built there does not
  yet describe a serialized binary payload. `ng_base.c:2881`'s
  `NGM_ASCII2BINARY` handler literally does
  `bcopy(ascii, binary, sizeof(*ascii))` before parsing proceeds — at
  the moment `getLength` would be called during this direction, the
  binary header's `arglen` slot at that address does not hold a byte
  count at all; it holds whatever the ASCII-side struct's layout put
  there, which for these particular commands is the **ASCII string
  length**, not the binary array element count.

A clamp keyed off that field (tried during implementation, and
reverted — see the project's SDD ledger) therefore computes a bogus
element budget during `ASCII2BINARY` and rejects legitimate hand-typed
input with `E2BIG` — breaking exactly the workflow
[`ngctl-examples.md`](ngctl-examples.md) depends on and that
row 27 of [`verification.md`](verification.md) requires (`ngctl` standalone operation,
including hand-typed rule loading). A `getLength` callback has no
parameter that tells it which direction it is being called from, so it
cannot apply the bound only where the bound is meaningful.

**What the residual gap actually allows:** a crafted
`NGM_BINARY2ASCII` request against a `struct ng_mesg` whose `nrules`/
`naddrs`/`returned` field claims more elements than the message's real
`arglen` supports could cause the ASCII printer to read past the
message buffer. Two things bound how much this matters in practice.
First, producing such a message requires already holding Netgraph
control-socket privilege against this node — the same privilege that
already permits installing a permit-everything policy or deleting
every endpoint, so this is not a privilege escalation, only an
information-disclosure-shaped over-read available to a caller who
could already reconfigure the node arbitrarily. Second, this is not
unique to `ng_policy` — it is the tree-wide idiom for every in-tree
Netgraph node with a variable-length array type (`ng_bridge`'s
`getTableLength`, for one concrete example, reads `numHosts` straight
out of the buffer with the identical lack of a bound). A correct fix
belongs upstream, in `ng_parse`'s `getLength` callback contract — it
would need to carry a real buffer length alongside `start`/`buf`, which
it does not today.

## Privilege model

No authentication, no authorisation logic, and no notion of "which
caller may issue which command" exists inside `ng_policy` itself. Every
`NGM_POLICY_*` command is available to anyone who can reach the node
over a Netgraph control socket. This mirrors every other Netgraph node
in the base system: the privilege boundary is "can this process open
this control socket at all" (ordinarily gated by filesystem/jail/
capability restrictions on `/dev/ng*` access at a level above this
module), not anything `ng_policy` checks per-command.

## Fuzzing coverage

`tests/ngp_fuzz.c` (seeded, reproducible — `xorshift32`, seed and
iteration count as command-line arguments) drives two independent
randomised surfaces through the same live node over the real control
and data sockets:

- **Control-message fuzzing**: randomised `NGM_POLICY_*` commands with
  bad lengths, invalid enum values, overflow-prone counts, and
  transaction-abuse sequences (mutating a transaction after commit,
  double-aborting, committing an unknown `tx_id`).
- **Packet fuzzing**: randomised Ethernet/IPv4/TCP/UDP/ICMP frames —
  truncated headers, invalid IHL, malformed transport headers,
  fragments, and unusual mbuf layouts (via
  `net.graph.policy.debug_force_copy`, which forces the parser's
  non-contiguous copy path unconditionally).

Success is defined negatively: the node must not panic, must not leak,
and must keep answering — `ngp_fuzz` does not attempt to assert
specific outcomes for arbitrary fuzzed input, only that the node
survives it and remains responsive. A verification run for this
document (seed `12345`, 200,000 iterations) completed cleanly: 149,991
packets survived to being counted, 29,250 as malformed and 35,920 as
unsupported, with the node still answering `ngctl` afterward.

## Parser bounds safety was established by review, not by fuzzing

This distinction matters and is worth stating precisely rather than
letting a green fuzzer run imply more than it proves.
`ng_policy_parse()`'s bounds discipline — every field read checked
against `m_pkthdr.len` before it happens, via the shared `ngp_at()`
helper, with no `m_pullup` and no assumption that any header is
contiguous in the first mbuf — is a property that was verified by
**direct code review** against the parser's own logic (every `ngp_at()`
call site checked, every offset arithmetic path checked for
mixing signed and unsigned in a way that could underflow), not
discovered or falsified by throwing random bytes at it. Fuzzing is
complementary evidence, not a replacement for that review: it
increases confidence that the reviewed invariant holds across inputs
the reviewer did not specifically construct, but a fuzzer that ran
200,000 iterations without finding a crash is not proof that no
crashing input exists — only that none of these particular
pseudorandom ones triggered one.

## What "no panic, no hang, no leak" does and does not establish

**This kernel is built with `INVARIANTS` disabled**
(`sys/netgraph/ng_policy/opt_global.h` — the compiled option set has
`SMP`, `MAC`, `VIMAGE`, `EARLY_AP_STARTUP`, `CC_CUBIC`, `NEW_PCIB`, and
`NETLINK`, and nothing else; no `INVARIANTS`, no `WITNESS`, no
`INVARIANT_SUPPORT`). This has a direct consequence for how much a
clean test run actually proves: `INVARIANTS` is what turns a
use-after-free, a double-free, or a lock-ordering violation into an
immediate, loud panic on the exact operation that triggered it. With it
off, all three of those bug classes can — and, in the general case,
often do — fail **silently**: a use-after-free may read stale-but-still
-mapped memory and produce a wrong answer instead of crashing; a
double-free may corrupt allocator metadata that only manifests as a
crash much later, on an unrelated allocation; a lock misuse may produce
a subtle ordering bug that never deadlocks in any particular test run.

So, precisely, what the 62-test suite, the fuzzer, and
`tests/ngp_stress.sh` establish:

- **No panic** during the runs actually performed.
- **No hang** — the node remains responsive to `ngctl` after every run,
  including after the fuzzer and after the concurrency stress tests.
- **No leak**, as measured by `vmstat -m`'s `ng_policy` malloc-type
  in-use count returning to its baseline (typically absent from the
  table entirely, or explicitly `0 0`) after repeated node
  create/destroy and module load/unload cycles.
- **The node stays responsive** — `ngctl list`/`ngctl msg` continue to
  work correctly after every stress run performed.

What none of that establishes on its own, given `INVARIANTS` is off:
**general memory safety** in the sense of "no use-after-free or
double-free is reachable by any input," independent of whether that
particular run happened to surface one. The confidence this project
has in memory safety comes from the combination of design (net-epoch
deferred reclamation with the pointer-discipline rule in
[`concurrency.md`](concurrency.md#no-epoch-deferred-object-may-point-back-to-priv)),
code review, and testing/fuzzing — not from testing and fuzzing alone,
and not from the absence of a panic under `INVARIANTS`-off, which would
mask exactly the class of bug a panic-based test methodology is
usually relied on to catch.
