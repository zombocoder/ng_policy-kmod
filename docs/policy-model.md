# Policy model

Rules, generations, and — the fact worth reading twice — statelessness.
For the wire format see [`control-api.md`](control-api.md); for how a
rule is evaluated against a live packet see
[`packet-path.md`](packet-path.md); for the endpoint identities a rule
references see [`endpoint-model.md`](endpoint-model.md).

## v0.1 is stateless

**An ALLOW rule in one direction does not permit the reverse
direction.** `A -> B tcp/443 ALLOW` says nothing about `B -> A`. There
is no connection table, no automatic "allow the reply," nothing that
remembers a flow was permitted a moment ago. If endpoint `B` needs to
answer, userland must compile and commit the reverse rule
(`src_endpoint=B, dst_endpoint=A, ...`) explicitly, in the same or a
later generation.

This is a deliberate scope boundary, not an oversight — the design
spec's out-of-scope list (§5) excludes "any stateful behaviour" from
v0.1 entirely, and a stateful flow table is listed as a v0.3 candidate
only after the stateless implementation is proven stable (design spec
§15). Every rule, every match, every commit in this module is a pure
function of the current generation and the current packet; nothing
about past packets changes future decisions. Concretely: `TCP` here
means "match on the TCP header's ports," not "track the connection" —
there is no SYN/ACK awareness, no sequence tracking, no notion of an
established flow. A rule matching `protocol=TCP` matches every TCP
segment independently, including a bare ACK with no matching SYN ever
seen.

If a userland compiler wants request/reply symmetry, it must generate
both directions itself — that is a compiler-level concern this
document flags precisely because the code gives no hint of it: a rule
set that "looks complete" by covering every intended request direction
will silently drop every reply unless the compiler also emitted the
mirror rules.

## Rules

```c
struct ng_policy_rule {
	uint64_t rule_id;
	uint32_t src_endpoint;
	uint32_t dst_endpoint;
	uint16_t src_port_min, src_port_max;
	uint16_t dst_port_min, dst_port_max;
	uint16_t priority;
	uint16_t flags;         /* ICMP_TYPE | ICMP_CODE */
	uint8_t  protocol;      /* 0=ANY, or an IPPROTO_* number */
	uint8_t  action;        /* ALLOW=1, DROP=2 */
	uint8_t  icmp_type;
	uint8_t  icmp_code;
};
```

32 bytes, no implicit padding (verified in
[`control-api.md`](control-api.md)'s batching arithmetic). `rule_id` is
caller-assigned and must be unique within a generation — a duplicate
`rule_id` inside one transaction fails the whole commit `EINVAL`
(`ngp_tx_validate_dups()`); IDs are not required to be unique *across*
generations, since a rule's identity and its counters both die with
the generation they were committed in.

### Wildcards

- `src_endpoint` / `dst_endpoint` of `NG_POLICY_EP_ANY` (`0`) matches
  any endpoint on that side.
- `protocol` of `NG_POLICY_PROTO_ANY` (`0`) matches any IP protocol.
- A port range of `[0, 65535]` — `NG_POLICY_PORT_ANY_MIN`/`_MAX` —
  matches any port. There is no separate "wildcard" flag for ports;
  the full range *is* the wildcard.

No mask or prefix semantics anywhere — endpoint IDs, protocol numbers,
and ports are matched by exact value or by the ANY/full-range sentinel,
never by a bitmask.

### Priority and evaluation order

**Lower numeric `priority` is evaluated first.** Ties are broken by
insertion order within the transaction that installed them (the
position each rule held in the `TX_ADD_RULE` calls that built the
generation), which makes the ordering total and deterministic across
repeated commits of the same input — see `ngp_rule_order_cmp()` in
`ng_policy_policy.c`, which sorts by `(priority, pos)` as a compound
key.

**First match wins.** There is no longest-match, most-specific-wins, or
any other specificity rule — evaluation stops at the first rule (in
priority-then-insertion order) whose fields all match the packet. A
broad, low-priority-number rule placed ahead of a narrower one will
shadow it completely; ordering rules correctly is the control plane's
responsibility, not something the node infers from how specific a rule
"looks."

A packet that matches no rule at all takes the generation's
`default_action` — see below. This is proven by
`test_rule_priority`, `test_rule_priority_ties_by_order`, and the three
`test_rule_merge_*` tests, which specifically check that the
source-endpoint index's merge-walk (see "Lookup structure" below)
preserves this exact ordering rather than only approximating it.

### ICMP

`icmp_type`/`icmp_code` are matched only when the corresponding flag
(`RULE_F_ICMP_TYPE`/`RULE_F_ICMP_CODE`) is set on the rule, and only
against ICMP packets — a rule with `RULE_F_ICMP_TYPE` set never matches
a TCP or UDP packet regardless of what `icmp_type` happens to contain
(`ngp_rule_matches()` checks `m->protocol == NG_POLICY_PROTO_ICMP` as
part of the flag check). A rule with neither flag set matches any ICMP
type/code, same as a wildcard.

## Default action

`default_action` is **not** part of `ng_policy_config` — it belongs to
the policy generation itself and is set once per transaction via
`TX_SET_DEFAULT`, which is mandatory: `TX_COMMIT` rejects a transaction
that never called it (`EINVAL`, via `ngp_tx_validate_refs()`'s
`!tx->has_default` check). This keeps "what happens when nothing
matches" versioned alongside the rules it applies to, rather than as a
node-wide setting that could silently outlive the generation that
assumed it. A brand-new node's *initial* empty snapshot (generation 0,
built by the constructor, before any transaction has ever committed)
hard-codes `default_action = DROP` — see the fail-closed warning in
[`ngctl-examples.md`](ngctl-examples.md).

## Generations

Every commit produces a new, immutable **generation**: a sorted rule
array, a source-endpoint index over it, an address map, a default
action, and per-rule counters, all living in one `struct
ng_policy_snapshot` with one lifetime. `TX_BEGIN`'s
`requested_generation` (0 meaning "active + 1") lets a caller either
take the next sequential generation or aim at a specific number; the
commit still requires `tx->generation > active` (`ESTALE` otherwise) and
optimistic concurrency via `base_generation` (see
[`control-api.md`](control-api.md)) independently gates whether the
swap is allowed to happen at all. A packet observes exactly one
generation in full, never a mixture of old rules and a new address map
or vice versa — the entire generation is replaced by a single pointer
swap. See [`concurrency.md`](concurrency.md) for why that swap is safe
without the reader taking a lock.

Rule and address-map counters are allocated **inside** the snapshot and
die with it: a new generation starts every rule at zero matches, and
the previous generation's counters are freed (after the net-epoch grace
period) along with everything else in it. `GET_RULE_STATS` and
`GET_STATS` both carry `generation` for exactly this reason — a caller
polling counters across a commit needs to know when the numbers reset
out from under it. See [`statistics.md`](statistics.md).

## Lookup structure

Rules are stored sorted by `(priority, insertion order)`. A
source-endpoint index (open-addressed hash buckets keyed by
`src_endpoint`, plus one separate list for `src_endpoint = ANY` rules)
holds **global rule indices in ascending order** in both the bucket and
the ANY list. A lookup merge-walks the packet's bucket and the ANY list
together, always taking the smaller global index next — because both
lists are already ascending, this visits candidates in exactly the
order a full linear scan of the sorted array would, while touching only
rules that could possibly match the packet's source endpoint. A hash
collision (a bucket holding rules for more than one `src_endpoint`)
costs an extra comparison, not a correctness bug, since
`ngp_rule_matches()` still checks `src_endpoint` explicitly. This
equivalence — merge-walk order equals full-scan order — is the load-
bearing correctness claim behind using an index at all, and it is
exercised directly (not just argued) by `test_rule_merge_any_wins`,
`test_rule_merge_specific_wins`, and `test_rule_merge_bucket_collision`.
The benchmark in `docs/performance.md` ("Lookup cost") independently
confirms the index is actually consulted at runtime: lookup latency
stays flat from 10 to 10,000 rules rather than growing linearly, which
a degenerate full-scan fallback would make visible.

Address lookup uses a separate open-addressed hash (linear probing,
sized to the next power of two at or above 2x the entry count, built
once per commit and never mutated), keyed on the IPv4 address in
network byte order. `0.0.0.0` is rejected at validation time
specifically so it can serve as the table's empty-slot marker.

## Reserved endpoint identities

| Name | Value |
|---|---|
| `NG_POLICY_EP_ANY` | `0x00000000` |
| (valid registered range) | `0x00000001` .. `0xfffffeff` |
| `NG_POLICY_EP_RESERVED_MIN` | `0xffffff00` |
| `NG_POLICY_EP_LOCAL_HOST` | `0xfffffffd` |
| `NG_POLICY_EP_EXTERNAL` | `0xffffffff` |

An address not present in the generation's address map resolves to
`EXTERNAL`, which — as covered in
[`packet-path.md`](packet-path.md#4-external-destination-rule-written-against-external)
— is a legal value to reference explicitly in a rule, not only an
internal fallback. `LOCAL_HOST` is never inferred from topology; see
[`endpoint-model.md`](endpoint-model.md) for exactly when it applies.

## What this document does not cover

Endpoint identity and hook binding: [`endpoint-model.md`](endpoint-model.md).
The concurrency and reclamation model behind "one pointer swap":
[`concurrency.md`](concurrency.md). Every counter's exact semantics:
[`statistics.md`](statistics.md). The commands that build and commit a
generation: [`control-api.md`](control-api.md).
