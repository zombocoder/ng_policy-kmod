# Verification

What the module is meant to guarantee, and the test or measurement that
shows each property. For the commands that run these checks, see
[`development.md`](development.md#full-verification-sequence).

Thirty properties the module is meant to have, each paired with the
thing that actually demonstrates it. **Where a row has no test that
proves it, the row says so** rather than covering the gap with a
plausible-sounding claim — which is the only reason a table like this
is worth reading instead of being a list of assertions.

The numbering is this project's own. It originally tracked a section of
a requirements document that is not part of this repository and cannot
be consulted here, so the numbers index these rows and nothing else.

| # | Property | Demonstrated by |
|---|---|---|
| 1 | Loads and unloads cleanly, with no leaks across the module lifecycle | `doas kldload`/`kldunload` + `test_node_lifecycle` + `vmstat -m | grep -c ng_policy` = 0 |
| 2 | Enforces ALLOW/DROP for TCP | `test_policy_matrix`, `test_forward_ep_to_fab`, `test_forward_fab_to_ep` |
| 3 | Enforces ALLOW/DROP for UDP | `test_udp_rules` |
| 4 | Enforces ALLOW/DROP for ICMP, matched on type/code | `test_icmp_type_code_rules` |
| 5 | Wildcards: `ANY` endpoint, `ANY` protocol, full port range | `test_wildcards` |
| 6 | Priority: lower first, ties by insertion order, first match wins | `test_rule_priority`, `test_rule_priority_ties_by_order`, `test_rule_merge_any_wins`, `test_rule_merge_specific_wins`, `test_rule_merge_bucket_collision` |
| 7 | Three operating modes: `DISABLED` / `PERMISSIVE` / `ENFORCE` | `test_disabled_bypasses_lookup`, `test_permissive_semantics`, `test_enforce_semantics` |
| 8 | IPv4 address-to-endpoint mapping, with an `EXTERNAL` fallback for unmapped addresses | `test_addr_map_resolves_destination`, `test_addr_map_resolves_source`, `test_addr_map_validation` |
| 9 | Malformed packets handled deterministically, never crash the node | `test_malformed_packets`, `test_ip_options`, `test_debug_force_copy_path` |
| 10 | Fragments handled deterministically; non-initial fragments never reach rule matching | `test_fragment_action` |
| 11 | ARP handled outside L4 policy, with its own configurable action | `test_arp_action` |
| 12 | Unsupported EtherTypes (non-IPv4/ARP, VLAN included) take `unsupported_action` | `test_unsupported_ethertype` |
| 13 | Unknown IPv4 protocols are matched by rule, not silently classed unsupported | `test_unknown_ip_protocol_is_matched` |
| 14 | Policy commits atomically via generations (single-pointer swap) | `test_default_action_and_generation`, `test_commit_validation`; `docs/performance.md` — `commit_usec` ~1us even at 100,000 rules |
| 15 | Stale-generation commits are rejected (optimistic concurrency) | `test_stale_generation_rejected` |
| 16 | Transactions carry deadlines; abandoned ones are reaped automatically | `test_transaction_timeout`, `test_transaction_abort` |
| 17 | Per-node counters with a defined, checked invariant | `test_reset_stats`; the `packets_total == allowed + dropped + no_peer` invariant checked in `test_concurrent_policy_replacement`/`_adversarial` |
| 18 | Per-endpoint counters, credited to the ingress endpoint | `test_endpoint_counters`, `test_endpoint_credit_targets_ingress_endpoint` |
| 19 | Per-rule counters, discarded with their generation | `test_rule_counters`, `test_rule_counters_reset_per_generation` |
| 20 | Memory accounting reported (policy / transaction / endpoint / address map) | `test_memory_accounting`, `test_tx_memory_released_on_abort` |
| 21 | Control input is validated as untrusted; malformed size, bad enum, or overflow-prone input is rejected with the correct errno | `test_short_message_rejected`, `test_commit_requires_default`, `test_unknown_transaction`, `test_endpoint_duplicate_rejected`, `test_endpoint_reserved_id_rejected`, `test_addr_map_validation`; `tests/ngp_fuzz.c` control-message fuzzing |
| 22 | Rules/addresses load in bulk without one message per entry, at real scale (100,000 rules) | `tests/ngp_bench.c` commit table; `test_rule_limit` |
| 23 | Large enumerations (endpoints, rule stats) are windowed rather than unbounded in one response, and paging across a real page boundary neither drops, duplicates, nor reorders entries | `test_endpoint_list_pagination`, `test_rule_stats_pagination` |
| 24 | Forwarding stays correct and the node stays responsive under sustained concurrent policy replacement | `test_concurrent_policy_replacement`, `test_concurrent_policy_replacement_adversarial` |
| 25 | Fuzz-tested on both the control-message path and the packet-parsing path | `tests/ngp_fuzz.c` (seed `12345`, 200,000 iterations, both surfaces) |
| 26 | Leaks nothing across repeated node create/destroy and module load/unload cycles | `tests/ngp_stress.sh` + `vmstat -m | grep -c ng_policy` = 0 |
| 27 | Drivable standalone from `ngctl`, including hand-typed ASCII rule loading | `docs/ngctl-examples.md` — executed sessions, hand-typed `txaddrule` array literal |
| 28 | Programmable by a daemon through a stable, versioned ABI (type cookie + `version` field) | The entire `tests/` suite drives the node exclusively through `libnetgraph`/the real `NGM_POLICY_COOKIE` ABI, exactly as a daemon would |
| 29 | Benchmarked: commit and lookup cost reported honestly, including measurement noise | `tests/ngp_bench.c` + `docs/performance.md` |
| 30 | Requires no jail-, bhyve-, tenant-, or VPC-specific knowledge | `grep -rli "jail\|bhyve\|tenant\|vpc" sys/netgraph/ng_policy/*.{c,h}` — no matches |

### Row 23 was a gap; closed

`ENDPOINT_LIST` and `GET_RULE_STATS` both implement `start_index`/
`max_entries` windowing, clamped to `NG_POLICY_BATCH_MAX = 512` per
response (see [`control-api.md`](control-api.md)). Until this
fix, every test that called either command did so with everything
fitting in one page — no test ever set `start_index` to a nonzero
value or walked `next_index` across a real page boundary.

Two tests were added to `tests/ngp_test.c`:
`test_endpoint_list_pagination` registers 20 endpoints and pages
through `ENDPOINT_LIST` at 7 entries per page (three pages: 7, 7, 6 —
the short final page deliberately, since an off-by-one is most likely
to surface there), asserting the union of every page is exactly the
20 registered, each exactly once, with no gaps or duplicates, and that
the walk terminates. `test_rule_stats_pagination` does the same for
`GET_RULE_STATS` against 20 rules, additionally checking sorted order
— each page's entries are checked against the exact global index and
`rule_id` expected at that position, not just membership in the set.

Both tests were verified to actually catch a paging bug, not just
pass by construction: `next_index` was deliberately advanced one too
far in `ng_policy_endpoint.c` and `returned` was deliberately clamped
one short in `ng_policy_stats.c`, one at a time, each rebuilt and
reloaded into the live kernel — `test_endpoint_list_pagination` and
`test_rule_stats_pagination` failed exactly as expected against their
respective bug, and continued passing when the *other* command's bug
was live but their own was not. Both bugs were then reverted (`git
diff` against `sys/netgraph/ng_policy/` confirmed byte-identical to
the committed source before rebuilding the clean module), and the full
62-test suite passes, with and without
`net.graph.policy.debug_force_copy`.
