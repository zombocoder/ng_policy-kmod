# ng_policy

> A FreeBSD Netgraph kernel node for fast, stateless, identity-aware
> network policy enforcement using precompiled endpoint-based rules and
> atomic policy generations.

`ng_policy` is a kernel-resident Netgraph node type (`NG_POLICY_NODE_TYPE
= "policy"`). It registers **endpoints** — each a pair of hooks, a
workload side and a fabric side — evaluates every frame crossing one of
those hooks against a **precompiled, priority-ordered rule set**, and
forwards or drops it. It compiles nothing itself: rules, endpoint
registrations, and an IPv4-to-endpoint address map arrive over a
Netgraph control socket, already in binary form, and are swapped into
place atomically as a single immutable **generation**. It knows
endpoint IDs, IPv4 addresses, protocols, ports, ICMP type/code, actions,
and generation numbers — nothing about tenants, VPCs, subnets, jails,
VMs, labels, applications, environments, or clusters. See
[`docs/architecture.md`](docs/architecture.md) for the full boundary.

## Where it sits

```
   +--------------------------------+        +---------------------------+
   |  userland policy compiler        |        |  ng_policy.ko (this repo)  |
   |  (tenant/label/security-group     |        |                            |
   |   intent -> endpoint IDs and      |        |  endpoint table            |
   |   IPv4 rules -- not in this repo) | -----> |  policy snapshot           |
   |                                    | control|  address map               |
   |                                    | socket |  counters                  |
   |                                    | (ngctl |                            |
   |                                    |  or a  |  match + forward,          |
   |                                    |  daemon| at line rate, no policy    |
   |                                    |  over  |  decisions of its own      |
   |                                    | NGM_*) |  beyond ALLOW/DROP         |
   +--------------------------------+        +---------------------------+
```

`ng_policy` is the kernel fast path only. Deciding *what* a rule should
say — translating tenant intent, security groups, or any higher-level
concept into `src_endpoint`/`dst_endpoint` numbers and IPv4 rules — is
entirely a userland concern, out of scope for this repository.

## Fail-closed by default

**A freshly constructed node starts at generation 0 with
`default_action = DROP` and `mode = ENFORCE`.** It blocks all traffic
until a policy generation is committed (or `mode` is set to
`DISABLED`). This is almost always the first thing that surprises
someone experimenting by hand — see the opening of
[`docs/ngctl-examples.md`](docs/ngctl-examples.md).

## Build and test

```sh
make -C src                            # build ng_policy.ko, -Werror clean
make -C tests                          # build ngp_test / ngp_fuzz / ngp_bench

doas kldload ./src/ng_policy.ko
doas ./tests/ngp_test                  # 59 run, 0 failed
doas ./tests/ngp_fuzz 12345 200000     # seeded control- and packet-path fuzzing
doas sh tests/ngp_stress.sh ./src/ng_policy.ko 50   # leak check
doas ./tests/ngp_bench                 # commit-cost and lookup-cost tables
doas kldunload ng_policy
vmstat -m | grep -c ng_policy          # expect 0 — nothing leaked
```

Full details, including how to add a new control message end to end:
[`docs/development.md`](docs/development.md).

## Documentation

| Document | Covers |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | The node model, the hook-pair endpoint decision, why the kernel makes no forwarding decision, the boundary against userland, and what the kernel deliberately does not know |
| [`docs/packet-path.md`](docs/packet-path.md) | Every packet outcome with its own flow: allowed, denied, unknown destination, external destination, ARP, fragment, malformed, permissive violation |
| [`docs/control-api.md`](docs/control-api.md) | Every control message, its wire structs, its errno values, the three deliberate departures from the requirements text, and the verified `net.graph.maxdgram` batching ceiling |
| [`docs/policy-model.md`](docs/policy-model.md) | Rules, wildcards, priority and first-match semantics, generations, and why v0.1 is stateless |
| [`docs/endpoint-model.md`](docs/endpoint-model.md) | Endpoint identity, reserved IDs, `LOCAL_HOST`, hook-name collisions, and lazy symmetric binding |
| [`docs/concurrency.md`](docs/concurrency.md) | Why Netgraph's own writer exclusivity — not the net epoch — protects a policy swap, what the epoch is actually for, and what a commit's timing fields mean |
| [`docs/statistics.md`](docs/statistics.md) | Every counter, its exact counting point, and the node-wide invariant |
| [`docs/security.md`](docs/security.md) | Untrusted-input validation, the threat list, the array-length-clamp non-fix, and what testing with `INVARIANTS` off does and does not prove |
| [`docs/performance.md`](docs/performance.md) | Measured commit and lookup costs, and what was not measured |
| [`docs/ngctl-examples.md`](docs/ngctl-examples.md) | Executed, real-output `ngctl` sessions: create, register, install, read stats, switch modes, tear down |
| [`docs/development.md`](docs/development.md) | Build/load/test/fuzz/benchmark commands, source layout, and adding a new control message |
| [`docs/phase0-single-host-fabric.md`](docs/phase0-single-host-fabric.md) | Manual proof (spec `vnetfabric` Phase 0): epair/tap attach identically, fail-closed, default-deny, cross-subnet routing with no custom routing code — and why `tun` cannot attach to `ng_policy` at all |

## Completion criteria

The requirements' §99 lists thirty completion criteria. **Neither the
source 100-section requirements document nor the design spec that
summarised it is present in this repository.** The table below was
reconstructed from that spec's summary (§14) and from a handful of
criterion numbers cited directly in the project's own history
(`§99.26` leaks, `§99.27` `ngctl` standalone operation, `§99.28`
stable ABI), decomposed to line up with the numbers that are directly
attested. It is this project's best-effort reconstruction — **not a
verbatim transcription of text this repository does not contain**, and
the sources it was built from cannot be consulted here. Where a row
has no test that proves it, that is stated plainly rather than covered
with a plausible-sounding claim.

| # | Criterion | Proven by |
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
| 30 | Requires no jail-, bhyve-, tenant-, or VPC-specific knowledge | `grep -rli "jail\|bhyve\|tenant\|vpc" src/*.{c,h}` — no matches |

### Criterion 23 was a gap; closed

`ENDPOINT_LIST` and `GET_RULE_STATS` both implement `start_index`/
`max_entries` windowing, clamped to `NG_POLICY_BATCH_MAX = 512` per
response (see [`control-api.md`](docs/control-api.md)). Until this
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
diff` against `src/` confirmed byte-identical to
the committed source before rebuilding the clean module), and the full
59-test suite passes, with and without
`net.graph.policy.debug_force_copy`. See the task report for the full
break/rebuild/fail/revert/pass transcript.
