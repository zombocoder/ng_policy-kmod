# Statistics

Every counter `ng_policy` exposes, its exact counting point, and what
it does and does not mean. For the wire format of `GET_STATS`,
`GET_ENDPOINT_STATS`, and `GET_RULE_STATS`, see
[`control-api.md`](control-api.md); for what "generation" means, see
[`policy-model.md`](policy-model.md); for why timing fields measure
what they measure, see [`concurrency.md`](concurrency.md).

All counters are `counter_u64_t` (per-CPU, `counter_u64_add()`/
`counter_u64_fetch()`), never a plain integer under a lock, so reading
them never contends with the packet path.

## Node counters (`GET_STATS`, `struct ng_policy_stats`)

### The invariant, and what it excludes

```
packets_total == allowed_packets + dropped_packets + no_peer_packets
```

This holds at quiescence (no traffic and no commit in flight) for the
whole node. **`unbound_hook_packets` is excluded from `packets_total`
entirely** — `ng_policy_rcvdata()` increments `packets_total` only
*after* confirming the hook resolves to a bound endpoint (`ep != NULL`);
a frame arriving on a hook with no endpoint binding at all never
reaches that increment, and is counted only in
`unbound_hook_packets`. **Do not derive a "total dropped" figure by
subtracting `allowed_packets` from `packets_total`** — the difference
is `dropped_packets + no_peer_packets`, and `no_peer_packets` is not a
policy decision at all (see below), so folding it into "dropped" would
misrepresent how much traffic policy actually rejected versus how much
never had anywhere to go.

Under sustained concurrent traffic (not quiescent), the correct
invariant is `packets_total >= allowed_packets + dropped_packets +
no_peer_packets`, because `packets_total` is incremented before the
outcome-specific counter for the same packet — a snapshot taken
mid-flight can catch a packet already counted in the total but not yet
credited to an outcome. `test_concurrent_policy_replacement_adversarial`
asserts this weaker form at every mid-run sample and the exact equality
once traffic has stopped.

### Counting points

- **`rx`** (per-endpoint, see below) increments on arrival from the
  workload side, **before any decision is made** — it counts a packet
  that is later dropped just as much as one that is later allowed.
  `rx_packets`/`rx_bytes` answer "how much did this endpoint send," not
  "how much of what it sent was permitted."
- **`tx`** (per-endpoint) increments **only when a packet is actually
  forwarded** toward the endpoint — i.e. only on the enforcement
  outcome, never on a decision that was computed but not applied
  (`PERMISSIVE`'s forward-anyway path still increments `tx`, since the
  packet genuinely is forwarded there; only `ENFORCE`'s DROP path
  withholds it).
- **`no_peer_packets`** counts a bound endpoint whose *partner* hook
  (`peer_hp`/`hp` on the other side) is not currently connected — there
  is a defined ingress but no defined egress. This is a topology gap,
  not a policy decision, which is exactly why it is excluded from
  `dropped_packets` and tracked separately.
- **`unbound_hook_packets`** counts a hook with no endpoint binding at
  all (`hp->ep == NULL`) — an even earlier failure than `no_peer_packets`,
  before the node even knows which endpoint, if any, this traffic
  belongs to.
- **`allowed_packets`/`dropped_packets`/`violations`** (per-endpoint)
  are credited to the **one endpoint bound to the ingress hook**, in
  *both* directions of travel — a packet arriving on `ep-1001`
  (workload side) credits endpoint 1001 whether it is ultimately
  ALLOWed or DROPped, and so does a packet arriving on `fab-1001`
  (fabric side, dst = 1001). They are never credited to the packet's
  *other* endpoint, because that other endpoint is resolved from the
  address map and may not correspond to any locally registered
  endpoint at all (it can be `EXTERNAL`, or an ID nothing ever
  registered). Proven, not merely stated: `test_endpoint_credit_targets_ingress_endpoint`
  registers two endpoints, drops a frame entering on one, and confirms
  the drop lands on that endpoint's counters while the other —
  wired up identically but untouched by this frame — stays at zero.
- **`rule_matches`**/**`default_matches`** are mutually exclusive per
  packet: a packet that matched a specific rule increments the former
  (and that rule's own per-rule counters, below); a packet that parsed
  OK but matched nothing increments the latter.
- **`addr_lookups`**/**`addr_hits`** count every call into
  `ng_policy_addr_lookup()` and every one of those calls that found a
  registered entry (as opposed to falling back to `EXTERNAL`),
  respectively — one lookup per packet that reaches address resolution
  at all (parse-category outcomes like ARP, fragment, malformed, and
  unsupported never reach it).
- **`commits`**/**`failed_commits`**/**`aborts`**/**`tx_timeouts`**
  count transaction *outcomes*, not transaction *attempts* — a commit
  that fails validation increments `failed_commits`, never `commits`;
  a transaction reaped by the timeout callout increments `tx_timeouts`
  specifically, distinct from an explicit `TX_ABORT`.

### Memory accounting

`policy_memory`/`tx_memory`/`endpoint_memory`/`addr_memory` are all
computed at query time in `ng_policy_stats_get()`, not maintained as
running counters — `policy_memory` and `addr_memory` come from the live
snapshot's own recorded `memsize` (and `addr_mask`, for the address
table's allocated size specifically), `endpoint_memory` from
`nendpoints * sizeof(struct ng_policy_ep)` plus the fixed hash-table
size, and `tx_memory` from `priv->tx_memory`, which the transaction
code itself maintains incrementally as buffers grow and shrink. See
[`concurrency.md`](concurrency.md) for exactly why `policy_memory` in
particular must be derived this way rather than decremented by a
deferred reclaim callback.

## Per-endpoint counters (`GET_ENDPOINT_STATS` / `ENDPOINT_LIST`)

`rx_packets`, `rx_bytes`, `tx_packets`, `tx_bytes`, `allowed_packets`,
`dropped_packets`, `violations` — semantics exactly as described above,
per endpoint rather than node-wide. These live in the `struct
ng_policy_ep` itself and survive a hook disconnect/reconnect (see
[`endpoint-model.md`](endpoint-model.md)); they are reset only by
`RESET_STATS` with `RESET_ENDPOINTS` set (optionally scoped to one
`endpoint_id`), or by the endpoint being deleted and re-added.

## Per-rule counters (`GET_RULE_STATS`)

`match_packets`/`match_bytes` are allocated **inside the snapshot**
(`sn->rule_pkts[]`/`sn->rule_bytes[]`, one `counter_u64_t` pair per
rule, built by `ngp_rule_counters_alloc()` as part of every commit) and
therefore **die with their generation** — a new commit's rules all
start at zero matches, even if an equivalent rule (same `rule_id`,
same fields) existed in the previous generation. There is no rule
counter persistence across generations in v0.1 (listed as a v0.2
candidate in the design spec, §15). This is exactly why **every
statistics response carries `generation`**
(`ng_policy_stats`, `ng_policy_ep_list_resp`, and
`ng_policy_rule_stats_resp` all have a `generation` field): a caller
polling rule counters across a commit needs a way to tell "these
counters reset because a new policy was committed" from "these
counters are anomalously low." `test_rule_counters_reset_per_generation`
proves the reset happens, not just that the field exists.

## Two timing fields that are easy to misread

Both are covered in more depth, with the full commit-timing picture, in
[`concurrency.md`](concurrency.md) and `docs/performance.md`; restated
here because they are statistics fields and belong in this document
too:

- **`reclaim_usec`** (in `ng_policy_tx_commit_resp`) measures the cost
  of *enqueuing* the `NET_EPOCH_CALL()` for the superseded snapshot's
  free — not the epoch grace period itself. Reclamation is
  asynchronous; its true latency is not attributable to the commit
  that triggered it, and a near-zero `reclaim_usec` is evidence that
  scheduling the callback is cheap, not that the memory has already
  been freed.
- **`validate_usec`** covers only the unlocked duplicate-`rule_id`/
  duplicate-address scan (`ngp_tx_validate_dups()`). The earlier,
  still-locked struct-field and endpoint-reference validation pass
  (`ngp_tx_validate_refs()` — port-range sanity, action/mode enum
  validity, reserved-ID usage, and, under `CFG_F_STRICT_ENDPOINTS`,
  endpoint existence) runs before `validate_usec`'s timer starts and is
  deliberately excluded, because it is cheap, `O(nrules)`, and not the
  part worth watching for regressions — see the comment in
  `ng_policy_tx_commit()` immediately before its `nanouptime(&t0)`
  call.

## What this document does not cover

The wire structures these counters travel in:
[`control-api.md`](control-api.md). Why the swap that replaces a
generation's counters is safe without a reader-side lock:
[`concurrency.md`](concurrency.md). Measured numbers from an actual
run: `docs/performance.md`.
