# Control API

The wire format for every `NGM_POLICY_*` message. All structures and
`ng_parse` type macros live in `sys/netgraph/ng_policy/ng_policy_msg.h`
(public, installed) and are wired into `ngctl`'s ASCII parser in
`ng_policy.c`'s `ng_policy_cmdlist[]`. For worked, executed examples see
[`ngctl-examples.md`](ngctl-examples.md); for how a control message is
serialised to and from the ASCII layer see the size-limit and hand-typing
notes below.

## ABI guard

Every message must carry `typecookie == NGM_POLICY_COOKIE`
(`1756036800`); anything else is rejected with `EINVAL` before the
`cmd` switch is even reached. Structures large enough to carry one
additionally have a `version` field where **`0` means "current ABI"**
(`NG_POLICY_ABI_VERSION` is `1`) — so a hand-typed `ngctl` command never
needs a version, but a daemon that pins a version gets `EPROTONOSUPPORT`
if the node's ABI has moved on. Payload length is checked against the
exact expected size for fixed-size commands (`NGP_ARGLEN()` in
`ng_policy.c`) and against a computed variable size for the two batched
commands (below) — a userland-supplied length is never trusted.

## Commands

| # | Command | ASCII name | Request | Response |
|---|---|---|---|---|
| 1 | `NGM_POLICY_GET_CONFIG` | `getconfig` | none | `ng_policy_config` |
| 2 | `NGM_POLICY_SET_CONFIG` | `setconfig` | `ng_policy_config` | none |
| 3 | `NGM_POLICY_SET_MODE` | `setmode` | `ng_policy_mode_req` | none |
| 4 | `NGM_POLICY_ENDPOINT_ADD` | `endpointadd` | `ng_policy_endpoint_add` | none |
| 5 | `NGM_POLICY_ENDPOINT_DEL` | `endpointdel` | `ng_policy_endpoint_del` | none |
| 6 | `NGM_POLICY_ENDPOINT_LIST` | `endpointlist` | `ng_policy_ep_query` | `ng_policy_ep_list_resp` |
| 7 | `NGM_POLICY_TX_BEGIN` | `txbegin` | `ng_policy_tx_begin_req` | `ng_policy_tx_begin_resp` |
| 8 | `NGM_POLICY_TX_ADD_RULE` | `txaddrule` | `ng_policy_tx_add_rule` (batched) | none |
| 9 | `NGM_POLICY_TX_ADD_ADDR` | `txaddaddr` | `ng_policy_tx_add_addr` (batched) | none |
| 10 | `NGM_POLICY_TX_SET_DEFAULT` | `txsetdefault` | `ng_policy_tx_set_default` | none |
| 11 | `NGM_POLICY_TX_COMMIT` | `txcommit` | `ng_policy_tx_commit_req` | `ng_policy_tx_commit_resp` |
| 12 | `NGM_POLICY_TX_ABORT` | `txabort` | `ng_policy_tx_id` | none |
| 13 | `NGM_POLICY_GET_STATS` | `getstats` | none | `ng_policy_stats` |
| 14 | `NGM_POLICY_GET_ENDPOINT_STATS` | (via `endpointlist`) | `ng_policy_ep_query` | `ng_policy_ep_list_resp` |
| 15 | `NGM_POLICY_GET_RULE_STATS` | `getrulestats` | `ng_policy_rule_query` | `ng_policy_rule_stats_resp` |
| 16 | `NGM_POLICY_RESET_STATS` | `resetstats` | `ng_policy_reset_req` | none |

`GET_ENDPOINT_STATS` and `ENDPOINT_LIST` share one handler
(`ng_policy_ep_list()`) and the same request/response shape — the
distinct opcode exists for callers that want to name their intent
explicitly, not because the wire format differs. `ngctl`'s cmdlist only
binds an ASCII name to `ENDPOINT_LIST`; `GET_ENDPOINT_STATS` is still
reachable from C with the numeric opcode (`ngp_msg_resp(c,
NGM_POLICY_GET_ENDPOINT_STATS, ...)`, as `tests/ngp_test.c` does).

None of these commands is marked `NGM_READONLY` — every one, including
the two `GET_*` reads, is delivered to `ng_policy_rcvmsg()` as a
Netgraph **writer** item. This is a fact the concurrency model depends
on; see [`concurrency.md`](concurrency.md) for what that guarantees and
what breaks if it is ever changed.

## Request/response fields

### `ng_policy_config` (1, 2)

```c
struct ng_policy_config {
	uint16_t version;
	uint16_t flags;         /* CFG_F_STRICT_ENDPOINTS = 0x0001 */
	uint8_t  mode;          /* DISABLED=0 PERMISSIVE=1 ENFORCE=2 */
	uint8_t  arp_action;
	uint8_t  frag_action;
	uint8_t  unsupported_action;
	uint8_t  malformed_action;
	uint8_t  reserved0;
	uint16_t reserved1;
};
```

Deliberately excludes `default_action` — that belongs to the policy
generation, set only via `TX_SET_DEFAULT` (§7.1 of the design spec).
`SET_CONFIG` validates `mode` and all four actions against their enum
ranges and rejects unknown `flags` bits, all with `EINVAL`.

### `ng_policy_mode_req` (3)

A single `uint32_t mode`. `SET_MODE` is the fast path for the one knob
operators change most often, without needing the rest of
`ng_policy_config`.

### `ng_policy_endpoint_add` / `_del` (4, 5)

```c
struct ng_policy_endpoint_add {
	uint32_t endpoint_id;
	uint32_t flags;        /* ENABLED | TRUSTED | F_REPLACE (request-only) */
	uint16_t version;
	uint16_t reserved;
	char     hook[NG_HOOKSIZ];
	char     peer_hook[NG_HOOKSIZ];   /* may be empty */
};
```

Two hook names — see "Departure 1" below. `endpoint_id` must satisfy
`NG_POLICY_EP_ID_VALID()` (nonzero, below the reserved range);
duplicate IDs are rejected `EEXIST` unless `flags & F_REPLACE` is set,
in which case the old registration (and its bindings — not its
counters, which live in a freshly allocated `struct ng_policy_ep`) is
replaced. `hook` and `peer_hook`, if not empty, must differ. See
[`endpoint-model.md`](endpoint-model.md) for what the flags mean and
for the two-endpoints-one-hook-name case.

### `ng_policy_ep_query` / `ng_policy_ep_list_resp` (6, 14)

Windowed: `endpoint_id = NG_POLICY_EP_ANY` (0) means "every endpoint,"
`start_index`/`max_entries` page through the result (`max_entries = 0`
or `> NG_POLICY_BATCH_MAX` clamps to `NG_POLICY_BATCH_MAX = 512`, then
a second, tighter clamp applies — see "Response paging and the
`net.graph.recvspace` ceiling" below). The
response carries `generation` (the active generation at query time —
endpoints are not versioned per-generation, but the field is there so
a caller can tell whether a concurrent commit happened between calls),
`total`, `returned`, and `next_index` for the caller to resume from.
Each `ng_policy_endpoint_info` entry reports the live counters and the
status flags `EP_S_CONNECTED` / `EP_S_PEER_CONNECTED` (set only when
`ep->hp`/`ep->peer_hp` is non-NULL at query time — see
[`endpoint-model.md`](endpoint-model.md)).

### Transactions (7-12)

```c
struct ng_policy_tx_begin_req {
	uint64_t requested_generation;  /* 0 = active + 1 */
	uint32_t timeout;               /* seconds, 0 = ng_policy_tx_timeout */
	uint16_t version;
	uint16_t flags;                 /* must be 0 in v0.1 */
};
struct ng_policy_tx_begin_resp {
	uint64_t tx_id;
	uint64_t generation;            /* the generation this tx will install */
	uint64_t active_generation;
	uint32_t timeout;
	uint32_t reserved;
};
```

`TX_ADD_RULE` / `TX_ADD_ADDR` are batched — see "Batching and the
`net.graph.maxdgram` ceiling" below. `TX_SET_DEFAULT` is mandatory:
`TX_COMMIT` returns `EINVAL` if no default action was ever set on the
transaction (`ngp_tx_validate_refs()`'s `!tx->has_default` check).

```c
struct ng_policy_tx_commit_req {
	uint64_t tx_id;
	uint64_t base_generation;   /* optimistic concurrency */
	uint16_t version;
	uint16_t flags;             /* TXC_F_FORCE = 0x0001 */
	uint32_t reserved;
};
struct ng_policy_tx_commit_resp {
	uint64_t generation;
	uint64_t memory;         /* snapshot's total memsize */
	uint64_t build_usec;
	uint64_t validate_usec;
	uint64_t commit_usec;
	uint64_t reclaim_usec;
	uint32_t nrules;
	uint32_t naddrs;
};
```

`base_generation` must equal the node's active generation, or the
commit fails `ESTALE`, unless `flags & TXC_F_FORCE` is set. See
[`policy-model.md`](policy-model.md) for generations and
[`concurrency.md`](concurrency.md) for exactly what each `_usec` field
does and does not measure.

### `ng_policy_stats` / `ng_policy_rule_stats_resp` (13, 15, 16)

See [`statistics.md`](statistics.md) for every counter's exact
semantics and counting point. `GET_RULE_STATS` is windowed the same
way as `ENDPOINT_LIST` (`start_index`/`max_entries`, capped at
`NG_POLICY_BATCH_MAX` and then at the byte budget described below),
against the *live* snapshot at query time —
each `ng_policy_rule_stat` entry carries the rule itself plus
`match_packets`/`match_bytes` and its `index` in the snapshot's sorted
order. `RESET_STATS`'s `what` bitmask (`RESET_NODE` / `RESET_ENDPOINTS`
/ `RESET_RULES`, `0` meaning all three) lets a caller reset node
counters, endpoint counters (optionally scoped to one `endpoint_id`),
or per-rule counters independently.

## Errno values

| errno | Meaning | Example sites |
|---|---|---|
| `EINVAL` | Malformed field, wrong size, unknown cookie, bad enum value, overflow-prone count | wrong `arglen`, invalid `mode`/`action`, `nrules`/`naddrs` overflow check in `ng_policy.c`, `port_min > port_max` |
| `ENOENT` | Unknown endpoint or transaction | `ENDPOINT_DEL` on a missing ID, any `TX_*` on an unknown `tx_id` |
| `EEXIST` | Duplicate endpoint ID without `F_REPLACE` | `ENDPOINT_ADD` |
| `ENOMEM` | Allocation failure | `NG_MKRESPONSE` failing, `counter_u64_alloc()` failing inside a commit |
| `ENOSPC` | A configured limit was exceeded | `max_endpoints`, `max_rules`, `max_addrs`, `max_tx`, `max_tx_bytes`, the address-map table-size guard |
| `ESTALE` | Stale generation | `TX_COMMIT` when `base_generation != active` (without `FORCE`), or when the transaction's own target generation has already been passed |
| `EBUSY` | Node shutting down, or a transaction is mid-commit | `ENDPOINT_ADD`/`TX_BEGIN` during `shutdown`; any `TX_ADD_RULE`/`TX_ADD_ADDR`/`TX_SET_DEFAULT`/`TX_ABORT`/second `TX_COMMIT` while `tx->committing` |
| `EPROTONOSUPPORT` | `version` field is nonzero and does not match `NG_POLICY_ABI_VERSION` | any versioned request struct |

This is the same threat list the requirements name and the fuzzer
targets — see [`security.md`](security.md).

## Three deliberate departures from the requirements text

1. **`ENDPOINT_ADD` carries two hook names, `hook` and `peer_hook`.**
   A direct consequence of Decision 1 in
   [`architecture.md`](architecture.md): an endpoint *is* a pair of
   hooks, so registering one means naming both. `peer_hook` may be the
   empty string — the endpoint still registers, but with no defined
   egress until a `peer_hook` is supplied (via `F_REPLACE`) or the hook
   itself connects.

2. **ICMP matches on dedicated `icmp_type`/`icmp_code` fields**, guarded
   by `RULE_F_ICMP_TYPE`/`RULE_F_ICMP_CODE` flags, rather than
   overloading the port-range fields the way some other filtering
   designs do. This keeps port semantics meaning ports in every rule,
   regardless of protocol, and keeps a userland policy compiler from
   having to special-case ICMP's port fields as "actually type/code
   here."

3. **There are no incremental address messages** — no `ADDR_ADD`,
   `ADDR_DEL`, or `ADDR_FLUSH`. The address map is populated only by
   `TX_ADD_ADDR`, inside a transaction, and lives inside the policy
   generation it is committed with. This is what lets the packet path
   read exactly one pointer for both rules and addresses together, and
   what keeps every statistics response's `generation` field
   unambiguous about which address map produced a given count. The
   cost, accepted deliberately: moving a single IP requires building
   and committing a whole new generation, not a one-message edit. See
   [`policy-model.md`](policy-model.md) and the design spec §3 for the
   full argument (`§24`/`§36` in the requirements conflict on this
   point; the design resolves it in favour of the atomicity
   requirement, `§35`).

## Batching and the `net.graph.maxdgram` ceiling

`TX_ADD_RULE` and `TX_ADD_ADDR` carry arrays precisely so a control
plane never has to send one message per rule — loading a 100,000-rule
policy one rule at a time would be dominated by per-message overhead.
But a single control message is still one Netgraph datagram, and
Netgraph control sockets cap a single send at `net.graph.maxdgram`
(`sys/netgraph/ng_socket.c`'s `ngpdg_sendspace`, **20480 bytes by
default**), enforced by `soreserve()` setting the socket's send
high-water mark at attach time and `sosend_dgram()` rejecting anything
over it with `EMSGSIZE` ("Message too long").

The byte count that counts against that ceiling is the **entire**
`struct ng_mesg` on the wire — `sizeof(struct ng_mesg)` (56 bytes: the
`ng_msghdr` header) plus `arglen` — not just the `ng_policy_tx_add_rule`
payload. Working through the exact sizes:

- `struct ng_policy_tx_add_rule` fixed header: `tx_id`(8) +
  `version`(2) + `reserved`(2) + `nrules`(4) = **16 bytes**.
- `struct ng_policy_rule`: **32 bytes**, confirmed no padding
  (`rule_id` 8 + `src_endpoint`/`dst_endpoint` 4+4 + four port fields
  2×4 + `priority`/`flags` 2+2 + `protocol`/`action`/`icmp_type`/
  `icmp_code` 1×4 = 32).

```
wire size = sizeof(struct ng_mesg) + arglen
          = 56 + (16 + 32 * nrules)
max nrules such that wire size <= 20480:
  56 + 16 + 32n <= 20480
  32n <= 20408
  n <= 637.75  ->  n_max = 637
```

This was verified empirically against the built module, not just
derived: a `TX_ADD_RULE` with `nrules = 637` (wire size 20456 bytes)
sends and commits successfully; `nrules = 638` (wire size 20488 bytes)
fails `NgSendMsg()` with `EMSGSIZE` before the message ever reaches the
node. **`docs/performance.md`'s existing text says "roughly 638 rules"
for this boundary; the precise, verified figure is 637 — 638 already
fails.** `docs/performance.md` predates this document and was left
unmodified per its own completion note; this document is the precise
reference.

The identical arithmetic applies to `TX_ADD_ADDR`: header 16 bytes,
`struct ng_policy_addr` 8 bytes (`ipv4` 4 + `endpoint_id` 4), giving
`n_max = (20480 - 56 - 16) / 8 = 2551` addresses per message.

Neither limit is `ng_policy`'s own — `ng_policy_max_rules` and
`ng_policy_max_tx_bytes` (both left at their defaults, 262144 rules and
64 MiB, in the measurement above) are untouched by this ceiling. A
control-plane client loading a large policy chunks its `TX_ADD_RULE`/
`TX_ADD_ADDR` calls under roughly 637/2551 entries per message (as
`tests/ngp_bench.c` does, with `BENCH_CHUNK = 512` for headroom), or an
operator raises `net.graph.maxdgram` — which is a generic Netgraph
transport setting, not anything `ng_policy` controls or validates.

## Response paging and the `net.graph.recvspace` ceiling

The `net.graph.maxdgram` ceiling above bounds the **request** direction
— what a control plane can send in one `TX_ADD_RULE`/`TX_ADD_ADDR`. The
**response** direction has an analogous ceiling that windowed
responses (`ENDPOINT_LIST`/`GET_ENDPOINT_STATS`'s `ng_policy_ep_list_resp`,
`GET_RULE_STATS`'s `ng_policy_rule_stats_resp`) must respect, and it is
a *different* number from 20480 bytes of payload: it is
`net.graph.recvspace` (`ngpdg_recvspace` in `sys/netgraph/ng_socket.c`,
also 20480 bytes by default), the ceiling `soreserve()` sets on the
**receiving** socket's buffer at attach time. A reply larger than that
fails the kernel's internal `sbappendaddr_locked()` with `ENOBUFS`
("No buffer space available"), which propagates back to the sender —
here, `ng_policy` itself — as the return value of the send inside
`NG_RESPOND_MSG`.

`NG_POLICY_BATCH_MAX` (512) was fixed before either windowed response
type existed and, unclamped, both response entry sizes blow through
this ceiling well before reaching it:

```
ENDPOINT_LIST / GET_ENDPOINT_STATS entry (struct ng_policy_endpoint_info): 128 bytes
GET_RULE_STATS entry (struct ng_policy_rule_stat):                          56 bytes
response header (either type, ng_policy_{ep_list,rule_stats}_resp):         24 bytes
ng_mesg header (struct ng_mesg, the wire envelope):                         56 bytes

wire size = 56 + 24 + entry_size * n <= 20480

ENDPOINT_LIST / GET_ENDPOINT_STATS:  128n <= 20400  ->  n_max = 159
GET_RULE_STATS:                       56n <= 20400  ->  n_max = 364
```

This was confirmed empirically, not just derived: registering 159
endpoints and calling `ENDPOINT_LIST` with `max_entries = 0`
("as many as fit") returns all 159 in one page; at 160 endpoints, the
same call fails `NgSendMsg()`/the kernel send path with `ENOBUFS`. That
matters because `max_entries = 0` is the documented default way to
enumerate endpoints, and 160 is far below the design's stated
10,000-endpoint scaling target (see `docs/architecture.md`) — so the
documented default path was broken for any node past a couple hundred
endpoints.

The fix: `ng_policy_ep_list()` (`ng_policy_endpoint.c`) and
`ng_policy_rule_stats()` (`ng_policy_stats.c`) each clamp their entry
count a second time, against `NG_POLICY_RESP_BYTE_BUDGET`
(`ng_policy.h`, currently `20 * 1024`, matching the default
`net.graph.recvspace`) using their own `sizeof(entry)` — the two
response types are clamped to different `n_max` values because their
entries are different sizes, which is why this is a per-type byte
budget rather than a single shared entry count. A caller that asks for
more than fits (including the `max_entries = 0` default) gets a
smaller page and keeps paging with `start_index`/`next_index`, exactly
as the windowing protocol already supports — this is not an ABI
change, and no caller correctly using the windowing fields observes
anything but a possibly-shorter `returned` count per call.

An operator who raises `net.graph.recvspace` on their own control
socket does not get bigger pages from this: the module has no way to
observe a particular caller's socket option, so the clamp is always
sized off the compiled-in default. Such an operator's client simply
pages more often than it strictly needed to, which is correct
behaviour, not a bug.

## The `max_tx` / `max_tx_bytes` pair

The sysctl bounding the number of concurrently open transactions is
named `net.graph.policy.max_tx` (default 16), deliberately paired in
name with `net.graph.policy.max_tx_bytes` (default 64 MiB) — the memory
ceiling across *all* open transactions' accumulated rule/address
buffers. A control plane opening several transactions at once (e.g. to
prepare more than one candidate generation) is bounded on both count
and memory independently.

## Writing a new response handler: `NG_MKRESPONSE` needs the original message

`NG_MKRESPONSE(resp, msg, size, flags)` dereferences its `msg` argument
to copy the request's token, typecookie, and command into the
response's header — that token is what `libnetgraph`/`ngctl` matches a
reply against the request that triggered it. Every handler in
`ng_policy.c` and `ng_policy_stats.c`/`ng_policy_endpoint.c` that builds
a response threads the original `struct ng_mesg *msg` through for
exactly this reason (see the comment above `NG_MKRESPONSE` in
`ng_policy_rule_stats()`: "passing NULL panics and would also strip the
token that libnetgraph matches the reply on"). Anyone adding a new
`NGM_POLICY_*` command that returns a response must do the same — take
`msg` (or the `item_p` it came from) as far as the `NG_MKRESPONSE` call,
not just the parsed request struct.

## Adding a new control message, end to end

See [`development.md`](development.md#adding-a-new-control-message-end-to-end) for
the full checklist (opcode, struct, `TYPE_INFO` macro, `ng_parse` type
registration, `cmdlist` entry, dispatch case, and a test).
