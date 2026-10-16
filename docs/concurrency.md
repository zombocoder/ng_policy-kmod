# Concurrency and reclamation

This is the document to read before touching anything in
`ng_policy_policy.c`'s commit path, `ng_policy.c`'s message dispatch, or
any of the `NGM_READONLY` handling in `ng_policy_rcvmsg()`. It states
what actually protects a policy swap, what the net epoch is actually
for, and what breaks — silently, since `INVARIANTS` is off on this
kernel (see [`security.md`](security.md)) — if either fact is
misunderstood.

## The headline fact: Netgraph's own node lock already excludes packets during a commit

Every `NGM_POLICY_*` control message reaches `ng_policy_rcvmsg()`
through `ng_package_msg()`
(`/usr/src/sys/netgraph/ng_base.c`, function starting at line 3552):

```c
/* Messages items count as writers unless explicitly exempted. */
if (msg->header.cmd & NGM_READONLY)
	item->el_flags |= NGQF_READER;
else
	item->el_flags |= NGQF_WRITER;
```

**`ng_policy` marks nothing `NGM_READONLY`** — not `GET_STATS`, not
`GET_RULE_STATS`, not `ENDPOINT_LIST`, nothing in
`ng_policy_cmdlist[]` in `ng_policy.c`. Every control message this node
receives is therefore delivered as a **writer** item. Netgraph's own
scheduler (`ng_acquire_write()`, `ng_base.c:2073`) only grants writer
access to a *completely idle* node:

```c
/* Writer needs completely idle node. */
if (atomic_cmpset_acq_int(&node->nd_input_queue.q_flags, 0,
    WRITER_ACTIVE)) { ... }
```

and `ng_acquire_read()` (`ng_base.c:2045`) refuses to grant reader
access — which is what a data item (a packet) needs — whenever a writer
flag or any pending item is set:

```c
/* Reader needs node without writer and pending items. */
for (;;) {
	long t = node->nd_input_queue.q_flags;
	if (t & NGQ_RMASK)
		break; /* Node is not ready for reader. */
	...
```

Put together: **no packet can be inside `ng_policy_rcvdata()` while a
`TX_COMMIT` (or any other control message) is being processed for this
node.** The framework itself provides mutual exclusion between "the
node is handling a control message" and "the node is handling a data
item" — this is not something `ng_policy` implements; it is a property
of every Netgraph node that does not opt out of it via `NGM_READONLY`.

## So what is the net epoch actually protecting?

Given the fact above, `NET_EPOCH_ENTER`/`NET_EPOCH_EXIT` around
`ng_policy_rcvdata()`'s body is **not** what makes the
`NGP_STORE_PTR(priv->policy, sn)` swap in `ng_policy_tx_commit()` safe
against a concurrently-executing reader — there cannot be one, for the
reason above. Its real, load-bearing job is **deferred reclamation**:

```c
old = priv->policy;
NGP_STORE_PTR(priv->policy, sn);        /* the swap: ~1us, under ctl_mtx */
...
if (old != NULL)
	NET_EPOCH_CALL(ngp_snapshot_reclaim, &old->ectx);   /* runs later */
```

`NET_EPOCH_CALL()` schedules `old`'s free for after the epoch's grace
period elapses, on whichever CPU happens to run the callback — which
genuinely can, and in practice does, overlap live packet traffic
running on *other* CPUs, none of which are excluded from the node by
anything at that point (the writer claim that excluded them was
released when `TX_COMMIT` returned). The epoch machinery's job in the
*current* code is entirely about *when the old snapshot's memory is
actually freed*, not about *whether a reader can observe a torn
swap* — the swap itself is already exclusive by construction.

Sequence, restated:

```
control path (writer-exclusive,       packet path (reader-exclusive
  no packet can be concurrent)          with control, but genuinely
                                          concurrent with reclamation)
  build snapshot N+1  (M_WAITOK,
    outside ctl_mtx, tx pinned by
    tx->committing)
  validate
  lock ctl_mtx
  NGP_STORE_PTR(policy, N+1)   <-- the swap, ~1us, exclusive by
  unlock ctl_mtx                    the Netgraph writer claim, not
  NET_EPOCH_CALL(free, N) ---.      by the epoch
  return                      \
                                `-> (later, any CPU, no node lock held)
                                     ngp_snapshot_reclaim(N)
                                     races nothing but time, because
                                     the last reader to have loaded N
                                     already exited its own epoch
                                     section before this runs
```

## Do not remove the epoch deferral as "redundant"

It is tempting, once the writer-exclusivity argument above is
understood, to conclude the epoch machinery is unnecessary and could be
replaced with an ordinary free at commit time. **Do not do this.** The
argument above depends entirely on the premise that every control
message — including the read-only-looking ones — is a writer. If a
future change marks `GET_STATS` or `GET_RULE_STATS` as `NGM_READONLY`
— a natural-looking optimisation, since it would let statistics reads
run concurrently with each other and with data traffic instead of
serialising through the writer queue — those handlers become genuine
**readers racing the swap**: `ng_policy_rule_stats()` already reads
`sn->rules[]`/`rule_pkts[]`/`rule_bytes[]` through
`NGP_LOAD_PTR(priv->policy)` inside its own `NET_EPOCH_ENTER`/`EXIT`
section specifically so that it is already safe on that day, without
needing to change. The epoch is exactly what makes that safe: a
concurrent `TX_COMMIT` can swap `priv->policy` to a new generation
while a now-reader `GET_RULE_STATS` still holds a pointer to the old
one, and the old one's memory stays valid until every such reader has
exited its epoch section, however long that takes. Remove the epoch
deferral and that stats read becomes a use-after-free the instant
`NGM_READONLY` is added to it — silently, since `INVARIANTS` is off
(see [`security.md`](security.md)). The deferral is future-proofing
against a change that has not been made yet, not dead code.

## What the concurrency test actually establishes

`test_concurrent_policy_replacement` and
`test_concurrent_policy_replacement_adversarial`
(`tests/ngp_test.c`) run a sender thread pushing packets through the
data socket continuously while the main thread commits up to 300
generations in a tight loop, with the adversarial variant additionally
varying commit pacing (0 to 3ms delays) and generation shape (0 to 8
rules, 0 to 32 addresses) so the interleaving is not the same every
run.

Given the writer-exclusivity argument above, **this is not — and
cannot be, on this framework — a test of "does a packet ever observe a
torn swap."** That window does not exist for `ng_policy` today: a
packet is either fully processed against generation N before a
`TX_COMMIT` for N+1 is even dequeued, or it is queued behind that
`TX_COMMIT` and processed against N+1 afterward, with the Netgraph
scheduler enforcing the ordering. What the test *does* establish, and
is the honest way to describe a green run of it:

1. **Commit/packet sequencing under load** — that a sustained,
   continuously-varying stream of commits interleaved with sustained
   packet traffic produces no panic, no stale-pointer access, no stuck
   node, and exactly consistent counters (`packets_total == allowed +
   dropped` at quiescence, with `no_peer_packets == 0` explicitly
   checked so the equality's precondition is verified rather than
   merely assumed; see [`statistics.md`](statistics.md) for why the
   general node-wide invariant needs the `no_peer_packets` term).
2. **Reclamation overlap** — that the epoch-deferred frees from up to
   300 (or, in the adversarial variant, 240) superseded generations,
   of varying size, genuinely queue up and run while the *next*
   generation is already active and traffic is flowing, without
   corrupting anything reachable from the still-live snapshot.

It does **not** prove the swap-vs-reader window is safe in general,
because that window is not exercised — the framework's own scheduling
prevents it from ever opening while every control message stays a
writer. A future contributor adding `NGM_READONLY` to a handler changes
this: at that point, the swap-vs-reader window becomes real for that
handler, and a test exercising *that* interleaving would become
necessary and does not exist yet.

## No epoch-deferred object may point back to `priv`

`ngp_snapshot_reclaim()` (freeing a superseded `struct
ng_policy_snapshot`) and `ngp_ep_reclaim()`/`ngp_hookpriv_reclaim()`
(freeing a superseded endpoint or hook private) touch only the object
being freed — never `priv` itself, and never anything reachable only
through `priv`. This is deliberate: **epoch callbacks are ordered only
within a CPU**, not globally, so a callback queued on CPU 0 during node
shutdown could in principle still be pending when a callback on CPU 1
(from an earlier, unrelated free) has already run — there is no
cross-CPU guarantee that "the node is being destroyed" implies "every
earlier epoch callback for this node has already fired." A deferred
free that dereferenced `priv` could therefore, in a pathological
interleaving, outlive `priv`'s own `free()` in `ng_policy_shutdown()`.

The consequence that is easy to miss: **per-node memory accounting is
computed at query time from the live snapshot's own recorded
`memsize`, not maintained as a running counter that a deferred callback
decrements.** `ng_policy_stats_get()` reads `sn->memsize` directly off
whatever `priv->policy` currently points to
(`NGP_LOAD_PTR(priv->policy)`) rather than subtracting the old
snapshot's size from a running total inside `ngp_snapshot_reclaim()` —
because doing the latter would require that callback to reach back into
`priv`, which is exactly the pointer discipline this section forbids.

## A large commit still holds the node's writer claim across `M_WAITOK`

`ng_policy_tx_commit()` deliberately drops `ctl_mtx` (a non-sleepable
mutex) before the two allocation-heavy phases — duplicate-ID detection
and `ngp_snapshot_build()` — and lets them run with `M_WAITOK`, because
`M_NOWAIT` on an allocation this large (up to ~8MB of rules today, plus
two `counter_u64_alloc()` calls per rule) fails spuriously under
fragmentation, and `M_WAITOK` cannot be used while holding a
non-sleepable mutex. `tx->committing` blocks any other mutation of that
same transaction while this runs (`TX_ADD_RULE`/`_ADD_ADDR`/
`_SET_DEFAULT`/`TX_ABORT` all return `EBUSY`), so nothing on the
control path can free or mutate `tx` underneath the unlocked read.

But dropping `ctl_mtx` does **not** drop the Netgraph **writer claim**
this control message is holding on the node — that claim is held by the
framework for the whole duration of `ng_policy_rcvmsg()`'s call into
`ng_policy_tx_commit()`, mutex or no mutex. A build that takes 131ms at
100,000 rules (see `docs/performance.md`, "Reading the commit table")
holds the node exclusively **for that whole 131ms** from every other
writer's — and, per the headline fact above, every *reader's* (i.e.
every packet's) — point of view. Other writer work, including data
items waiting to be delivered to `rcvdata`, queues up behind it rather
than the commit failing or the queued packets being dropped.

This is a deliberate, measured trade, not an oversight: the actual
node-exclusive portion of any commit — the pointer swap itself
(`commit_usec`) — is on the order of **1 microsecond even at 100,000
rules**, but the *build* that produces the snapshot to swap in is not
node-exclusive by size, only by the writer claim's duration. A control
plane pushing very large generations should expect a commit of that
size to visibly delay traffic and other control messages for roughly
its `build_usec`, not its `commit_usec` — 131ms of build versus ~1us of
swap at 100,000 rules, per `docs/performance.md`. Sizing generations
(or splitting a huge policy across more, smaller commits) is a
control-plane decision this document flags rather than one the kernel
makes for you.

## What this document does not cover

Exact counter semantics and which `_usec` field means what:
[`statistics.md`](statistics.md). The `M_WAITOK`/`M_NOWAIT` choices in
each allocation site individually: read the comments in
`ng_policy_policy.c` directly — they are extensive and specific to each
call site. INVARIANTS being off and what that means for what testing
can and cannot prove: [`security.md`](security.md).
