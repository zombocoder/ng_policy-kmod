# Performance

This document records what was actually measured for `ng_policy`, on
what host, and what the numbers do and do not mean. Two benchmarks
(`tests/ngp_bench.c`) run entirely through the control and data
sockets and were run on the development host. A third, line-rate
dataplane throughput (`tools/bench-dataplane.sh`), needs real network
interfaces and was **not** run here — see "Dataplane throughput
(not measured)" below.

See also: [`concurrency.md`](concurrency.md) for what `commit_usec`,
`build_usec`, `validate_usec`, and `reclaim_usec` each actually
measure and why holding the node's writer claim across a large
commit's build phase is a deliberate trade; and
[`control-api.md`](control-api.md#batching-and-the-netgraphmaxdgram-ceiling)
for the precise (verified, not "roughly") `net.graph.maxdgram` batch
ceiling referenced below — 637 rules per `TX_ADD_RULE` message, not
638, at stock settings.

## Host

```
$ uname -a
Linux bsdlab 5.15.0 FreeBSD 14.3-RELEASE-p3 GENERIC x86_64 x86_64 x86_64 GNU/Linux
```

`uname -a`'s own output is internally inconsistent on this host: it
reports sysname `Linux`, yet the version string it also prints is a
FreeBSD kernel identification. This is a quirk of the sandboxed shell
this session runs commands through, not of the kernel itself — every
other signal available (`freebsd-version`, `sysctl kern.ostype`,
`kldload`/`kldstat` operating on real `.ko` files, `dmesg` showing a
FreeBSD/QEMU boot sequence) agrees the kernel is genuinely FreeBSD:

```
$ freebsd-version
14.3-RELEASE-p3
$ sysctl kern.ostype kern.osrelease
kern.ostype: FreeBSD
kern.osrelease: 14.3-RELEASE-p3
$ sysctl hw.model hw.ncpu
hw.model: Intel Core i7 9xx (Nehalem Class Core i7)
hw.ncpu: 6
```

The host is a QEMU/KVM virtual machine (6 vCPUs modeled as "Nehalem
Class Core i7", 4 GiB RAM) shared with other sandboxed sessions, not
dedicated hardware. Absolute wall-clock numbers below should be read
with that in mind: this is not an isolated, pinned-core benchmarking
rig, and run-to-run jitter (documented per-table below) reflects that.

## Commit cost

Measured with `tests/ngp_bench.c`'s `bench_commit()`, which reports
the kernel's own phase timings from `struct ng_policy_tx_commit_resp`
rather than timing the whole control-message round trip from
userland. Each row replaces the entire rule set with `n` freshly
generated, non-overlapping rules (so this is a full-generation build
cost, not an incremental one).

Raw output (one full run, `make -C tests && doas tests/ngp_bench`):

```
commit cost (microseconds)
   rules   userland   validate      build     commit       memory
     100         241         55        136          0         5568
            (build: 1360 ns/rule, memory: 55 bytes/rule)
    1000         598         81       2453          0        54160
            (build: 2453 ns/rule, memory: 54 bytes/rule)
   10000        4960        875      17244          0       552880
            (build: 1724 ns/rule, memory: 55 bytes/rule)
  100000       29242        7595     131000          0      5232880
            (build: 1310 ns/rule, memory: 52 bytes/rule)
```

All four sizes, including 100,000 rules, completed. At 100,000 rules
the whole `bench_commit()` call — userland building and sending 196
chunked `ADD_RULE` messages of 512 rules each, plus the kernel's
validate/build/commit phases — took about 168ms end to end (29.2ms
userland + 7.6ms validate + 131.0ms build + ~0ms commit; see
"BENCH_CHUNK" below for why sending is chunked). Of that, only the
last fraction of a millisecond — the `commit_usec` pointer swap — is
time the node is held exclusively; see the headline below.

Two more runs, to show repeatability (same host, back to back):

```
   rules   userland   validate      build     commit       memory
     100         239          50        110          0         5568
    1000         568          91        636          0        54160
   10000        2669         828      12225          0       552880
  100000       26913        7775      96209          0       5232880

     100         156          48         91          1         5568
    1000         446          77        720          0        54160
   10000        2689         819     10371          0        552880
  100000       25615        8259     95854          0       5232880
```

### Reading the commit table

**The headline: the only part of a commit that holds the node
exclusively is a pointer swap costing about a microsecond, even at
100,000 rules.** `commit_usec` — the `NGP_STORE_PTR(priv->policy, sn)`
swap, done under the control mutex — measured 0-1us at every size in
every run, including the largest. Everything expensive (`build_usec`,
up to 131ms at 100,000 rules) happens *before* that swap, off the
node's control mutex, using `M_WAITOK`. That is the payoff of Task 7's
restructuring: the new snapshot — including its 200,000
`counter_u64_alloc()` calls at 100,000 rules — is fully built before
the node is ever touched exclusively, so the exclusive-hold portion of
a commit does not scale with rule count at all. A large commit is
still expensive to the calling control-plane client (userland send
time) and to the node's writer queue (caveat 3 below, since the writer
*claim* is held across the build even though the mutex is not), but
not because the swap itself is slow — it never is, at any size
measured.

- **`build_usec` dominates, exactly as predicted.** At 100,000 rules it
  is 96-131ms across three runs — larger than `userland` (26-29ms),
  larger than `validate_usec` (7.6-8.3ms) by an order of magnitude, and
  `commit_usec` is 0-1us every time. It is the single most expensive
  operation measured anywhere in this project: one 100,000-rule commit
  costs roughly 2000x a single lookup round trip (see below, ~50-80us).
  This matches the prediction: the snapshot builder allocates two
  `counter_u64_t` per rule (200,000 `counter_u64_alloc()` calls at
  100,000 rules), and that allocation cost is what `build_usec` now
  measures, because Task 7's commit restructuring moved this work
  outside the node lock with `M_WAITOK`.
- **Per-rule build cost is fairly flat but noisy**, roughly 900-2500
  ns/rule across all three runs and all four sizes, with no strong
  trend by `n` — if anything it dips slightly at the largest size
  rather than growing further. The one clear outlier is the first
  run's 1000-rule row at 2453 ns/rule, nearly double every other
  1000-rule measurement (636, 720 ns/rule in the next two runs). This
  looks like allocator/UMA-zone warm-up on the very first large
  allocation burst in the process's lifetime, not a property of `n`
  itself, but it was not root-caused further -- flagging it rather
  than smoothing it over.
- **`commit_usec` is genuinely near-zero** (0-1us) at every size —
  see the headline above for why that is the whole point.
- **Memory is a steady ~52-55 bytes/rule** regardless of `n`, as
  expected for a per-rule fixed-size record plus amortized index
  overhead.

### `BENCH_CHUNK` and a real finding about `net.graph.maxdgram`

The task brief's reference implementation batches `ADD_RULE` messages
in chunks of 1024 rules. On this host, with the stock netgraph socket
limits, **that chunk size does not work**: `struct ng_policy_rule` is
32 bytes, so 1024 rules is 32768 bytes of rule data alone, and a
single `NGM_POLICY_TX_ADD_RULE` control message adds another ~56 bytes
of header (`struct ng_mesg` + `struct ng_policy_tx_add_rule`). That
overflows `net.graph.maxdgram`, a netgraph *socket-layer* sysctl
(default 20480 bytes = "Maximum outgoing Netgraph datagram size",
confirmed live on this host with `sysctl net.graph.maxdgram`), and
`NgSendMsg()` fails with `EMSGSIZE` ("Message too long") for any chunk
above roughly 638 rules. This is unrelated to `ng_policy_max_rules` or
`ng_policy_max_tx_bytes` (`ng_policy`'s own limits, both left at their
defaults and never approached here) — it is a generic netgraph
transport limit that any control-plane client batching more than
~600 rules per message would hit.

`tests/ngp_bench.c` uses `BENCH_CHUNK = 512` instead of 1024, which
fits comfortably under the 20480-byte cap. This is a benchmark
implementation fix, not a kernel change: no sysctl was raised, and
`net.graph.maxdgram` was left at its default. A real control-plane
client (or a future `ngp_install()`/harness helper) batching rules at
scale needs to either chunk under this limit too, or the operator
needs to raise `net.graph.maxdgram` — worth knowing, since it is easy
to hit by surprise the first time someone tries to push a large ruleset
in one message.

## Lookup cost

Measured with `tests/ngp_bench.c`'s `bench_lookup()`: 20,000
send-then-receive round trips of a single TCP SYN frame through the
node's data socket, at five points from a 0-rule (`DISABLED` mode)
baseline to 10,000 rules. Each non-baseline size installs `n - 1`
non-matching rules (so a scan degenerates to its full length if the
index is not being consulted) plus one matching low-priority rule and
one address-map entry, then re-measures the same 20,000 round trips.

Raw output (same run as above):

```
lookup cost, 20000 round trips (microseconds)
disabled     1183910
      10     1060176
     100     1265075
    1000     1479508
   10000     1354844
```

Two more runs:

```
disabled     1145273        disabled     1187900
      10     1131037              10     1240055
     100     1204658             100     1378766
    1000     1481414            1000     1589998
   10000     1253772           10000     1351232
```

Per-round-trip average (total / 20000), all three runs, in
microseconds — plus a fourth column from an independent re-run of the
same binary in a separate review session, on the same class of shared
VM but not back-to-back with the other three:

| rules    | run 1 | run 2 | run 3 | independent session |
|----------|------:|------:|------:|---------------------:|
| disabled | 59.2  | 57.3  | 59.4  | 54.1                  |
| 10       | 53.0  | 56.6  | 62.0  | 65.0                  |
| 100      | 63.3  | 60.2  | 68.9  | 56.3                  |
| 1000     | 74.0  | 74.1  | 79.5  | 59.1                  |
| 10000    | 67.7  | 62.7  | 67.6  | 54.8                  |

The independent column matters for how the two paragraphs below read:
runs 1-3 are correlated with each other (same session, same process
lifetime, back to back on a shared VM) and are not, by themselves,
independent confirmation of anything about the pattern *between* rule
counts. The fourth column is.

### Reading the lookup table

**These absolute numbers are not a measurement of `ng_policy_match()`
cost.** Every row pays two `NgSendData()`/`NgRecvData()` calls,
`select()`, and a full traverse through `ng_socket` → `ng_policy` →
`ng_socket` and back, all through a single-threaded userland test
program on a shared VM. That round-trip and scheduling overhead is
tens of microseconds by itself; the actual rule match inside the node
is very unlikely to be more than a small fraction of any of these
numbers. Only the *delta between rule counts* was ever meant to be
informative, because that delta is what the source-endpoint index
exists to keep flat.

**The delta stays flat, and does not grow with rule count.** Across
four independent runs (three same-session, one from a different
session — see the table above) and a 1000x range in rule count (10 to
10,000 rules), every per-round-trip average falls in a 53-80us band.
There is no scaling trend with `n` — if `ng_policy_match()` were
falling back to a full linear scan of `sn->rules` instead of consulting
`sn->idx`, going from 10 to 10,000 non-matching rules would be expected
to add on the order of 10,000x the per-rule comparison cost, which at
even a generous 10ns per comparison would add ~100us per lookup on top
of the baseline — easily visible against a 53-80us baseline. Nothing
like that appears in any of the four runs. This confirms
`ng_policy_match()` is consulting the source-endpoint index rather than
degenerating into a full scan, matching the "escalate if this grows
linearly" instruction in the task brief. This is an argument from the
*absence* of ~100us-scale growth, and it holds regardless of the noise
discussed in the next two paragraphs — a scan degenerating to O(n)
would be visible on top of that noise floor, not hidden by it.

**A small residual gap between `disabled` and the largest rule count
is visible in some runs, and is worth naming rather than leaving for a
skeptical reader to notice unaddressed.** In this session's three
runs, `n=10000` averaged 62.7-67.7us/rt against a `disabled` baseline
of 57.3-59.4us/rt — a fairly consistent 8-10us gap. The independent
session's run showed essentially none (`disabled` 54.1us vs `n=10000`
54.8us, a 0.7us difference). Read together, the honest conclusion is
that this gap is within this measurement's run-to-run variance, not a
reproducible cost that scales with rule count: it shows up in one
session and is absent in another. Even taking the larger, unreproduced
8-10us figure at face value, it is an order of magnitude smaller than
the ~100us a degenerate full scan at 10,000 rules would add (previous
paragraph) — so it does not weaken the "index is consulted" conclusion,
it just is not precise enough to support any conclusion of its own.

**A within-session bump at n=1000, in retrospect, does not survive
independent re-measurement and should be read as noise, not as a
property of the index.** This session's three back-to-back runs all
put n=1000 as the single slowest point measured (74.0-79.5us/rt),
consistently slower than n=10000 (62.7-67.7us/rt) — which looked at
the time like it might be a real, if unexplained, effect at that
particular table size, and an earlier draft of this document reported
it that way. It was not: an independent re-run of the same binary in a
different session put the *highest* value at **n=10** instead
(65.0us/rt), with n=1000 unremarkable at 59.1us/rt — see the table
above. Three runs in the same session, on the same shared VM, back to
back, are correlated with each other; they are not independent
confirmation of a pattern between rule counts. The fact that the
"slowest n" moved from 1000 to 10 between sessions is the signature of
scheduler and socket jitter, not a code-level effect: at a ~54us
measurement floor, a 10-20us bump is comparable in width to the noise
itself. It is reported here because the original within-session pattern
was real and worth naming when first seen, but it did not reproduce,
and the correct reading is measurement noise rather than an
unexplained property of `ng_policy`'s index.

## Dataplane throughput (not measured)

`tools/bench-dataplane.sh` generates load with `ng_source` against a
real interface and reads `ng_policy`'s own packet counters. It was
**written but not run**: this development sandbox has no real or
virtual network interface that is safe to flood (only `lo0` and a
single `em0` that carries this session's own connectivity), so
**line-rate packets-per-second has not been measured for `ng_policy`
anywhere in this project's history so far.**

Measuring it for real requires:

- A FreeBSD host (verified with `sysctl kern.ostype`, not `uname -s` —
  see the script's own comments for why) with root access.
- At least one interface that can be safely saturated with synthetic
  traffic for the duration of the test — i.e., not the interface
  carrying the operator's own connection to the host.
- `ng_ether`, `ng_source`, and a built `ng_policy.ko`, all loadable.
- Explicit confirmation (`-y`/`--yes`) that the operator understands
  the interface will be flooded.

The script refuses to run without every one of those, rather than
silently producing a number from a topology that was never actually
exercised. Even where run, note what it measures: `ng_source` pushing
synthetic frames into the node's endpoint hook, with the far hook
(`fab-1001`) deliberately left unconnected so packets are counted and
dropped rather than requiring a second interface. That is a real
measurement of `ng_policy`'s own per-packet processing rate, but it is
**not** a two-NIC "bare `ng_bridge` vs. `ng_policy` in line" wire
comparison — a true line-rate comparison needs two physical or virtual
interfaces and an external traffic source (or a second host) driving
one of them at a known rate, which is out of scope for this script.

## The four things to keep in mind reading any of this

1. **`reclaim_usec` measures the `NET_EPOCH_CALL()` enqueue, not the
   grace period.** Reclamation of the old snapshot is asynchronous;
   its true latency is not attributable to the commit that triggered
   it, and a near-zero `reclaim_usec` is not evidence that reclamation
   itself is free — it just means enqueuing the callback is cheap.
   (Not shown in the tables above since `bench_commit()` doesn't print
   it, but it is present in every `ng_policy_tx_commit_resp` and worth
   restating here since it is easy to misread if seen elsewhere, e.g.
   via `ngctl`.)
2. **`validate_usec` covers only the unlocked duplicate-rule-id scan.**
   The locked struct-field and endpoint-reference validation pass
   (`ngp_tx_validate_refs()`) runs earlier, still under the control
   mutex, and is deliberately not included in this figure — see the
   comment in `ng_policy_policy.c` above the `nanouptime(&t0)` that
   starts timing it.
3. **`build_usec` measures work done outside the node's control mutex**,
   using `M_WAITOK`, because the commit path was restructured (Task 7)
   to build the new snapshot off the lock. That is more honest than
   timing it under the lock, but it means a large commit still holds
   the node's *writer* claim (Netgraph's queueing exclusivity, not the
   mutex) across a possibly-sleeping allocation burst — other writer
   work, including data items, queues up behind it rather than the
   commit failing. A 100,000-rule commit's ~100-130ms `build_usec` is
   that long a stall for anything else waiting on the node. This is
   the flip side of the headline in "Reading the commit table" above:
   the swap that actually needs the node exclusively is ~1us, but the
   *writer claim* is held for the whole build, so the practical cost
   of a huge commit to its neighbors is `build_usec`, not
   `commit_usec`.
4. **The lookup benchmark's absolute numbers are dominated by socket
   round-trip overhead**, not `ng_policy_match()`. Only the delta
   between rule counts is meaningful, and as shown above, that delta
   stays flat (53-80us/rt, no growth with `n`) from 10 to 10,000
   rules — which is the whole point of the source-endpoint index.
   Publishing the absolute per-round-trip numbers as "forwarding cost"
   would overstate `ng_policy`'s actual per-packet cost by roughly two
   orders of magnitude.

## Reproducing

```sh
make -C sys/netgraph/ng_policy
doas kldload sys/netgraph/ng_policy/ng_policy.ko   # if not already loaded
make -C tests
doas tests/ngp_bench
```

Runs in a few seconds; re-run it as many times as you like (each run
tears down its own throwaway node). `tools/bench-dataplane.sh` needs
the prerequisites listed above and was not run as part of producing
this document.
