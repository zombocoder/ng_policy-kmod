# Development

Building, loading, testing, fuzzing, and benchmarking `ng_policy`, plus
the source layout and how to add a new control message end to end. For
worked, executed `ngctl` sessions see
[`ngctl-examples.md`](ngctl-examples.md); for measured numbers see
`docs/performance.md`.

## Environment

FreeBSD 14.3-RELEASE, passwordless `doas` (no `sudo`), `ng_socket`
available. All commands below are run from this repository's root.

## Build

```sh
make -C sys/netgraph/ng_policy
```

Builds `sys/netgraph/ng_policy/ng_policy.ko`. Clean at `-Werror`; no
warnings is the bar, not merely "compiles."

```sh
make -C tests
```

Builds `tests/ngp_test`, `tests/ngp_fuzz`, `tests/ngp_bench` (all link
`-lnetgraph`; `ngp_test` additionally links `-lpthread` for its
concurrency tests). Also `-Werror`.

```sh
make
```

Descends into `src`, `man` and `tests`. `doas make install` puts the
module in `/boot/modules` (running `kldxref`, so `kldload ng_policy`
then works by name) and `man/ng_policy.4` in `/usr/share/man/man4`.

The man page lives in `man/` with its own `Makefile` rather than
alongside the sources because `sys/conf/kmod.mk` has no man-page
handling at all — a `MAN=` in a kmod `Makefile` is silently ignored.
The FreeBSD tree separates them the same way, keeping netgraph pages
in `share/man/man4/` and the modules under `sys/netgraph/`. That
`Makefile` includes `bsd.prog.mk` with no `PROG`, which is the
man-page-only pattern `share/man/man4/` itself uses; `bsd.man.mk`
refuses to be included directly.

## Load / unload

```sh
doas kldload ./sys/netgraph/ng_policy/ng_policy.ko
doas kldstat | grep policy      # confirm it's loaded
doas kldunload ng_policy
```

## Run the tests

```sh
doas ./tests/ngp_test               # all 62 cases
doas ./tests/ngp_test <case_name>   # a single case, e.g. rule_priority
```

Expect `62 run, 0 failed`. The module must already be built (loading is
handled by the harness itself per test — each test creates and tears
down its own throwaway node).

## Run the fuzzer with a seed

```sh
doas ./tests/ngp_fuzz <seed> <iterations>
doas ./tests/ngp_fuzz 12345 200000      # the run behind docs/security.md
```

Both arguments are optional (default seed `12345`, default 200,000
iterations); passing an explicit seed is what makes a run reproducible
for bisection. The RNG is a plain `xorshift32` seeded directly from the
argument — the same seed and iteration count always drive the identical
sequence of control messages and frames.

## Run the benchmarks

```sh
doas ./tests/ngp_bench
```

Prints two tables — commit cost at 100/1,000/10,000/100,000 rules with
userland/validate/build/commit/memory columns, and lookup cost at
0 (disabled)/10/100/1,000/10,000 rules over 20,000 round trips each. See
`docs/performance.md` for a full reading of a real run, including the
caveats about what the absolute lookup numbers do and do not measure.

## Leak checking

```sh
doas sh tests/ngp_stress.sh ./sys/netgraph/ng_policy/ng_policy.ko 50
```

Loads the module, runs 50 (or however many are given) node
create/`ENDPOINT_ADD`×2/shutdown cycles via `ngctl -f -`, and reports
the `ng_policy` malloc type's in-use count/bytes from `vmstat -m`
before, during, and after — then unloads the module *without*
tolerating a failed unload (a stuck reference fails the script). A
completely absent `ng_policy` row in `vmstat -m` and a row reading
`0 0` mean the same thing — this kernel does not list a malloc type
until it has had at least one allocation request, so "after load" with
no live node yet showing blank is expected, not a bug in the script.

## Full verification sequence

The exact sequence this project's own completion gate runs:

```sh
make -C sys/netgraph/ng_policy
make -C tests
doas kldunload ng_policy 2>/dev/null || true
doas kldload ./sys/netgraph/ng_policy/ng_policy.ko
doas ./tests/ngp_test
doas ./tests/ngp_fuzz 12345 200000
doas sh tests/ngp_stress.sh ./sys/netgraph/ng_policy/ng_policy.ko 50
doas ./tests/ngp_bench
doas kldunload ng_policy
vmstat -m | grep -c ng_policy
```

Expect `62 run, 0 failed`; the fuzzer survives to its final summary
line; the stress script exits 0 with the in-use count returned to
baseline; the benchmark prints both tables; the final `grep -c` prints
`0` (no `ng_policy` malloc-type entries remain once the module is
unloaded).

## Source layout and each file's responsibility

```
sys/netgraph/ng_policy/
  ng_policy.h           public constants: node type, actions, modes, reserved endpoint IDs
  ng_policy_msg.h        public control ABI: cookie, opcodes, wire structs, ng_parse TYPE_INFO macros
  ng_policy_var.h        internal structures shared across the .c files; not installed
  ng_policy.c             type registration, ng_parse type wiring, constructor/shutdown,
                         newhook/disconnect, message dispatch (ng_policy_rcvmsg),
                         rcvdata and the top-level decision function (ngp_decide)
  ng_policy_packet.c      Ethernet/IPv4/TCP/UDP/ICMP parsing into flat ng_policy_meta;
                         bounds-safe, no m_pullup, no policy knowledge
  ng_policy_policy.c      snapshot lifecycle, transactions, validation, atomic commit,
                         the source-endpoint rule index, and ng_policy_match()
  ng_policy_endpoint.c    endpoint table, hook binding (either order), address-map build
                         and lookup
  ng_policy_stats.c       counter allocation/init/fini, GET_STATS/GET_RULE_STATS
                         aggregation, RESET_STATS
  Makefile
man/
  ng_policy.4              the reference page; see the note under Build
  Makefile
tests/
  ngp_harness.{c,h}       shared setup/teardown, message helpers, frame builders,
                         used by all three test binaries
  ngp_test.c               62 functional/behavioural test cases (ngp_cases[])
  ngp_fuzz.c               seeded control- and packet-path fuzzer
  ngp_bench.c              commit-cost and lookup-cost benchmarks
  ngp_stress.sh            leak-checking create/destroy cycle script
tools/
  bench-dataplane.sh       line-rate dataplane probe (needs real interfaces; not run
                         in this sandbox — see docs/performance.md)
```

Boundaries worth preserving when extending this: the parser
(`ng_policy_packet.c`) takes an `mbuf` and returns metadata, and knows
nothing about policy; the matcher (`ng_policy_policy.c`) takes metadata
and a snapshot, and knows nothing about mbufs or hooks; the endpoint
table (`ng_policy_endpoint.c`) knows nothing about packets. Each is
independently testable, and each has stayed that way across the
project's development — see `docs/architecture.md` for the same
boundaries stated from the design side.

## Adding a new control message end to end

Using `NGM_POLICY_RESET_STATS` as the concrete example of every step
this requires (all in `ng_policy_msg.h` and `ng_policy.c` unless noted):

1. **Add the opcode** to the `enum` in `ng_policy_msg.h`
   (`NGM_POLICY_RESET_STATS = ...`).
2. **Define the request/response struct(s)**, sized and laid out
   deliberately (no implicit padding assumed — check with a comment or
   a `sizeof()` build-time assertion if it matters, as
   `ng_policy_rule` does), plus a `NG_POLICY_<NAME>_TYPE_INFO` macro
   listing each field's name and `ng_parse` type
   (`&ng_parse_uint32_type`, `&ng_parse_hint32_type` for flags fields
   that should print as hex, `&ng_parse_hookbuf_type` for hook names,
   `&ng_parse_ipaddr_type` for IPv4 addresses).
3. **If the message carries a variable-length array**, write a
   `getLength` callback for it and read the comment above
   `ng_policy_rule_ary_len()` in `ng_policy.c` first — see
   [`security.md`](security.md#the-array-length-clamp-is-deliberately-absent)
   for exactly why no bound is derived from the surrounding buffer.
4. **Register the `ng_parse` type** in `ng_policy.c`: a
   `static const struct ng_parse_struct_field foo_fields[] = NG_POLICY_FOO_TYPE_INFO`
   followed by a `static const struct ng_parse_type foo_type = {
   &ng_parse_struct_type, &foo_fields }`, in the same block as the
   other message types, in opcode order.
5. **Add an entry to `ng_policy_cmdlist[]`** — the ASCII name `ngctl`
   will accept, the cookie, the opcode, and the request/response
   `ng_parse_type` pointers (`NULL` for either side if the message has
   no request body or no response).
6. **Add the dispatch case** in `ng_policy_rcvmsg()`'s `switch`: check
   `msg->header.arglen` against the expected size first (`NGP_ARGLEN()`
   for a fixed-size request, or the batched-message pattern in the
   `TX_ADD_RULE`/`TX_ADD_ADDR` cases for a variable-length one), then
   call into the implementation function (which should live in
   whichever `.c` file owns the state being touched — do not put
   endpoint-table logic in `ng_policy.c` itself). If the command
   returns data, use `NG_MKRESPONSE(resp, msg, size, M_NOWAIT)` —
   `msg` must be the original request, not just the parsed struct; see
   [`control-api.md`](control-api.md#writing-a-new-response-handler-ng_mkresponse-needs-the-original-message).
7. **Validate every field before using it.** Every existing handler is
   the model: check `version` against `NG_POLICY_ABI_VERSION` if the
   struct carries one, check enum fields against their `_VALID()`
   macro, check array counts for overflow before multiplying by the
   element size, and never trust `arglen` beyond what the exact-size
   check already confirmed.
8. **Write a test** in `tests/ngp_test.c` (new `static int
   test_foo(struct ngp_ctx *c)` function) and register it in
   `ngp_cases[]`. If the new command's inputs are attacker-shaped
   (sizes, counts, enum values), consider whether `ngp_fuzz.c`'s
   control-message fuzzing should exercise it too.
9. **Document it** — a row in the [`control-api.md`](control-api.md)
   command table, and an entry in the errno table if it introduces a
   new failure mode.

## Two things that cost real time to discover

**`NgSendData()` can report `ENOBUFS` for a frame the node already
received and counted.** All three `ENOBUFS` return sites in
`ng_socket.c` are on the *receive* side — inside
`sbappendaddr_locked(&so->so_rcv, ...)`, i.e. delivering data (or a
control response) into a socket's own receive buffer, never on the
send path from userland into the graph. Concretely: when a harness
sends a frame through socket A, the node processes it (incrementing
`packets_total` and whatever else applies) and forwards it toward
socket B; if socket B's receive buffer happens to be full at that
moment, the resulting `ENOBUFS` propagates back up the same call chain
to the original `NgSendData()` on socket A that started it, even
though the node already received, counted, and forwarded the frame
successfully. A test harness that treats `ENOBUFS` from a send call as
"the packet never made it into the node" will chase a phantom — count
it separately from other send errors instead, and expect
`packets_total` to still reflect it.
`test_concurrent_policy_replacement`'s sender thread does exactly this
(`sent_enobufs` tracked apart from `sent_other_error`, with
`packets_total == sent + sent_enobufs` asserted rather than a naive
`packets_total == sent`).

**A restored source file with an mtime older than its `.o` will not be
rebuilt.** If a file is reverted via `git checkout`, restored from a
patch, or otherwise written back with a timestamp that predates the
already-built `.o`, `make` sees the object file as up to date and
silently skips recompilation — the test binary keeps running the *old*
code, and a fix that looks correct in the source tree produces no
observable change in test behaviour, which is a confusing way to lose
time. After restoring any tracked file that a `.o` already depends on,
`touch` it (or otherwise force its mtime forward) before rebuilding, or
just `rm` the stale `.o`/binary and let `make` start clean.
