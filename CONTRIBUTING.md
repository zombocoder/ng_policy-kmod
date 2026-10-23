# Contributing to ng_policy

Thanks for taking the time. `ng_policy` is a kernel module: a bug in it
can panic a machine or let traffic through that policy says to drop, so
the bar for changes is set by that, not by how small a patch looks.
This document says what that bar is.

## Before you start

- **Bugs**: open an issue with the bug report template. A reproduction
  — an `ngctl` script, a failing `ngp_test` case, or a fuzzer seed — is
  worth more than any description.
- **Security issues**: do **not** open a public issue. See
  [`SECURITY.md`](SECURITY.md).
- **New features or behaviour changes**: open an issue first and
  describe the problem before the patch. Read
  [`docs/architecture.md`](docs/architecture.md) beforehand; the
  module deliberately knows nothing about tenants, VPCs, jails, labels
  or any other higher-level concept, and changes that teach it one
  will be declined — that belongs in the userland compiler.

## Environment

FreeBSD 14.3-RELEASE or later, amd64, with a source tree in
`/usr/src` (the module builds against it) and root access via `doas`
or `sudo`. Tests load a kernel module and create netgraph nodes, so
use a VM or a test machine you can afford to panic, not a production
host.

## Build, test, verify

[`docs/development.md`](docs/development.md) has the full commands. A
change is ready for review when this sequence passes on your machine:

```sh
make -C sys/netgraph/ng_policy          # -Werror, no warnings
make -C tests                           # WARNS=6, no warnings
doas kldunload ng_policy 2>/dev/null || true
doas kldload ./sys/netgraph/ng_policy/ng_policy.ko
doas ./tests/ngp_test                   # N run, 0 failed
doas sysctl net.graph.policy.debug_force_copy=1
doas ./tests/ngp_test                   # again, on the copy path
doas sysctl net.graph.policy.debug_force_copy=0
doas ./tests/ngp_fuzz 12345 200000      # survives to its summary line
doas sh tests/ngp_stress.sh ./sys/netgraph/ng_policy/ng_policy.ko 50
doas kldunload ng_policy
vmstat -m | grep -c ng_policy           # 0 — nothing leaked
```

If you touched `man/ng_policy.4`, also run `mandoc -Tlint
man/ng_policy.4` and expect no output.

If the change can plausibly affect performance (anything on the packet
path or in commit), run `doas ./tests/ngp_bench` before and after and
include both tables in the pull request.

Building with `INVARIANTS` and `WITNESS` enabled in the kernel is
encouraged; say in the pull request whether you did. See
[`docs/security.md`](docs/security.md) for what testing with them off
does and does not prove.

## What a change needs

- **A test.** Behaviour changes and bug fixes come with a case in
  `tests/ngp_test.c`, registered in `ngp_cases[]`. For a bug fix, the
  test should fail without the fix — say in the pull request that you
  checked this.
- **Untrusted input stays untrusted.** Everything arriving over the
  control socket or in a frame is hostile until validated: sizes
  checked against `arglen`, enums against their `_VALID()` macros,
  counts checked for overflow before multiplying. If the change adds
  or alters a control message, consider whether `tests/ngp_fuzz.c`
  should exercise it. Follow
  [the end-to-end recipe](docs/development.md#adding-a-new-control-message-end-to-end).
- **Module boundaries hold.** The parser knows nothing about policy,
  the matcher knows nothing about mbufs or hooks, the endpoint table
  knows nothing about packets. See
  [`docs/development.md`](docs/development.md#source-layout-and-each-files-responsibility).
- **ABI changes are deliberate.** Anything that changes a wire struct
  in `ng_policy_msg.h` or the meaning of a field bumps
  `NG_POLICY_ABI_VERSION`, and the pull request says why.
- **Documentation follows the code.** New or changed control messages,
  sysctls, counters or errno values are reflected in
  `man/ng_policy.4` and the relevant file under `docs/`. If the test
  count changes, update it everywhere it is stated (`grep -rn
  "62 run"` is a good start).
- **No claims without evidence.** The table in `docs/verification.md` pairs
  every property with what demonstrates it. Keep it that way: if a
  change adds a property, add the row and the test; if it cannot be
  tested here, say so in the row.

## Style

Kernel and test code follow [style(9)](https://man.freebsd.org/style/9).
`tools/build/checkstyle9.pl` from the FreeBSD source tree is a useful
check; it reports one known false positive on
`LIST_HEAD(, ng_policy_ep) *ephash;`. Every new file carries an
`SPDX-License-Identifier: BSD-2-Clause` tag and a copyright line.

## Commits and pull requests

- One logical change per commit. Keep unrelated cleanups out.
- Subject line: `area: what changed`, imperative, under ~72 characters
  — for example `man: add ng_policy.4` or `tests: cover paging past
  the last endpoint`. Use `ng_policy:` for the module itself.
- The body explains *why*, and what was verified and on what — FreeBSD
  version and architecture, and the test/fuzz/stress results. Say what
  you did not verify, too.
- Fill in the pull request template; it is the same checklist as above.

## License

By contributing, you agree that your contributions are licensed under
the [BSD-2-Clause license](LICENSE) that covers this project.
