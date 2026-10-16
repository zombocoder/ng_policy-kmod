## What and why

<!-- What this changes, and the problem it solves. Link the issue if there is one. -->

## How it was verified

FreeBSD version / arch: <!-- uname -a -->
Kernel INVARIANTS / WITNESS: <!-- yes / no -->

- [ ] `make -C sys/netgraph/ng_policy` and `make -C tests` build with no warnings
- [ ] `doas ./tests/ngp_test` — ___ run, 0 failed
- [ ] the same with `net.graph.policy.debug_force_copy=1`
- [ ] `doas ./tests/ngp_fuzz 12345 200000` survives
- [ ] `doas sh tests/ngp_stress.sh ./sys/netgraph/ng_policy/ng_policy.ko 50` exits 0
- [ ] `vmstat -m | grep -c ng_policy` prints `0` after `kldunload`
- [ ] `mandoc -Tlint man/ng_policy.4` is clean (if the man page changed)
- [ ] `ngp_bench` before/after tables included (if the packet path or commit changed)

## Checklist

- [ ] New or changed behaviour has a test in `tests/ngp_test.c`; for a bug fix, the test fails without the fix
- [ ] Control-socket and frame input is validated before use
- [ ] Wire-struct changes bump `NG_POLICY_ABI_VERSION`
- [ ] `man/ng_policy.4` and `docs/` updated, including test counts
- [ ] style(9)
