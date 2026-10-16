# Security policy

`ng_policy` runs in the kernel and enforces network policy, so two
kinds of bug are security bugs here:

- anything reachable from the control socket or from a frame that can
  crash, hang, corrupt or leak kernel memory; and
- anything that makes the node forward a frame that the committed
  policy says to drop, or report counters that hide it.

[`docs/security.md`](docs/security.md) describes the threat model and
what has and has not been tested.

## Supported versions

Only the latest tagged release and `main` receive fixes.

| Version | Supported |
|---|---|
| `main` | yes |
| `v0.1` | yes |

## Reporting a vulnerability

Please **do not open a public issue.** Report privately through
GitHub's [private vulnerability reporting](https://github.com/zombocoder/ng_policy-kmod/security/advisories/new),
or by email to the address in [`LICENSE`](LICENSE).

Include what you can of:

- the FreeBSD version and architecture, and whether the kernel has
  `INVARIANTS`/`WITNESS`;
- the `ng_policy` commit or tag;
- a reproduction — an `ngctl` script, a C program, a frame as hex, or
  an `ngp_fuzz` seed and iteration count;
- the observed effect (panic message and backtrace, wrong forwarding
  decision, leaked memory as reported by `vmstat -m`).

You should get an acknowledgement within a week. Once a fix is ready,
it is released together with an advisory, and you are credited unless
you ask not to be.
