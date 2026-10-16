# FreeBSD port skeleton

A skeleton for `net/ng-policy`. It is not a finished port, and the two
things it is missing cannot be produced here.

## What is missing, and why

**`distinfo`.** It carries the SHA256 and byte size of the release
tarball, which do not exist until a release is tagged and GitHub serves
the distfile. Generate it, never write it by hand:

```sh
mkdir -p /usr/ports/net/ng-policy
cp Makefile pkg-descr /usr/ports/net/ng-policy/
cd /usr/ports/net/ng-policy
make makesum
```

**A test build.** With no distfile there is nothing to fetch, so
`make stage`, `poudriere testport` and `portlint` have not been run
against this. Treat the file below as a first draft that compiles the
right things, not as a port known to build in a clean jail.

## What it does express

- `USES=kmod uidfix` — `kmod` installs into `${KMODDIR}` and adds the
  `kld` category; `uidfix` lets the build run unprivileged.
- `DISTVERSION=0.1` with `DISTVERSIONPREFIX=v`, so the distfile comes
  from tag `v0.1`. This tracks `NG_POLICY_VERSION`, which the running
  module reports as `net.graph.policy.version`. It is **not** the
  control ABI version (`net.graph.policy.abi_version`); the two move
  independently.
- `MAKE_ARGS` sets `MANDIR` under `${PREFIX}`, because `man/Makefile`
  goes through `bsd.prog.mk`, whose default is `/usr/share/man/man` —
  correct for `make install` from a source tree, wrong for a package.
- `MAKE_ARGS` also sets `NGP_SUBDIR` to the module and the man page
  only. `tests/` needs a loaded module and root, and `bsd.progs.mk`
  would otherwise stage three binaries into `bin/` that the plist does
  not list. It has to be `NGP_SUBDIR` and not `SUBDIR`: see the comment
  in the top-level `Makefile`.
- `PLIST_FILES` lists exactly the two installed files.

## Checked

`make -n install NGP_SUBDIR="sys/netgraph/ng_policy man"
MANDIR=/usr/local/share/man/man` stages `ng_policy.ko` into
`/boot/modules` with `kldxref`, and `ng_policy.4.gz` into
`/usr/local/share/man/man4`, and descends into no other directory.
That is the behaviour the port depends on; the port itself is still
unbuilt.
