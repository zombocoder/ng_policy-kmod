# FreeBSD port skeleton

A skeleton for `net/ng-policy`. It is not a finished port, and the two
things it is missing cannot be produced here.

## What is missing, and why

**`distinfo`.** It carries the SHA256 and byte size of the release
tarball. The `v0.1` tag now exists and is pushed, and the port resolves
the right URL from it:

```
$ make -V MASTER_SITES
https://codeload.github.com/zombocoder/ng_policy-kmod/tar.gz/v0.1?dummy=/
```

But that URL answers 404, because **the repository is private**.
codeload does not distinguish private from absent for an
unauthenticated client, and the anonymous HTTPS git endpoint hangs
asking for credentials while SSH works — which is how the diagnosis was
confirmed. So `make makesum` has nothing to hash:

```
=> Attempting to fetch http://distcache.FreeBSD.org/ports-distfiles/...
=> Couldn't fetch it - please try to retrieve this
*** Error code 1
```

Making the repository public is the one remaining step. After that:

```sh
mkdir -p /usr/ports/net/ng-policy
cp Makefile pkg-descr /usr/ports/net/ng-policy/
cd /usr/ports/net/ng-policy
make makesum          # writes distinfo; copy it back here
```

`distinfo` is never written by hand. The hash has to be of the exact
bytes GitHub serves, and those depend on its own archiving, so a
locally built tarball would produce a different and wrong value. An
invented hash is worse than a missing file: it fails at install time,
on somebody else's machine, looking like a corrupted download.

**A test build.** With nothing fetchable, `make stage`,
`poudriere testport` and `portlint` have not been run against this.
Treat the Makefile as a draft that names the right things, not as a
port known to build in a clean jail.

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

The Makefile was also placed in a real ports tree and queried, which is
what established that the variables resolve correctly:

| | |
|---|---|
| `MASTER_SITES` | `https://codeload.github.com/zombocoder/ng_policy-kmod/tar.gz/v0.1?dummy=/` |
| `DISTFILES` | `zombocoder-ng_policy-kmod-v0.1_GH0.tar.gz` |
| `WRKSRC` | `work/ng_policy-kmod-0.1` |
| `USE_GITHUB` | `yes` |

So the tag, the version and the GitHub account and project all line up,
and `WRKSRC` lands where `LICENSE_FILE` and `MAKE_ARGS` expect. What is
unverified is everything downstream of the fetch: the build, the stage,
the plist and the package.
