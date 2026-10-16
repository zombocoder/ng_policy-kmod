PORTNAME=	ng-policy
DISTVERSIONPREFIX=	v
DISTVERSION=	0.1
CATEGORIES=	net

MAINTAINER=	zombocoder@gmail.com
COMMENT=	Netgraph identity-aware policy enforcement node
WWW=		https://github.com/zombocoder/ng_policy-kmod

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

USE_GITHUB=	yes
GH_ACCOUNT=	zombocoder
GH_PROJECT=	ng_policy-kmod

# kmod adds the kld category and installs into ${KMODDIR}; uidfix lets the
# build run unprivileged and stage as the port framework expects.
USES=	kmod uidfix

# The man page is built by man/Makefile through bsd.prog.mk, whose MANDIR
# defaults to /usr/share/man/man.  A port must stage under ${PREFIX}, so
# point it there rather than patching the Makefile.
MAKE_ARGS=	MANDIR=${PREFIX}/share/man/man

# tests/ needs a loaded module and root, so it is no part of a port
# build: only the module and its page are built and installed here.
# NGP_SUBDIR rather than SUBDIR, because bmake propagates command-line
# variables into every sub-make, so overriding SUBDIR recurses. See the
# comment in the top-level Makefile.
MAKE_ARGS+=	NGP_SUBDIR="sys/netgraph/ng_policy man"

PLIST_FILES=	${KMODDIR}/ng_policy.ko \
		share/man/man4/ng_policy.4.gz

.include <bsd.port.mk>
