# The man page is built and installed from here rather than from src/:
# sys/conf/kmod.mk has no man-page handling whatsoever, so a MAN= in a
# kmod Makefile is silently ignored. The FreeBSD tree keeps netgraph man
# pages in share/man/man4/ for the same reason, separate from the module
# under sys/netgraph/.
#
# bsd.prog.mk with no PROG is the man-page-only pattern share/man/man4/
# itself uses; bsd.man.mk refuses to be included directly.
MAN=	ng_policy.4

.include <bsd.prog.mk>
