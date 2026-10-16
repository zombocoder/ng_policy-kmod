# Developer default: the module, its man page and the test programs.
#
# A packaging build limits this with NGP_SUBDIR rather than SUBDIR. bmake
# propagates command-line variables into every sub-make, so overriding
# SUBDIR directly makes each subdirectory re-apply the same list and
# recurse into sys/netgraph/ng_policy/sys/netgraph/ng_policy. NGP_SUBDIR
# is read only here, where nothing descends into it twice, and the leaf
# Makefiles ignore it.
#
# tests/ is deliberately not installable from a port: bsd.progs.mk would
# stage three binaries into bin/, which is not what a kernel module
# package contains.
NGP_SUBDIR?=	sys/netgraph/ng_policy man tests
SUBDIR=	${NGP_SUBDIR}

.include <bsd.subdir.mk>
