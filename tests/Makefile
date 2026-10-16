PROGS=	ngp_test ngp_fuzz ngp_bench
SRCS.ngp_test=	ngp_test.c ngp_harness.c
SRCS.ngp_fuzz=	ngp_fuzz.c ngp_harness.c
SRCS.ngp_bench=	ngp_bench.c ngp_harness.c
MAN=
LDADD=	-lnetgraph
# ${.CURDIR}/../include is include, which carries the
# netgraph/ng_policy/ symlink shim (see src/Makefile) so
# <netgraph/ng_policy/ng_policy.h> resolves from here the same way it
# does for the kernel module build.
CFLAGS+=	-I${.CURDIR} -I${.CURDIR}/../include
# ngp_test deliberately over-allocates a variable-length response struct
# by following it with a fixed-size array in an outer struct, e.g.
# "struct { struct ng_policy_ep_list_resp r; struct ng_policy_endpoint_info
# e[4]; } out;".  That is a well-understood idiom for receiving a bounded
# flexible-array response into stack space, but clang's GNU-extension
# diagnostic doesn't know the intent; silence it here rather than restructure
# the test bodies.
CFLAGS.ngp_test+=	-Wno-gnu-variable-sized-type-not-at-end
LDADD.ngp_test=	-lpthread
# Matches the FreeBSD src tree's default (DEFAULTWARNS, share/mk/bsd.sys.mk)
# rather than settling for a weaker level than "warning-clean" implies. No
# additional warning fired when this was raised from the out-of-tree
# default of 3: -Wcast-qual/-Wshadow/-Wcast-align/-Wold-style-definition/
# -Wmissing-variable-declarations/-Wthread-safety and the rest of the
# WARNS 4/6 tiers were all already clean, so there was nothing to trade off.
WARNS?=	6

.include <bsd.progs.mk>
