KMOD=	ng_policy
SRCS=	ng_policy.c ng_policy_packet.c ng_policy_policy.c \
	ng_policy_endpoint.c ng_policy_stats.c

# Lets the sources say <netgraph/ng_policy/ng_policy.h>, exactly as they
# would in an in-tree build under sys/.  ../include is the include root;
# ../include/netgraph/ng_policy is a symlink to this directory (../src,
# from ../include/netgraph/'s own location), so the flat layout here
# still satisfies the <netgraph/ng_policy/...> spelling without a
# duplicated or nested source tree.  The symlink points downward
# (include/ -> src/), not upward from inside src/ itself, so there is
# no filesystem loop -- see ../include/netgraph/ng_policy.
CFLAGS+=	-I${.CURDIR}/../include

.include <bsd.kmod.mk>
