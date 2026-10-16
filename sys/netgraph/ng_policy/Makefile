KMOD=	ng_policy
SRCS=	ng_policy.c ng_policy_packet.c ng_policy_policy.c \
	ng_policy_endpoint.c ng_policy_stats.c

# The sources say <netgraph/ng_policy/ng_policy.h>, exactly as they would
# in an in-tree build under sys/.  This directory *is* sys/netgraph/ng_policy,
# so the include root that spelling needs is simply sys/ -- two levels up.
# No symlink shim, and nothing to go wrong if the tree is copied, archived
# or checked out on a filesystem without symlinks.
CFLAGS+=	-I${.CURDIR}/../..

.include <bsd.kmod.mk>
