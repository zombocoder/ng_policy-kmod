#ifndef _NETGRAPH_NG_POLICY_VAR_H_
#define _NETGRAPH_NG_POLICY_VAR_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/epoch.h>
#include <sys/counter.h>
#include <sys/sysctl.h>
#include <sys/callout.h>

#include <netgraph/ng_message.h>
#include <netgraph/netgraph.h>
#include <netgraph/ng_parse.h>

#include <netgraph/ng_policy/ng_policy.h>

MALLOC_DECLARE(M_NG_POLICY);

/* Load and store the policy snapshot pointer with the right barriers. */
#define	NGP_LOAD_PTR(p) \
	((void *)atomic_load_acq_ptr((volatile uintptr_t *)&(p)))
#define	NGP_STORE_PTR(p, v) \
	atomic_store_rel_ptr((volatile uintptr_t *)&(p), (uintptr_t)(v))

struct ng_policy_rlist {
	uint32_t	off;		/* index into snapshot->idx_store */
	uint32_t	count;
};

struct ng_policy_snapshot {
	uint64_t		generation;
	uint32_t		nrules;
	uint8_t			default_action;
	uint8_t			pad[3];
	struct ng_policy_rule	*rules;		/* sorted, immutable */
	/* source-endpoint index, built in Task 7 */
	uint32_t		idx_mask;
	struct ng_policy_rlist	*idx;
	struct ng_policy_rlist	any_src;
	uint32_t		*idx_store;
	/* address map, built in Task 6 */
	uint32_t		addr_mask;
	uint32_t		naddrs;
	struct ng_policy_addr	*addrs;
	/* per-rule counters, added in Task 7 */
	counter_u64_t		*rule_pkts;
	counter_u64_t		*rule_bytes;
	size_t			memsize;
	struct epoch_context	ectx;
};

struct ng_policy_tx {
	LIST_ENTRY(ng_policy_tx) link;
	uint64_t	tx_id;
	uint64_t	generation;
	uint8_t		default_action;
	uint8_t		has_default;
	uint8_t		committing;	/* validate/build in progress, unlocked */
	uint32_t	nrules, rules_cap;
	struct ng_policy_rule *rules;
	uint32_t	naddrs, addrs_cap;
	struct ng_policy_addr *addrs;
	size_t		memsize;
	time_t		expires;	/* uptime seconds */
};

#define	NGP_EPHASH_SIZE	1024
#define	NGP_EPHASH(id)	((id) & (NGP_EPHASH_SIZE - 1))

#define	NGP_SIDE_NONE	0
#define	NGP_SIDE_EP	1	/* workload side: ingress means "from endpoint" */
#define	NGP_SIDE_FAB	2	/* fabric side: ingress means "to endpoint" */

struct ng_policy_hookpriv {
	hook_p			hook;
	struct ng_policy_ep	*ep;		/* NULL when unbound */
	uint8_t			side;
	char			name[NG_HOOKSIZ];
	struct epoch_context	ectx;
};

struct ng_policy_ep {
	LIST_ENTRY(ng_policy_ep) hashlink;	/* id hash */
	TAILQ_ENTRY(ng_policy_ep) alllink;	/* insertion order, for listing */
	uint32_t		endpoint_id;
	uint32_t		flags;
	char			hook[NG_HOOKSIZ];
	char			peer_hook[NG_HOOKSIZ];
	struct ng_policy_hookpriv *hp;		/* workload-side hook, or NULL */
	struct ng_policy_hookpriv *peer_hp;	/* fabric-side hook, or NULL */
	counter_u64_t		rx_packets, rx_bytes;
	counter_u64_t		tx_packets, tx_bytes;
	counter_u64_t		allowed_packets, dropped_packets, violations;
	struct epoch_context	ectx;
};

/*
 * Per-packet metadata, filled in by parsing (Task 4) and consumed by
 * matching (Task 7).  Zeroed and left mostly unfilled until then.
 */
struct ng_policy_meta {
	uint32_t	src_endpoint;
	uint32_t	dst_endpoint;
	uint32_t	src_ipv4;	/* network byte order */
	uint32_t	dst_ipv4;	/* network byte order */
	uint16_t	ether_type;	/* host order */
	uint16_t	src_port;	/* host order, 0 if not applicable */
	uint16_t	dst_port;
	uint8_t		ip_version;
	uint8_t		protocol;
	uint8_t		icmp_type;
	uint8_t		icmp_code;
	uint8_t		flags;
};
#define	NGP_META_F_FIRSTFRAG	0x01

/*
 * Parse outcome categories.  Everything but OK is routed to its own
 * configured action in ngp_decide(), and never reaches rule matching.
 */
enum ng_policy_parse_result {
	NG_POLICY_PARSE_OK = 0,
	NG_POLICY_PARSE_ARP,
	NG_POLICY_PARSE_FRAGMENT,	/* non-initial: no transport header */
	NG_POLICY_PARSE_UNSUPPORTED,	/* non-IPv4, non-ARP EtherType */
	NG_POLICY_PARSE_MALFORMED,
};

struct ng_policy_decision {
	uint64_t	rule_id;
	uint8_t		action;
	uint8_t		matched;
};

#define	NGP_NODE_COUNTERS(X)						\
	X(packets_total) X(bytes_total)					\
	X(allowed_packets) X(allowed_bytes)				\
	X(dropped_packets) X(dropped_bytes)				\
	X(permissive_violations)					\
	X(malformed_packets) X(unsupported_packets)			\
	X(fragmented_packets) X(arp_packets)				\
	X(unbound_hook_packets) X(no_peer_packets)			\
	X(rule_matches) X(default_matches)				\
	X(addr_lookups) X(addr_hits)					\
	X(commits) X(failed_commits) X(aborts) X(tx_timeouts)

struct ng_policy_ctrs {
#define	X(n)	counter_u64_t n;
	NGP_NODE_COUNTERS(X)
#undef X
};

#define	NGP_CTR(priv, name, v)	counter_u64_add((priv)->ctrs.name, (v))

struct ng_policy_priv {
	node_p		node;
	struct mtx	ctl_mtx;
	struct ng_policy_config cfg;
	struct ng_policy_snapshot * volatile policy;
	LIST_HEAD(, ng_policy_ep) *ephash;	/* NGP_EPHASH_SIZE buckets */
	TAILQ_HEAD(, ng_policy_ep) eplist;	/* insertion order */
	uint32_t	nendpoints;
	int		shutting_down;
	struct ng_policy_ctrs ctrs;
	LIST_HEAD(, ng_policy_tx) txlist;
	uint32_t	ntx;
	uint64_t	next_tx_id;
	size_t		tx_memory;
	struct callout	tx_callout;
	int		tx_callout_armed;
};
typedef struct ng_policy_priv *priv_p;

/* ng_policy_endpoint.c */
int	ng_policy_ep_add(priv_p, const struct ng_policy_endpoint_add *);
int	ng_policy_ep_del(priv_p, uint32_t id);
struct ng_policy_ep *ng_policy_ep_lookup(priv_p, uint32_t id);
void	ng_policy_ep_flush(priv_p);
int	ng_policy_ep_list(priv_p, const struct ng_mesg *,
	    const struct ng_policy_ep_query *, struct ng_mesg **rp);
void	ng_policy_hook_attach(priv_p, struct ng_policy_hookpriv *);
void	ng_policy_hook_detach(priv_p, struct ng_policy_hookpriv *);
/* Build the open-addressed table into sn->addrs / addr_mask / naddrs. */
int	ng_policy_addrmap_build(struct ng_policy_snapshot *sn,
	    const struct ng_policy_addr *src, uint32_t n);
/* ipv4 in network byte order.  Returns NG_POLICY_EP_EXTERNAL when absent. */
uint32_t ng_policy_addr_lookup(const struct ng_policy_snapshot *sn,
	    uint32_t ipv4);

/* ng_policy_stats.c */
int	ng_policy_ep_counters_init(struct ng_policy_ep *);
void	ng_policy_ep_counters_fini(struct ng_policy_ep *);
int	ng_policy_stats_init(priv_p);
void	ng_policy_stats_fini(priv_p);
void	ng_policy_stats_get(priv_p, struct ng_policy_stats *);
void	ng_policy_stats_reset(priv_p, const struct ng_policy_reset_req *);
/* Allocate sn->rule_pkts / sn->rule_bytes for sn->nrules rules. */
int	ngp_rule_counters_alloc(struct ng_policy_snapshot *sn);
int	ng_policy_rule_stats(priv_p, const struct ng_mesg *,
	    const struct ng_policy_rule_query *, struct ng_mesg **rp);

/* ng_policy_packet.c */
enum ng_policy_parse_result ng_policy_parse(struct mbuf *m,
	    struct ng_policy_meta *meta);

/* ng_policy_policy.c */
struct ng_policy_snapshot *ng_policy_snapshot_empty(void);
void	ng_policy_snapshot_free(struct ng_policy_snapshot *);
void	ngp_snapshot_reclaim(epoch_context_t);
uint64_t ng_policy_active_generation(priv_p);
int	ng_policy_tx_begin(priv_p, const struct ng_policy_tx_begin_req *,
	    struct ng_policy_tx_begin_resp *);
int	ng_policy_tx_add_rules(priv_p, uint64_t tx_id,
	    const struct ng_policy_rule *, uint32_t n);
int	ng_policy_tx_add_addrs(priv_p, uint64_t tx_id,
	    const struct ng_policy_addr *, uint32_t n);
int	ng_policy_tx_set_default(priv_p, uint64_t tx_id, uint8_t action);
int	ng_policy_tx_commit(priv_p, const struct ng_policy_tx_commit_req *,
	    struct ng_policy_tx_commit_resp *);
int	ng_policy_tx_abort(priv_p, uint64_t tx_id);
void	ng_policy_tx_reap(priv_p, int force);
/* Returns the matching rule, or NULL for no match.  On a match, *idx
   receives the rule's index in sn->rules, for counter attribution.
   Must be called inside the net epoch. */
const struct ng_policy_rule *ng_policy_match(
	    const struct ng_policy_snapshot *sn,
	    const struct ng_policy_meta *meta, uint32_t *idx);

/* ng_policy.c */
extern u_int ng_policy_max_endpoints;
extern u_int ng_policy_debug_force_copy;
extern u_int ng_policy_max_rules;
extern u_int ng_policy_max_addrs;
extern u_int ng_policy_max_tx;
extern u_long ng_policy_max_tx_bytes;
extern u_int ng_policy_tx_timeout;

/* Module-scoped diagnostic counters: they outlive any individual node,
   so they live at module scope rather than in priv_p. */
extern counter_u64_t ng_policy_g_nodes;
extern counter_u64_t ng_policy_g_commits;
extern counter_u64_t ng_policy_g_failed_commits;

#endif /* _NETGRAPH_NG_POLICY_VAR_H_ */
