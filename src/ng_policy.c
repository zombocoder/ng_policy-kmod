/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ng_policy - identity-aware network policy enforcement for Netgraph.
 */

#include <netgraph/ng_policy/ng_policy_var.h>

MALLOC_DEFINE(M_NG_POLICY, "ng_policy", "ng_policy data");

static SYSCTL_NODE(_net_graph, OID_AUTO, policy, CTLFLAG_RW | CTLFLAG_MPSAFE,
    0, "ng_policy");
u_int ng_policy_max_endpoints = 65536;
SYSCTL_UINT(_net_graph_policy, OID_AUTO, max_endpoints, CTLFLAG_RW,
    &ng_policy_max_endpoints, 0, "Maximum endpoints per node");

u_int ng_policy_debug_force_copy = 0;
SYSCTL_UINT(_net_graph_policy, OID_AUTO, debug_force_copy, CTLFLAG_RW,
    &ng_policy_debug_force_copy, 0,
    "Test aid: always take the non-contiguous copy path in the parser");

u_int ng_policy_max_rules = 262144;
SYSCTL_UINT(_net_graph_policy, OID_AUTO, max_rules, CTLFLAG_RW,
    &ng_policy_max_rules, 0, "Maximum rules per policy generation");
u_int ng_policy_max_addrs = 262144;
SYSCTL_UINT(_net_graph_policy, OID_AUTO, max_addrs, CTLFLAG_RW,
    &ng_policy_max_addrs, 0, "Maximum address-map entries per generation");
u_int ng_policy_max_tx = 16;
SYSCTL_UINT(_net_graph_policy, OID_AUTO, max_tx, CTLFLAG_RW,
    &ng_policy_max_tx, 0, "Maximum concurrent open transactions per node");
u_long ng_policy_max_tx_bytes = 64UL * 1024 * 1024;
SYSCTL_ULONG(_net_graph_policy, OID_AUTO, max_tx_bytes, CTLFLAG_RW,
    &ng_policy_max_tx_bytes, 0, "Maximum memory held by open transactions");
u_int ng_policy_tx_timeout = 60;
SYSCTL_UINT(_net_graph_policy, OID_AUTO, tx_timeout, CTLFLAG_RW,
    &ng_policy_tx_timeout, 0, "Default transaction timeout in seconds");

counter_u64_t ng_policy_g_nodes;
counter_u64_t ng_policy_g_commits;
counter_u64_t ng_policy_g_failed_commits;

static int
ng_policy_sysctl_counter(SYSCTL_HANDLER_ARGS)
{
	counter_u64_t c = *(counter_u64_t *)arg1;
	uint64_t v = counter_u64_fetch(c);

	return (sysctl_handle_64(oidp, &v, 0, req));
}

SYSCTL_PROC(_net_graph_policy, OID_AUTO, nodes,
    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE, &ng_policy_g_nodes, 0,
    ng_policy_sysctl_counter, "QU", "Live ng_policy nodes");
SYSCTL_PROC(_net_graph_policy, OID_AUTO, commits,
    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE, &ng_policy_g_commits, 0,
    ng_policy_sysctl_counter, "QU", "Successful policy commits");
SYSCTL_PROC(_net_graph_policy, OID_AUTO, failed_commits,
    CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_MPSAFE, &ng_policy_g_failed_commits, 0,
    ng_policy_sysctl_counter, "QU", "Rejected policy commits");

static int
ng_policy_mod_event(module_t mod, int event, void *data)
{

	switch (event) {
	case MOD_LOAD:
		ng_policy_g_nodes = counter_u64_alloc(M_WAITOK);
		ng_policy_g_commits = counter_u64_alloc(M_WAITOK);
		ng_policy_g_failed_commits = counter_u64_alloc(M_WAITOK);
		break;
	case MOD_UNLOAD:
		/*
		 * Every node is gone by the time Netgraph calls this, but
		 * deferred snapshot and endpoint frees may still be queued.
		 */
		NET_EPOCH_DRAIN_CALLBACKS();
		counter_u64_free(ng_policy_g_nodes);
		counter_u64_free(ng_policy_g_commits);
		counter_u64_free(ng_policy_g_failed_commits);
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (0);
}

static ng_constructor_t	ng_policy_constructor;
static ng_rcvmsg_t	ng_policy_rcvmsg;
static ng_shutdown_t	ng_policy_shutdown;
static ng_newhook_t	ng_policy_newhook;
static ng_rcvdata_t	ng_policy_rcvdata;
static ng_disconnect_t	ng_policy_disconnect;

static const struct ng_parse_struct_field ng_policy_config_fields[]
	= NG_POLICY_CONFIG_TYPE_INFO;
static const struct ng_parse_type ng_policy_config_type = {
	&ng_parse_struct_type, &ng_policy_config_fields
};

static const struct ng_parse_struct_field ng_policy_mode_req_fields[]
	= NG_POLICY_MODE_REQ_TYPE_INFO;
static const struct ng_parse_type ng_policy_mode_req_type = {
	&ng_parse_struct_type, &ng_policy_mode_req_fields
};

static const struct ng_parse_struct_field ng_policy_stats_fields[]
	= NG_POLICY_STATS_TYPE_INFO;
static const struct ng_parse_type ng_policy_stats_type = {
	&ng_parse_struct_type, &ng_policy_stats_fields
};

static const struct ng_parse_struct_field ng_policy_reset_req_fields[]
	= NG_POLICY_RESET_REQ_TYPE_INFO;
static const struct ng_parse_type ng_policy_reset_req_type = {
	&ng_parse_struct_type, &ng_policy_reset_req_fields
};

static const struct ng_parse_struct_field ng_policy_ep_add_fields[]
	= NG_POLICY_ENDPOINT_ADD_TYPE_INFO;
static const struct ng_parse_type ng_policy_ep_add_type = {
	&ng_parse_struct_type, &ng_policy_ep_add_fields
};

static const struct ng_parse_struct_field ng_policy_ep_del_fields[]
	= NG_POLICY_ENDPOINT_DEL_TYPE_INFO;
static const struct ng_parse_type ng_policy_ep_del_type = {
	&ng_parse_struct_type, &ng_policy_ep_del_fields
};

static const struct ng_parse_struct_field ng_policy_ep_query_fields[]
	= NG_POLICY_EP_QUERY_TYPE_INFO;
static const struct ng_parse_type ng_policy_ep_query_type = {
	&ng_parse_struct_type, &ng_policy_ep_query_fields
};

static const struct ng_parse_struct_field ng_policy_ep_info_fields[]
	= NG_POLICY_ENDPOINT_INFO_TYPE_INFO;
static const struct ng_parse_type ng_policy_ep_info_type = {
	&ng_parse_struct_type, &ng_policy_ep_info_fields
};

static int
ng_policy_ep_ary_len(const struct ng_parse_type *type, const u_char *start,
    const u_char *buf)
{
	const struct ng_policy_ep_list_resp *r;

	r = (const struct ng_policy_ep_list_resp *)(buf -
	    offsetof(struct ng_policy_ep_list_resp, entries));
	return (r->returned);
}

static const struct ng_parse_array_info ng_policy_ep_ary_info = {
	&ng_policy_ep_info_type, ng_policy_ep_ary_len
};
static const struct ng_parse_type ng_policy_ep_ary_type = {
	&ng_parse_array_type, &ng_policy_ep_ary_info
};

static const struct ng_parse_struct_field ng_policy_ep_list_fields[]
	= NG_POLICY_EP_LIST_RESP_TYPE_INFO(&ng_policy_ep_ary_type);
static const struct ng_parse_type ng_policy_ep_list_type = {
	&ng_parse_struct_type, &ng_policy_ep_list_fields
};

static const struct ng_parse_struct_field ng_policy_rule_fields[]
	= NG_POLICY_RULE_TYPE_INFO;
static const struct ng_parse_type ng_policy_rule_type = {
	&ng_parse_struct_type, &ng_policy_rule_fields
};

static const struct ng_parse_struct_field ng_policy_addr_fields[]
	= NG_POLICY_ADDR_TYPE_INFO;
static const struct ng_parse_type ng_policy_addr_type = {
	&ng_parse_struct_type, &ng_policy_addr_fields
};

/*
 * No length clamp here on purpose.  'start' means different things in
 * the two directions this callback runs in (NGM_BINARY2ASCII: the real
 * struct ng_mesg's data[], where header.arglen could bound the read;
 * NGM_ASCII2BINARY: an output buffer under construction, where the
 * bytes before 'start' are not a struct ng_mesg at all), and a getLength
 * callback has no way to tell which direction it is being called from.
 * A clamp keyed off msg->header.arglen (tried and reverted) computes a
 * bogus element budget during ASCII2BINARY and breaks hand-typed ngctl
 * rule loading -- e.g. "txaddrule { nrules=3 rules=[...] }" -- with
 * E2BIG, and hand-typed rule loading is a stated completion criterion.
 * A correct, direction-aware fix belongs in ng_parse itself, not here.
 *
 * The residual over-read this leaves for a crafted NGM_BINARY2ASCII
 * blob requires netgraph control-socket privilege -- the same privilege
 * that already lets the caller install a permit-everything policy or
 * unload the module outright -- and is the tree-wide idiom: every
 * in-tree node with a variable-length array type has the identical
 * property (e.g. ng_bridge's getTableLength reads numHosts straight out
 * of the buffer with no bound check).  Do not "fix" this without also
 * fixing ng_parse's getLength callback contract to carry a buffer
 * length, or you will silently re-break ngctl again.
 */
static int
ng_policy_rule_ary_len(const struct ng_parse_type *type, const u_char *start,
    const u_char *buf)
{
	const struct ng_policy_tx_add_rule *r;

	r = (const struct ng_policy_tx_add_rule *)(buf -
	    offsetof(struct ng_policy_tx_add_rule, rules));
	return (r->nrules);
}

static const struct ng_parse_array_info ng_policy_rule_ary_info = {
	&ng_policy_rule_type, ng_policy_rule_ary_len
};
static const struct ng_parse_type ng_policy_rule_ary_type = {
	&ng_parse_array_type, &ng_policy_rule_ary_info
};

static const struct ng_parse_struct_field ng_policy_tx_add_rule_fields[]
	= NG_POLICY_TX_ADD_RULE_TYPE_INFO(&ng_policy_rule_ary_type);
static const struct ng_parse_type ng_policy_tx_add_rule_type = {
	&ng_parse_struct_type, &ng_policy_tx_add_rule_fields
};

/* No length clamp here either: see the comment on ng_policy_rule_ary_len
   above -- the same direction-ambiguity applies verbatim to naddrs. */
static int
ng_policy_addr_ary_len(const struct ng_parse_type *type, const u_char *start,
    const u_char *buf)
{
	const struct ng_policy_tx_add_addr *a;

	a = (const struct ng_policy_tx_add_addr *)(buf -
	    offsetof(struct ng_policy_tx_add_addr, addrs));
	return (a->naddrs);
}

static const struct ng_parse_array_info ng_policy_addr_ary_info = {
	&ng_policy_addr_type, ng_policy_addr_ary_len
};
static const struct ng_parse_type ng_policy_addr_ary_type = {
	&ng_parse_array_type, &ng_policy_addr_ary_info
};

static const struct ng_parse_struct_field ng_policy_tx_add_addr_fields[]
	= NG_POLICY_TX_ADD_ADDR_TYPE_INFO(&ng_policy_addr_ary_type);
static const struct ng_parse_type ng_policy_tx_add_addr_type = {
	&ng_parse_struct_type, &ng_policy_tx_add_addr_fields
};

static const struct ng_parse_struct_field ng_policy_tx_begin_req_fields[]
	= NG_POLICY_TX_BEGIN_REQ_TYPE_INFO;
static const struct ng_parse_type ng_policy_tx_begin_req_type = {
	&ng_parse_struct_type, &ng_policy_tx_begin_req_fields
};

static const struct ng_parse_struct_field ng_policy_tx_begin_resp_fields[]
	= NG_POLICY_TX_BEGIN_RESP_TYPE_INFO;
static const struct ng_parse_type ng_policy_tx_begin_resp_type = {
	&ng_parse_struct_type, &ng_policy_tx_begin_resp_fields
};

static const struct ng_parse_struct_field ng_policy_tx_set_default_fields[]
	= NG_POLICY_TX_SET_DEFAULT_TYPE_INFO;
static const struct ng_parse_type ng_policy_tx_set_default_type = {
	&ng_parse_struct_type, &ng_policy_tx_set_default_fields
};

static const struct ng_parse_struct_field ng_policy_tx_commit_req_fields[]
	= NG_POLICY_TX_COMMIT_REQ_TYPE_INFO;
static const struct ng_parse_type ng_policy_tx_commit_req_type = {
	&ng_parse_struct_type, &ng_policy_tx_commit_req_fields
};

static const struct ng_parse_struct_field ng_policy_tx_commit_resp_fields[]
	= NG_POLICY_TX_COMMIT_RESP_TYPE_INFO;
static const struct ng_parse_type ng_policy_tx_commit_resp_type = {
	&ng_parse_struct_type, &ng_policy_tx_commit_resp_fields
};

static const struct ng_parse_struct_field ng_policy_tx_id_fields[]
	= NG_POLICY_TX_ID_TYPE_INFO;
static const struct ng_parse_type ng_policy_tx_id_type = {
	&ng_parse_struct_type, &ng_policy_tx_id_fields
};

static const struct ng_parse_struct_field ng_policy_rule_stat_fields[]
	= NG_POLICY_RULE_STAT_TYPE_INFO(&ng_policy_rule_type);
static const struct ng_parse_type ng_policy_rule_stat_type = {
	&ng_parse_struct_type, &ng_policy_rule_stat_fields
};

static int
ng_policy_rule_stat_ary_len(const struct ng_parse_type *type,
    const u_char *start, const u_char *buf)
{
	const struct ng_policy_rule_stats_resp *r;

	r = (const struct ng_policy_rule_stats_resp *)(buf -
	    offsetof(struct ng_policy_rule_stats_resp, entries));
	return (r->returned);
}

static const struct ng_parse_array_info ng_policy_rule_stat_ary_info = {
	&ng_policy_rule_stat_type, ng_policy_rule_stat_ary_len
};
static const struct ng_parse_type ng_policy_rule_stat_ary_type = {
	&ng_parse_array_type, &ng_policy_rule_stat_ary_info
};

static const struct ng_parse_struct_field ng_policy_rule_query_fields[]
	= NG_POLICY_RULE_QUERY_TYPE_INFO;
static const struct ng_parse_type ng_policy_rule_query_type = {
	&ng_parse_struct_type, &ng_policy_rule_query_fields
};

static const struct ng_parse_struct_field ng_policy_rule_stats_resp_fields[]
	= NG_POLICY_RULE_STATS_RESP_TYPE_INFO(&ng_policy_rule_stat_ary_type);
static const struct ng_parse_type ng_policy_rule_stats_resp_type = {
	&ng_parse_struct_type, &ng_policy_rule_stats_resp_fields
};

static const struct ng_cmdlist ng_policy_cmdlist[] = {
	{ NGM_POLICY_COOKIE, NGM_POLICY_GET_CONFIG, "getconfig",
	    NULL, &ng_policy_config_type },
	{ NGM_POLICY_COOKIE, NGM_POLICY_SET_CONFIG, "setconfig",
	    &ng_policy_config_type, NULL },
	{ NGM_POLICY_COOKIE, NGM_POLICY_SET_MODE, "setmode",
	    &ng_policy_mode_req_type, NULL },
	{ NGM_POLICY_COOKIE, NGM_POLICY_ENDPOINT_ADD, "endpointadd",
	    &ng_policy_ep_add_type, NULL },
	{ NGM_POLICY_COOKIE, NGM_POLICY_ENDPOINT_DEL, "endpointdel",
	    &ng_policy_ep_del_type, NULL },
	{ NGM_POLICY_COOKIE, NGM_POLICY_ENDPOINT_LIST, "endpointlist",
	    &ng_policy_ep_query_type, &ng_policy_ep_list_type },
	{ NGM_POLICY_COOKIE, NGM_POLICY_GET_ENDPOINT_STATS, "getendpointstats",
	    &ng_policy_ep_query_type, &ng_policy_ep_list_type },
	{ NGM_POLICY_COOKIE, NGM_POLICY_TX_BEGIN, "txbegin",
	    &ng_policy_tx_begin_req_type, &ng_policy_tx_begin_resp_type },
	{ NGM_POLICY_COOKIE, NGM_POLICY_TX_ADD_RULE, "txaddrule",
	    &ng_policy_tx_add_rule_type, NULL },
	{ NGM_POLICY_COOKIE, NGM_POLICY_TX_ADD_ADDR, "txaddaddr",
	    &ng_policy_tx_add_addr_type, NULL },
	{ NGM_POLICY_COOKIE, NGM_POLICY_TX_SET_DEFAULT, "txsetdefault",
	    &ng_policy_tx_set_default_type, NULL },
	{ NGM_POLICY_COOKIE, NGM_POLICY_TX_COMMIT, "txcommit",
	    &ng_policy_tx_commit_req_type, &ng_policy_tx_commit_resp_type },
	{ NGM_POLICY_COOKIE, NGM_POLICY_TX_ABORT, "txabort",
	    &ng_policy_tx_id_type, NULL },
	{ NGM_POLICY_COOKIE, NGM_POLICY_GET_STATS, "getstats",
	    NULL, &ng_policy_stats_type },
	{ NGM_POLICY_COOKIE, NGM_POLICY_RESET_STATS, "resetstats",
	    &ng_policy_reset_req_type, NULL },
	{ NGM_POLICY_COOKIE, NGM_POLICY_GET_RULE_STATS, "getrulestats",
	    &ng_policy_rule_query_type, &ng_policy_rule_stats_resp_type },
	{ 0 }
};

static struct ng_type ng_policy_typestruct = {
	.version =	NG_ABI_VERSION,
	.name =		NG_POLICY_NODE_TYPE,
	.constructor =	ng_policy_constructor,
	.rcvmsg =	ng_policy_rcvmsg,
	.shutdown =	ng_policy_shutdown,
	.newhook =	ng_policy_newhook,
	.rcvdata =	ng_policy_rcvdata,
	.disconnect =	ng_policy_disconnect,
	.cmdlist =	ng_policy_cmdlist,
	.mod_event =	ng_policy_mod_event,
};
NETGRAPH_INIT(policy, &ng_policy_typestruct);

static int
ng_policy_constructor(node_p node)
{
	priv_p priv;

	priv = malloc(sizeof(*priv), M_NG_POLICY, M_WAITOK | M_ZERO);
	mtx_init(&priv->ctl_mtx, "ng_policy", NULL, MTX_DEF);
	priv->cfg.version = NG_POLICY_ABI_VERSION;
	priv->cfg.mode = NG_POLICY_MODE_ENFORCE;
	priv->cfg.arp_action = NG_POLICY_ALLOW;
	priv->cfg.frag_action = NG_POLICY_DROP;
	priv->cfg.unsupported_action = NG_POLICY_DROP;
	priv->cfg.malformed_action = NG_POLICY_DROP;
	priv->node = node;
	priv->ephash = malloc(NGP_EPHASH_SIZE * sizeof(*priv->ephash),
	    M_NG_POLICY, M_WAITOK | M_ZERO);
	TAILQ_INIT(&priv->eplist);
	LIST_INIT(&priv->txlist);
	ng_callout_init(&priv->tx_callout);
	if (ng_policy_stats_init(priv) != 0) {
		free(priv->ephash, M_NG_POLICY);
		mtx_destroy(&priv->ctl_mtx);
		free(priv, M_NG_POLICY);
		return (ENOMEM);
	}
	priv->policy = ng_policy_snapshot_empty();
	NG_NODE_SET_PRIVATE(node, priv);
	counter_u64_add(ng_policy_g_nodes, 1);
	return (0);
}

static int
ng_policy_newhook(node_p node, hook_p hook, const char *name)
{
	priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_policy_hookpriv *hp;

	hp = malloc(sizeof(*hp), M_NG_POLICY, M_NOWAIT | M_ZERO);
	if (hp == NULL)
		return (ENOMEM);
	hp->hook = hook;
	strlcpy(hp->name, name, sizeof(hp->name));
	NG_HOOK_SET_PRIVATE(hook, hp);
	ng_policy_hook_attach(priv, hp);
	return (0);
}

#define	NGP_ARGLEN(m, t)	((m)->header.arglen == sizeof(t))

static int
ng_policy_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	struct ng_mesg *msg;
	int error = 0;

	NGI_GET_MSG(item, msg);
	if (msg->header.typecookie != NGM_POLICY_COOKIE) {
		error = EINVAL;
		goto done;
	}
	switch (msg->header.cmd) {
	case NGM_POLICY_GET_CONFIG:
		NG_MKRESPONSE(resp, msg, sizeof(struct ng_policy_config),
		    M_NOWAIT);
		if (resp == NULL) {
			error = ENOMEM;
			break;
		}
		mtx_lock(&priv->ctl_mtx);
		*(struct ng_policy_config *)resp->data = priv->cfg;
		mtx_unlock(&priv->ctl_mtx);
		break;
	case NGM_POLICY_SET_CONFIG: {
		struct ng_policy_config *c;

		if (!NGP_ARGLEN(msg, struct ng_policy_config)) {
			error = EINVAL;
			break;
		}
		c = (struct ng_policy_config *)msg->data;
		if (c->version != 0 && c->version != NG_POLICY_ABI_VERSION) {
			error = EPROTONOSUPPORT;
			break;
		}
		if (!NG_POLICY_MODE_VALID(c->mode) ||
		    !NG_POLICY_ACTION_VALID(c->arp_action) ||
		    !NG_POLICY_ACTION_VALID(c->frag_action) ||
		    !NG_POLICY_ACTION_VALID(c->unsupported_action) ||
		    !NG_POLICY_ACTION_VALID(c->malformed_action) ||
		    (c->flags & ~NG_POLICY_CFG_F_MASK) != 0) {
			error = EINVAL;
			break;
		}
		mtx_lock(&priv->ctl_mtx);
		priv->cfg.flags = c->flags;
		priv->cfg.mode = c->mode;
		priv->cfg.arp_action = c->arp_action;
		priv->cfg.frag_action = c->frag_action;
		priv->cfg.unsupported_action = c->unsupported_action;
		priv->cfg.malformed_action = c->malformed_action;
		mtx_unlock(&priv->ctl_mtx);
		break;
	}
	case NGM_POLICY_SET_MODE: {
		struct ng_policy_mode_req *r;

		if (!NGP_ARGLEN(msg, struct ng_policy_mode_req)) {
			error = EINVAL;
			break;
		}
		r = (struct ng_policy_mode_req *)msg->data;
		if (!NG_POLICY_MODE_VALID(r->mode)) {
			error = EINVAL;
			break;
		}
		mtx_lock(&priv->ctl_mtx);
		priv->cfg.mode = (uint8_t)r->mode;
		mtx_unlock(&priv->ctl_mtx);
		break;
	}
	case NGM_POLICY_GET_STATS:
		NG_MKRESPONSE(resp, msg, sizeof(struct ng_policy_stats),
		    M_NOWAIT);
		if (resp == NULL) {
			error = ENOMEM;
			break;
		}
		ng_policy_stats_get(priv,
		    (struct ng_policy_stats *)resp->data);
		break;
	case NGM_POLICY_RESET_STATS: {
		struct ng_policy_reset_req *r;

		if (!NGP_ARGLEN(msg, struct ng_policy_reset_req)) {
			error = EINVAL;
			break;
		}
		r = (struct ng_policy_reset_req *)msg->data;
		if ((r->what & ~NG_POLICY_RESET_MASK) != 0) {
			error = EINVAL;
			break;
		}
		ng_policy_stats_reset(priv, r);
		break;
	}
	case NGM_POLICY_ENDPOINT_ADD:
		if (!NGP_ARGLEN(msg, struct ng_policy_endpoint_add)) {
			error = EINVAL;
			break;
		}
		error = ng_policy_ep_add(priv,
		    (struct ng_policy_endpoint_add *)msg->data);
		break;
	case NGM_POLICY_ENDPOINT_DEL: {
		struct ng_policy_endpoint_del *d;

		if (!NGP_ARGLEN(msg, struct ng_policy_endpoint_del)) {
			error = EINVAL;
			break;
		}
		d = (struct ng_policy_endpoint_del *)msg->data;
		/*
		 * No flag bit is defined for ENDPOINT_DEL today, but an
		 * unchecked reserved-shaped field can never be given
		 * meaning later: the kernel would have no way to tell an
		 * old client's stack garbage from a new client's deliberate
		 * value.  Reject any nonzero value now, uniformly with
		 * every other reserved/flags field.
		 */
		if (d->flags != 0) {
			error = EINVAL;
			break;
		}
		error = ng_policy_ep_del(priv, d->endpoint_id);
		break;
	}
	case NGM_POLICY_ENDPOINT_LIST:
	case NGM_POLICY_GET_ENDPOINT_STATS:
		if (!NGP_ARGLEN(msg, struct ng_policy_ep_query)) {
			error = EINVAL;
			break;
		}
		error = ng_policy_ep_list(priv, msg,
		    (struct ng_policy_ep_query *)msg->data, &resp);
		break;
	case NGM_POLICY_GET_RULE_STATS:
		if (!NGP_ARGLEN(msg, struct ng_policy_rule_query)) {
			error = EINVAL;
			break;
		}
		error = ng_policy_rule_stats(priv, msg,
		    (struct ng_policy_rule_query *)msg->data, &resp);
		break;
	case NGM_POLICY_TX_BEGIN: {
		struct ng_policy_tx_begin_req *req;

		if (!NGP_ARGLEN(msg, struct ng_policy_tx_begin_req)) {
			error = EINVAL;
			break;
		}
		req = (struct ng_policy_tx_begin_req *)msg->data;
		NG_MKRESPONSE(resp, msg,
		    sizeof(struct ng_policy_tx_begin_resp), M_NOWAIT);
		if (resp == NULL) {
			error = ENOMEM;
			break;
		}
		error = ng_policy_tx_begin(priv, req,
		    (struct ng_policy_tx_begin_resp *)resp->data);
		if (error != 0) {
			NG_FREE_MSG(resp);
			resp = NULL;
		}
		break;
	}
	case NGM_POLICY_TX_ADD_RULE: {
		struct ng_policy_tx_add_rule *a;
		size_t need;

		if (msg->header.arglen < sizeof(*a)) {
			error = EINVAL;
			break;
		}
		a = (struct ng_policy_tx_add_rule *)msg->data;
		if (a->version != 0 && a->version != NG_POLICY_ABI_VERSION) {
			error = EPROTONOSUPPORT;
			break;
		}
		if (a->reserved != 0) {
			error = EINVAL;
			break;
		}
		if (a->nrules == 0 ||
		    a->nrules > (UINT32_MAX - sizeof(*a)) /
		    sizeof(struct ng_policy_rule)) {
			error = EINVAL;
			break;
		}
		need = sizeof(*a) +
		    (size_t)a->nrules * sizeof(struct ng_policy_rule);
		if (msg->header.arglen != need) {
			error = EINVAL;
			break;
		}
		error = ng_policy_tx_add_rules(priv, a->tx_id, a->rules,
		    a->nrules);
		break;
	}
	case NGM_POLICY_TX_ADD_ADDR: {
		struct ng_policy_tx_add_addr *a;
		size_t need;

		if (msg->header.arglen < sizeof(*a)) {
			error = EINVAL;
			break;
		}
		a = (struct ng_policy_tx_add_addr *)msg->data;
		if (a->version != 0 && a->version != NG_POLICY_ABI_VERSION) {
			error = EPROTONOSUPPORT;
			break;
		}
		if (a->reserved != 0) {
			error = EINVAL;
			break;
		}
		if (a->naddrs == 0 ||
		    a->naddrs > (UINT32_MAX - sizeof(*a)) /
		    sizeof(struct ng_policy_addr)) {
			error = EINVAL;
			break;
		}
		need = sizeof(*a) +
		    (size_t)a->naddrs * sizeof(struct ng_policy_addr);
		if (msg->header.arglen != need) {
			error = EINVAL;
			break;
		}
		error = ng_policy_tx_add_addrs(priv, a->tx_id, a->addrs,
		    a->naddrs);
		break;
	}
	case NGM_POLICY_TX_SET_DEFAULT: {
		struct ng_policy_tx_set_default *sd;

		if (!NGP_ARGLEN(msg, struct ng_policy_tx_set_default)) {
			error = EINVAL;
			break;
		}
		sd = (struct ng_policy_tx_set_default *)msg->data;
		if (sd->reserved0 != 0 || sd->reserved1 != 0 ||
		    sd->reserved2 != 0) {
			error = EINVAL;
			break;
		}
		error = ng_policy_tx_set_default(priv, sd->tx_id,
		    sd->default_action);
		break;
	}
	case NGM_POLICY_TX_COMMIT: {
		struct ng_policy_tx_commit_req *req;

		if (!NGP_ARGLEN(msg, struct ng_policy_tx_commit_req)) {
			error = EINVAL;
			break;
		}
		req = (struct ng_policy_tx_commit_req *)msg->data;
		NG_MKRESPONSE(resp, msg,
		    sizeof(struct ng_policy_tx_commit_resp), M_NOWAIT);
		if (resp == NULL) {
			error = ENOMEM;
			break;
		}
		error = ng_policy_tx_commit(priv, req,
		    (struct ng_policy_tx_commit_resp *)resp->data);
		if (error != 0) {
			NG_FREE_MSG(resp);
			resp = NULL;
		}
		break;
	}
	case NGM_POLICY_TX_ABORT: {
		struct ng_policy_tx_id *id;

		if (!NGP_ARGLEN(msg, struct ng_policy_tx_id)) {
			error = EINVAL;
			break;
		}
		id = (struct ng_policy_tx_id *)msg->data;
		error = ng_policy_tx_abort(priv, id->tx_id);
		break;
	}
	default:
		error = EINVAL;
		break;
	}
done:
	NG_RESPOND_MSG(error, node, item, resp);
	NG_FREE_MSG(msg);
	(void)lasthook;
	return (error);
}

/*
 * Decide what to do with a packet.  Resolves the endpoint the hook left
 * unfixed via the address map, then matches the sorted rule set; a
 * packet that parses OK but matches nothing takes the generation's
 * default action.  Called inside the net epoch.
 */
static void
ngp_decide(priv_p priv, struct mbuf *m, struct ng_policy_meta *meta,
    struct ng_policy_decision *d)
{
	struct ng_policy_snapshot *sn;
	const struct ng_policy_rule *rule;
	enum ng_policy_parse_result pr;
	uint32_t ridx;

	d->rule_id = 0;
	d->matched = 0;

	pr = ng_policy_parse(m, meta);
	switch (pr) {
	case NG_POLICY_PARSE_ARP:
		NGP_CTR(priv, arp_packets, 1);
		d->action = priv->cfg.arp_action;
		return;
	case NG_POLICY_PARSE_UNSUPPORTED:
		NGP_CTR(priv, unsupported_packets, 1);
		d->action = priv->cfg.unsupported_action;
		return;
	case NG_POLICY_PARSE_MALFORMED:
		NGP_CTR(priv, malformed_packets, 1);
		d->action = priv->cfg.malformed_action;
		return;
	case NG_POLICY_PARSE_FRAGMENT:
		NGP_CTR(priv, fragmented_packets, 1);
		d->action = priv->cfg.frag_action;
		return;
	case NG_POLICY_PARSE_OK:
		break;
	}
	/* Count a first fragment too: it is fragmented, it just parses. */
	if ((meta->flags & NGP_META_F_FIRSTFRAG) != 0)
		NGP_CTR(priv, fragmented_packets, 1);

	sn = NGP_LOAD_PTR(priv->policy);
	if (__predict_false(sn == NULL)) {
		d->action = NG_POLICY_DROP;
		return;
	}

	/*
	 * The hook fixes one side of the packet's identity authoritatively;
	 * the address map resolves the other.  An unmapped address is
	 * EXTERNAL.
	 */
	if (meta->src_endpoint == NG_POLICY_EP_EXTERNAL) {
		NGP_CTR(priv, addr_lookups, 1);
		meta->src_endpoint = ng_policy_addr_lookup(sn, meta->src_ipv4);
		if (meta->src_endpoint != NG_POLICY_EP_EXTERNAL)
			NGP_CTR(priv, addr_hits, 1);
	} else {
		NGP_CTR(priv, addr_lookups, 1);
		meta->dst_endpoint = ng_policy_addr_lookup(sn, meta->dst_ipv4);
		if (meta->dst_endpoint != NG_POLICY_EP_EXTERNAL)
			NGP_CTR(priv, addr_hits, 1);
	}

	rule = ng_policy_match(sn, meta, &ridx);
	if (rule != NULL) {
		counter_u64_add(sn->rule_pkts[ridx], 1);
		counter_u64_add(sn->rule_bytes[ridx],
		    (uint64_t)m->m_pkthdr.len);
		NGP_CTR(priv, rule_matches, 1);
		d->rule_id = rule->rule_id;
		d->matched = 1;
		d->action = rule->action;
		return;
	}
	NGP_CTR(priv, default_matches, 1);
	d->matched = 0;
	d->action = sn->default_action;
}

static int
ng_policy_rcvdata(hook_p hook, item_p item)
{
	node_p node = NG_HOOK_NODE(hook);
	priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_policy_hookpriv *hp = NG_HOOK_PRIVATE(hook);
	struct ng_policy_decision d;
	struct ng_policy_meta meta;
	struct epoch_tracker et;
	struct ng_policy_ep *ep;
	struct mbuf *m;
	hook_p out;
	uint32_t len;
	uint8_t enforce, mode;
	int error = 0;

	NGI_GET_M(item, m);
	if (__predict_false(m->m_pkthdr.len < 0)) {
		NG_FREE_M(m);
		NG_FREE_ITEM(item);
		return (0);
	}
	len = (uint32_t)m->m_pkthdr.len;

	/*
	 * hp->ep and the hook privates are freed only through the net
	 * epoch, so a pointer read inside the section stays valid.
	 */
	NET_EPOCH_ENTER(et);

	ep = (hp != NULL) ? hp->ep : NULL;
	if (__predict_false(ep == NULL)) {
		NGP_CTR(priv, unbound_hook_packets, 1);
		goto drop;
	}

	NGP_CTR(priv, packets_total, 1);
	NGP_CTR(priv, bytes_total, len);

	if (hp->side == NGP_SIDE_EP) {
		out = (ep->peer_hp != NULL) ? ep->peer_hp->hook : NULL;
		counter_u64_add(ep->rx_packets, 1);
		counter_u64_add(ep->rx_bytes, len);
	} else {
		out = (ep->hp != NULL) ? ep->hp->hook : NULL;
	}
	if (__predict_false(out == NULL)) {
		NGP_CTR(priv, no_peer_packets, 1);
		goto drop;
	}

	mode = priv->cfg.mode;
	if (mode == NG_POLICY_MODE_DISABLED) {
		d.action = NG_POLICY_ALLOW;
		d.matched = 0;
		d.rule_id = 0;
	} else {
		memset(&meta, 0, sizeof(meta));
		if (hp->side == NGP_SIDE_EP) {
			meta.src_endpoint = ep->endpoint_id;
			meta.dst_endpoint = NG_POLICY_EP_EXTERNAL;
		} else {
			meta.dst_endpoint = ep->endpoint_id;
			meta.src_endpoint = NG_POLICY_EP_EXTERNAL;
		}
		ngp_decide(priv, m, &meta, &d);
	}

	enforce = (mode == NG_POLICY_MODE_ENFORCE) ? d.action : NG_POLICY_ALLOW;
	if (d.action == NG_POLICY_DROP && mode == NG_POLICY_MODE_PERMISSIVE) {
		NGP_CTR(priv, permissive_violations, 1);
		counter_u64_add(ep->violations, 1);
	}

	if (enforce == NG_POLICY_ALLOW) {
		NGP_CTR(priv, allowed_packets, 1);
		NGP_CTR(priv, allowed_bytes, len);
		counter_u64_add(ep->allowed_packets, 1);
		if (hp->side == NGP_SIDE_FAB) {
			counter_u64_add(ep->tx_packets, 1);
			counter_u64_add(ep->tx_bytes, len);
		}
		NET_EPOCH_EXIT(et);
		NG_FWD_NEW_DATA(error, item, out, m);
		return (error);
	}

	NGP_CTR(priv, dropped_packets, 1);
	NGP_CTR(priv, dropped_bytes, len);
	counter_u64_add(ep->dropped_packets, 1);
drop:
	NET_EPOCH_EXIT(et);
	NG_FREE_M(m);
	NG_FREE_ITEM(item);
	/* A policy drop is not an error. */
	return (0);
}

static void
ngp_hookpriv_reclaim(epoch_context_t ctx)
{
	struct ng_policy_hookpriv *hp;

	hp = __containerof(ctx, struct ng_policy_hookpriv, ectx);
	free(hp, M_NG_POLICY);
}

static int
ng_policy_disconnect(hook_p hook)
{
	node_p node = NG_HOOK_NODE(hook);
	priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_policy_hookpriv *hp = NG_HOOK_PRIVATE(hook);

	if (hp != NULL) {
		ng_policy_hook_detach(priv, hp);
		NG_HOOK_SET_PRIVATE(hook, NULL);
		NET_EPOCH_CALL(ngp_hookpriv_reclaim, &hp->ectx);
	}
	if (NG_NODE_NUMHOOKS(node) == 0 && NG_NODE_IS_VALID(node))
		ng_rmnode_self(node);
	return (0);
}

static int
ng_policy_shutdown(node_p node)
{
	priv_p priv = NG_NODE_PRIVATE(node);
	struct ng_policy_snapshot *sn;

	mtx_lock(&priv->ctl_mtx);
	priv->shutting_down = 1;
	ng_policy_tx_reap(priv, 1);
	mtx_unlock(&priv->ctl_mtx);
	ng_uncallout(&priv->tx_callout, node);
	ng_policy_ep_flush(priv);
	sn = priv->policy;
	NGP_STORE_PTR(priv->policy, NULL);
	if (sn != NULL)
		NET_EPOCH_CALL(ngp_snapshot_reclaim, &sn->ectx);

	free(priv->ephash, M_NG_POLICY);
	ng_policy_stats_fini(priv);

	NG_NODE_SET_PRIVATE(node, NULL);
	NG_NODE_UNREF(node);
	mtx_destroy(&priv->ctl_mtx);
	free(priv, M_NG_POLICY);
	counter_u64_add(ng_policy_g_nodes, -1);
	return (0);
}
