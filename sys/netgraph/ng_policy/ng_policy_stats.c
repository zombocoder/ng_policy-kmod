/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zombocoder <zombocoder@gmail.com>
 *
 * ng_policy - counters.
 */

#include <netgraph/ng_policy/ng_policy_var.h>

int
ng_policy_ep_counters_init(struct ng_policy_ep *ep)
{
	counter_u64_t *c[] = {
		&ep->rx_packets, &ep->rx_bytes,
		&ep->tx_packets, &ep->tx_bytes,
		&ep->allowed_packets, &ep->dropped_packets, &ep->violations,
	};
	size_t i;

	for (i = 0; i < nitems(c); i++) {
		*c[i] = counter_u64_alloc(M_NOWAIT);
		if (*c[i] == NULL) {
			ng_policy_ep_counters_fini(ep);
			return (ENOMEM);
		}
	}
	return (0);
}

void
ng_policy_ep_counters_fini(struct ng_policy_ep *ep)
{
	counter_u64_t *c[] = {
		&ep->rx_packets, &ep->rx_bytes,
		&ep->tx_packets, &ep->tx_bytes,
		&ep->allowed_packets, &ep->dropped_packets, &ep->violations,
	};
	size_t i;

	for (i = 0; i < nitems(c); i++) {
		if (*c[i] != NULL) {
			counter_u64_free(*c[i]);
			*c[i] = NULL;
		}
	}
}

int
ng_policy_stats_init(priv_p priv)
{
#define	X(n)								\
	priv->ctrs.n = counter_u64_alloc(M_NOWAIT);			\
	if (priv->ctrs.n == NULL) {					\
		ng_policy_stats_fini(priv);				\
		return (ENOMEM);					\
	}
	NGP_NODE_COUNTERS(X)
#undef X
	return (0);
}

void
ng_policy_stats_fini(priv_p priv)
{
#define	X(n)								\
	if (priv->ctrs.n != NULL) {					\
		counter_u64_free(priv->ctrs.n);				\
		priv->ctrs.n = NULL;					\
	}
	NGP_NODE_COUNTERS(X)
#undef X
}

void
ng_policy_stats_get(priv_p priv, struct ng_policy_stats *st)
{
	struct ng_policy_snapshot *sn;

	memset(st, 0, sizeof(*st));
#define	X(n)	st->n = counter_u64_fetch(priv->ctrs.n);
	NGP_NODE_COUNTERS(X)
#undef X
	mtx_lock(&priv->ctl_mtx);
	st->mode = priv->cfg.mode;
	st->nendpoints = priv->nendpoints;
	st->endpoint_memory = (uint64_t)priv->nendpoints *
	    sizeof(struct ng_policy_ep) +
	    NGP_EPHASH_SIZE * sizeof(*priv->ephash);
	sn = NGP_LOAD_PTR(priv->policy);
	if (sn != NULL) {
		st->generation = sn->generation;
		st->nrules = sn->nrules;
		st->naddrs = sn->naddrs;
		st->policy_memory = sn->memsize;
		st->addr_memory = (uint64_t)(sn->addr_mask != 0 ?
		    (sn->addr_mask + 1) * sizeof(struct ng_policy_addr) : 0);
	}
	st->ntx = priv->ntx;
	st->tx_memory = priv->tx_memory;
	mtx_unlock(&priv->ctl_mtx);
}

/*
 * Allocate the per-rule counter arrays for sn->nrules rules.  Called
 * from ngp_snapshot_build(), which runs outside ctl_mtx with M_WAITOK,
 * so the two arrays allocate the same way.  The per-rule
 * counter_u64_alloc() calls stay M_NOWAIT and can still fail; on
 * failure this leaves the arrays allocated with some entries NULL,
 * which ng_policy_snapshot_free() already tolerates (it guards
 * rule_pkts/rule_bytes independently and skips NULL slots).
 */
int
ngp_rule_counters_alloc(struct ng_policy_snapshot *sn)
{
	uint32_t i;

	sn->rule_pkts = malloc((size_t)sn->nrules * sizeof(counter_u64_t),
	    M_NG_POLICY, M_WAITOK | M_ZERO);
	sn->rule_bytes = malloc((size_t)sn->nrules * sizeof(counter_u64_t),
	    M_NG_POLICY, M_WAITOK | M_ZERO);
	sn->memsize += 2 * (size_t)sn->nrules * sizeof(counter_u64_t);
	for (i = 0; i < sn->nrules; i++) {
		sn->rule_pkts[i] = counter_u64_alloc(M_NOWAIT);
		sn->rule_bytes[i] = counter_u64_alloc(M_NOWAIT);
		if (sn->rule_pkts[i] == NULL || sn->rule_bytes[i] == NULL)
			return (ENOMEM);
	}
	return (0);
}

/*
 * Windowed rule-stats response, following ng_policy_ep_list's pattern:
 * size the response with the lock released (here, inside its own net
 * epoch section), allocate, then re-enter the epoch to fill it in.  The
 * snapshot can only shrink or be replaced between the two sections
 * (never mutated in place), so the fill loop re-clamps n against the
 * freshly-read sn->nrules before touching sn->rules[]/rule_pkts[]/
 * rule_bytes[], and never walks past it.
 */
int
ng_policy_rule_stats(priv_p priv, const struct ng_mesg *msg,
    const struct ng_policy_rule_query *q, struct ng_mesg **rp)
{
	struct ng_policy_rule_stats_resp *resp;
	struct ng_policy_snapshot *sn;
	struct epoch_tracker et;
	struct ng_mesg *r;
	uint32_t want, n, i, byte_max;
	size_t len;

	want = q->max_entries;
	if (want == 0 || want > NG_POLICY_BATCH_MAX)
		want = NG_POLICY_BATCH_MAX;
	/*
	 * Clamp separately against the control socket's receive ceiling.
	 * See the matching comment in ng_policy_ep_list() and
	 * NG_POLICY_RESP_BYTE_BUDGET's comment in ng_policy.h: at 56 bytes
	 * per struct ng_policy_rule_stat, NG_POLICY_BATCH_MAX (512) alone
	 * would ask NG_MKRESPONSE for more than the default 20KB
	 * net.graph.recvspace once the response headers are added.
	 */
	byte_max = (NG_POLICY_RESP_BYTE_BUDGET >
	    sizeof(struct ng_mesg) + sizeof(*resp)) ?
	    (uint32_t)((NG_POLICY_RESP_BYTE_BUDGET - sizeof(struct ng_mesg) -
	    sizeof(*resp)) / sizeof(struct ng_policy_rule_stat)) : 0;
	if (want > byte_max)
		want = byte_max;

	NET_EPOCH_ENTER(et);
	sn = NGP_LOAD_PTR(priv->policy);
	n = (sn != NULL && q->start_index < sn->nrules) ?
	    sn->nrules - q->start_index : 0;
	NET_EPOCH_EXIT(et);
	if (n > want)
		n = want;

	len = sizeof(*resp) + (size_t)n * sizeof(struct ng_policy_rule_stat);
	/*
	 * NG_MKRESPONSE dereferences msg for the token, typecookie and
	 * cmd; passing NULL panics and would also strip the token that
	 * libnetgraph matches the reply on.
	 */
	NG_MKRESPONSE(r, msg, len, M_NOWAIT);
	if (r == NULL)
		return (ENOMEM);
	resp = (struct ng_policy_rule_stats_resp *)r->data;

	NET_EPOCH_ENTER(et);
	sn = NGP_LOAD_PTR(priv->policy);
	if (sn == NULL) {
		NET_EPOCH_EXIT(et);
		NG_FREE_MSG(r);
		return (ENOENT);
	}
	resp->generation = sn->generation;
	resp->total = sn->nrules;
	/* The snapshot may have changed between the two epoch sections. */
	if (q->start_index + n > sn->nrules)
		n = (q->start_index < sn->nrules) ?
		    sn->nrules - q->start_index : 0;
	/*
	 * With M_WAITOK for both arrays and a builder that is never
	 * published on a per-rule counter_u64_alloc() failure, nrules > 0
	 * implies both arrays are non-NULL today.  Check anyway: this is
	 * the control path, INVARIANTS is off, and a future regression in
	 * that invariant must not become a silent NULL dereference here.
	 */
	if (sn->rule_pkts == NULL || sn->rule_bytes == NULL)
		n = 0;
	for (i = 0; i < n; i++) {
		uint32_t ri = q->start_index + i;

		resp->entries[i].rule = sn->rules[ri];
		resp->entries[i].match_packets =
		    counter_u64_fetch(sn->rule_pkts[ri]);
		resp->entries[i].match_bytes =
		    counter_u64_fetch(sn->rule_bytes[ri]);
		resp->entries[i].index = ri;
		resp->entries[i].reserved = 0;
	}
	resp->returned = n;
	resp->next_index = q->start_index + n;
	resp->reserved = 0;
	NET_EPOCH_EXIT(et);

	*rp = r;
	return (0);
}

void
ng_policy_stats_reset(priv_p priv, const struct ng_policy_reset_req *rr)
{
	struct ng_policy_ep *ep;
	uint32_t what = rr->what;

	if (what == 0)
		what = NG_POLICY_RESET_MASK;
	if ((what & NG_POLICY_RESET_NODE) != 0) {
#define	X(n)	counter_u64_zero(priv->ctrs.n);
		NGP_NODE_COUNTERS(X)
#undef X
	}
	if ((what & NG_POLICY_RESET_ENDPOINTS) != 0) {
		mtx_lock(&priv->ctl_mtx);
		TAILQ_FOREACH(ep, &priv->eplist, alllink) {
			if (rr->endpoint_id != NG_POLICY_EP_ANY &&
			    ep->endpoint_id != rr->endpoint_id)
				continue;
			counter_u64_zero(ep->rx_packets);
			counter_u64_zero(ep->rx_bytes);
			counter_u64_zero(ep->tx_packets);
			counter_u64_zero(ep->tx_bytes);
			counter_u64_zero(ep->allowed_packets);
			counter_u64_zero(ep->dropped_packets);
			counter_u64_zero(ep->violations);
		}
		mtx_unlock(&priv->ctl_mtx);
	}
	if ((what & NG_POLICY_RESET_RULES) != 0) {
		struct ng_policy_snapshot *sn;
		struct epoch_tracker et;
		uint32_t i;

		NET_EPOCH_ENTER(et);
		sn = NGP_LOAD_PTR(priv->policy);
		/*
		 * See the matching comment in ng_policy_rule_stats(): the
		 * array-level NULL check is unreachable today (M_WAITOK,
		 * never-published partial builds) but cheap, and this is
		 * the control path with INVARIANTS off.
		 */
		if (sn != NULL && sn->rule_pkts != NULL &&
		    sn->rule_bytes != NULL) {
			for (i = 0; i < sn->nrules; i++) {
				if (sn->rule_pkts[i] != NULL)
					counter_u64_zero(sn->rule_pkts[i]);
				if (sn->rule_bytes[i] != NULL)
					counter_u64_zero(sn->rule_bytes[i]);
			}
		}
		NET_EPOCH_EXIT(et);
	}
}
