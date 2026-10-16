/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ng_policy - policy generations, transactions, atomic replacement.
 */

#include <netgraph/ng_policy/ng_policy_var.h>

#include <sys/libkern.h>

#define	NGP_TX_REAP_TICKS	(2 * hz)

static uint64_t
ngp_uptime(void)
{
	struct timespec ts;

	getnanouptime(&ts);
	return ((uint64_t)ts.tv_sec);
}

static uint64_t
ngp_usec_since(const struct timespec *start)
{
	struct timespec now;

	nanouptime(&now);
	return ((uint64_t)(now.tv_sec - start->tv_sec) * 1000000 +
	    ((uint64_t)now.tv_nsec - start->tv_nsec) / 1000);
}

struct ng_policy_snapshot *
ng_policy_snapshot_empty(void)
{
	struct ng_policy_snapshot *sn;

	sn = malloc(sizeof(*sn), M_NG_POLICY, M_WAITOK | M_ZERO);
	sn->generation = 0;
	sn->default_action = NG_POLICY_DROP;	/* fail closed */
	sn->memsize = sizeof(*sn);
	return (sn);
}

void
ng_policy_snapshot_free(struct ng_policy_snapshot *sn)
{
	uint32_t i;

	if (sn == NULL)
		return;
	/*
	 * Guarded independently: a future allocation failure between the
	 * two counter arrays (Task 7) must not NULL-deref the array that
	 * was never allocated.
	 */
	if (sn->rule_pkts != NULL) {
		for (i = 0; i < sn->nrules; i++)
			if (sn->rule_pkts[i] != NULL)
				counter_u64_free(sn->rule_pkts[i]);
		free(sn->rule_pkts, M_NG_POLICY);
	}
	if (sn->rule_bytes != NULL) {
		for (i = 0; i < sn->nrules; i++)
			if (sn->rule_bytes[i] != NULL)
				counter_u64_free(sn->rule_bytes[i]);
		free(sn->rule_bytes, M_NG_POLICY);
	}
	free(sn->rules, M_NG_POLICY);
	free(sn->idx, M_NG_POLICY);
	free(sn->idx_store, M_NG_POLICY);
	free(sn->addrs, M_NG_POLICY);
	free(sn, M_NG_POLICY);
}

/*
 * Deferred reclamation.  Deliberately touches nothing but the snapshot:
 * a pointer back to priv could outlive priv, because epoch callbacks are
 * ordered only within a CPU.
 */
void
ngp_snapshot_reclaim(epoch_context_t ctx)
{
	struct ng_policy_snapshot *sn;

	sn = __containerof(ctx, struct ng_policy_snapshot, ectx);
	ng_policy_snapshot_free(sn);
}

uint64_t
ng_policy_active_generation(priv_p priv)
{
	struct ng_policy_snapshot *sn;

	sn = NGP_LOAD_PTR(priv->policy);
	return (sn != NULL ? sn->generation : 0);
}

static struct ng_policy_tx *
ngp_tx_find(priv_p priv, uint64_t tx_id)
{
	struct ng_policy_tx *tx;

	mtx_assert(&priv->ctl_mtx, MA_OWNED);
	LIST_FOREACH(tx, &priv->txlist, link)
		if (tx->tx_id == tx_id)
			return (tx);
	return (NULL);
}

static void
ngp_tx_destroy(priv_p priv, struct ng_policy_tx *tx)
{

	mtx_assert(&priv->ctl_mtx, MA_OWNED);
	LIST_REMOVE(tx, link);
	priv->ntx--;
	priv->tx_memory -= tx->memsize;
	free(tx->rules, M_NG_POLICY);
	free(tx->addrs, M_NG_POLICY);
	free(tx, M_NG_POLICY);
}

/* Reap expired transactions.  force reaps everything, for shutdown. */
void
ng_policy_tx_reap(priv_p priv, int force)
{
	struct ng_policy_tx *tx, *ttx;
	uint64_t now = ngp_uptime();

	mtx_assert(&priv->ctl_mtx, MA_OWNED);
	LIST_FOREACH_SAFE(tx, &priv->txlist, link, ttx) {
		/*
		 * A committing transaction is being read unlocked by
		 * ng_policy_tx_commit() right now (see there): the timeout
		 * path must never reap it out from under that read.
		 *
		 * The force path (shutdown, force=1) does NOT actually skip
		 * this check for a live commit -- the KASSERT below is why.
		 * ng_policy_shutdown() runs inside ng_policy_rcvmsg()-style
		 * dispatch, i.e. only after NGM_SHUTDOWN has acquired the
		 * node's writer claim; ng_apply_item()
		 * (/usr/src/sys/netgraph/ng_base.c) does not call
		 * ng_leave_write() until the type method (here,
		 * ng_policy_shutdown()) has returned. ng_policy_tx_commit()
		 * is itself only ever reached the same way, as the body of
		 * the TX_COMMIT type method, and Netgraph never runs two
		 * writer items concurrently on one node. So a shutdown can
		 * never observe tx->committing == 1: whichever of the two
		 * writer claims (this shutdown's, or an in-flight commit's)
		 * was granted first runs to completion, unlock included,
		 * before the other is even dequeued. Reaping a genuinely
		 * committing transaction here would free tx->rules/tx while
		 * ngp_snapshot_build() still reads them across its M_WAITOK
		 * sleep -- a silent use-after-free with INVARIANTS off. That
		 * combination cannot happen today; the KASSERT makes the
		 * claim provable rather than merely asserted in a comment,
		 * and would fire immediately if a future change (e.g.
		 * marking a handler NGM_READONLY, see docs/concurrency.md)
		 * ever made shutdown and a commit interleave.
		 */
		KASSERT(!(force && tx->committing),
		    ("ng_policy_tx_reap: force-reaping a committing tx"));
		if (!force && tx->committing)
			continue;
		if (!force && (uint64_t)tx->expires > now)
			continue;
		if (!force)
			NGP_CTR(priv, tx_timeouts, 1);
		ngp_tx_destroy(priv, tx);
	}
}

static void
ngp_tx_timer(node_p node, hook_p hook, void *arg1, int arg2)
{
	priv_p priv = NG_NODE_PRIVATE(node);

	if (priv == NULL)
		return;
	mtx_lock(&priv->ctl_mtx);
	ng_policy_tx_reap(priv, 0);
	if (!LIST_EMPTY(&priv->txlist) && !priv->shutting_down) {
		/*
		 * ng_callout can fail (M_NOWAIT item allocation): only
		 * claim armed on success.  If it fails here, the next
		 * TX_BEGIN's own re-arm attempt will retry; begin and
		 * commit both reap inline and shutdown force-reaps, so a
		 * missed re-arm cannot strand a transaction forever.
		 */
		if (ng_callout(&priv->tx_callout, node, NULL,
		    NGP_TX_REAP_TICKS, ngp_tx_timer, NULL, 0) == 0)
			priv->tx_callout_armed = 1;
		else
			priv->tx_callout_armed = 0;
	} else
		priv->tx_callout_armed = 0;
	mtx_unlock(&priv->ctl_mtx);
	(void)hook; (void)arg1; (void)arg2;
}

int
ng_policy_tx_begin(priv_p priv, const struct ng_policy_tx_begin_req *req,
    struct ng_policy_tx_begin_resp *resp)
{
	struct ng_policy_tx *tx;
	uint32_t timeout;
	uint64_t active;
	int error = 0;

	if (req->version != 0 && req->version != NG_POLICY_ABI_VERSION)
		return (EPROTONOSUPPORT);
	if (req->flags != 0)
		return (EINVAL);
	timeout = req->timeout != 0 ? req->timeout : ng_policy_tx_timeout;
	if (timeout > 3600)
		return (EINVAL);

	tx = malloc(sizeof(*tx), M_NG_POLICY, M_WAITOK | M_ZERO);

	mtx_lock(&priv->ctl_mtx);
	if (priv->shutting_down) {
		error = EBUSY;
		goto out;
	}
	ng_policy_tx_reap(priv, 0);
	if (priv->ntx >= ng_policy_max_tx) {
		error = ENOSPC;
		goto out;
	}
	active = ng_policy_active_generation(priv);
	/*
	 * A requested_generation absurdly far ahead of active would let a
	 * single commit push the active generation to UINT64_MAX, after
	 * which active+1 wraps to 0 and every later TX_BEGIN would see
	 * requested_generation(0)->active+1 <= active forever, bricking
	 * policy updates for the life of the node.  Reject the jump
	 * itself rather than ever letting active get near the wrap.
	 */
	if (req->requested_generation != 0 &&
	    req->requested_generation > active &&
	    req->requested_generation - active > ((uint64_t)1 << 32)) {
		error = EINVAL;
		goto out;
	}
	tx->generation = req->requested_generation != 0 ?
	    req->requested_generation : active + 1;
	if (tx->generation <= active) {
		error = ESTALE;
		goto out;
	}
	tx->tx_id = ++priv->next_tx_id;
	tx->expires = (time_t)(ngp_uptime() + timeout);
	tx->memsize = sizeof(*tx);
	LIST_INSERT_HEAD(&priv->txlist, tx, link);
	priv->ntx++;
	priv->tx_memory += tx->memsize;

	resp->tx_id = tx->tx_id;
	resp->generation = tx->generation;
	resp->active_generation = active;
	resp->timeout = timeout;
	resp->reserved = 0;

	if (!priv->tx_callout_armed) {
		if (ng_callout(&priv->tx_callout, priv->node, NULL,
		    NGP_TX_REAP_TICKS, ngp_tx_timer, NULL, 0) == 0)
			priv->tx_callout_armed = 1;
	}
	tx = NULL;
out:
	mtx_unlock(&priv->ctl_mtx);
	free(tx, M_NG_POLICY);
	return (error);
}

/*
 * Grow a transaction array.  Allocation happens with the lock dropped
 * would be cleaner, but transactions are control-path only and the
 * arrays are bounded by max_tx_bytes, so M_NOWAIT under the lock keeps
 * the code honest about never sleeping while locked.
 */
static int
ngp_tx_grow(priv_p priv, struct ng_policy_tx *tx, void **arr, uint32_t *cap,
    uint32_t need, size_t esz, uint32_t hardmax)
{
	uint32_t ncap;
	void *na;
	size_t add;

	if (need > hardmax)
		return (ENOSPC);
	if (need <= *cap)
		return (0);
	ncap = *cap != 0 ? *cap : 64;
	while (ncap < need) {
		if (ncap > hardmax / 2) {
			ncap = need;
			break;
		}
		ncap *= 2;
	}
	add = (size_t)(ncap - *cap) * esz;
	if (priv->tx_memory + add > ng_policy_max_tx_bytes)
		return (ENOSPC);
	na = malloc((size_t)ncap * esz, M_NG_POLICY, M_NOWAIT | M_ZERO);
	if (na == NULL)
		return (ENOMEM);
	if (*arr != NULL) {
		memcpy(na, *arr, (size_t)*cap * esz);
		free(*arr, M_NG_POLICY);
	}
	*arr = na;
	*cap = ncap;
	tx->memsize += add;
	priv->tx_memory += add;
	return (0);
}

int
ng_policy_tx_add_rules(priv_p priv, uint64_t tx_id,
    const struct ng_policy_rule *rules, uint32_t n)
{
	struct ng_policy_tx *tx;
	int error;

	if (n == 0)
		return (EINVAL);
	mtx_lock(&priv->ctl_mtx);
	tx = ngp_tx_find(priv, tx_id);
	if (tx == NULL) {
		mtx_unlock(&priv->ctl_mtx);
		return (ENOENT);
	}
	if (tx->committing) {
		mtx_unlock(&priv->ctl_mtx);
		return (EBUSY);
	}
	if (tx->nrules > UINT32_MAX - n) {
		mtx_unlock(&priv->ctl_mtx);
		return (EINVAL);
	}
	error = ngp_tx_grow(priv, tx, (void **)&tx->rules, &tx->rules_cap,
	    tx->nrules + n, sizeof(*rules), ng_policy_max_rules);
	if (error == 0) {
		memcpy(&tx->rules[tx->nrules], rules, (size_t)n * sizeof(*rules));
		tx->nrules += n;
	}
	mtx_unlock(&priv->ctl_mtx);
	return (error);
}

int
ng_policy_tx_add_addrs(priv_p priv, uint64_t tx_id,
    const struct ng_policy_addr *addrs, uint32_t n)
{
	struct ng_policy_tx *tx;
	int error;

	if (n == 0)
		return (EINVAL);
	mtx_lock(&priv->ctl_mtx);
	tx = ngp_tx_find(priv, tx_id);
	if (tx == NULL) {
		mtx_unlock(&priv->ctl_mtx);
		return (ENOENT);
	}
	if (tx->committing) {
		mtx_unlock(&priv->ctl_mtx);
		return (EBUSY);
	}
	if (tx->naddrs > UINT32_MAX - n) {
		mtx_unlock(&priv->ctl_mtx);
		return (EINVAL);
	}
	error = ngp_tx_grow(priv, tx, (void **)&tx->addrs, &tx->addrs_cap,
	    tx->naddrs + n, sizeof(*addrs), ng_policy_max_addrs);
	if (error == 0) {
		memcpy(&tx->addrs[tx->naddrs], addrs, (size_t)n * sizeof(*addrs));
		tx->naddrs += n;
	}
	mtx_unlock(&priv->ctl_mtx);
	return (error);
}

int
ng_policy_tx_set_default(priv_p priv, uint64_t tx_id, uint8_t action)
{
	struct ng_policy_tx *tx;

	if (!NG_POLICY_ACTION_VALID(action))
		return (EINVAL);
	mtx_lock(&priv->ctl_mtx);
	tx = ngp_tx_find(priv, tx_id);
	if (tx == NULL) {
		mtx_unlock(&priv->ctl_mtx);
		return (ENOENT);
	}
	if (tx->committing) {
		mtx_unlock(&priv->ctl_mtx);
		return (EBUSY);
	}
	tx->default_action = action;
	tx->has_default = 1;
	mtx_unlock(&priv->ctl_mtx);
	return (0);
}

int
ng_policy_tx_abort(priv_p priv, uint64_t tx_id)
{
	struct ng_policy_tx *tx;

	mtx_lock(&priv->ctl_mtx);
	tx = ngp_tx_find(priv, tx_id);
	if (tx == NULL) {
		mtx_unlock(&priv->ctl_mtx);
		return (ENOENT);
	}
	if (tx->committing) {
		mtx_unlock(&priv->ctl_mtx);
		return (EBUSY);
	}
	ngp_tx_destroy(priv, tx);
	mtx_unlock(&priv->ctl_mtx);
	NGP_CTR(priv, aborts, 1);
	return (0);
}

static int
ngp_rule_id_cmp(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return (x < y ? -1 : (x > y ? 1 : 0));
}

static __inline int
ngp_endpoint_ref_ok(uint32_t id)
{

	return (id == NG_POLICY_EP_ANY || id == NG_POLICY_EP_EXTERNAL ||
	    id == NG_POLICY_EP_LOCAL_HOST || NG_POLICY_EP_ID_VALID(id));
}

static int
ngp_addr_cmp(const void *a, const void *b)
{
	uint32_t x = ((const struct ng_policy_addr *)a)->ipv4;
	uint32_t y = ((const struct ng_policy_addr *)b)->ipv4;

	return (x < y ? -1 : (x > y ? 1 : 0));
}

static int
ngp_check_dup_addrs(struct ng_policy_tx *tx)
{
	struct ng_policy_addr *copy;
	uint32_t i;
	int error = 0;

	/*
	 * M_WAITOK: called only from ng_policy_tx_commit's unlocked
	 * validation phase (never while holding ctl_mtx).
	 */
	copy = malloc((size_t)tx->naddrs * sizeof(*copy), M_NG_POLICY,
	    M_WAITOK);
	memcpy(copy, tx->addrs, (size_t)tx->naddrs * sizeof(*copy));
	qsort(copy, tx->naddrs, sizeof(*copy), ngp_addr_cmp);
	for (i = 1; i < tx->naddrs; i++)
		if (copy[i].ipv4 == copy[i - 1].ipv4) {
			error = EINVAL;
			break;
		}
	free(copy, M_NG_POLICY);
	return (error);
}

/*
 * Struct-field and endpoint-reference validation.  Requires ctl_mtx: the
 * strict-endpoints branch calls ng_policy_ep_lookup(), which asserts the
 * lock and walks a hash bucket that is only safe to walk while holding
 * it.  This whole pass is O(nrules) with no allocation (bounded by
 * ng_policy_max_rules, already enforced below), so holding the lock
 * across it does not carry the M_NOWAIT-under-lock failure mode the
 * duplicate-detection and snapshot-build steps had -- that is why only
 * those two moved out from under the lock, not this one.
 */
static int
ngp_tx_validate_refs(priv_p priv, struct ng_policy_tx *tx)
{
	const struct ng_policy_rule *r;
	uint32_t i;

	mtx_assert(&priv->ctl_mtx, MA_OWNED);

	if (!tx->has_default)
		return (EINVAL);
	if (tx->nrules > ng_policy_max_rules ||
	    tx->naddrs > ng_policy_max_addrs)
		return (ENOSPC);

	for (i = 0; i < tx->nrules; i++) {
		r = &tx->rules[i];
		if (!NG_POLICY_ACTION_VALID(r->action))
			return (EINVAL);
		if ((r->flags & ~NG_POLICY_RULE_F_MASK) != 0)
			return (EINVAL);
		if (r->src_port_min > r->src_port_max ||
		    r->dst_port_min > r->dst_port_max)
			return (EINVAL);
		if (!ngp_endpoint_ref_ok(r->src_endpoint) ||
		    !ngp_endpoint_ref_ok(r->dst_endpoint))
			return (EINVAL);
		if ((priv->cfg.flags & NG_POLICY_CFG_F_STRICT_ENDPOINTS) != 0) {
			if (NG_POLICY_EP_ID_VALID(r->src_endpoint) &&
			    ng_policy_ep_lookup(priv, r->src_endpoint) == NULL)
				return (ENOENT);
			if (NG_POLICY_EP_ID_VALID(r->dst_endpoint) &&
			    ng_policy_ep_lookup(priv, r->dst_endpoint) == NULL)
				return (ENOENT);
		}
	}
	for (i = 0; i < tx->naddrs; i++) {
		if (tx->addrs[i].ipv4 == 0)
			return (EINVAL);
		if (!NG_POLICY_EP_ID_VALID(tx->addrs[i].endpoint_id) &&
		    tx->addrs[i].endpoint_id != NG_POLICY_EP_LOCAL_HOST)
			return (EINVAL);
	}
	return (0);
}

/*
 * Duplicate-detection.  Touches only the transaction's own arrays, no
 * priv access, so it carries no lock requirement of its own -- it is
 * called from ng_policy_tx_commit's unlocked phase, with tx pinned by
 * tx->committing, and uses M_WAITOK because that phase never holds
 * ctl_mtx.
 */
static int
ngp_tx_validate_dups(struct ng_policy_tx *tx)
{
	uint64_t *ids;
	uint32_t i;
	int error = 0;

	/* Duplicate rule IDs: sort a copy of the IDs and scan. */
	if (tx->nrules > 1) {
		ids = malloc((size_t)tx->nrules * sizeof(*ids), M_NG_POLICY,
		    M_WAITOK);
		for (i = 0; i < tx->nrules; i++)
			ids[i] = tx->rules[i].rule_id;
		qsort(ids, tx->nrules, sizeof(*ids), ngp_rule_id_cmp);
		for (i = 1; i < tx->nrules; i++)
			if (ids[i] == ids[i - 1]) {
				error = EINVAL;
				break;
			}
		free(ids, M_NG_POLICY);
		if (error != 0)
			return (error);
	}
	/* Duplicate addresses, same technique. */
	if (tx->naddrs > 1) {
		error = ngp_check_dup_addrs(tx);
		if (error != 0)
			return (error);
	}
	return (0);
}

/*
 * Sort by (priority, original position).  Including the position makes
 * the order total, so equal priorities resolve by insertion order and
 * the result is deterministic across commits.
 */
struct ngp_sortent {
	uint16_t	priority;
	uint32_t	pos;
};

static int
ngp_rule_order_cmp(const void *a, const void *b)
{
	const struct ngp_sortent *x = a, *y = b;

	if (x->priority != y->priority)
		return (x->priority < y->priority ? -1 : 1);
	return (x->pos < y->pos ? -1 : (x->pos > y->pos ? 1 : 0));
}

/*
 * Index rules by source endpoint.  Buckets and the ANY list both hold
 * global rule indices in ascending order, so merging the two by index
 * visits candidates in exactly the order a full linear scan would.
 * A bucket may hold rules for other source endpoints; matching still
 * compares src_endpoint, so a collision costs a comparison, not a bug.
 */
static int
ngp_index_build(struct ng_policy_snapshot *sn)
{
	uint32_t i, b, buckets, mask, total, *counts, off;
	size_t sz;

	if (sn->nrules == 0)
		return (0);
	buckets = 16;
	while (buckets < sn->nrules / 4 && buckets < 4096)
		buckets *= 2;
	mask = buckets - 1;
	sn->idx_mask = mask;

	sz = (size_t)buckets * sizeof(*sn->idx);
	sn->idx = malloc(sz, M_NG_POLICY, M_WAITOK | M_ZERO);
	sn->memsize += sz;

	counts = malloc((size_t)buckets * sizeof(*counts), M_NG_POLICY,
	    M_WAITOK | M_ZERO);

	/* Pass 1: count. */
	sn->any_src.count = 0;
	for (i = 0; i < sn->nrules; i++) {
		if (sn->rules[i].src_endpoint == NG_POLICY_EP_ANY)
			sn->any_src.count++;
		else
			counts[sn->rules[i].src_endpoint & mask]++;
	}
	total = sn->any_src.count;
	for (b = 0; b < buckets; b++)
		total += counts[b];

	sz = (size_t)total * sizeof(*sn->idx_store);
	sn->idx_store = malloc(sz, M_NG_POLICY, M_WAITOK);
	sn->memsize += sz;

	/* Pass 2: assign offsets. */
	sn->any_src.off = 0;
	off = sn->any_src.count;
	for (b = 0; b < buckets; b++) {
		sn->idx[b].off = off;
		sn->idx[b].count = 0;
		off += counts[b];
	}
	free(counts, M_NG_POLICY);

	/* Pass 3: fill, ascending, so each list stays sorted by index. */
	sn->any_src.count = 0;
	for (i = 0; i < sn->nrules; i++) {
		if (sn->rules[i].src_endpoint == NG_POLICY_EP_ANY) {
			sn->idx_store[sn->any_src.off +
			    sn->any_src.count++] = i;
		} else {
			b = sn->rules[i].src_endpoint & mask;
			sn->idx_store[sn->idx[b].off + sn->idx[b].count++] = i;
		}
	}
	return (0);
}

/*
 * Snapshot builder.  Copies the rules in sorted (priority, insertion
 * order) order, builds the source-endpoint index and allocates the
 * per-rule counters, then builds the address map.  M_WAITOK: called
 * only from ng_policy_tx_commit's unlocked phase, with tx pinned by
 * tx->committing.
 */
static int
ngp_snapshot_build(struct ng_policy_tx *tx, struct ng_policy_snapshot **snp)
{
	struct ng_policy_snapshot *sn;
	uint32_t i;
	int error;

	sn = malloc(sizeof(*sn), M_NG_POLICY, M_WAITOK | M_ZERO);
	sn->generation = tx->generation;
	sn->default_action = tx->default_action;
	sn->memsize = sizeof(*sn);
	sn->nrules = tx->nrules;
	if (tx->nrules > 0) {
		struct ngp_sortent *ord;
		size_t sz = (size_t)tx->nrules * sizeof(*sn->rules);

		sn->rules = malloc(sz, M_NG_POLICY, M_WAITOK);
		ord = malloc((size_t)tx->nrules * sizeof(*ord), M_NG_POLICY,
		    M_WAITOK);
		for (i = 0; i < tx->nrules; i++) {
			ord[i].priority = tx->rules[i].priority;
			ord[i].pos = i;
		}
		qsort(ord, tx->nrules, sizeof(*ord), ngp_rule_order_cmp);
		for (i = 0; i < tx->nrules; i++)
			sn->rules[i] = tx->rules[ord[i].pos];
		free(ord, M_NG_POLICY);
		sn->memsize += sz;

		error = ngp_index_build(sn);
		if (error == 0)
			error = ngp_rule_counters_alloc(sn);
		if (error != 0) {
			ng_policy_snapshot_free(sn);
			return (error);
		}
	}
	if (tx->naddrs > 0) {
		error = ng_policy_addrmap_build(sn, tx->addrs, tx->naddrs);
		if (error != 0) {
			ng_policy_snapshot_free(sn);
			return (error);
		}
	}
	*snp = sn;
	return (0);
}

int
ng_policy_tx_commit(priv_p priv, const struct ng_policy_tx_commit_req *req,
    struct ng_policy_tx_commit_resp *resp)
{
	struct ng_policy_snapshot *sn = NULL, *old;
	struct ng_policy_tx *tx;
	struct timespec t0;
	uint64_t active;
	int error;

	if (req->version != 0 && req->version != NG_POLICY_ABI_VERSION)
		return (EPROTONOSUPPORT);
	if ((req->flags & ~NG_POLICY_TXC_F_MASK) != 0)
		return (EINVAL);
	if (req->reserved != 0)
		return (EINVAL);

	memset(resp, 0, sizeof(*resp));

	mtx_lock(&priv->ctl_mtx);
	ng_policy_tx_reap(priv, 0);
	tx = ngp_tx_find(priv, req->tx_id);
	if (tx == NULL) {
		mtx_unlock(&priv->ctl_mtx);
		return (ENOENT);
	}
	if (tx->committing) {
		mtx_unlock(&priv->ctl_mtx);
		return (EBUSY);
	}
	active = ng_policy_active_generation(priv);
	if ((req->flags & NG_POLICY_TXC_F_FORCE) == 0 &&
	    req->base_generation != active) {
		mtx_unlock(&priv->ctl_mtx);
		NGP_CTR(priv, failed_commits, 1);
		counter_u64_add(ng_policy_g_failed_commits, 1);
		return (ESTALE);
	}
	if (tx->generation <= active) {
		mtx_unlock(&priv->ctl_mtx);
		NGP_CTR(priv, failed_commits, 1);
		counter_u64_add(ng_policy_g_failed_commits, 1);
		return (ESTALE);
	}

	/*
	 * Struct-field and endpoint-reference validation: still locked
	 * (see ngp_tx_validate_refs), still cheap, deliberately not timed
	 * into validate_usec -- that field now measures only the unlocked
	 * work below, which is the part worth watching for regressions.
	 */
	error = ngp_tx_validate_refs(priv, tx);
	if (error != 0) {
		mtx_unlock(&priv->ctl_mtx);
		NGP_CTR(priv, failed_commits, 1);
		counter_u64_add(ng_policy_g_failed_commits, 1);
		return (error);
	}

	/*
	 * Pin the transaction and drop the lock before the two
	 * allocation-heavy steps: duplicate detection (scratch arrays up
	 * to ~2MB each at max_rules/max_addrs) and the snapshot build
	 * itself (up to ~8MB of rules today; in Task 7, also two
	 * counter_u64_alloc() calls per rule).  M_NOWAIT on allocations
	 * this large fails spuriously under fragmentation; M_WAITOK needs
	 * to not hold this non-sleepable mutex.  tx->committing makes
	 * ng_policy_tx_add_rules/_add_addrs/_set_default and
	 * ng_policy_tx_abort refuse with EBUSY while it is set, so
	 * nothing on this control path can mutate or free tx while it is
	 * read unlocked below.
	 */
	tx->committing = 1;
	mtx_unlock(&priv->ctl_mtx);

	nanouptime(&t0);
	error = ngp_tx_validate_dups(tx);
	resp->validate_usec = ngp_usec_since(&t0);
	if (error == 0) {
		nanouptime(&t0);
		error = ngp_snapshot_build(tx, &sn);
		resp->build_usec = ngp_usec_since(&t0);
	}

	mtx_lock(&priv->ctl_mtx);
	/*
	 * Re-verify tx is still the live transaction before touching it
	 * again: look it up by the tx_id from the request rather than
	 * trusting the possibly-stale tx pointer, so a hypothetical (see
	 * above: believed unreachable) concurrent free is never
	 * dereferenced, let alone written to.
	 */
	if (ngp_tx_find(priv, req->tx_id) != tx) {
		mtx_unlock(&priv->ctl_mtx);
		ng_policy_snapshot_free(sn);	/* never published: safe */
		NGP_CTR(priv, failed_commits, 1);
		counter_u64_add(ng_policy_g_failed_commits, 1);
		return (ESTALE);
	}
	if (error != 0) {
		tx->committing = 0;
		mtx_unlock(&priv->ctl_mtx);
		/*
		 * error here is either ngp_tx_validate_dups()'s EINVAL, for
		 * which sn is still NULL from its "= NULL" initializer
		 * above (ngp_snapshot_build() is never called), or a
		 * nonzero return from ngp_snapshot_build() itself -- from
		 * the address-map size guard, the index build, or a
		 * per-rule counter_u64_alloc() failure.  On every one of
		 * those, the builder frees its own local snapshot before
		 * returning but never writes through its output parameter,
		 * so our sn is untouched and still NULL from the same
		 * initializer.  Either way sn is NULL by the time we get
		 * here; freeing unconditionally is just defensive -- it
		 * stays correct even if a future change to the builder ever
		 * left a non-NULL, never-published snapshot in sn.
		 */
		ng_policy_snapshot_free(sn);
		NGP_CTR(priv, failed_commits, 1);
		counter_u64_add(ng_policy_g_failed_commits, 1);
		return (error);
	}

	/*
	 * Re-verify the active generation hasn't moved while unlocked.
	 * Nothing on this node can actually mutate priv->policy
	 * concurrently with this call (see the commit message / task
	 * report for the netgraph writer-exclusivity argument), but
	 * re-checking is cheap and keeps the invariant provable locally
	 * rather than resting on framework internals.
	 */
	if (ng_policy_active_generation(priv) != active) {
		tx->committing = 0;
		mtx_unlock(&priv->ctl_mtx);
		ng_policy_snapshot_free(sn);	/* never published: safe */
		NGP_CTR(priv, failed_commits, 1);
		counter_u64_add(ng_policy_g_failed_commits, 1);
		return (ESTALE);
	}

	nanouptime(&t0);
	old = priv->policy;
	NGP_STORE_PTR(priv->policy, sn);	/* the swap */
	resp->commit_usec = ngp_usec_since(&t0);

	resp->generation = sn->generation;
	resp->nrules = sn->nrules;
	resp->naddrs = sn->naddrs;
	resp->memory = sn->memsize;

	ngp_tx_destroy(priv, tx);
	mtx_unlock(&priv->ctl_mtx);

	nanouptime(&t0);
	if (old != NULL)
		NET_EPOCH_CALL(ngp_snapshot_reclaim, &old->ectx);
	resp->reclaim_usec = ngp_usec_since(&t0);

	NGP_CTR(priv, commits, 1);
	counter_u64_add(ng_policy_g_commits, 1);
	return (0);
}

static __inline int
ngp_rule_matches(const struct ng_policy_rule *r,
    const struct ng_policy_meta *m)
{

	if (r->src_endpoint != NG_POLICY_EP_ANY &&
	    r->src_endpoint != m->src_endpoint)
		return (0);
	if (r->dst_endpoint != NG_POLICY_EP_ANY &&
	    r->dst_endpoint != m->dst_endpoint)
		return (0);
	if (r->protocol != NG_POLICY_PROTO_ANY && r->protocol != m->protocol)
		return (0);
	if (m->src_port < r->src_port_min || m->src_port > r->src_port_max)
		return (0);
	if (m->dst_port < r->dst_port_min || m->dst_port > r->dst_port_max)
		return (0);
	if ((r->flags & NG_POLICY_RULE_F_ICMP_TYPE) != 0 &&
	    (m->protocol != NG_POLICY_PROTO_ICMP ||
	    m->icmp_type != r->icmp_type))
		return (0);
	if ((r->flags & NG_POLICY_RULE_F_ICMP_CODE) != 0 &&
	    (m->protocol != NG_POLICY_PROTO_ICMP ||
	    m->icmp_code != r->icmp_code))
		return (0);
	return (1);
}

/*
 * Merge the packet's source-endpoint bucket with the ANY-source list,
 * both ascending by global rule index, always taking the smaller index
 * next.  That reproduces the visiting order of a full linear scan over
 * sn->rules using only the candidates that could possibly match, so
 * first-match-wins keeps the same meaning as a naive scan.
 */
const struct ng_policy_rule *
ng_policy_match(const struct ng_policy_snapshot *sn,
    const struct ng_policy_meta *meta, uint32_t *idxp)
{
	const struct ng_policy_rlist *bucket, *any;
	uint32_t i = 0, j = 0, ri;

	if (sn->nrules == 0)
		return (NULL);
	any = &sn->any_src;
	bucket = (meta->src_endpoint != NG_POLICY_EP_ANY) ?
	    &sn->idx[meta->src_endpoint & sn->idx_mask] : NULL;

	for (;;) {
		if (bucket != NULL && i < bucket->count) {
			if (j < any->count) {
				uint32_t a = sn->idx_store[bucket->off + i];
				uint32_t b = sn->idx_store[any->off + j];

				ri = (a < b) ? sn->idx_store[bucket->off + i++]
				    : sn->idx_store[any->off + j++];
			} else
				ri = sn->idx_store[bucket->off + i++];
		} else if (j < any->count)
			ri = sn->idx_store[any->off + j++];
		else
			break;

		if (ngp_rule_matches(&sn->rules[ri], meta)) {
			*idxp = ri;
			return (&sn->rules[ri]);
		}
	}
	return (NULL);
}
