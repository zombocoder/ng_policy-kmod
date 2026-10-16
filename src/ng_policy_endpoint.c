/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ng_policy - endpoint table and hook binding.
 */

#include <netgraph/ng_policy/ng_policy_var.h>

struct ng_policy_ep *
ng_policy_ep_lookup(priv_p priv, uint32_t id)
{
	struct ng_policy_ep *ep;

	mtx_assert(&priv->ctl_mtx, MA_OWNED);
	LIST_FOREACH(ep, &priv->ephash[NGP_EPHASH(id)], hashlink)
		if (ep->endpoint_id == id)
			return (ep);
	return (NULL);
}

/*
 * Bind a hook private to whichever endpoint claims its name, if any.
 * Called when a hook appears and again when an endpoint is registered,
 * so that the two may arrive in either order.
 */
static void
ngp_bind_one(struct ng_policy_ep *ep, struct ng_policy_hookpriv *hp)
{

	if (strcmp(ep->hook, hp->name) == 0) {
		ep->hp = hp;
		hp->ep = ep;
		hp->side = NGP_SIDE_EP;
	} else if (ep->peer_hook[0] != '\0' &&
	    strcmp(ep->peer_hook, hp->name) == 0) {
		ep->peer_hp = hp;
		hp->ep = ep;
		hp->side = NGP_SIDE_FAB;
	}
}

void
ng_policy_hook_attach(priv_p priv, struct ng_policy_hookpriv *hp)
{
	struct ng_policy_ep *ep;

	mtx_lock(&priv->ctl_mtx);
	TAILQ_FOREACH(ep, &priv->eplist, alllink) {
		ngp_bind_one(ep, hp);
		if (hp->ep != NULL)
			break;
	}
	mtx_unlock(&priv->ctl_mtx);
}

void
ng_policy_hook_detach(priv_p priv, struct ng_policy_hookpriv *hp)
{
	struct ng_policy_ep *ep;

	mtx_lock(&priv->ctl_mtx);
	ep = hp->ep;
	if (ep != NULL) {
		if (ep->hp == hp)
			ep->hp = NULL;
		if (ep->peer_hp == hp)
			ep->peer_hp = NULL;
	}
	hp->ep = NULL;
	hp->side = NGP_SIDE_NONE;
	mtx_unlock(&priv->ctl_mtx);
}

/* Walk every hook of the node, binding those this endpoint claims. */
static void
ngp_rebind_hooks(priv_p priv, struct ng_policy_ep *ep)
{
	struct ng_policy_hookpriv *hp;
	hook_p hook;

	LIST_FOREACH(hook, &priv->node->nd_hooks, hk_hooks) {
		hp = NG_HOOK_PRIVATE(hook);
		if (hp != NULL && hp->ep == NULL)
			ngp_bind_one(ep, hp);
	}
}

static void
ngp_ep_unbind(struct ng_policy_ep *ep)
{

	if (ep->hp != NULL) {
		ep->hp->ep = NULL;
		ep->hp->side = NGP_SIDE_NONE;
		ep->hp = NULL;
	}
	if (ep->peer_hp != NULL) {
		ep->peer_hp->ep = NULL;
		ep->peer_hp->side = NGP_SIDE_NONE;
		ep->peer_hp = NULL;
	}
}

static void
ngp_ep_reclaim(epoch_context_t ctx)
{
	struct ng_policy_ep *ep;

	ep = __containerof(ctx, struct ng_policy_ep, ectx);
	ng_policy_ep_counters_fini(ep);
	free(ep, M_NG_POLICY);
}

int
ng_policy_ep_add(priv_p priv, const struct ng_policy_endpoint_add *req)
{
	struct ng_policy_ep *ep, *old;
	int error = 0;

	if (req->version != 0 && req->version != NG_POLICY_ABI_VERSION)
		return (EPROTONOSUPPORT);
	if (req->reserved != 0)
		return (EINVAL);
	if (!NG_POLICY_EP_ID_VALID(req->endpoint_id))
		return (EINVAL);
	if ((req->flags & ~(NG_POLICY_EP_CFG_MASK | NG_POLICY_EP_F_REPLACE)) != 0)
		return (EINVAL);
	if (req->hook[0] == '\0')
		return (EINVAL);
	/* NG_HOOKSIZ-sized fields from userland need not be terminated. */
	if (memchr(req->hook, '\0', NG_HOOKSIZ) == NULL ||
	    memchr(req->peer_hook, '\0', NG_HOOKSIZ) == NULL)
		return (EINVAL);
	if (req->peer_hook[0] != '\0' &&
	    strcmp(req->hook, req->peer_hook) == 0)
		return (EINVAL);

	ep = malloc(sizeof(*ep), M_NG_POLICY, M_WAITOK | M_ZERO);
	if (ng_policy_ep_counters_init(ep) != 0) {
		free(ep, M_NG_POLICY);
		return (ENOMEM);
	}
	ep->endpoint_id = req->endpoint_id;
	/*
	 * Flags are stored verbatim and reported back.  ENABLED is
	 * reserved in v0.1 and deliberately not enforced in the data
	 * path: no requirement covers disable-without-delete, and a
	 * semantic no test exercises is worse than a reserved bit.
	 */
	ep->flags = req->flags & NG_POLICY_EP_CFG_MASK;
	strlcpy(ep->hook, req->hook, sizeof(ep->hook));
	strlcpy(ep->peer_hook, req->peer_hook, sizeof(ep->peer_hook));

	mtx_lock(&priv->ctl_mtx);
	if (priv->shutting_down) {
		error = EBUSY;
		goto out;
	}
	old = ng_policy_ep_lookup(priv, req->endpoint_id);
	if (old != NULL && (req->flags & NG_POLICY_EP_F_REPLACE) == 0) {
		error = EEXIST;
		goto out;
	}
	if (old == NULL && priv->nendpoints >= ng_policy_max_endpoints) {
		error = ENOSPC;
		goto out;
	}
	if (old != NULL) {
		ngp_ep_unbind(old);
		LIST_REMOVE(old, hashlink);
		TAILQ_REMOVE(&priv->eplist, old, alllink);
		priv->nendpoints--;
		NET_EPOCH_CALL(ngp_ep_reclaim, &old->ectx);
	}
	LIST_INSERT_HEAD(&priv->ephash[NGP_EPHASH(ep->endpoint_id)], ep,
	    hashlink);
	TAILQ_INSERT_TAIL(&priv->eplist, ep, alllink);
	priv->nendpoints++;
	ngp_rebind_hooks(priv, ep);
	ep = NULL;
out:
	mtx_unlock(&priv->ctl_mtx);
	if (ep != NULL) {
		ng_policy_ep_counters_fini(ep);
		free(ep, M_NG_POLICY);
	}
	return (error);
}

int
ng_policy_ep_del(priv_p priv, uint32_t id)
{
	struct ng_policy_ep *ep;

	if (!NG_POLICY_EP_ID_VALID(id))
		return (EINVAL);
	mtx_lock(&priv->ctl_mtx);
	ep = ng_policy_ep_lookup(priv, id);
	if (ep == NULL) {
		mtx_unlock(&priv->ctl_mtx);
		return (ENOENT);
	}
	ngp_ep_unbind(ep);
	LIST_REMOVE(ep, hashlink);
	TAILQ_REMOVE(&priv->eplist, ep, alllink);
	priv->nendpoints--;
	mtx_unlock(&priv->ctl_mtx);
	/*
	 * Deferred: a packet already in the epoch section may still hold
	 * this pointer through its hook private.
	 */
	NET_EPOCH_CALL(ngp_ep_reclaim, &ep->ectx);
	return (0);
}

void
ng_policy_ep_flush(priv_p priv)
{
	struct ng_policy_ep *ep;

	mtx_lock(&priv->ctl_mtx);
	while ((ep = TAILQ_FIRST(&priv->eplist)) != NULL) {
		ngp_ep_unbind(ep);
		LIST_REMOVE(ep, hashlink);
		TAILQ_REMOVE(&priv->eplist, ep, alllink);
		priv->nendpoints--;
		NET_EPOCH_CALL(ngp_ep_reclaim, &ep->ectx);
	}
	mtx_unlock(&priv->ctl_mtx);
}

static void
ng_policy_ep_export(struct ng_policy_ep *ep,
    struct ng_policy_endpoint_info *info)
{

	memset(info, 0, sizeof(*info));
	info->endpoint_id = ep->endpoint_id;
	info->flags = ep->flags;
	if (ep->hp != NULL)
		info->flags |= NG_POLICY_EP_S_CONNECTED;
	if (ep->peer_hp != NULL)
		info->flags |= NG_POLICY_EP_S_PEER_CONNECTED;
	info->rx_packets = counter_u64_fetch(ep->rx_packets);
	info->rx_bytes = counter_u64_fetch(ep->rx_bytes);
	info->tx_packets = counter_u64_fetch(ep->tx_packets);
	info->tx_bytes = counter_u64_fetch(ep->tx_bytes);
	info->allowed_packets = counter_u64_fetch(ep->allowed_packets);
	info->dropped_packets = counter_u64_fetch(ep->dropped_packets);
	info->violations = counter_u64_fetch(ep->violations);
	strlcpy(info->hook, ep->hook, sizeof(info->hook));
	strlcpy(info->peer_hook, ep->peer_hook, sizeof(info->peer_hook));
}

int
ng_policy_ep_list(priv_p priv, const struct ng_mesg *msg,
    const struct ng_policy_ep_query *q, struct ng_mesg **rp)
{
	struct ng_policy_ep_list_resp *resp;
	struct ng_policy_endpoint_info *info;
	struct ng_policy_ep *ep;
	struct ng_mesg *r;
	uint32_t want, n, idx, total, byte_max;
	size_t len;

	if (q->reserved != 0)
		return (EINVAL);

	want = q->max_entries;
	if (want == 0 || want > NG_POLICY_BATCH_MAX)
		want = NG_POLICY_BATCH_MAX;
	/*
	 * Clamp separately against the control socket's receive ceiling:
	 * NG_POLICY_BATCH_MAX alone would ask NG_MKRESPONSE for up to
	 * 512 * sizeof(*info) bytes of entries, more than three times the
	 * default 20KB net.graph.recvspace once the response headers are
	 * added, and the reply send would fail with ENOBUFS instead of
	 * paging.  See NG_POLICY_RESP_BYTE_BUDGET's comment in
	 * ng_policy.h.
	 */
	byte_max = (NG_POLICY_RESP_BYTE_BUDGET >
	    sizeof(struct ng_mesg) + sizeof(*resp)) ?
	    (uint32_t)((NG_POLICY_RESP_BYTE_BUDGET - sizeof(struct ng_mesg) -
	    sizeof(*resp)) / sizeof(*info)) : 0;
	if (want > byte_max)
		want = byte_max;

	mtx_lock(&priv->ctl_mtx);
	total = (q->endpoint_id != NG_POLICY_EP_ANY) ? 1 : priv->nendpoints;
	if (want > total)
		want = total;
	len = sizeof(*resp) + want * sizeof(*info);
	mtx_unlock(&priv->ctl_mtx);

	NG_MKRESPONSE(r, msg, len, M_NOWAIT);
	if (r == NULL)
		return (ENOMEM);
	resp = (struct ng_policy_ep_list_resp *)r->data;

	mtx_lock(&priv->ctl_mtx);
	resp->generation = ng_policy_active_generation(priv);
	n = idx = 0;
	TAILQ_FOREACH(ep, &priv->eplist, alllink) {
		if (q->endpoint_id != NG_POLICY_EP_ANY &&
		    ep->endpoint_id != q->endpoint_id)
			continue;
		if (idx++ < q->start_index)
			continue;
		if (n >= want)
			break;
		info = &resp->entries[n++];
		ng_policy_ep_export(ep, info);
	}
	resp->total = (q->endpoint_id != NG_POLICY_EP_ANY) ? idx :
	    priv->nendpoints;
	resp->returned = n;
	resp->next_index = q->start_index + n;
	mtx_unlock(&priv->ctl_mtx);

	*rp = r;
	return (0);
}

/*
 * Open addressing with linear probing.  The table is built once at
 * commit and never mutated, so probing needs no tombstones and the
 * whole thing is one cache-friendly array.  0.0.0.0 marks an empty
 * slot, which ngp_tx_validate_refs() guarantees is never a real entry.
 */
static __inline uint32_t
ngp_addr_hash(uint32_t ipv4)
{
	uint32_t h = ipv4 * 2654435761u;

	return (h ^ (h >> 16));
}

/*
 * Build the address map into sn->addrs/addr_mask/naddrs.  Called from
 * ngp_snapshot_build(), which runs outside ctl_mtx with M_WAITOK, so this
 * allocates the same way.  The ENOMEM/ENOSPC-capable signature stays part
 * of the contract even though the size guard below is the only path that
 * can fail today: Task 7 adds a counter_u64_alloc() per rule to the same
 * builder, which makes the whole thing fallible again, and the commit
 * path already frees a partially built snapshot on any nonzero return.
 */
int
ng_policy_addrmap_build(struct ng_policy_snapshot *sn,
    const struct ng_policy_addr *src, uint32_t n)
{
	uint32_t i, slots, mask, j;
	size_t sz;

	if (n == 0)
		return (0);
	/*
	 * Load factor at most 0.5.  That bound is what guarantees the
	 * insert loop below terminates: at least half the slots are
	 * always empty, so the linear probe can never wrap all the way
	 * around without finding one.
	 */
	slots = 16;
	while (slots < n * 2) {
		if (slots > (UINT32_MAX / 2))
			return (ENOSPC);
		slots *= 2;
	}
	mask = slots - 1;
	sz = (size_t)slots * sizeof(*sn->addrs);
	sn->addrs = malloc(sz, M_NG_POLICY, M_WAITOK | M_ZERO);
	sn->addr_mask = mask;
	sn->naddrs = n;
	sn->memsize += sz;

	for (i = 0; i < n; i++) {
		j = ngp_addr_hash(src[i].ipv4) & mask;
		while (sn->addrs[j].ipv4 != 0)
			j = (j + 1) & mask;
		sn->addrs[j] = src[i];
	}
	return (0);
}

/*
 * Resolve an IPv4 address (network byte order, matching how the parser
 * fills ng_policy_meta and how ng_parse_ipaddr_type delivers TX_ADD_ADDR
 * entries -- no conversion happens anywhere) to an endpoint id.  A
 * snapshot with no address map at all has sn->addrs == NULL, which
 * resolves every address to EXTERNAL rather than dereferencing a null
 * table.
 */
uint32_t
ng_policy_addr_lookup(const struct ng_policy_snapshot *sn, uint32_t ipv4)
{
	uint32_t j, mask;

	if (sn->addrs == NULL || ipv4 == 0)
		return (NG_POLICY_EP_EXTERNAL);
	mask = sn->addr_mask;
	j = ngp_addr_hash(ipv4) & mask;
	while (sn->addrs[j].ipv4 != 0) {
		if (sn->addrs[j].ipv4 == ipv4)
			return (sn->addrs[j].endpoint_id);
		j = (j + 1) & mask;
	}
	return (NG_POLICY_EP_EXTERNAL);
}
