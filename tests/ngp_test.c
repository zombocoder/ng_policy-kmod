#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include <netgraph.h>

#include "ngp_harness.h"

static int
test_node_lifecycle(struct ngp_ctx *c)
{

	/* ngp_setup() already created and named the node. */
	ASSERT_EQ(NgSendAsciiMsg(c->cs, c->path, "nodeinfo") >= 0, 1);
	return (0);
}

static int
test_endpoint_add_and_list(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_ep_list_resp r;
		struct ng_policy_endpoint_info e[4];
	} out;
	struct ng_policy_ep_query q;

	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_OK(ngp_ep_add(c, 2001, "ep-2001", "fab-2001", 0));

	memset(&q, 0, sizeof(q));
	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_ENDPOINT_LIST, &q, sizeof(q),
	    &out, sizeof(out.r)));
	ASSERT_EQ(out.r.total, 2);
	return (0);
}

/*
 * Shared page size for the two windowed-enumeration pagination tests
 * below.  20 entries at a page size of 7 gives three pages (7, 7, 6),
 * with the final page deliberately short: an off-by-one in next_index
 * or in the returned clamp is most likely to surface exactly there.
 */
#define	NGP_PAGE_SZ		7

#define	NGP_PAGE_EP_BASE	5000
#define	NGP_PAGE_EP_N		20

/*
 * ENDPOINT_LIST pagination across a real page boundary.  Registers 20
 * endpoints and walks them NGP_PAGE_SZ at a time, following next_index,
 * asserting the union of every page is exactly the set registered --
 * each endpoint seen exactly once, no gaps, no duplicates -- and that
 * the walk actually terminates.
 */
static int
test_endpoint_list_pagination(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_ep_list_resp r;
		struct ng_policy_endpoint_info e[NGP_PAGE_SZ];
	} out;
	struct ng_policy_ep_query q;
	char hook[NG_HOOKSIZ], peer[NG_HOOKSIZ];
	int seen[NGP_PAGE_EP_N];
	uint32_t i, start, iter, total_seen, n, j;

	for (i = 0; i < NGP_PAGE_EP_N; i++) {
		snprintf(hook, sizeof(hook), "ep-%u", NGP_PAGE_EP_BASE + i);
		snprintf(peer, sizeof(peer), "fab-%u", NGP_PAGE_EP_BASE + i);
		ASSERT_OK(ngp_ep_add(c, NGP_PAGE_EP_BASE + i, hook, peer, 0));
	}

	memset(seen, 0, sizeof(seen));
	total_seen = 0;
	start = 0;
	for (iter = 0; iter < 10; iter++) {
		memset(&q, 0, sizeof(q));
		q.endpoint_id = NG_POLICY_EP_ANY;
		q.start_index = start;
		q.max_entries = NGP_PAGE_SZ;

		/*
		 * ENDPOINT_LIST sizes its response to the *requested
		 * window*, clamped only against the total matching count
		 * -- not against what actually remains after start_index
		 * -- so every page here, including the short final one,
		 * is sized for the full NGP_PAGE_SZ (total 20 exceeds
		 * NGP_PAGE_SZ on every page of this walk).  See
		 * docs/control-api.md.
		 */
		ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_ENDPOINT_LIST, &q,
		    sizeof(q), &out, sizeof(out.r) +
		    NGP_PAGE_SZ * sizeof(out.e[0])));
		ASSERT_EQ(out.r.total, NGP_PAGE_EP_N);

		n = out.r.returned;
		ASSERT_EQ(out.r.next_index, start + n);
		ASSERT_EQ(n <= NGP_PAGE_SZ, 1);
		if (n == 0)
			break;

		for (j = 0; j < n; j++) {
			uint32_t id = out.e[j].endpoint_id;
			int idx;

			ASSERT_EQ(id >= NGP_PAGE_EP_BASE &&
			    id < NGP_PAGE_EP_BASE + NGP_PAGE_EP_N, 1);
			idx = (int)(id - NGP_PAGE_EP_BASE);
			/* Exactly once across the whole walk: fail loudly
			   on a repeat rather than merely counting totals. */
			ASSERT_EQ(seen[idx], 0);
			seen[idx] = 1;
			total_seen++;
		}

		start = out.r.next_index;
		if (start >= out.r.total)
			break;
	}
	/* The walk must have actually terminated well inside the
	   generous 10-iteration cap (3 pages expected), not looped. */
	ASSERT_EQ(iter < 10, 1);
	ASSERT_EQ(total_seen, NGP_PAGE_EP_N);
	for (i = 0; i < NGP_PAGE_EP_N; i++)
		ASSERT_EQ(seen[i], 1);
	return (0);
}

/*
 * The byte-budget entry count for one ENDPOINT_LIST/GET_ENDPOINT_STATS
 * page, computed the same way ng_policy_ep_list() computes it, so this
 * test tracks the implementation rather than a copy of its current
 * numeric answer. NG_POLICY_RESP_BYTE_BUDGET, sizeof(struct ng_mesg)
 * and struct ng_policy_ep_list_resp/ng_policy_endpoint_info come from
 * the same kernel headers the module builds against -- see
 * ng_policy.h, "safe to include from userland."
 */
#define	NGP_EP_ENTRY_BYTE_MAX					\
	((NG_POLICY_RESP_BYTE_BUDGET - sizeof(struct ng_mesg) -	\
	sizeof(struct ng_policy_ep_list_resp)) /			\
	sizeof(struct ng_policy_endpoint_info))

#define	NGP_CEIL_EP_BASE	20000
#define	NGP_CEIL_EP_N		200

/*
 * Regression test for the final-review defect: ENDPOINT_LIST's
 * documented default ("max_entries = 0" means "as many as fit") must
 * still enumerate every endpoint when the endpoint count exceeds what
 * one reply can carry within net.graph.recvspace
 * (NGP_EP_ENTRY_BYTE_MAX, 159 at the default 20KB budget) -- not just
 * across an ordinary page boundary the way
 * test_endpoint_list_pagination() above already covers.
 * NGP_CEIL_EP_N (200) is chosen to exceed NGP_EP_ENTRY_BYTE_MAX, so
 * this walk cannot finish in one page; the final assertion confirms
 * that actually happened rather than passing vacuously. Before the
 * per-type byte clamp in ng_policy_ep_list(), this exact shape
 * (max_entries = 0, > 159 endpoints registered) failed the reply send
 * outright instead of paging -- reproduced empirically as "160
 * endpoints -> FAILED: No buffer space available" against the
 * unclamped code.
 */
static int
test_endpoint_list_recvspace_ceiling(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_ep_list_resp r;
		struct ng_policy_endpoint_info e[NGP_EP_ENTRY_BYTE_MAX];
	} out;
	struct ng_policy_ep_query q;
	char hook[NG_HOOKSIZ], peer[NG_HOOKSIZ];
	int seen[NGP_CEIL_EP_N];
	uint32_t i, start, iter, total_seen, n, j, pages;

	for (i = 0; i < NGP_CEIL_EP_N; i++) {
		snprintf(hook, sizeof(hook), "ep-%u", NGP_CEIL_EP_BASE + i);
		snprintf(peer, sizeof(peer), "fab-%u", NGP_CEIL_EP_BASE + i);
		ASSERT_OK(ngp_ep_add(c, NGP_CEIL_EP_BASE + i, hook, peer, 0));
	}

	memset(seen, 0, sizeof(seen));
	total_seen = 0;
	start = 0;
	pages = 0;
	for (iter = 0; iter < 10; iter++) {
		memset(&q, 0, sizeof(q));
		q.endpoint_id = NG_POLICY_EP_ANY;
		q.start_index = start;
		q.max_entries = 0;	/* "as many as fit" -- the documented default */

		/*
		 * ng_policy_ep_list() sizes the response off `total`, not
		 * off what remains after start_index (see the comment in
		 * test_endpoint_list_pagination() above), so with `total`
		 * fixed at NGP_CEIL_EP_N for this whole walk, every page's
		 * allocated size is the same: NGP_EP_ENTRY_BYTE_MAX entries.
		 */
		ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_ENDPOINT_LIST, &q,
		    sizeof(q), &out, sizeof(out.r) +
		    NGP_EP_ENTRY_BYTE_MAX * sizeof(out.e[0])));
		ASSERT_EQ(out.r.total, NGP_CEIL_EP_N);
		ASSERT_EQ(out.r.returned <= NGP_EP_ENTRY_BYTE_MAX, 1);
		pages++;

		n = out.r.returned;
		ASSERT_EQ(out.r.next_index, start + n);
		if (n == 0)
			break;

		for (j = 0; j < n; j++) {
			uint32_t id = out.e[j].endpoint_id;
			int idx;

			ASSERT_EQ(id >= NGP_CEIL_EP_BASE &&
			    id < NGP_CEIL_EP_BASE + NGP_CEIL_EP_N, 1);
			idx = (int)(id - NGP_CEIL_EP_BASE);
			ASSERT_EQ(seen[idx], 0);
			seen[idx] = 1;
			total_seen++;
		}

		start = out.r.next_index;
		if (start >= out.r.total)
			break;
	}
	ASSERT_EQ(iter < 10, 1);
	ASSERT_EQ(total_seen, NGP_CEIL_EP_N);
	for (i = 0; i < NGP_CEIL_EP_N; i++)
		ASSERT_EQ(seen[i], 1);
	/* Must actually have crossed the byte-budget ceiling, not merely
	   fit in one generous page. */
	ASSERT_EQ(pages >= 2, 1);
	return (0);
}

static int
test_endpoint_duplicate_rejected(struct ngp_ctx *c)
{

	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_ERRNO(ngp_ep_add(c, 1001, "ep-x", "fab-x", 0), EEXIST);
	/* ...unless replacement is explicitly requested. */
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-y", "fab-y",
	    NG_POLICY_EP_F_REPLACE));
	return (0);
}

static int
test_endpoint_reserved_id_rejected(struct ngp_ctx *c)
{

	ASSERT_ERRNO(ngp_ep_add(c, NG_POLICY_EP_ANY, "a", "b", 0), EINVAL);
	ASSERT_ERRNO(ngp_ep_add(c, NG_POLICY_EP_EXTERNAL, "a", "b", 0), EINVAL);
	ASSERT_ERRNO(ngp_ep_add(c, NG_POLICY_EP_LOCAL_HOST, "a", "b", 0),
	    EINVAL);
	return (0);
}

static int
test_endpoint_del(struct ngp_ctx *c)
{

	ASSERT_ERRNO(ngp_ep_del(c, 1001), ENOENT);
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_OK(ngp_ep_del(c, 1001));
	ASSERT_ERRNO(ngp_ep_del(c, 1001), ENOENT);
	return (0);
}

/*
 * Binding must work in both orders: hook connected first, then endpoint
 * registered, and the reverse.  The status flags in the list response
 * report which hooks are actually connected.
 */
static int
test_endpoint_binds_either_order(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_ep_list_resp r;
		struct ng_policy_endpoint_info e[2];
	} out;
	struct ng_policy_ep_query q;

	/* hook first, endpoint second */
	ASSERT_OK(ngp_hook(c, "d1", "ep-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	/* endpoint first, hook second */
	ASSERT_OK(ngp_ep_add(c, 2001, "ep-2001", "fab-2001", 0));
	ASSERT_OK(ngp_hook(c, "d2", "ep-2001"));

	memset(&q, 0, sizeof(q));
	q.max_entries = 2;
	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_ENDPOINT_LIST, &q, sizeof(q),
	    &out, sizeof(out)));
	ASSERT_EQ(out.r.returned, 2);
	ASSERT_EQ((out.e[0].flags & NG_POLICY_EP_S_CONNECTED) != 0, 1);
	ASSERT_EQ((out.e[1].flags & NG_POLICY_EP_S_CONNECTED) != 0, 1);
	/* Neither fabric hook was connected. */
	ASSERT_EQ(out.e[0].flags & NG_POLICY_EP_S_PEER_CONNECTED, 0);
	return (0);
}

/*
 * A frame sent into the workload-side hook must come out the fabric-side
 * hook of the same endpoint, byte for byte, and be counted once.
 */
static int
test_forward_ep_to_fab(struct ngp_ctx *c)
{
	uint8_t f[NGP_MAXFRAME], out[NGP_MAXFRAME];
	char hook[NG_HOOKSIZ];
	struct ng_policy_stats st;
	size_t len;
	int n;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_OK(ngp_set_mode(c, NG_POLICY_MODE_DISABLED));

	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 40000, 443);
	ASSERT_OK(ngp_send(c, "d_ep", f, len));

	n = ngp_recv(c, hook, sizeof(hook), out, sizeof(out), 500);
	ASSERT_EQ(n, (int)len);
	ASSERT_EQ(strcmp(hook, "d_fab"), 0);
	ASSERT_EQ(memcmp(f, out, len), 0);

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.packets_total, 1);
	ASSERT_EQ(st.bytes_total, len);
	ASSERT_EQ(st.allowed_packets, 1);
	ASSERT_EQ(st.dropped_packets, 0);
	return (0);
}

/* And the reverse direction, which is how Mode A destination resolution works. */
static int
test_forward_fab_to_ep(struct ngp_ctx *c)
{
	uint8_t f[NGP_MAXFRAME], out[NGP_MAXFRAME];
	char hook[NG_HOOKSIZ];
	size_t len;
	int n;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_OK(ngp_set_mode(c, NG_POLICY_MODE_DISABLED));

	len = ngp_tcp(f, 0x0a320210, 0x0a320110, 443, 40000);
	ASSERT_OK(ngp_send(c, "d_fab", f, len));
	n = ngp_recv(c, hook, sizeof(hook), out, sizeof(out), 500);
	ASSERT_EQ(n, (int)len);
	ASSERT_EQ(strcmp(hook, "d_ep"), 0);
	return (0);
}

/* A hook nobody claimed drops, in every mode, and is counted separately. */
static int
test_unbound_hook_drops(struct ngp_ctx *c)
{
	uint8_t f[NGP_MAXFRAME], out[NGP_MAXFRAME];
	struct ng_policy_stats st;
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_x", "orphan"));
	ASSERT_OK(ngp_set_mode(c, NG_POLICY_MODE_DISABLED));
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	ASSERT_OK(ngp_send(c, "d_x", f, len));
	ASSERT_EQ(ngp_recv(c, NULL, 0, out, sizeof(out), 200), 0);
	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.unbound_hook_packets, 1);
	return (0);
}

/* A bound endpoint whose partner hook is absent has nowhere to forward. */
static int
test_no_peer_drops(struct ngp_ctx *c)
{
	uint8_t f[NGP_MAXFRAME], out[NGP_MAXFRAME];
	struct ng_policy_stats st;
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_OK(ngp_set_mode(c, NG_POLICY_MODE_DISABLED));
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	ASSERT_OK(ngp_send(c, "d_ep", f, len));
	ASSERT_EQ(ngp_recv(c, NULL, 0, out, sizeof(out), 200), 0);
	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.no_peer_packets, 1);
	return (0);
}

/* Per-endpoint rx counts arrivals; tx counts what was actually forwarded. */
static int
test_endpoint_counters(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_ep_list_resp r;
		struct ng_policy_endpoint_info e[1];
	} out;
	struct ng_policy_ep_query q;
	uint8_t f[NGP_MAXFRAME], buf[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_OK(ngp_set_mode(c, NG_POLICY_MODE_DISABLED));

	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	ASSERT_OK(ngp_send(c, "d_ep", f, len));		/* rx only */
	ASSERT_EQ(ngp_recv(c, NULL, 0, buf, sizeof(buf), 500), (int)len);
	ASSERT_OK(ngp_send(c, "d_fab", f, len));	/* tx */
	ASSERT_EQ(ngp_recv(c, NULL, 0, buf, sizeof(buf), 500), (int)len);
	ASSERT_OK(ngp_send(c, "d_fab", f, len));	/* tx */
	ASSERT_EQ(ngp_recv(c, NULL, 0, buf, sizeof(buf), 500), (int)len);

	memset(&q, 0, sizeof(q));
	q.endpoint_id = 1001;
	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_ENDPOINT_STATS, &q,
	    sizeof(q), &out, sizeof(out)));
	ASSERT_EQ(out.r.returned, 1);
	ASSERT_EQ(out.e[0].rx_packets, 1);
	ASSERT_EQ(out.e[0].rx_bytes, len);
	ASSERT_EQ(out.e[0].tx_packets, 2);
	ASSERT_EQ(out.e[0].tx_bytes, 2 * len);
	return (0);
}

static int
test_config_roundtrip(struct ngp_ctx *c)
{
	struct ng_policy_config cfg, got;

	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_CONFIG, NULL, 0, &got,
	    sizeof(got)));
	/* Secure defaults, with ARP allowed so reachability is not broken. */
	ASSERT_EQ(got.mode, NG_POLICY_MODE_ENFORCE);
	ASSERT_EQ(got.arp_action, NG_POLICY_ALLOW);
	ASSERT_EQ(got.frag_action, NG_POLICY_DROP);
	ASSERT_EQ(got.unsupported_action, NG_POLICY_DROP);
	ASSERT_EQ(got.malformed_action, NG_POLICY_DROP);

	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = NG_POLICY_MODE_PERMISSIVE;
	cfg.arp_action = NG_POLICY_DROP;
	cfg.frag_action = NG_POLICY_ALLOW;
	cfg.unsupported_action = NG_POLICY_ALLOW;
	cfg.malformed_action = NG_POLICY_DROP;
	ASSERT_OK(ngp_msg(c, NGM_POLICY_SET_CONFIG, &cfg, sizeof(cfg)));
	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_CONFIG, NULL, 0, &got,
	    sizeof(got)));
	ASSERT_EQ(got.mode, NG_POLICY_MODE_PERMISSIVE);
	ASSERT_EQ(got.frag_action, NG_POLICY_ALLOW);

	/* Invalid enum values must be refused, not clamped. */
	cfg.arp_action = 99;
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_SET_CONFIG, &cfg, sizeof(cfg)),
	    EINVAL);
	cfg.arp_action = NG_POLICY_ALLOW;
	cfg.mode = 7;
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_SET_CONFIG, &cfg, sizeof(cfg)),
	    EINVAL);
	return (0);
}

static int
test_reset_stats(struct ngp_ctx *c)
{
	struct ng_policy_reset_req rr;
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME], buf[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_OK(ngp_set_mode(c, NG_POLICY_MODE_DISABLED));
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	ASSERT_OK(ngp_send(c, "d_ep", f, len));
	ASSERT_EQ(ngp_recv(c, NULL, 0, buf, sizeof(buf), 500), (int)len);

	memset(&rr, 0, sizeof(rr));
	ASSERT_OK(ngp_msg(c, NGM_POLICY_RESET_STATS, &rr, sizeof(rr)));
	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.packets_total, 0);
	ASSERT_EQ(st.allowed_packets, 0);
	return (0);
}

/* Rejecting a truncated payload is the cheapest defence against a hostile
   controller, so assert it explicitly rather than trusting the dispatcher. */
static int
test_short_message_rejected(struct ngp_ctx *c)
{
	struct ng_policy_endpoint_add a;

	memset(&a, 0, sizeof(a));
	a.endpoint_id = 1001;
	strlcpy(a.hook, "ep-1001", sizeof(a.hook));
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_ENDPOINT_ADD, &a, sizeof(a) - 4),
	    EINVAL);
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_SET_MODE, &a, 1), EINVAL);
	return (0);
}

/* Each category must be independently steerable, so drive them one at a time. */
static int
ngp_cfg_actions(struct ngp_ctx *c, uint8_t arp, uint8_t frag, uint8_t unsup,
    uint8_t malformed)
{
	struct ng_policy_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = NG_POLICY_MODE_ENFORCE;
	cfg.arp_action = arp;
	cfg.frag_action = frag;
	cfg.unsupported_action = unsup;
	cfg.malformed_action = malformed;
	return (ngp_msg(c, NGM_POLICY_SET_CONFIG, &cfg, sizeof(cfg)));
}

/* Returns 1 if the frame was forwarded, 0 if it was dropped. */
static int
ngp_passes(struct ngp_ctx *c, const uint8_t *f, size_t len)
{
	uint8_t out[NGP_MAXFRAME];

	/*
	 * A frame this function itself forwarded on a previous call, but
	 * whose arrival fell outside that call's own recv window, would
	 * otherwise sit on the data socket and be picked up by THIS call
	 * instead -- read as a pass for a frame that was never sent this
	 * time. Drain any such leftover before sending.
	 */
	ngp_drain(c);
	if (ngp_send(c, "d_ep", f, len) < 0)
		return (-1);
	return (ngp_recv(c, NULL, 0, out, sizeof(out), 300) > 0);
}

static int
ngp_wire(struct ngp_ctx *c)
{

	if (ngp_hook(c, "d_ep", "ep-1001") < 0 ||
	    ngp_hook(c, "d_fab", "fab-1001") < 0 ||
	    ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0) < 0)
		return (-1);
	/*
	 * Generation 0 is fail-closed, and these parser tests all assume
	 * the OK path is permissive, so install an empty generation with
	 * default ALLOW.
	 */
	return (ngp_install(c, NULL, 0, NULL, 0, NG_POLICY_ALLOW));
}

static int
test_arp_action(struct ngp_ctx *c)
{
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_wire(c));
	len = ngp_arp(f);

	ASSERT_OK(ngp_cfg_actions(c, NG_POLICY_ALLOW, NG_POLICY_DROP,
	    NG_POLICY_DROP, NG_POLICY_DROP));
	ASSERT_EQ(ngp_passes(c, f, len), 1);

	ASSERT_OK(ngp_cfg_actions(c, NG_POLICY_DROP, NG_POLICY_DROP,
	    NG_POLICY_DROP, NG_POLICY_DROP));
	ASSERT_EQ(ngp_passes(c, f, len), 0);

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.arp_packets, 2);
	return (0);
}

/* VLAN is unsupported in v0.1 and must take the unsupported action, not
   silently bypass policy. */
static int
test_unsupported_ethertype(struct ngp_ctx *c)
{
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_wire(c));
	len = ngp_eth(f, 0x8100);	/* 802.1Q */
	memset(f + len, 0, 32);
	len += 32;

	ASSERT_OK(ngp_cfg_actions(c, NG_POLICY_ALLOW, NG_POLICY_DROP,
	    NG_POLICY_DROP, NG_POLICY_DROP));
	ASSERT_EQ(ngp_passes(c, f, len), 0);
	ASSERT_OK(ngp_cfg_actions(c, NG_POLICY_ALLOW, NG_POLICY_DROP,
	    NG_POLICY_ALLOW, NG_POLICY_DROP));
	ASSERT_EQ(ngp_passes(c, f, len), 1);

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.unsupported_packets, 2);
	return (0);
}

/*
 * Every one of these has bitten a real parser.  The node must never read
 * past the mbuf, and must count them as malformed rather than as
 * anything else.
 */
static int
test_malformed_packets(struct ngp_ctx *c)
{
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;
	struct ip *ip;

	ASSERT_OK(ngp_wire(c));
	ASSERT_OK(ngp_cfg_actions(c, NG_POLICY_ALLOW, NG_POLICY_DROP,
	    NG_POLICY_DROP, NG_POLICY_DROP));

	/* 1. truncated Ethernet header */
	len = ngp_eth(f, ETHERTYPE_IP);
	ASSERT_EQ(ngp_passes(c, f, 8), 0);

	/* 2. Ethernet header only, no IPv4 header at all */
	ASSERT_EQ(ngp_passes(c, f, len), 0);

	/* 3. IHL below the minimum */
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	ip = (struct ip *)(f + ETHER_HDR_LEN);
	ip->ip_hl = 3;
	ASSERT_EQ(ngp_passes(c, f, len), 0);

	/* 4. version is not 4 */
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	ip->ip_v = 6;
	ASSERT_EQ(ngp_passes(c, f, len), 0);

	/* 5. ip_len smaller than the header it claims */
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	ip->ip_len = htons(10);
	ASSERT_EQ(ngp_passes(c, f, len), 0);

	/* 6. transport header cut off past the end of the frame */
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	ASSERT_EQ(ngp_passes(c, f, ETHER_HDR_LEN + sizeof(struct ip) + 2), 0);

	/* 7. UDP length field below the minimum */
	len = ngp_udp(f, 0x0a320110, 0x0a320210, 1, 2);
	((struct udphdr *)(f + ETHER_HDR_LEN + sizeof(struct ip)))->uh_ulen =
	    htons(4);
	ASSERT_EQ(ngp_passes(c, f, len), 0);

	/* 8. IHL claims more header than the frame actually carries.
	   ip_len is raised to match hlen so the ip_len < hlen check does
	   not fire first: this exercises the off + hlen > m_pkthdr.len
	   check specifically (74 > 54). */
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	ip->ip_hl = 15;
	ip->ip_len = htons(60);
	ASSERT_EQ(ngp_passes(c, f, len), 0);

	/* 9. UDP length field claims more than the IP payload holds. */
	len = ngp_udp(f, 0x0a320110, 0x0a320210, 1, 2);
	((struct udphdr *)(f + ETHER_HDR_LEN + sizeof(struct ip)))->uh_ulen =
	    htons(9000);
	ASSERT_EQ(ngp_passes(c, f, len), 0);

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.malformed_packets, 9);
	return (0);
}

static int
test_fragment_action(struct ngp_ctx *c)
{
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_wire(c));

	/* Non-initial fragment: no transport header exists, so the
	   fragment action decides and rule matching never runs. */
	len = ngp_frag(f, 0x0a320110, 0x0a320210, 1480, 0);
	ASSERT_OK(ngp_cfg_actions(c, NG_POLICY_ALLOW, NG_POLICY_DROP,
	    NG_POLICY_DROP, NG_POLICY_DROP));
	ASSERT_EQ(ngp_passes(c, f, len), 0);
	ASSERT_OK(ngp_cfg_actions(c, NG_POLICY_ALLOW, NG_POLICY_ALLOW,
	    NG_POLICY_DROP, NG_POLICY_DROP));
	ASSERT_EQ(ngp_passes(c, f, len), 1);

	/* First fragment: transport header is present, so it parses and
	   matches normally, and default ALLOW lets it through even with
	   frag_action DROP. */
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 443);
	((struct ip *)(f + ETHER_HDR_LEN))->ip_off = htons(IP_MF);
	ASSERT_OK(ngp_cfg_actions(c, NG_POLICY_ALLOW, NG_POLICY_DROP,
	    NG_POLICY_DROP, NG_POLICY_DROP));
	ASSERT_EQ(ngp_passes(c, f, len), 1);

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.fragmented_packets, 3);
	return (0);
}

/*
 * An IPv4 protocol the module has no special knowledge of must reach
 * rule matching with zero ports, not be waved through as "unsupported".
 */
static int
test_unknown_ip_protocol_is_matched(struct ngp_ctx *c)
{
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_wire(c));
	ASSERT_OK(ngp_cfg_actions(c, NG_POLICY_ALLOW, NG_POLICY_DROP,
	    NG_POLICY_ALLOW, NG_POLICY_DROP));
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	((struct ip *)(f + ETHER_HDR_LEN))->ip_p = 47;	/* GRE */
	ASSERT_EQ(ngp_passes(c, f, len), 1);	/* default ALLOW */

	ASSERT_OK(ngp_get_stats(c, &st));
	/* Counted as a normal packet, not as unsupported. */
	ASSERT_EQ(st.unsupported_packets, 0);
	return (0);
}

/*
 * Every other test frame has ip_hl == 5, so the transport-header offset
 * never differs from the fixed 20-byte case.  Prove the parser actually
 * follows a non-default IHL by inserting 4 bytes of IP options and
 * checking the transport header is read 4 bytes further in, not at the
 * usual offset.
 */
static int
test_ip_options(struct ngp_ctx *c)
{
	uint8_t f[NGP_MAXFRAME];
	struct ip *ip;
	size_t len;

	ASSERT_OK(ngp_wire(c));
	ASSERT_OK(ngp_cfg_actions(c, NG_POLICY_ALLOW, NG_POLICY_DROP,
	    NG_POLICY_DROP, NG_POLICY_DROP));

	/* TCP behind a 4-byte options header: the transport header must be
	   read at ETHER_HDR_LEN + 24, not + 20, and the frame must still
	   be forwarded rather than treated as malformed padding. */
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	memmove(f + ETHER_HDR_LEN + 24, f + ETHER_HDR_LEN + 20,
	    len - (ETHER_HDR_LEN + 20));
	memset(f + ETHER_HDR_LEN + 20, 0x01, 4);	/* option padding */
	ip = (struct ip *)(f + ETHER_HDR_LEN);
	ip->ip_hl = 6;
	ip->ip_len = htons(ntohs(ip->ip_len) + 4);
	len += 4;
	ASSERT_EQ(ngp_passes(c, f, len), 1);

	/*
	 * UDP behind the same 4-byte options header, chosen so a shift
	 * bug -- one that forgot to add the option bytes to the offset,
	 * and so read the transport header 4 bytes too early -- would
	 * land uh_ulen on the real header's source port (1) instead of
	 * its length field (8).  1 is below the UDP minimum, so that
	 * wrong read would come back MALFORMED; only the correctly
	 * shifted read finds the real uh_ulen of 8 and forwards.  This
	 * makes the assertion depend on the shift being right, not just
	 * on the parse not crashing.
	 */
	len = ngp_udp(f, 0x0a320110, 0x0a320210, 1, 2);
	memmove(f + ETHER_HDR_LEN + 24, f + ETHER_HDR_LEN + 20,
	    len - (ETHER_HDR_LEN + 20));
	memset(f + ETHER_HDR_LEN + 20, 0x01, 4);
	ip = (struct ip *)(f + ETHER_HDR_LEN);
	ip->ip_hl = 6;
	ip->ip_len = htons(ntohs(ip->ip_len) + 4);
	len += 4;
	ASSERT_EQ(ngp_passes(c, f, len), 1);

	return (0);
}

/*
 * Every other test sends a single-mbuf frame over a socket, so m_len is
 * always >= off + len and ngp_at()'s m_copydata fallback never runs.
 * net.graph.policy.debug_force_copy forces that path unconditionally;
 * drive one forwarded and one malformed shape through it and confirm the
 * verdict matches the zero-copy path.  The sysctl is restored on every
 * exit path, including assertion failure, so a failure here cannot leave
 * the rest of the suite running the forced-copy path by accident.
 */
static int
test_debug_force_copy_path(struct ngp_ctx *c)
{
	const char *oid = "net.graph.policy.debug_force_copy";
	u_int old, want = 1;
	size_t oldlen = sizeof(old);
	uint8_t f[NGP_MAXFRAME];
	struct ip *ip;
	size_t len;
	int r1 = -1, r2 = -1, rc = 0;

	if (sysctlbyname(oid, &old, &oldlen, NULL, 0) < 0) {
		printf("    FAIL %s:%d: sysctlbyname get: %s\n", __FILE__,
		    __LINE__, strerror(errno));
		return (1);
	}
	if (sysctlbyname(oid, NULL, 0, &want, sizeof(want)) < 0) {
		printf("    FAIL %s:%d: sysctlbyname set: %s\n", __FILE__,
		    __LINE__, strerror(errno));
		return (1);
	}

	if (ngp_wire(c) < 0 || ngp_cfg_actions(c, NG_POLICY_ALLOW,
	    NG_POLICY_DROP, NG_POLICY_DROP, NG_POLICY_DROP) < 0) {
		printf("    FAIL %s:%d: setup\n", __FILE__, __LINE__);
		rc = 1;
		goto restore;
	}

	/* Must still be forwarded through the copy path. */
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	r1 = ngp_passes(c, f, len);

	/* Must still come back MALFORMED through the copy path. */
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2);
	ip = (struct ip *)(f + ETHER_HDR_LEN);
	ip->ip_hl = 15;
	ip->ip_len = htons(60);
	r2 = ngp_passes(c, f, len);

	if (r1 != 1) {
		printf("    FAIL %s:%d: forced-copy TCP frame not forwarded "
		    "(%d)\n", __FILE__, __LINE__, r1);
		rc = 1;
	}
	if (r2 != 0) {
		printf("    FAIL %s:%d: forced-copy oversized-IHL frame not "
		    "malformed (%d)\n", __FILE__, __LINE__, r2);
		rc = 1;
	}

restore:
	if (sysctlbyname(oid, NULL, 0, &old, sizeof(old)) < 0) {
		printf("    FAIL %s:%d: sysctlbyname restore: %s\n", __FILE__,
		    __LINE__, strerror(errno));
		rc = 1;
	}
	return (rc);
}

/* A node with no policy at all must fail closed. */
static int
test_fresh_node_fails_closed(struct ngp_ctx *c)
{
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.generation, 0);

	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 443);
	ASSERT_EQ(ngp_passes(c, f, len), 0);
	return (0);
}

static int
test_default_action_and_generation(struct ngp_ctx *c)
{
	struct ng_policy_tx_begin_resp b;
	struct ng_policy_tx_commit_resp r;
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_wire(c));	/* installs generation 1, default ALLOW */
	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.generation, 1);
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 443);
	ASSERT_EQ(ngp_passes(c, f, len), 1);

	ASSERT_OK(ngp_begin(c, &b, 0));
	ASSERT_EQ(b.generation, 2);
	ASSERT_EQ(b.active_generation, 1);
	ASSERT_OK(ngp_setdef(c, b.tx_id, NG_POLICY_DROP));
	/* Nothing changes until commit. */
	ASSERT_EQ(ngp_passes(c, f, len), 1);
	ASSERT_OK(ngp_commit(c, b.tx_id, 1, &r));
	ASSERT_EQ(r.generation, 2);
	ASSERT_EQ(ngp_passes(c, f, len), 0);

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.generation, 2);
	ASSERT_EQ(st.commits, 2);
	return (0);
}

/* Optimistic concurrency: a controller working from a stale view loses. */
static int
test_stale_generation_rejected(struct ngp_ctx *c)
{
	struct ng_policy_tx_begin_resp b1, b2, b3;
	struct ng_policy_tx_commit_resp r;

	ASSERT_OK(ngp_wire(c));		/* generation 1 */

	ASSERT_OK(ngp_begin(c, &b1, 0));
	ASSERT_OK(ngp_setdef(c, b1.tx_id, NG_POLICY_DROP));
	ASSERT_OK(ngp_begin(c, &b2, 0));
	ASSERT_OK(ngp_setdef(c, b2.tx_id, NG_POLICY_ALLOW));

	/* First writer wins. */
	ASSERT_OK(ngp_commit(c, b1.tx_id, 1, &r));
	/* Second writer still believes the base is 1 and must be refused.
	   (This also trips monotonicity, since b2's generation (2) is no
	   longer greater than the new active generation (2) -- see b3
	   below for a case that isolates the base_generation check.) */
	ASSERT_ERRNO(ngp_commit(c, b2.tx_id, 1, &r), ESTALE);

	/* b3 is begun after b1's commit, so its generation (3) legitimately
	   clears monotonicity against the new active generation (2).
	   Committing it with a stale base=1 must still be refused, and
	   only the optimistic-concurrency (base_generation) check can be
	   responsible -- deleting that check would leave this green. */
	ASSERT_OK(ngp_begin(c, &b3, 0));
	ASSERT_EQ(b3.generation, 3);
	ASSERT_EQ(b3.active_generation, 2);
	ASSERT_OK(ngp_setdef(c, b3.tx_id, NG_POLICY_ALLOW));
	ASSERT_ERRNO(ngp_commit(c, b3.tx_id, 1, &r), ESTALE);
	return (0);
}

static int
test_transaction_abort(struct ngp_ctx *c)
{
	struct ng_policy_tx_begin_resp b;
	struct ng_policy_tx_id id;
	struct ng_policy_stats st;

	ASSERT_OK(ngp_wire(c));
	ASSERT_OK(ngp_begin(c, &b, 0));
	ASSERT_OK(ngp_setdef(c, b.tx_id, NG_POLICY_DROP));

	memset(&id, 0, sizeof(id));
	id.tx_id = b.tx_id;
	ASSERT_OK(ngp_msg(c, NGM_POLICY_TX_ABORT, &id, sizeof(id)));
	/* Aborting twice is ENOENT, not a silent success. */
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_TX_ABORT, &id, sizeof(id)), ENOENT);

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.generation, 1);	/* unchanged */
	ASSERT_EQ(st.aborts, 1);
	ASSERT_EQ(st.ntx, 0);
	return (0);
}

static int
test_transaction_timeout(struct ngp_ctx *c)
{
	struct ng_policy_tx_begin_resp b;
	struct ng_policy_tx_commit_resp r;
	struct ng_policy_stats st;

	ASSERT_OK(ngp_wire(c));
	ASSERT_OK(ngp_begin(c, &b, 1));		/* one-second deadline */
	ASSERT_OK(ngp_setdef(c, b.tx_id, NG_POLICY_DROP));
	sleep(4);				/* reaper runs every 2s */

	ASSERT_ERRNO(ngp_commit(c, b.tx_id, 1, &r), ENOENT);
	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.tx_timeouts, 1);
	ASSERT_EQ(st.ntx, 0);
	return (0);
}

/* Validation runs before anything is swapped: a bad rule fails the
   commit and leaves the active generation untouched. */
static int
test_commit_validation(struct ngp_ctx *c)
{
	struct ng_policy_tx_begin_resp b;
	struct ng_policy_tx_commit_resp r;
	struct ng_policy_tx_add_rule *ar;
	struct ng_policy_stats st;
	uint8_t buf[512];
	size_t len;

	ASSERT_OK(ngp_wire(c));
	ASSERT_OK(ngp_begin(c, &b, 0));

	ar = (void *)buf;
	len = sizeof(*ar) + 2 * sizeof(struct ng_policy_rule);
	memset(buf, 0, len);
	ar->tx_id = b.tx_id;
	ar->nrules = 2;
	ar->rules[0].rule_id = 1;
	ar->rules[0].action = NG_POLICY_ALLOW;
	ar->rules[0].dst_port_max = 65535;
	ar->rules[0].src_port_max = 65535;
	/* duplicate rule_id, and an inverted port range */
	ar->rules[1].rule_id = 1;
	ar->rules[1].action = NG_POLICY_ALLOW;
	ar->rules[1].dst_port_min = 500;
	ar->rules[1].dst_port_max = 100;
	ASSERT_OK(ngp_msg(c, NGM_POLICY_TX_ADD_RULE, ar, len));
	ASSERT_OK(ngp_setdef(c, b.tx_id, NG_POLICY_DROP));
	ASSERT_ERRNO(ngp_commit(c, b.tx_id, 1, &r), EINVAL);

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.generation, 1);
	ASSERT_EQ(st.failed_commits, 1);

	/* An unsupported action value must not be accepted either. */
	ASSERT_OK(ngp_begin(c, &b, 0));
	len = sizeof(*ar) + sizeof(struct ng_policy_rule);
	memset(buf, 0, len);
	ar->tx_id = b.tx_id;
	ar->nrules = 1;
	ar->rules[0].rule_id = 1;
	ar->rules[0].action = 3;		/* reserved for REJECT */
	ar->rules[0].src_port_max = 65535;
	ar->rules[0].dst_port_max = 65535;
	ASSERT_OK(ngp_msg(c, NGM_POLICY_TX_ADD_RULE, ar, len));
	ASSERT_OK(ngp_setdef(c, b.tx_id, NG_POLICY_DROP));
	ASSERT_ERRNO(ngp_commit(c, b.tx_id, 1, &r), EINVAL);
	return (0);
}

/* A generation must define its default action; inheriting silently
   would make a partially-built transaction look complete. */
static int
test_commit_requires_default(struct ngp_ctx *c)
{
	struct ng_policy_tx_begin_resp b;
	struct ng_policy_tx_commit_resp r;

	ASSERT_OK(ngp_wire(c));
	ASSERT_OK(ngp_begin(c, &b, 0));
	ASSERT_ERRNO(ngp_commit(c, b.tx_id, 1, &r), EINVAL);
	return (0);
}

static int
test_unknown_transaction(struct ngp_ctx *c)
{
	struct ng_policy_tx_commit_resp r;

	ASSERT_OK(ngp_wire(c));
	ASSERT_ERRNO(ngp_setdef(c, 999999, NG_POLICY_DROP), ENOENT);
	ASSERT_ERRNO(ngp_commit(c, 999999, 1, &r), ENOENT);
	return (0);
}

/*
 * A reserved field that has never been required to be zero can never
 * safely be given meaning later: the kernel has no way to tell an old
 * client's stack garbage from a new client's deliberate value. Every
 * NGM_POLICY_* reserved/flags field that carries no currently-defined
 * bits must reject a nonzero value with EINVAL. One case per field is
 * enough to lock the rule in for the whole ABI -- not an exhaustive
 * bit sweep of each field's width.
 */
static int
test_reserved_fields_rejected(struct ngp_ctx *c)
{
	struct ng_policy_endpoint_add ea;
	struct ng_policy_endpoint_del ed;
	struct ng_policy_ep_query q;
	struct ng_policy_tx_begin_resp b;
	struct ng_policy_tx_set_default sd;
	struct ng_policy_tx_commit_req creq;
	struct ng_policy_tx_commit_resp cresp;
	struct ng_policy_rule rule;
	struct ng_policy_addr addr;
	uint8_t abuf[sizeof(struct ng_policy_tx_add_rule) +
	    sizeof(struct ng_policy_rule)];
	uint8_t bbuf[sizeof(struct ng_policy_tx_add_addr) +
	    sizeof(struct ng_policy_addr)];
	struct ng_policy_tx_add_rule *ar = (void *)abuf;
	struct ng_policy_tx_add_addr *aa = (void *)bbuf;

	/* ENDPOINT_ADD.reserved */
	memset(&ea, 0, sizeof(ea));
	ea.endpoint_id = 1001;
	strlcpy(ea.hook, "ep-1001", sizeof(ea.hook));
	ea.reserved = 1;
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_ENDPOINT_ADD, &ea, sizeof(ea)),
	    EINVAL);

	/* ENDPOINT_DEL.flags -- no bit is defined for it either. */
	memset(&ed, 0, sizeof(ed));
	ed.endpoint_id = 1001;
	ed.flags = 1;
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_ENDPOINT_DEL, &ed, sizeof(ed)),
	    EINVAL);

	/* EP_QUERY.reserved, shared by ENDPOINT_LIST and GET_ENDPOINT_STATS. */
	memset(&q, 0, sizeof(q));
	q.reserved = 1;
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_ENDPOINT_LIST, &q, sizeof(q)),
	    EINVAL);
	q.reserved = 1;
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_GET_ENDPOINT_STATS, &q, sizeof(q)),
	    EINVAL);

	ASSERT_OK(ngp_begin(c, &b, 0));

	/* TX_SET_DEFAULT.reserved0/reserved1/reserved2, checked independently. */
	memset(&sd, 0, sizeof(sd));
	sd.tx_id = b.tx_id;
	sd.default_action = NG_POLICY_ALLOW;
	sd.reserved0 = 1;
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_TX_SET_DEFAULT, &sd, sizeof(sd)),
	    EINVAL);
	sd.reserved0 = 0;
	sd.reserved1 = 1;
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_TX_SET_DEFAULT, &sd, sizeof(sd)),
	    EINVAL);
	sd.reserved1 = 0;
	sd.reserved2 = 1;
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_TX_SET_DEFAULT, &sd, sizeof(sd)),
	    EINVAL);

	/* TX_ADD_RULE.reserved */
	memset(&rule, 0, sizeof(rule));
	rule.rule_id = 1;
	rule.action = NG_POLICY_ALLOW;
	rule.src_port_max = 65535;
	rule.dst_port_max = 65535;
	memset(ar, 0, sizeof(*ar));
	ar->tx_id = b.tx_id;
	ar->nrules = 1;
	ar->reserved = 1;
	memcpy(ar->rules, &rule, sizeof(rule));
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_TX_ADD_RULE, ar,
	    sizeof(*ar) + sizeof(rule)), EINVAL);

	/* TX_ADD_ADDR.reserved */
	memset(&addr, 0, sizeof(addr));
	addr.ipv4 = htonl(0x0a000001);
	addr.endpoint_id = NG_POLICY_EP_LOCAL_HOST;
	memset(aa, 0, sizeof(*aa));
	aa->tx_id = b.tx_id;
	aa->naddrs = 1;
	aa->reserved = 1;
	memcpy(aa->addrs, &addr, sizeof(addr));
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_TX_ADD_ADDR, aa,
	    sizeof(*aa) + sizeof(addr)), EINVAL);

	/* TX_COMMIT.reserved */
	memset(&creq, 0, sizeof(creq));
	creq.tx_id = b.tx_id;
	creq.base_generation = 0;
	creq.reserved = 1;
	ASSERT_ERRNO(ngp_msg_resp(c, NGM_POLICY_TX_COMMIT, &creq, sizeof(creq),
	    &cresp, sizeof(cresp)), EINVAL);

	return (0);
}

/*
 * Mode B: the destination endpoint comes from the address map.  With a
 * rule that only permits 1001 -> 2001, a packet to a mapped address
 * passes and the same packet to an unmapped address does not, because
 * an unmapped address resolves to EXTERNAL.
 */
static int
test_addr_map_resolves_destination(struct ngp_ctx *c)
{
	struct ng_policy_rule r[1];
	struct ng_policy_addr a[2];
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	r[0].rule_id = 1;
	r[0].src_endpoint = 1001;
	r[0].dst_endpoint = 2001;
	r[0].protocol = NG_POLICY_PROTO_TCP;
	r[0].action = NG_POLICY_ALLOW;
	r[0].src_port_max = 65535;
	r[0].dst_port_min = 443;
	r[0].dst_port_max = 443;

	memset(a, 0, sizeof(a));
	a[0].ipv4 = htonl(0x0a320210);	/* 10.50.2.16 -> 2001 */
	a[0].endpoint_id = 2001;
	a[1].ipv4 = htonl(0x0a320110);	/* 10.50.1.16 -> 1001 */
	a[1].endpoint_id = 1001;
	ASSERT_OK(ngp_install(c, r, 1, a, 2, NG_POLICY_DROP));

	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 40000, 443);
	ASSERT_EQ(ngp_passes(c, f, len), 1);

	/* Same rule, unmapped destination: resolves to EXTERNAL, no match. */
	len = ngp_tcp(f, 0x0a320110, 0x0a329999, 40000, 443);
	ASSERT_EQ(ngp_passes(c, f, len), 0);
	return (0);
}

/* Mode A: arriving on the fabric hook, the destination is the hook's
   endpoint and the source comes from the map. */
static int
test_addr_map_resolves_source(struct ngp_ctx *c)
{
	struct ng_policy_rule r[1];
	struct ng_policy_addr a[1];
	uint8_t f[NGP_MAXFRAME], out[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-2001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-2001"));
	ASSERT_OK(ngp_ep_add(c, 2001, "ep-2001", "fab-2001", 0));

	memset(r, 0, sizeof(r));
	r[0].rule_id = 1;
	r[0].src_endpoint = 1001;
	r[0].dst_endpoint = 2001;
	r[0].protocol = NG_POLICY_PROTO_TCP;
	r[0].action = NG_POLICY_ALLOW;
	r[0].src_port_max = 65535;
	r[0].dst_port_min = 443;
	r[0].dst_port_max = 443;

	memset(a, 0, sizeof(a));
	a[0].ipv4 = htonl(0x0a320110);
	a[0].endpoint_id = 1001;
	ASSERT_OK(ngp_install(c, r, 1, a, 1, NG_POLICY_DROP));

	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 40000, 443);
	ASSERT_OK(ngp_send(c, "d_fab", f, len));
	ASSERT_EQ(ngp_recv(c, NULL, 0, out, sizeof(out), 300) > 0, 1);
	return (0);
}

static int
test_addr_map_validation(struct ngp_ctx *c)
{
	struct ng_policy_addr a[2];

	ASSERT_OK(ngp_wire(c));

	/* 0.0.0.0 is the empty-slot marker and cannot be an entry. */
	memset(a, 0, sizeof(a));
	a[0].ipv4 = 0;
	a[0].endpoint_id = 2001;
	ASSERT_ERRNO(ngp_install(c, NULL, 0, a, 1, NG_POLICY_DROP), EINVAL);

	/* Duplicate addresses are ambiguous, so refuse them. */
	a[0].ipv4 = htonl(0x0a320210);
	a[0].endpoint_id = 2001;
	a[1].ipv4 = htonl(0x0a320210);
	a[1].endpoint_id = 3001;
	ASSERT_ERRNO(ngp_install(c, NULL, 0, a, 2, NG_POLICY_DROP), EINVAL);
	return (0);
}

/* Many entries, to exercise probing rather than the trivial case.
   The forwarding assertion is deferred to Task 7 (see above); this task
   verifies only that the address map itself is built and used, via
   st.naddrs and st.addr_hits. */
static int
test_addr_map_scale(struct ngp_ctx *c)
{
	struct ng_policy_addr *a;
	struct ng_policy_rule r[1];
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;
	uint32_t i, n = 200;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	a = calloc(n, sizeof(*a));
	ASSERT_EQ(a != NULL, 1);
	for (i = 0; i < n; i++) {
		a[i].ipv4 = htonl(0x0a000000 + i);
		a[i].endpoint_id = 2000 + i;
	}
	memset(r, 0, sizeof(r));
	r[0].rule_id = 1;
	r[0].src_endpoint = 1001;
	r[0].dst_endpoint = 2000 + n - 1;	/* the last one inserted */
	r[0].action = NG_POLICY_ALLOW;
	r[0].src_port_max = 65535;
	r[0].dst_port_max = 65535;

	ASSERT_OK(ngp_install(c, r, 1, a, n, NG_POLICY_DROP));
	free(a);

	len = ngp_tcp(f, 0x0a320110, 0x0a000000 + n - 1, 1, 2);
	ASSERT_EQ(ngp_passes(c, f, len), 1);

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.naddrs, n);
	ASSERT_EQ(st.addr_hits > 0, 1);
	return (0);
}

/* The exact matrix from the requirements. */
static int
test_policy_matrix(struct ngp_ctx *c)
{
	struct ng_policy_rule r[2];
	struct ng_policy_addr a[3];
	uint8_t f[NGP_MAXFRAME];

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	r[0].rule_id = 44;
	r[0].src_endpoint = 1001; r[0].dst_endpoint = 2001;
	r[0].protocol = NG_POLICY_PROTO_TCP;
	r[0].action = NG_POLICY_ALLOW;
	r[0].src_port_max = 65535;
	r[0].dst_port_min = 443; r[0].dst_port_max = 443;

	r[1].rule_id = 45;
	r[1].src_endpoint = 2001; r[1].dst_endpoint = 3001;
	r[1].protocol = NG_POLICY_PROTO_TCP;
	r[1].action = NG_POLICY_ALLOW;
	r[1].src_port_max = 65535;
	r[1].dst_port_min = 5432; r[1].dst_port_max = 5432;

	memset(a, 0, sizeof(a));
	a[0].ipv4 = htonl(0x0a320110); a[0].endpoint_id = 1001;
	a[1].ipv4 = htonl(0x0a320210); a[1].endpoint_id = 2001;
	a[2].ipv4 = htonl(0x0a320310); a[2].endpoint_id = 3001;
	ASSERT_OK(ngp_install(c, r, 2, a, 3, NG_POLICY_DROP));

	/* 1001 -> 2001 TCP/443 PASS */
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320210, 40000, 443)), 1);
	/* 1001 -> 2001 TCP/80 DROP */
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320210, 40000, 80)), 0);
	/* 1001 -> 3001 TCP/5432 DROP: the allow rule is for src 2001 */
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320310, 40000, 5432)), 0);
	return (0);
}

/* Lower numeric priority wins, and the winner is the one whose action
   is applied even when a later rule would allow. */
static int
test_rule_priority(struct ngp_ctx *c)
{
	struct ng_policy_rule r[2];
	uint8_t f[NGP_MAXFRAME];

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	/* Deliberately supplied in the wrong order: the sort must fix it. */
	r[0].rule_id = 2; r[0].priority = 1000;
	r[0].src_endpoint = 1001; r[0].action = NG_POLICY_ALLOW;
	r[0].src_port_max = 65535; r[0].dst_port_max = 65535;

	r[1].rule_id = 1; r[1].priority = 100;
	r[1].src_endpoint = 1001; r[1].action = NG_POLICY_DROP;
	r[1].src_port_max = 65535; r[1].dst_port_max = 65535;

	ASSERT_OK(ngp_install(c, r, 2, NULL, 0, NG_POLICY_ALLOW));
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2)), 0);
	return (0);
}

/*
 * Equal priority falls back to insertion order.  Needs at least seven
 * rules: FreeBSD libkern's qsort insertion-sorts inputs under seven
 * elements with a "cmp(...) > 0" swap predicate, which never swaps two
 * elements a comparator calls equal, so a two-rule tie cannot tell a
 * real position tiebreak from a comparator that always returns 0 for
 * equal priorities.  Eight rules forces the quicksort partition path,
 * which can reorder equal elements around a pivot if there is no
 * tiebreak.  Verify the order directly via GET_RULE_STATS rather than
 * through a single winning packet, so this actually inspects the
 * full sorted sequence rather than just its first element.
 */
static int
test_rule_priority_ties_by_order(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_rule_stats_resp r;
		struct ng_policy_rule_stat e[8];
	} out;
	struct ng_policy_rule_query q;
	struct ng_policy_rule r[8];
	int i;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	for (i = 0; i < 8; i++) {
		r[i].rule_id = i + 1;
		r[i].priority = 100;
		r[i].src_endpoint = 1001;
		r[i].action = NG_POLICY_ALLOW;
		r[i].src_port_max = 65535;
		r[i].dst_port_max = 65535;
	}
	ASSERT_OK(ngp_install(c, r, 8, NULL, 0, NG_POLICY_DROP));

	memset(&q, 0, sizeof(q));
	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_RULE_STATS, &q, sizeof(q),
	    &out, sizeof(out.r) + 8 * sizeof(out.e[0])));
	ASSERT_EQ(out.r.total, 8);
	ASSERT_EQ(out.r.returned, 8);
	for (i = 0; i < 8; i++)
		ASSERT_EQ(out.e[i].rule.rule_id, i + 1);
	return (0);
}

/*
 * The merge in ng_policy_match() walks the packet's source-endpoint
 * bucket and the ANY-source list together, always taking the smaller
 * global rule index next.  None of the tests above exercise the branch
 * that actually compares the two candidate indices: in every one of
 * them, either list is empty.  These three pin that comparison from
 * both directions, plus a same-bucket collision between two distinct
 * endpoints.
 */

/* Case A: the ANY rule sits at the lower (winning) priority, so the
   merge must prefer it over the endpoint-specific rule even though the
   specific rule's bucket is walked as well. */
static int
test_rule_merge_any_wins(struct ngp_ctx *c)
{
	struct ng_policy_rule r[3];
	uint8_t f[NGP_MAXFRAME];

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	r[0].rule_id = 1; r[0].priority = 10;
	r[0].action = NG_POLICY_DROP;			/* src ANY, dst ANY */
	r[0].src_port_max = 65535; r[0].dst_port_max = 65535;
	r[1].rule_id = 2; r[1].priority = 20;
	r[1].src_endpoint = 1001; r[1].action = NG_POLICY_ALLOW;
	r[1].src_port_max = 65535; r[1].dst_port_max = 65535;
	r[2].rule_id = 3; r[2].priority = 30;
	r[2].action = NG_POLICY_ALLOW;			/* src ANY, dst ANY */
	r[2].src_port_max = 65535; r[2].dst_port_max = 65535;

	ASSERT_OK(ngp_install(c, r, 3, NULL, 0, NG_POLICY_ALLOW));
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2)), 0);
	return (0);
}

/* Case B: the same shape with the first two priorities swapped, so the
   endpoint-specific rule now wins.  Case A alone would still pass a
   merge that always drained the ANY list first; this pins the
   comparison from the other side too. */
static int
test_rule_merge_specific_wins(struct ngp_ctx *c)
{
	struct ng_policy_rule r[3];
	uint8_t f[NGP_MAXFRAME];

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	r[0].rule_id = 1; r[0].priority = 10;
	r[0].src_endpoint = 1001; r[0].action = NG_POLICY_ALLOW;
	r[0].src_port_max = 65535; r[0].dst_port_max = 65535;
	r[1].rule_id = 2; r[1].priority = 20;
	r[1].action = NG_POLICY_DROP;			/* src ANY, dst ANY */
	r[1].src_port_max = 65535; r[1].dst_port_max = 65535;
	r[2].rule_id = 3; r[2].priority = 30;
	r[2].action = NG_POLICY_ALLOW;			/* src ANY, dst ANY */
	r[2].src_port_max = 65535; r[2].dst_port_max = 65535;

	ASSERT_OK(ngp_install(c, r, 3, NULL, 0, NG_POLICY_ALLOW));
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2)), 1);
	return (0);
}

/* With the default bucket count (mask 0xf), endpoints 1001 and 1017
   collide: 1001 & 15 == 1017 & 15 == 9.  The colliding rule belongs to
   a different endpoint and sits at a lower (winning) priority, so a
   packet from 1001 must skip it -- proving a bucket collision costs a
   comparison against src_endpoint, not a wrong match. */
static int
test_rule_merge_bucket_collision(struct ngp_ctx *c)
{
	struct ng_policy_rule r[2];
	uint8_t f[NGP_MAXFRAME];

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	r[0].rule_id = 1; r[0].priority = 10;
	r[0].src_endpoint = 1017; r[0].action = NG_POLICY_DROP;
	r[0].src_port_max = 65535; r[0].dst_port_max = 65535;
	r[1].rule_id = 2; r[1].priority = 20;
	r[1].src_endpoint = 1001; r[1].action = NG_POLICY_ALLOW;
	r[1].src_port_max = 65535; r[1].dst_port_max = 65535;

	ASSERT_OK(ngp_install(c, r, 2, NULL, 0, NG_POLICY_DROP));
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2)), 1);
	return (0);
}

static int
test_wildcards(struct ngp_ctx *c)
{
	struct ng_policy_rule r[1];
	uint8_t f[NGP_MAXFRAME];

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	/* Everything wildcarded: src ANY, dst ANY, proto ANY, ports ANY. */
	memset(r, 0, sizeof(r));
	r[0].rule_id = 1;
	r[0].action = NG_POLICY_ALLOW;
	r[0].src_port_max = 65535;
	r[0].dst_port_max = 65535;
	ASSERT_OK(ngp_install(c, r, 1, NULL, 0, NG_POLICY_DROP));

	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2)), 1);
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_udp(f, 0x0a320110, 0x0a320210, 1, 2)), 1);
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_icmp(f, 0x0a320110, 0x0a320210, 8, 0)), 1);
	return (0);
}

static int
test_udp_rules(struct ngp_ctx *c)
{
	struct ng_policy_rule r[1];
	uint8_t f[NGP_MAXFRAME];

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	r[0].rule_id = 1;
	r[0].src_endpoint = 1001;
	r[0].protocol = NG_POLICY_PROTO_UDP;
	r[0].action = NG_POLICY_ALLOW;
	r[0].src_port_max = 65535;
	r[0].dst_port_min = 53; r[0].dst_port_max = 53;
	ASSERT_OK(ngp_install(c, r, 1, NULL, 0, NG_POLICY_DROP));

	ASSERT_EQ(ngp_passes(c, f,
	    ngp_udp(f, 0x0a320110, 0x0a320210, 40000, 53)), 1);
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_udp(f, 0x0a320110, 0x0a320210, 40000, 54)), 0);
	/* Same ports, wrong protocol. */
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320210, 40000, 53)), 0);
	return (0);
}

static int
test_icmp_type_code_rules(struct ngp_ctx *c)
{
	struct ng_policy_rule r[1];
	uint8_t f[NGP_MAXFRAME];

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	/* Allow echo request only. */
	memset(r, 0, sizeof(r));
	r[0].rule_id = 1;
	r[0].src_endpoint = 1001;
	r[0].protocol = NG_POLICY_PROTO_ICMP;
	r[0].action = NG_POLICY_ALLOW;
	r[0].src_port_max = 65535; r[0].dst_port_max = 65535;
	r[0].flags = NG_POLICY_RULE_F_ICMP_TYPE | NG_POLICY_RULE_F_ICMP_CODE;
	r[0].icmp_type = 8; r[0].icmp_code = 0;
	ASSERT_OK(ngp_install(c, r, 1, NULL, 0, NG_POLICY_DROP));

	ASSERT_EQ(ngp_passes(c, f,
	    ngp_icmp(f, 0x0a320110, 0x0a320210, 8, 0)), 1);
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_icmp(f, 0x0a320110, 0x0a320210, 0, 0)), 0);	/* echo reply */
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_icmp(f, 0x0a320110, 0x0a320210, 8, 1)), 0);	/* wrong code */
	return (0);
}

static int
test_rule_counters(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_rule_stats_resp r;
		struct ng_policy_rule_stat e[4];
	} out;
	struct ng_policy_rule_query q;
	struct ng_policy_rule r[2];
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	r[0].rule_id = 100; r[0].priority = 10;
	r[0].src_endpoint = 1001; r[0].protocol = NG_POLICY_PROTO_TCP;
	r[0].action = NG_POLICY_ALLOW;
	r[0].src_port_max = 65535;
	r[0].dst_port_min = 443; r[0].dst_port_max = 443;
	r[1].rule_id = 200; r[1].priority = 20;
	r[1].src_endpoint = 1001; r[1].protocol = NG_POLICY_PROTO_TCP;
	r[1].action = NG_POLICY_DROP;
	r[1].src_port_max = 65535; r[1].dst_port_max = 65535;
	ASSERT_OK(ngp_install(c, r, 2, NULL, 0, NG_POLICY_DROP));

	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 443);
	ASSERT_EQ(ngp_passes(c, f, len), 1);
	ASSERT_EQ(ngp_passes(c, f, len), 1);
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 80)), 0);

	memset(&q, 0, sizeof(q));
	/*
	 * ngp_msg_resp() requires the response to be at least resplen
	 * bytes (it refuses to memcpy() past what the kernel actually
	 * sent): the response body holds exactly 2 rule_stat entries, so
	 * ask for exactly that, not the full 4-entry capacity of `out`.
	 */
	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_RULE_STATS, &q, sizeof(q),
	    &out, sizeof(out.r) + 2 * sizeof(out.e[0])));
	ASSERT_EQ(out.r.total, 2);
	ASSERT_EQ(out.r.returned, 2);
	/* Sorted by priority, so rule 100 is first. */
	ASSERT_EQ(out.e[0].rule.rule_id, 100);
	ASSERT_EQ(out.e[0].match_packets, 2);
	ASSERT_EQ(out.e[0].match_bytes, 2 * len);
	ASSERT_EQ(out.e[1].rule.rule_id, 200);
	ASSERT_EQ(out.e[1].match_packets, 1);

	/* Statistics are always tagged with the generation that produced them. */
	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(out.r.generation, st.generation);
	ASSERT_EQ(st.rule_matches, 3);
	return (0);
}

/* A new generation starts with fresh rule counters. */
static int
test_rule_counters_reset_per_generation(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_rule_stats_resp r;
		struct ng_policy_rule_stat e[2];
	} out;
	struct ng_policy_rule_query q;
	struct ng_policy_rule r[1];
	uint8_t f[NGP_MAXFRAME];

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	r[0].rule_id = 1;
	r[0].src_endpoint = 1001; r[0].action = NG_POLICY_ALLOW;
	r[0].src_port_max = 65535; r[0].dst_port_max = 65535;
	ASSERT_OK(ngp_install(c, r, 1, NULL, 0, NG_POLICY_DROP));
	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2)), 1);

	/* Re-install the identical policy as a new generation. */
	ASSERT_OK(ngp_install(c, r, 1, NULL, 0, NG_POLICY_DROP));
	memset(&q, 0, sizeof(q));
	/* One rule, one returned entry: see the sizing note above. */
	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_RULE_STATS, &q, sizeof(q),
	    &out, sizeof(out.r) + 1 * sizeof(out.e[0])));
	ASSERT_EQ(out.e[0].match_packets, 0);
	return (0);
}

#define	NGP_PAGE_RULE_N		20

/*
 * GET_RULE_STATS pagination across a real page boundary.  Same shape
 * as test_endpoint_list_pagination() above, but rules are matched by
 * (global index, rule_id) rather than an unordered id set, because
 * sorted order is itself a load-bearing part of the contract
 * (docs/policy-model.md): priority ascending, ties by insertion
 * order. Rules here are built with priority == insertion position, so
 * the sorted snapshot order is 0..N-1 by construction and rule_id ==
 * index + 1 predicts exactly which rule must appear at which global
 * index -- catching a paging bug that reorders or substitutes rules,
 * not merely one that drops or duplicates them.
 */
static int
test_rule_stats_pagination(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_rule_stats_resp r;
		struct ng_policy_rule_stat e[NGP_PAGE_SZ];
	} out;
	struct ng_policy_rule_query q;
	struct ng_policy_rule r[NGP_PAGE_RULE_N];
	int seen[NGP_PAGE_RULE_N];
	uint32_t i, start, iter, total_seen, remaining, want, n, j;

	memset(r, 0, sizeof(r));
	for (i = 0; i < NGP_PAGE_RULE_N; i++) {
		r[i].rule_id = i + 1;
		r[i].priority = (uint16_t)i;
		r[i].src_endpoint = NG_POLICY_EP_ANY;
		r[i].dst_endpoint = NG_POLICY_EP_ANY;
		r[i].protocol = NG_POLICY_PROTO_TCP;
		r[i].action = NG_POLICY_ALLOW;
		r[i].src_port_max = 65535;
		r[i].dst_port_max = 65535;
	}
	ASSERT_OK(ngp_install(c, r, NGP_PAGE_RULE_N, NULL, 0, NG_POLICY_DROP));

	memset(seen, 0, sizeof(seen));
	total_seen = 0;
	start = 0;
	for (iter = 0; iter < 10; iter++) {
		memset(&q, 0, sizeof(q));
		q.start_index = start;
		q.max_entries = NGP_PAGE_SZ;

		/*
		 * Unlike ENDPOINT_LIST, GET_RULE_STATS sizes its response
		 * to the *returned* count -- the exact remainder after
		 * start_index, clamped to the requested window -- so the
		 * expected size has to be computed the same way here or
		 * ngp_msg_resp() rejects it (EPROTO) on the short final
		 * page.  See docs/control-api.md and the comment above
		 * ng_policy_rule_stats().
		 */
		remaining = (start < NGP_PAGE_RULE_N) ?
		    NGP_PAGE_RULE_N - start : 0;
		want = (remaining < NGP_PAGE_SZ) ? remaining : NGP_PAGE_SZ;

		ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_RULE_STATS, &q,
		    sizeof(q), &out, sizeof(out.r) +
		    want * sizeof(out.e[0])));
		ASSERT_EQ(out.r.total, NGP_PAGE_RULE_N);
		ASSERT_EQ(out.r.returned, want);
		ASSERT_EQ(out.r.next_index, start + want);

		n = out.r.returned;
		if (n == 0)
			break;

		for (j = 0; j < n; j++) {
			uint32_t global_idx = start + j;

			/* The entry at this position must be exactly the
			   rule built for that position, not merely *some*
			   unseen rule -- this is what proves order, not
			   just membership. */
			ASSERT_EQ(out.e[j].index, global_idx);
			ASSERT_EQ(out.e[j].rule.rule_id, global_idx + 1);
			ASSERT_EQ(seen[global_idx], 0);
			seen[global_idx] = 1;
			total_seen++;
		}

		start = out.r.next_index;
		if (start >= out.r.total)
			break;
	}
	ASSERT_EQ(iter < 10, 1);
	ASSERT_EQ(total_seen, NGP_PAGE_RULE_N);
	for (i = 0; i < NGP_PAGE_RULE_N; i++)
		ASSERT_EQ(seen[i], 1);
	return (0);
}

/*
 * The byte-budget entry count for one GET_RULE_STATS page, computed
 * the same way ng_policy_rule_stats() computes it -- see the matching
 * comment on NGP_EP_ENTRY_BYTE_MAX above.
 */
#define	NGP_RULE_ENTRY_BYTE_MAX					\
	((NG_POLICY_RESP_BYTE_BUDGET - sizeof(struct ng_mesg) -	\
	sizeof(struct ng_policy_rule_stats_resp)) /			\
	sizeof(struct ng_policy_rule_stat))

#define	NGP_CEIL_RULE_N		400
#define	NGP_CEIL_RULE_CHUNK	200	/* well under ngp_install's 8KiB
					   staging buffer and the 637-rule
					   net.graph.maxdgram cap */

/*
 * Regression test for the final-review defect, rule-stats side:
 * GET_RULE_STATS's "as many as fit" default must enumerate every rule
 * when the rule count exceeds NGP_RULE_ENTRY_BYTE_MAX (364 at the
 * default budget), the same way test_endpoint_list_recvspace_ceiling()
 * proves it for ENDPOINT_LIST. NGP_CEIL_RULE_N (400) is installed in
 * two TX_ADD_RULE chunks because it does not fit ngp_install()'s
 * single-message staging buffer -- an orthogonal limit
 * (docs/control-api.md's `net.graph.maxdgram` ceiling) from the one
 * this test targets (the response-side `net.graph.recvspace`
 * ceiling).
 */
static int
test_rule_stats_recvspace_ceiling(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_rule_stats_resp r;
		struct ng_policy_rule_stat e[NGP_RULE_ENTRY_BYTE_MAX];
	} out;
	struct ng_policy_rule_query q;
	struct ng_policy_rule rules[NGP_CEIL_RULE_N];
	struct ng_policy_tx_begin_resp b;
	struct ng_policy_tx_commit_resp cr;
	struct ng_policy_stats st0;
	uint8_t abuf[sizeof(struct ng_policy_tx_add_rule) +
	    NGP_CEIL_RULE_CHUNK * sizeof(struct ng_policy_rule)];
	struct ng_policy_tx_add_rule *ar = (void *)abuf;
	int seen[NGP_CEIL_RULE_N];
	uint32_t i, start, iter, total_seen, remaining, want, n, j, pages, off;

	memset(rules, 0, sizeof(rules));
	for (i = 0; i < NGP_CEIL_RULE_N; i++) {
		rules[i].rule_id = i + 1;
		rules[i].priority = (uint16_t)i;
		rules[i].src_endpoint = NG_POLICY_EP_ANY;
		rules[i].dst_endpoint = NG_POLICY_EP_ANY;
		rules[i].protocol = NG_POLICY_PROTO_TCP;
		rules[i].action = NG_POLICY_ALLOW;
		rules[i].src_port_max = 65535;
		rules[i].dst_port_max = 65535;
	}

	ASSERT_OK(ngp_get_stats(c, &st0));
	ASSERT_OK(ngp_begin(c, &b, 0));
	for (off = 0; off < NGP_CEIL_RULE_N; off += NGP_CEIL_RULE_CHUNK) {
		uint32_t chunk = NGP_CEIL_RULE_N - off;
		size_t len;

		if (chunk > NGP_CEIL_RULE_CHUNK)
			chunk = NGP_CEIL_RULE_CHUNK;
		memset(ar, 0, sizeof(*ar));
		ar->tx_id = b.tx_id;
		ar->nrules = chunk;
		memcpy(ar->rules, &rules[off], chunk * sizeof(rules[0]));
		len = sizeof(*ar) + (size_t)chunk * sizeof(rules[0]);
		ASSERT_OK(ngp_msg(c, NGM_POLICY_TX_ADD_RULE, ar, len));
	}
	ASSERT_OK(ngp_setdef(c, b.tx_id, NG_POLICY_DROP));
	ASSERT_OK(ngp_commit(c, b.tx_id, st0.generation, &cr));
	ASSERT_EQ(cr.nrules, NGP_CEIL_RULE_N);

	memset(seen, 0, sizeof(seen));
	total_seen = 0;
	start = 0;
	pages = 0;
	for (iter = 0; iter < 10; iter++) {
		memset(&q, 0, sizeof(q));
		q.start_index = start;
		q.max_entries = 0;	/* "as many as fit" -- the documented default */

		/*
		 * Unlike ENDPOINT_LIST, GET_RULE_STATS sizes its response to
		 * the exact remainder after start_index, clamped to the
		 * byte-budget quota -- see the comment above
		 * test_rule_stats_pagination().
		 */
		remaining = (start < NGP_CEIL_RULE_N) ?
		    NGP_CEIL_RULE_N - start : 0;
		want = (remaining < NGP_RULE_ENTRY_BYTE_MAX) ? remaining :
		    NGP_RULE_ENTRY_BYTE_MAX;

		ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_RULE_STATS, &q,
		    sizeof(q), &out, sizeof(out.r) +
		    want * sizeof(out.e[0])));
		ASSERT_EQ(out.r.total, NGP_CEIL_RULE_N);
		ASSERT_EQ(out.r.returned, want);
		ASSERT_EQ(out.r.next_index, start + want);
		pages++;

		n = out.r.returned;
		if (n == 0)
			break;

		for (j = 0; j < n; j++) {
			uint32_t global_idx = start + j;

			ASSERT_EQ(out.e[j].index, global_idx);
			ASSERT_EQ(out.e[j].rule.rule_id, global_idx + 1);
			ASSERT_EQ(seen[global_idx], 0);
			seen[global_idx] = 1;
			total_seen++;
		}

		start = out.r.next_index;
		if (start >= out.r.total)
			break;
	}
	ASSERT_EQ(iter < 10, 1);
	ASSERT_EQ(total_seen, NGP_CEIL_RULE_N);
	for (i = 0; i < NGP_CEIL_RULE_N; i++)
		ASSERT_EQ(seen[i], 1);
	ASSERT_EQ(pages >= 2, 1);
	return (0);
}

/* Permissive: forwarded, violation counted, actual drop untouched. */
static int
test_permissive_semantics(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_ep_list_resp r;
		struct ng_policy_endpoint_info e[1];
	} out;
	struct ng_policy_ep_query q;
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_OK(ngp_install(c, NULL, 0, NULL, 0, NG_POLICY_DROP));
	ASSERT_OK(ngp_set_mode(c, NG_POLICY_MODE_PERMISSIVE));

	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 443);
	ASSERT_EQ(ngp_passes(c, f, len), 1);

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.permissive_violations, 1);
	ASSERT_EQ(st.dropped_packets, 0);
	ASSERT_EQ(st.allowed_packets, 1);

	memset(&q, 0, sizeof(q));
	q.endpoint_id = 1001;
	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_ENDPOINT_STATS, &q,
	    sizeof(q), &out, sizeof(out)));
	ASSERT_EQ(out.e[0].violations, 1);
	ASSERT_EQ(out.e[0].dropped_packets, 0);
	return (0);
}

/* Enforce: the same packet, dropped, with no violation recorded. */
static int
test_enforce_semantics(struct ngp_ctx *c)
{
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_OK(ngp_install(c, NULL, 0, NULL, 0, NG_POLICY_DROP));
	ASSERT_OK(ngp_set_mode(c, NG_POLICY_MODE_ENFORCE));

	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 443);
	ASSERT_EQ(ngp_passes(c, f, len), 0);
	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.dropped_packets, 1);
	ASSERT_EQ(st.dropped_bytes, len);
	ASSERT_EQ(st.permissive_violations, 0);
	return (0);
}

/* Disabled: no lookup at all, so a policy that would drop is bypassed
   and no rule counter moves. */
static int
test_disabled_bypasses_lookup(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_rule_stats_resp r;
		struct ng_policy_rule_stat e[2];
	} out;
	struct ng_policy_rule_query rq;
	struct ng_policy_rule r[1];
	uint8_t f[NGP_MAXFRAME];

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	r[0].rule_id = 1;
	r[0].src_endpoint = 1001; r[0].action = NG_POLICY_DROP;
	r[0].src_port_max = 65535; r[0].dst_port_max = 65535;
	ASSERT_OK(ngp_install(c, r, 1, NULL, 0, NG_POLICY_DROP));
	ASSERT_OK(ngp_set_mode(c, NG_POLICY_MODE_DISABLED));

	ASSERT_EQ(ngp_passes(c, f,
	    ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 2)), 1);

	memset(&rq, 0, sizeof(rq));
	/*
	 * Only 1 rule was installed, so the response body holds exactly 1
	 * rule_stat entry: as in test_rule_counters_reset_per_generation,
	 * ask ngp_msg_resp() for exactly that, not the full 2-entry capacity
	 * of `out` -- it refuses to memcpy() past what the kernel sent.
	 */
	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_RULE_STATS, &rq, sizeof(rq),
	    &out, sizeof(out.r) + 1 * sizeof(out.e[0])));
	ASSERT_EQ(out.e[0].match_packets, 0);
	return (0);
}

/* Permissive applies to parse categories too: "observe only" must mean
   observe only, not "observe only for rule decisions". */
static int
test_permissive_covers_parse_categories(struct ngp_ctx *c)
{
	struct ng_policy_stats st;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));
	ASSERT_OK(ngp_install(c, NULL, 0, NULL, 0, NG_POLICY_ALLOW));
	ASSERT_OK(ngp_cfg_actions(c, NG_POLICY_DROP, NG_POLICY_DROP,
	    NG_POLICY_DROP, NG_POLICY_DROP));
	ASSERT_OK(ngp_set_mode(c, NG_POLICY_MODE_PERMISSIVE));

	len = ngp_arp(f);
	ASSERT_EQ(ngp_passes(c, f, len), 1);
	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.permissive_violations, 1);
	ASSERT_EQ(st.dropped_packets, 0);
	return (0);
}

/*
 * Task 3's review noted that crediting allowed/dropped/violations to the
 * *ingress* endpoint (rather than to the packet's other endpoint) was
 * unobservable, because every earlier test registers a single endpoint.
 * Register two, drop a frame entering on endpoint 1001's workload hook,
 * and pin that the drop lands on endpoint 1001's counters while endpoint
 * 2002 -- wired up identically but never touched by this frame -- stays
 * at zero.
 */
static int
test_endpoint_credit_targets_ingress_endpoint(struct ngp_ctx *c)
{
	struct {
		struct ng_policy_ep_list_resp r;
		struct ng_policy_endpoint_info e[1];
	} out1, out2;
	struct ng_policy_ep_query q;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	ASSERT_OK(ngp_hook(c, "d_ep1", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab1", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	ASSERT_OK(ngp_hook(c, "d_ep2", "ep-2002"));
	ASSERT_OK(ngp_hook(c, "d_fab2", "fab-2002"));
	ASSERT_OK(ngp_ep_add(c, 2002, "ep-2002", "fab-2002", 0));

	/* Empty generation, default DROP: every packet is a drop. */
	ASSERT_OK(ngp_install(c, NULL, 0, NULL, 0, NG_POLICY_DROP));
	ASSERT_OK(ngp_set_mode(c, NG_POLICY_MODE_ENFORCE));

	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 1, 443);
	ASSERT_OK(ngp_send(c, "d_ep1", f, len));
	ASSERT_EQ(ngp_recv(c, NULL, 0, f, sizeof(f), 300), 0);

	memset(&q, 0, sizeof(q));
	q.endpoint_id = 1001;
	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_ENDPOINT_STATS, &q,
	    sizeof(q), &out1, sizeof(out1)));
	ASSERT_EQ(out1.e[0].dropped_packets, 1);
	ASSERT_EQ(out1.e[0].violations, 0);
	ASSERT_EQ(out1.e[0].allowed_packets, 0);

	memset(&q, 0, sizeof(q));
	q.endpoint_id = 2002;
	ASSERT_OK(ngp_msg_resp(c, NGM_POLICY_GET_ENDPOINT_STATS, &q,
	    sizeof(q), &out2, sizeof(out2)));
	ASSERT_EQ(out2.e[0].dropped_packets, 0);
	ASSERT_EQ(out2.e[0].violations, 0);
	ASSERT_EQ(out2.e[0].allowed_packets, 0);
	return (0);
}

static int
ngp_sysctl_u32(const char *name, uint32_t *out)
{
	size_t sz = sizeof(*out);

	return (sysctlbyname(name, out, &sz, NULL, 0));
}

static int
ngp_sysctl_set_u32(const char *name, uint32_t v)
{

	return (sysctlbyname(name, NULL, NULL, &v, sizeof(v)));
}

/* The three diagnostic counters are CTLTYPE_U64: reading them with the
   u32 helper above fails with ENOMEM rather than returning a truncated
   value, so a separate helper exists for them. */
static int
ngp_sysctl_u64(const char *name, uint64_t *out)
{
	size_t sz = sizeof(*out);

	return (sysctlbyname(name, out, &sz, NULL, 0));
}

/*
 * Each of the three limit-test bodies below runs under a sysctl that has
 * been temporarily lowered.  The body is factored out so the caller can
 * restore the sysctl unconditionally after it returns, rather than around
 * it: ASSERT_* returns immediately on the first failing assertion, so a
 * save/restore wrapped around the assertions themselves would leak the
 * lowered limit into every test that runs after a failure here.
 */

/* A limit that cannot be exceeded is the whole point of having one. */
static int
ngp_test_endpoint_limit_body(struct ngp_ctx *c)
{
	uint32_t i;
	char hook[NG_HOOKSIZ], peer[NG_HOOKSIZ];

	for (i = 0; i < 4; i++) {
		snprintf(hook, sizeof(hook), "ep-%u", 1000 + i);
		snprintf(peer, sizeof(peer), "fab-%u", 1000 + i);
		ASSERT_OK(ngp_ep_add(c, 1000 + i, hook, peer, 0));
	}
	ASSERT_ERRNO(ngp_ep_add(c, 2000, "ep-2000", "fab-2000", 0), ENOSPC);
	return (0);
}

static int
test_endpoint_limit(struct ngp_ctx *c)
{
	uint32_t saved;
	int rc;

	ASSERT_OK(ngp_sysctl_u32("net.graph.policy.max_endpoints", &saved));
	ASSERT_OK(ngp_sysctl_set_u32("net.graph.policy.max_endpoints", 4));

	rc = ngp_test_endpoint_limit_body(c);

	ASSERT_OK(ngp_sysctl_set_u32("net.graph.policy.max_endpoints", saved));
	return (rc);
}

static int
ngp_test_rule_limit_body(struct ngp_ctx *c)
{
	struct ng_policy_tx_begin_resp b;
	struct ng_policy_tx_add_rule *ar;
	uint8_t buf[1024];
	size_t len;

	ASSERT_OK(ngp_begin(c, &b, 0));
	ar = (void *)buf;
	len = sizeof(*ar) + 3 * sizeof(struct ng_policy_rule);
	memset(buf, 0, len);
	ar->tx_id = b.tx_id;
	ar->nrules = 3;
	ASSERT_ERRNO(ngp_msg(c, NGM_POLICY_TX_ADD_RULE, ar, len), ENOSPC);
	return (0);
}

static int
test_rule_limit(struct ngp_ctx *c)
{
	uint32_t saved;
	int rc;

	ASSERT_OK(ngp_sysctl_u32("net.graph.policy.max_rules", &saved));
	ASSERT_OK(ngp_sysctl_set_u32("net.graph.policy.max_rules", 2));

	rc = ngp_test_rule_limit_body(c);

	ASSERT_OK(ngp_sysctl_set_u32("net.graph.policy.max_rules", saved));
	return (rc);
}

static int
ngp_test_transaction_limit_body(struct ngp_ctx *c)
{
	struct ng_policy_tx_begin_resp b;

	ASSERT_OK(ngp_begin(c, &b, 0));
	ASSERT_OK(ngp_begin(c, &b, 0));
	ASSERT_ERRNO(ngp_begin(c, &b, 0), ENOSPC);
	return (0);
}

static int
test_transaction_limit(struct ngp_ctx *c)
{
	uint32_t saved;
	int rc;

	ASSERT_OK(ngp_sysctl_u32("net.graph.policy.max_tx", &saved));
	ASSERT_OK(ngp_sysctl_set_u32("net.graph.policy.max_tx", 2));

	rc = ngp_test_transaction_limit_body(c);

	ASSERT_OK(ngp_sysctl_set_u32("net.graph.policy.max_tx", saved));
	return (rc);
}

/* Memory accounting must move when policy is installed, and fall back
   when the generation is replaced with an empty one. */
static int
test_memory_accounting(struct ngp_ctx *c)
{
	struct ng_policy_rule *r;
	struct ng_policy_stats st0, st1, st2;
	uint32_t i, n = 500;

	ASSERT_OK(ngp_wire(c));
	ASSERT_OK(ngp_get_stats(c, &st0));

	r = calloc(n, sizeof(*r));
	ASSERT_EQ(r != NULL, 1);
	for (i = 0; i < n; i++) {
		r[i].rule_id = i + 1;
		r[i].src_endpoint = 1001;
		r[i].priority = (uint16_t)i;
		r[i].action = NG_POLICY_ALLOW;
		r[i].src_port_max = 65535;
		r[i].dst_port_max = 65535;
	}
	/* ngp_install has an 8 KiB staging buffer; send in two batches. */
	{
		struct ng_policy_tx_begin_resp b;
		struct ng_policy_tx_commit_resp cr;
		struct ng_policy_tx_add_rule *ar;
		uint8_t *buf;
		size_t len;
		uint32_t half = n / 2;

		buf = malloc(sizeof(*ar) + n * sizeof(*r));
		ASSERT_EQ(buf != NULL, 1);
		ar = (void *)buf;
		ASSERT_OK(ngp_begin(c, &b, 0));
		len = sizeof(*ar) + half * sizeof(*r);
		memset(ar, 0, sizeof(*ar));
		ar->tx_id = b.tx_id;
		ar->nrules = half;
		memcpy(ar->rules, r, half * sizeof(*r));
		ASSERT_OK(ngp_msg(c, NGM_POLICY_TX_ADD_RULE, ar, len));
		len = sizeof(*ar) + (n - half) * sizeof(*r);
		ar->nrules = n - half;
		memcpy(ar->rules, r + half, (n - half) * sizeof(*r));
		ASSERT_OK(ngp_msg(c, NGM_POLICY_TX_ADD_RULE, ar, len));
		ASSERT_OK(ngp_setdef(c, b.tx_id, NG_POLICY_DROP));
		ASSERT_OK(ngp_commit(c, b.tx_id, st0.generation, &cr));
		ASSERT_EQ(cr.nrules, n);
		ASSERT_EQ(cr.memory > 0, 1);
		free(buf);
	}
	free(r);

	ASSERT_OK(ngp_get_stats(c, &st1));
	ASSERT_EQ(st1.nrules, n);
	ASSERT_EQ(st1.policy_memory > st0.policy_memory, 1);

	/* An empty generation releases it again. */
	ASSERT_OK(ngp_install(c, NULL, 0, NULL, 0, NG_POLICY_DROP));
	ASSERT_OK(ngp_get_stats(c, &st2));
	ASSERT_EQ(st2.nrules, 0);
	ASSERT_EQ(st2.policy_memory < st1.policy_memory, 1);
	return (0);
}

/* Transaction memory is accounted while the transaction is open and
   released when it is aborted. */
static int
test_tx_memory_released_on_abort(struct ngp_ctx *c)
{
	struct ng_policy_tx_begin_resp b;
	struct ng_policy_tx_add_rule *ar;
	struct ng_policy_tx_id id;
	struct ng_policy_stats st;
	uint8_t buf[4096];
	size_t len;

	ASSERT_OK(ngp_wire(c));
	ASSERT_OK(ngp_begin(c, &b, 0));

	ar = (void *)buf;
	len = sizeof(*ar) + 32 * sizeof(struct ng_policy_rule);
	memset(buf, 0, len);
	ar->tx_id = b.tx_id;
	ar->nrules = 32;
	ASSERT_OK(ngp_msg(c, NGM_POLICY_TX_ADD_RULE, ar, len));

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.tx_memory > 0, 1);
	ASSERT_EQ(st.ntx, 1);

	memset(&id, 0, sizeof(id));
	id.tx_id = b.tx_id;
	ASSERT_OK(ngp_msg(c, NGM_POLICY_TX_ABORT, &id, sizeof(id)));
	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ(st.tx_memory, 0);
	return (0);
}

static int
test_diagnostic_sysctls(struct ngp_ctx *c)
{
	uint64_t nodes = 0;

	ASSERT_OK(ngp_wire(c));
	ASSERT_OK(ngp_sysctl_u64("net.graph.policy.nodes", &nodes));
	ASSERT_EQ(nodes >= 1, 1);
	return (0);
}

struct ngp_stress {
	struct ngp_ctx	*c;
	volatile int	stop;
	uint64_t	sent;
	/*
	 * At this test's unthrottled send rate, NgSendData() occasionally
	 * reports ENOBUFS from the sending socket's own buffer accounting
	 * even though the frame still reached the node and was counted in
	 * packets_total (confirmed empirically -- see the comment above
	 * the packets_total assertion in
	 * test_concurrent_policy_replacement()).  Tally those separately
	 * from any other send failure, which would be unexpected.
	 */
	uint64_t	sent_enobufs;
	uint64_t	sent_other_error;
};

/*
 * ASSERT_OK() and ASSERT_EQ() (ngp_harness.h) return straight out of
 * the calling test function on failure.  That is unsafe anywhere
 * between pthread_create() and pthread_join() of a stress sender: the
 * sender thread is still running against *sp -- a local of this stack
 * frame that is about to become stale once we return and the harness
 * moves on to ngp_teardown()/ngp_setup() for the next test case -- and
 * against c->ds, an fd number the next test's NgMkSockNode() may
 * immediately reuse.  A bare ASSERT_* firing mid-storm would therefore
 * leave a thread writing into a dead frame and reading/writing a
 * recycled socket while the rest of the suite runs.  ASSERT_STOP()
 * checks the same way but stops and joins the sender first, so a
 * failure detected mid-storm cannot corrupt whatever runs next.
 */
#define	ASSERT_STOP(cond, sp, thp) do {				\
	if (!(cond)) {							\
		printf("    FAIL %s:%d: %s\n", __FILE__, __LINE__,	\
		    #cond);						\
		(sp)->stop = 1;						\
		(void)pthread_join(*(thp), NULL);			\
		return (1);						\
	}								\
} while (0)

/*
 * ngp_install() and ngp_get_stats() run only on the control socket
 * (c->cs), driven only by the calling (main) thread; ngp_send() and
 * ngp_drain() here run only on the data socket (c->ds), driven only by
 * this sender thread.  That split is why the two threads can share one
 * struct ngp_ctx without any lock: each socket has exactly one thread
 * that ever touches it.  Do not "fix" this by adding a mutex and letting
 * both threads use both sockets.
 *
 * What this concurrent traffic can and cannot reach: ng_policy does not
 * mark TX_COMMIT NGM_READONLY, so Netgraph treats it as a writer item,
 * and a writer only runs against a completely idle node -- readers are
 * refused entry while one is pending or active (ng_base.c's queue-flags
 * handling around NGQF_WRITER/WRITER_ACTIVE).  That means no packet can
 * ever be inside ng_policy_rcvdata() while a commit's NGP_STORE_PTR()
 * executes, with one sender thread here or a hundred -- that specific
 * interleaving is structurally unreachable, not merely untested.  What
 * this sender genuinely exercises is commit/packet *sequencing* at
 * varied phase (a burst right before or right after a commit), and the
 * epoch-deferred reclamation of the *previous* snapshot, which runs
 * later via NET_EPOCH_CALL() with no node lock held and can genuinely
 * overlap live traffic on another CPU.  If a future change ever marks a
 * statistics-read message (GET_STATS, GET_RULE_STATS) NGM_READONLY so
 * it can run concurrently with other readers, those reads would become
 * genuine readers racing a commit's swap, and that epoch deferral is
 * exactly what would keep them safe -- do not remove it as redundant to
 * the writer-exclusivity argument above, which only covers
 * TX_COMMIT-vs-data-packets.
 */
static void *
ngp_stress_sender(void *arg)
{
	struct ngp_stress *s = arg;
	uint8_t f[NGP_MAXFRAME];
	size_t len;

	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 40000, 443);
	while (!s->stop) {
		if (ngp_send(s->c, "d_ep", f, len) == 0)
			s->sent++;
		else if (errno == ENOBUFS)
			s->sent_enobufs++;
		else
			s->sent_other_error++;
		ngp_drain(s->c);
	}
	return (NULL);
}

/*
 * Replace the policy continuously while packets flow.  A packet must
 * see either the old generation or the new one; it must never see a
 * half-built one, and the node must not panic or leak.
 */
static int
test_concurrent_policy_replacement(struct ngp_ctx *c)
{
	struct ng_policy_rule r[8];
	struct ng_policy_addr a[1];
	struct ng_policy_stats st;
	struct ngp_stress s;
	pthread_t th;
	uint32_t i, gen;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	memset(r, 0, sizeof(r));
	for (i = 0; i < nitems(r); i++) {
		r[i].rule_id = i + 1;
		r[i].priority = (uint16_t)(i * 10);
		r[i].src_endpoint = 1001;
		r[i].dst_endpoint = 2001;
		r[i].protocol = NG_POLICY_PROTO_TCP;
		r[i].action = NG_POLICY_ALLOW;
		r[i].src_port_max = 65535;
		r[i].dst_port_min = 443;
		r[i].dst_port_max = 443;
	}
	memset(a, 0, sizeof(a));
	a[0].ipv4 = htonl(0x0a320210);
	a[0].endpoint_id = 2001;
	ASSERT_OK(ngp_install(c, r, nitems(r), a, 1, NG_POLICY_DROP));

	memset(&s, 0, sizeof(s));
	s.c = c;
	ASSERT_EQ(pthread_create(&th, NULL, ngp_stress_sender, &s), 0);

	for (i = 0; i < 300; i++)
		ASSERT_STOP(ngp_install(c, r, nitems(r), a, 1,
		    (i & 1) ? NG_POLICY_DROP : NG_POLICY_ALLOW) == 0,
		    &s, &th);

	s.stop = 1;
	ASSERT_EQ(pthread_join(th, NULL), 0);

	ASSERT_OK(ngp_get_stats(c, &st));
	gen = (uint32_t)st.generation;
	ASSERT_EQ(gen >= 301, 1);
	ASSERT_EQ(s.sent > 0, 1);
	/*
	 * Any send failure other than ENOBUFS is unexpected -- catch it
	 * here before it could be misread as the tolerated case below.
	 */
	ASSERT_EQ(s.sent_other_error, 0);
	/*
	 * NgSendData() returning 0 means the frame was handed to the node
	 * synchronously, so naively one might expect packets_total to
	 * equal s.sent exactly at quiescence.  It does not, reliably: at
	 * this test's unthrottled send rate, NgSendData() occasionally
	 * reports ENOBUFS from the sending socket's own buffer accounting
	 * even though the frame still reached the node and was counted.
	 * Confirmed empirically -- instrumenting the sender to record
	 * errno on every failure, packets_total exceeded s.sent by
	 * exactly the ENOBUFS count on every occurrence, with no other
	 * errno ever seen and no case where sent alone matched.  So the
	 * exact identity is packets_total == sent + sent_enobufs, and
	 * this is still the check that actually fails if a packet were
	 * silently swallowed mid-swap: the balanced-sum identity a few
	 * lines down is weaker, since a packet missing from packets_total
	 * is also missing from the sum, so that identity alone stays
	 * balanced even if packets vanish.
	 */
	ASSERT_EQ(st.packets_total, s.sent + s.sent_enobufs);
	/*
	 * The node-wide invariant is actually packets_total == allowed +
	 * dropped + no_peer_packets: unbound-hook packets never reach
	 * packets_total at all, while no-peer drops are counted in it.
	 * The narrower form below holds here specifically because every
	 * frame in this test enters through "d_ep", which is bound to
	 * endpoint 1001 with a live partner hook ("d_fab") for the whole
	 * run, so no_peer_packets stays zero throughout.  A topology with
	 * an unbound partner would need the wider form.
	 */
	ASSERT_EQ(st.packets_total,
	    st.allowed_packets + st.dropped_packets);
	ASSERT_EQ(st.no_peer_packets, 0);
	return (0);
}

/*
 * Build the i'th generation's rule set and address map with a shape
 * that depends deterministically on i, so that consecutive commits vary
 * in size rather than just in default action: rule counts cycle 0..8
 * and the address map alternates between empty and populated (1..32
 * entries), so the swap under test frees differently sized snapshots
 * on each commit.
 */
#define	NGP_ADV_MAXRULES	8
#define	NGP_ADV_MAXADDRS	32

static void
ngp_stress_shape(uint32_t i, struct ng_policy_rule *r, uint32_t *nrules,
    struct ng_policy_addr *a, uint32_t *naddrs, uint8_t *defact)
{
	uint32_t nr, na, j;

	nr = i % (NGP_ADV_MAXRULES + 1);
	for (j = 0; j < nr; j++) {
		memset(&r[j], 0, sizeof(r[j]));
		r[j].rule_id = j + 1;
		r[j].priority = (uint16_t)(j * 10);
		r[j].src_endpoint = 1001;
		r[j].dst_endpoint = 2001;
		r[j].protocol = NG_POLICY_PROTO_TCP;
		r[j].action = ((i >> 2) & 1) ? NG_POLICY_DROP :
		    NG_POLICY_ALLOW;
		r[j].src_port_max = 65535;
		r[j].dst_port_min = 443;
		r[j].dst_port_max = 443;
	}
	*nrules = nr;

	if ((i / 3) % 2) {
		na = 1 + (i % NGP_ADV_MAXADDRS);
		for (j = 0; j < na; j++) {
			a[j].ipv4 = htonl(0x0a320210 + j);
			a[j].endpoint_id = 2001 + j;
		}
	} else
		na = 0;
	*naddrs = na;

	*defact = (i & 1) ? NG_POLICY_DROP : NG_POLICY_ALLOW;
}

/*
 * Vary the pacing of commits relative to the sender's tight send/drain
 * loop, so that the generation swap lands at different points in the
 * packet stream instead of a fixed cadence: two back-to-back commits,
 * then increasingly long pauses, repeating.  The sequence is a pure
 * function of the loop index, so the run is deterministic and
 * re-runnable even though the actual scheduling interleaving it
 * produces is not.
 */
static void
ngp_stress_pace(uint32_t i)
{
	static const useconds_t delays[] = { 0, 0, 50, 200, 1000, 3000 };

	if (delays[i % nitems(delays)] != 0)
		usleep(delays[i % nitems(delays)]);
}

/*
 * Task 10's review noted that the serial fuzzer never interleaves
 * TX_COMMIT with packet traffic at all.  This test makes that
 * interleaving adversarial: commits land at varying intervals against
 * a continuously running sender, and successive generations differ in
 * shape (rule count, and whether the address map is empty or
 * populated), so the snapshot epoch-reclaimed after each commit is a
 * different size every time.
 *
 * As the comment above ngp_stress_sender() explains, TX_COMMIT is a
 * writer message and so cannot actually execute while a packet is
 * inside ng_policy_rcvdata() -- that specific interleaving is
 * structurally unreachable, not just untested here.  What this test can
 * and does reach is commit/packet *sequencing* at varied phase, and
 * epoch-deferred reclamation of old snapshots overlapping live traffic
 * on other CPUs.  What must hold regardless of interleaving: every
 * packet is accounted for exactly once, the generation only ever
 * increases, and stats sampled mid-storm are never internally
 * impossible.
 */
static int
test_concurrent_policy_replacement_adversarial(struct ngp_ctx *c)
{
	struct ng_policy_rule r[NGP_ADV_MAXRULES];
	struct ng_policy_addr a[NGP_ADV_MAXADDRS];
	struct ng_policy_stats st;
	struct ngp_stress s;
	pthread_t th;
	uint32_t i, nrules, naddrs, gen0, last_gen;
	uint8_t defact;
	const uint32_t ncommits = 240;
	const uint32_t sample_every = 20;

	ASSERT_OK(ngp_hook(c, "d_ep", "ep-1001"));
	ASSERT_OK(ngp_hook(c, "d_fab", "fab-1001"));
	ASSERT_OK(ngp_ep_add(c, 1001, "ep-1001", "fab-1001", 0));

	ngp_stress_shape(0, r, &nrules, a, &naddrs, &defact);
	ASSERT_OK(ngp_install(c, r, nrules, a, naddrs, defact));
	ASSERT_OK(ngp_get_stats(c, &st));
	gen0 = (uint32_t)st.generation;
	last_gen = gen0;

	memset(&s, 0, sizeof(s));
	s.c = c;
	ASSERT_EQ(pthread_create(&th, NULL, ngp_stress_sender, &s), 0);

	for (i = 1; i <= ncommits; i++) {
		ngp_stress_shape(i, r, &nrules, a, &naddrs, &defact);
		ASSERT_STOP(ngp_install(c, r, nrules, a, naddrs, defact) == 0,
		    &s, &th);
		ngp_stress_pace(i);

		if (i % sample_every == 0) {
			uint32_t g;

			ASSERT_STOP(ngp_get_stats(c, &st) == 0, &s, &th);
			g = (uint32_t)st.generation;
			/* The generation must never regress. */
			ASSERT_STOP(g >= last_gen, &s, &th);
			last_gen = g;
			/*
			 * packets_total is incremented before the
			 * outcome-specific counter for the same packet,
			 * so a snapshot taken mid-storm may catch a
			 * packet counted in the total but not yet
			 * credited to allowed/dropped/no_peer -- total
			 * may lead the sum, but can never trail it.
			 */
			ASSERT_STOP(st.packets_total >= st.allowed_packets +
			    st.dropped_packets + st.no_peer_packets,
			    &s, &th);
		}
	}

	s.stop = 1;
	ASSERT_EQ(pthread_join(th, NULL), 0);

	ASSERT_OK(ngp_get_stats(c, &st));
	ASSERT_EQ((uint32_t)st.generation, gen0 + ncommits);
	ASSERT_EQ(s.sent > 0, 1);
	/* See the comment in test_concurrent_policy_replacement() about
	   why send failures other than ENOBUFS are unexpected, and why
	   this identity -- rather than packets_total == s.sent -- is the
	   one that actually fails on a swallowed packet, unlike the
	   balanced-sum check below it. */
	ASSERT_EQ(s.sent_other_error, 0);
	ASSERT_EQ(st.packets_total, s.sent + s.sent_enobufs);
	/* Quiescent now: the sum must match exactly. See the comment in
	   test_concurrent_policy_replacement() about why the narrow form
	   is valid for this endpoint topology. */
	ASSERT_EQ(st.packets_total,
	    st.allowed_packets + st.dropped_packets);
	ASSERT_EQ(st.no_peer_packets, 0);
	return (0);
}

const struct ngp_case ngp_cases[] = {
	{ "node_lifecycle",	test_node_lifecycle },
	{ "endpoint_add_and_list",	test_endpoint_add_and_list },
	{ "endpoint_list_pagination", test_endpoint_list_pagination },
	{ "endpoint_list_recvspace_ceiling",
	    test_endpoint_list_recvspace_ceiling },
	{ "endpoint_duplicate_rejected", test_endpoint_duplicate_rejected },
	{ "endpoint_reserved_id_rejected", test_endpoint_reserved_id_rejected },
	{ "endpoint_del",	test_endpoint_del },
	{ "endpoint_binds_either_order", test_endpoint_binds_either_order },
	{ "forward_ep_to_fab",	test_forward_ep_to_fab },
	{ "forward_fab_to_ep",	test_forward_fab_to_ep },
	{ "unbound_hook_drops",	test_unbound_hook_drops },
	{ "no_peer_drops",	test_no_peer_drops },
	{ "endpoint_counters",	test_endpoint_counters },
	{ "config_roundtrip",	test_config_roundtrip },
	{ "reset_stats",	test_reset_stats },
	{ "short_message_rejected", test_short_message_rejected },
	{ "arp_action",		test_arp_action },
	{ "unsupported_ethertype", test_unsupported_ethertype },
	{ "malformed_packets",	test_malformed_packets },
	{ "fragment_action",	test_fragment_action },
	{ "unknown_ip_protocol_is_matched", test_unknown_ip_protocol_is_matched },
	{ "ip_options",		test_ip_options },
	{ "debug_force_copy_path", test_debug_force_copy_path },
	{ "fresh_node_fails_closed", test_fresh_node_fails_closed },
	{ "default_action_and_generation", test_default_action_and_generation },
	{ "stale_generation_rejected", test_stale_generation_rejected },
	{ "transaction_abort",	test_transaction_abort },
	{ "transaction_timeout", test_transaction_timeout },
	{ "commit_validation",	test_commit_validation },
	{ "commit_requires_default", test_commit_requires_default },
	{ "unknown_transaction", test_unknown_transaction },
	{ "reserved_fields_rejected", test_reserved_fields_rejected },
	{ "addr_map_validation", test_addr_map_validation },
	{ "addr_map_scale",	test_addr_map_scale },
	{ "addr_map_resolves_destination", test_addr_map_resolves_destination },
	{ "addr_map_resolves_source", test_addr_map_resolves_source },
	{ "policy_matrix",	test_policy_matrix },
	{ "rule_priority",	test_rule_priority },
	{ "rule_priority_ties_by_order", test_rule_priority_ties_by_order },
	{ "rule_merge_any_wins", test_rule_merge_any_wins },
	{ "rule_merge_specific_wins", test_rule_merge_specific_wins },
	{ "rule_merge_bucket_collision", test_rule_merge_bucket_collision },
	{ "wildcards",		test_wildcards },
	{ "udp_rules",		test_udp_rules },
	{ "icmp_type_code_rules", test_icmp_type_code_rules },
	{ "rule_counters",	test_rule_counters },
	{ "rule_counters_reset_per_generation",
	    test_rule_counters_reset_per_generation },
	{ "rule_stats_pagination", test_rule_stats_pagination },
	{ "rule_stats_recvspace_ceiling", test_rule_stats_recvspace_ceiling },
	{ "permissive_semantics",	test_permissive_semantics },
	{ "enforce_semantics",	test_enforce_semantics },
	{ "disabled_bypasses_lookup", test_disabled_bypasses_lookup },
	{ "permissive_covers_parse_categories",
	    test_permissive_covers_parse_categories },
	{ "endpoint_credit_targets_ingress_endpoint",
	    test_endpoint_credit_targets_ingress_endpoint },
	{ "endpoint_limit",	test_endpoint_limit },
	{ "rule_limit",		test_rule_limit },
	{ "transaction_limit",	test_transaction_limit },
	{ "memory_accounting",	test_memory_accounting },
	{ "tx_memory_released_on_abort", test_tx_memory_released_on_abort },
	{ "diagnostic_sysctls",	test_diagnostic_sysctls },
	{ "concurrent_policy_replacement",
	    test_concurrent_policy_replacement },
	{ "concurrent_policy_replacement_adversarial",
	    test_concurrent_policy_replacement_adversarial },
};
const int ngp_ncases = sizeof(ngp_cases) / sizeof(ngp_cases[0]);

int
main(int argc, char **argv)
{
	struct ngp_ctx c;
	const char *only = (argc > 1) ? argv[1] : NULL;
	int i, rc, err, failed = 0, ran = 0;

	/*
	 * Preflight, before any case runs.
	 *
	 * Every case begins with ngp_setup(), so anything wrong with the
	 * environment rather than the module fails all sixty-two of them
	 * identically -- and by far the most common cause is ng_policy
	 * simply not being loaded. Diagnosed per case, that reads as
	 * sixty-two bare "SETUP FAILED" lines and a "0 run, 62 failed"
	 * summary, which names neither the cause nor the fix and invites
	 * the reader to go looking for a fault in the module. So probe
	 * once, report the errno and the likely reason, and stop.
	 *
	 * Exit 2, not 1: "the suite could not run" is a different answer
	 * to "the suite ran and the module failed it", and a caller that
	 * cannot tell them apart will eventually read the first as the
	 * second.
	 */
	if (ngp_setup(&c) < 0) {
		err = errno;
		ngp_teardown(&c);
		fprintf(stderr, "%s: cannot create a '%s' node: %s\n",
		    argv[0], NG_POLICY_NODE_TYPE, strerror(err));
		/*
		 * The two environmental causes are distinguishable, so name
		 * one rather than listing both: the node type is unknown to
		 * the kernel (ENOENT) or opening a netgraph socket was
		 * refused (EPERM). Guessing between them is what the caller
		 * came here to avoid.
		 */
		if (err == EPERM || err == EACCES)
			fprintf(stderr, "  Netgraph sockets are root-only; "
			    "re-run under doas.\n");
		else
			fprintf(stderr, "  ng_policy does not appear to be "
			    "loaded. Check with `kldstat -m ng_policy`, "
			    "then\n  build and load it with "
			    "`make -C src && doas kldload "
			    "./src/ng_policy.ko`.\n");
		return (2);
	}
	ngp_teardown(&c);

	for (i = 0; i < ngp_ncases; i++) {
		if (only != NULL && strcmp(only, ngp_cases[i].name) != 0)
			continue;
		printf("  %-32s ", ngp_cases[i].name);
		fflush(stdout);
		if (ngp_setup(&c) < 0) {
			/*
			 * Reached only if setup breaks after the preflight
			 * succeeded -- resource exhaustion, or a node name
			 * collision -- so the errno is the whole message.
			 */
			err = errno;
			printf("SETUP FAILED (%s)\n", strerror(err));
			ngp_teardown(&c);
			failed++;
			continue;
		}
		rc = ngp_cases[i].fn(&c);
		ngp_teardown(&c);
		ran++;
		if (rc == 0)
			printf("ok\n");
		else {
			printf("  ^ FAILED\n");
			failed++;
		}
	}
	if (only != NULL && ran == 0) {
		/*
		 * A filter that matched nothing (e.g. a case renamed or
		 * removed since the caller last checked) must not report
		 * success: "0 run, 0 failed" with a zero exit is a CI job
		 * silently testing nothing rather than the named case.
		 */
		printf("no test matched %s\n", only);
		return (1);
	}
	printf("\n%d run, %d failed\n", ran, failed);
	return (failed != 0);
}
