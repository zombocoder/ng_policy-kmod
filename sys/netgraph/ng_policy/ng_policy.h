/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zombocoder <zombocoder@gmail.com>
 *
 * ng_policy - identity-aware network policy enforcement for Netgraph.
 *
 * Public constants.  This header is safe to include from userland.
 */

#ifndef _NETGRAPH_NG_POLICY_H_
#define _NETGRAPH_NG_POLICY_H_

#define	NG_POLICY_NODE_TYPE	"policy"
#define	NG_POLICY_VERSION	"0.1"

/*
 * Advisory hook naming convention.  Hook names carry no authority: the
 * numeric endpoint ID assigned by NGM_POLICY_ENDPOINT_ADD is the only
 * identity the node recognises.
 */
#define	NG_POLICY_HOOK_EP_FMT	"ep-%u"
#define	NG_POLICY_HOOK_FAB_FMT	"fab-%u"

/* Reserved endpoint identities. */
#define	NG_POLICY_EP_ANY		0x00000000u
#define	NG_POLICY_EP_RESERVED_MIN	0xffffff00u
#define	NG_POLICY_EP_LOCAL_HOST		0xfffffffdu
#define	NG_POLICY_EP_EXTERNAL		0xffffffffu
#define	NG_POLICY_EP_ID_MAX		(NG_POLICY_EP_RESERVED_MIN - 1u)
#define	NG_POLICY_EP_ID_VALID(id) \
	((id) != NG_POLICY_EP_ANY && (id) <= NG_POLICY_EP_ID_MAX)

/* Endpoint flags: persistent configuration. */
#define	NG_POLICY_EP_ENABLED	0x00000001u
#define	NG_POLICY_EP_TRUSTED	0x00000002u
#define	NG_POLICY_EP_CFG_MASK	0x00000003u

/* Endpoint flags: request-only, never stored. */
#define	NG_POLICY_EP_F_REPLACE	0x00010000u

/* Endpoint flags: status-only, set by the kernel in list responses. */
#define	NG_POLICY_EP_S_CONNECTED	0x01000000u
#define	NG_POLICY_EP_S_PEER_CONNECTED	0x02000000u

/*
 * Actions.  Values 3..7 are reserved for REJECT, LOG, RATE_LIMIT,
 * REDIRECT and MIRROR; v0.1 must reject them.
 */
enum ng_policy_action {
	NG_POLICY_ALLOW	= 1,
	NG_POLICY_DROP	= 2,
};
#define	NG_POLICY_ACTION_VALID(a) \
	((a) == NG_POLICY_ALLOW || (a) == NG_POLICY_DROP)

/* Operating modes. */
enum ng_policy_mode {
	NG_POLICY_MODE_DISABLED		= 0,
	NG_POLICY_MODE_PERMISSIVE	= 1,
	NG_POLICY_MODE_ENFORCE		= 2,
};
#define	NG_POLICY_MODE_VALID(m)	((m) <= NG_POLICY_MODE_ENFORCE)

/*
 * Protocols.  Values match IPPROTO_*; spelled numerically so that this
 * header carries no dependency on <netinet/in.h>.
 */
#define	NG_POLICY_PROTO_ANY	0
#define	NG_POLICY_PROTO_ICMP	1	/* IPPROTO_ICMP */
#define	NG_POLICY_PROTO_TCP	6	/* IPPROTO_TCP */
#define	NG_POLICY_PROTO_UDP	17	/* IPPROTO_UDP */

/* Rule flags. */
#define	NG_POLICY_RULE_F_ICMP_TYPE	0x0001
#define	NG_POLICY_RULE_F_ICMP_CODE	0x0002
#define	NG_POLICY_RULE_F_MASK		0x0003

/* Node configuration flags. */
#define	NG_POLICY_CFG_F_STRICT_ENDPOINTS	0x0001
#define	NG_POLICY_CFG_F_MASK			0x0001

/* Commit flags. */
#define	NG_POLICY_TXC_F_FORCE	0x0001
#define	NG_POLICY_TXC_F_MASK	0x0001

/* Statistics reset targets.  Zero means everything. */
#define	NG_POLICY_RESET_NODE		0x0001
#define	NG_POLICY_RESET_ENDPOINTS	0x0002
#define	NG_POLICY_RESET_RULES		0x0004
#define	NG_POLICY_RESET_MASK		0x0007

/* A port range of [0, 65535] is the wildcard. */
#define	NG_POLICY_PORT_ANY_MIN	0
#define	NG_POLICY_PORT_ANY_MAX	65535

/*
 * Largest number of entries any single windowed response returns,
 * before the per-response-type byte-budget clamp below narrows it
 * further.
 */
#define	NG_POLICY_BATCH_MAX	512

/*
 * Netgraph control sockets bound a single incoming datagram to
 * net.graph.recvspace (`ngpdg_recvspace` in sys/netgraph/ng_socket.c),
 * 20480 bytes by default.  NG_POLICY_BATCH_MAX alone does not respect
 * that: it was frozen before either windowed response type existed,
 * and at either entry size, 512 entries plus the response headers
 * exceeds the default ceiling.  Each windowed response handler
 * (ng_policy_ep_list(), ng_policy_rule_stats()) additionally clamps
 * its per-call entry count so that sizeof(struct ng_mesg) +
 * sizeof(<its resp header>) + n * sizeof(<its entry>) never exceeds
 * this budget -- a caller asking for more than fits simply gets a
 * smaller page and keeps paging via start_index/next_index, which the
 * windowing protocol already supports without any ABI change.  An
 * operator who has raised net.graph.recvspace on their own socket can
 * still only be served pages sized off this default, because the
 * module cannot observe a particular caller's socket option; that
 * caller just pages more often, which is correct, not broken.  See
 * "Response paging and the net.graph.recvspace ceiling" in
 * docs/control-api.md.
 */
#define	NG_POLICY_RESP_BYTE_BUDGET	(20 * 1024)

#include <netgraph/ng_policy/ng_policy_msg.h>

#endif /* _NETGRAPH_NG_POLICY_H_ */
