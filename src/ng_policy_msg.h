/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ng_policy - control message ABI.
 *
 * The type cookie is the primary ABI guard.  Structures additionally
 * carry a "version" field in which 0 means "current ABI", so that ngctl
 * stays usable for hand debugging without typing a version every time.
 */

#ifndef _NETGRAPH_NG_POLICY_MSG_H_
#define _NETGRAPH_NG_POLICY_MSG_H_

#include <netgraph/ng_message.h>

#define	NGM_POLICY_COOKIE	1756036800
#define	NG_POLICY_ABI_VERSION	1

enum {
	NGM_POLICY_GET_CONFIG = 1,
	NGM_POLICY_SET_CONFIG,
	NGM_POLICY_SET_MODE,
	NGM_POLICY_ENDPOINT_ADD,
	NGM_POLICY_ENDPOINT_DEL,
	NGM_POLICY_ENDPOINT_LIST,
	NGM_POLICY_TX_BEGIN,
	NGM_POLICY_TX_ADD_RULE,
	NGM_POLICY_TX_ADD_ADDR,
	NGM_POLICY_TX_SET_DEFAULT,
	NGM_POLICY_TX_COMMIT,
	NGM_POLICY_TX_ABORT,
	NGM_POLICY_GET_STATS,
	NGM_POLICY_GET_ENDPOINT_STATS,
	NGM_POLICY_GET_RULE_STATS,
	NGM_POLICY_RESET_STATS,
};

/*
 * Node configuration.  Settable knobs only: the default action belongs
 * to the policy generation and is set with TX_SET_DEFAULT.
 */
struct ng_policy_config {
	uint16_t	version;
	uint16_t	flags;
	uint8_t		mode;
	uint8_t		arp_action;
	uint8_t		frag_action;
	uint8_t		unsupported_action;
	uint8_t		malformed_action;
	uint8_t		reserved0;
	uint16_t	reserved1;
};

#define	NG_POLICY_CONFIG_TYPE_INFO {				\
	{ "version",		&ng_parse_uint16_type	},	\
	{ "flags",		&ng_parse_hint16_type	},	\
	{ "mode",		&ng_parse_uint8_type	},	\
	{ "arp_action",		&ng_parse_uint8_type	},	\
	{ "frag_action",	&ng_parse_uint8_type	},	\
	{ "unsupported_action",	&ng_parse_uint8_type	},	\
	{ "malformed_action",	&ng_parse_uint8_type	},	\
	{ "reserved0",		&ng_parse_uint8_type	},	\
	{ "reserved1",		&ng_parse_uint16_type	},	\
	{ NULL }						\
}

struct ng_policy_mode_req {
	uint32_t	mode;
};

#define	NG_POLICY_MODE_REQ_TYPE_INFO {				\
	{ "mode",		&ng_parse_uint32_type	},	\
	{ NULL }						\
}

/*
 * Endpoint registration.  Two hook names: the workload side and the
 * fabric side.  An allowed packet arriving on one is forwarded to the
 * other.  peer_hook may be the empty string, in which case the endpoint
 * has no egress and all of its traffic is dropped and counted.
 */
struct ng_policy_endpoint_add {
	uint32_t	endpoint_id;
	uint32_t	flags;
	uint16_t	version;
	uint16_t	reserved;
	char		hook[NG_HOOKSIZ];
	char		peer_hook[NG_HOOKSIZ];
};

#define	NG_POLICY_ENDPOINT_ADD_TYPE_INFO {			\
	{ "endpoint_id",	&ng_parse_uint32_type	},	\
	{ "flags",		&ng_parse_hint32_type	},	\
	{ "version",		&ng_parse_uint16_type	},	\
	{ "reserved",		&ng_parse_uint16_type	},	\
	{ "hook",		&ng_parse_hookbuf_type	},	\
	{ "peer_hook",		&ng_parse_hookbuf_type	},	\
	{ NULL }						\
}

struct ng_policy_endpoint_del {
	uint32_t	endpoint_id;
	uint32_t	flags;
};

#define	NG_POLICY_ENDPOINT_DEL_TYPE_INFO {			\
	{ "endpoint_id",	&ng_parse_uint32_type	},	\
	{ "flags",		&ng_parse_hint32_type	},	\
	{ NULL }						\
}

/*
 * Windowed enumeration.  endpoint_id 0 means "all endpoints".
 * max_entries 0 means "as many as fit", capped at NG_POLICY_BATCH_MAX.
 */
struct ng_policy_ep_query {
	uint32_t	endpoint_id;
	uint32_t	start_index;
	uint32_t	max_entries;
	uint32_t	reserved;
};

#define	NG_POLICY_EP_QUERY_TYPE_INFO {				\
	{ "endpoint_id",	&ng_parse_uint32_type	},	\
	{ "start_index",	&ng_parse_uint32_type	},	\
	{ "max_entries",	&ng_parse_uint32_type	},	\
	{ "reserved",		&ng_parse_uint32_type	},	\
	{ NULL }						\
}

struct ng_policy_endpoint_info {
	uint32_t	endpoint_id;
	uint32_t	flags;
	uint64_t	rx_packets;
	uint64_t	rx_bytes;
	uint64_t	tx_packets;
	uint64_t	tx_bytes;
	uint64_t	allowed_packets;
	uint64_t	dropped_packets;
	uint64_t	violations;
	char		hook[NG_HOOKSIZ];
	char		peer_hook[NG_HOOKSIZ];
};

#define	NG_POLICY_ENDPOINT_INFO_TYPE_INFO {			\
	{ "endpoint_id",	&ng_parse_uint32_type	},	\
	{ "flags",		&ng_parse_hint32_type	},	\
	{ "rx_packets",		&ng_parse_uint64_type	},	\
	{ "rx_bytes",		&ng_parse_uint64_type	},	\
	{ "tx_packets",		&ng_parse_uint64_type	},	\
	{ "tx_bytes",		&ng_parse_uint64_type	},	\
	{ "allowed_packets",	&ng_parse_uint64_type	},	\
	{ "dropped_packets",	&ng_parse_uint64_type	},	\
	{ "violations",		&ng_parse_uint64_type	},	\
	{ "hook",		&ng_parse_hookbuf_type	},	\
	{ "peer_hook",		&ng_parse_hookbuf_type	},	\
	{ NULL }						\
}

struct ng_policy_ep_list_resp {
	uint64_t	generation;
	uint32_t	total;
	uint32_t	returned;
	uint32_t	next_index;
	uint32_t	reserved;
	struct ng_policy_endpoint_info entries[];
};

#define	NG_POLICY_EP_LIST_RESP_TYPE_INFO(atype) {		\
	{ "generation",		&ng_parse_uint64_type	},	\
	{ "total",		&ng_parse_uint32_type	},	\
	{ "returned",		&ng_parse_uint32_type	},	\
	{ "next_index",		&ng_parse_uint32_type	},	\
	{ "reserved",		&ng_parse_uint32_type	},	\
	{ "entries",		(atype)			},	\
	{ NULL }						\
}

/*
 * A rule.  32 bytes, no implicit padding.  ICMP type and code are
 * matched through dedicated fields guarded by RULE_F_ICMP_TYPE and
 * RULE_F_ICMP_CODE, never by overloading the port ranges.
 */
struct ng_policy_rule {
	uint64_t	rule_id;
	uint32_t	src_endpoint;
	uint32_t	dst_endpoint;
	uint16_t	src_port_min;
	uint16_t	src_port_max;
	uint16_t	dst_port_min;
	uint16_t	dst_port_max;
	uint16_t	priority;
	uint16_t	flags;
	uint8_t		protocol;
	uint8_t		action;
	uint8_t		icmp_type;
	uint8_t		icmp_code;
};

#define	NG_POLICY_RULE_TYPE_INFO {				\
	{ "rule_id",		&ng_parse_uint64_type	},	\
	{ "src_endpoint",	&ng_parse_uint32_type	},	\
	{ "dst_endpoint",	&ng_parse_uint32_type	},	\
	{ "src_port_min",	&ng_parse_uint16_type	},	\
	{ "src_port_max",	&ng_parse_uint16_type	},	\
	{ "dst_port_min",	&ng_parse_uint16_type	},	\
	{ "dst_port_max",	&ng_parse_uint16_type	},	\
	{ "priority",		&ng_parse_uint16_type	},	\
	{ "flags",		&ng_parse_hint16_type	},	\
	{ "protocol",		&ng_parse_uint8_type	},	\
	{ "action",		&ng_parse_uint8_type	},	\
	{ "icmp_type",		&ng_parse_uint8_type	},	\
	{ "icmp_code",		&ng_parse_uint8_type	},	\
	{ NULL }						\
}

/* An address-map entry.  ipv4 is in network byte order; 0.0.0.0 is invalid. */
struct ng_policy_addr {
	uint32_t	ipv4;
	uint32_t	endpoint_id;
};

#define	NG_POLICY_ADDR_TYPE_INFO {				\
	{ "ipv4",		&ng_parse_ipaddr_type	},	\
	{ "endpoint_id",	&ng_parse_uint32_type	},	\
	{ NULL }						\
}

struct ng_policy_tx_begin_req {
	uint64_t	requested_generation;	/* 0 = active + 1 */
	uint32_t	timeout;		/* seconds, 0 = default */
	uint16_t	version;
	uint16_t	flags;
};

#define	NG_POLICY_TX_BEGIN_REQ_TYPE_INFO {			\
	{ "requested_generation", &ng_parse_uint64_type	},	\
	{ "timeout",		&ng_parse_uint32_type	},	\
	{ "version",		&ng_parse_uint16_type	},	\
	{ "flags",		&ng_parse_hint16_type	},	\
	{ NULL }						\
}

struct ng_policy_tx_begin_resp {
	uint64_t	tx_id;
	uint64_t	generation;
	uint64_t	active_generation;
	uint32_t	timeout;
	uint32_t	reserved;
};

#define	NG_POLICY_TX_BEGIN_RESP_TYPE_INFO {			\
	{ "tx_id",		&ng_parse_uint64_type	},	\
	{ "generation",		&ng_parse_uint64_type	},	\
	{ "active_generation",	&ng_parse_uint64_type	},	\
	{ "timeout",		&ng_parse_uint32_type	},	\
	{ "reserved",		&ng_parse_uint32_type	},	\
	{ NULL }						\
}

/* Rules and addresses are batched: 100,000 single-rule messages is not a design. */
struct ng_policy_tx_add_rule {
	uint64_t	tx_id;
	uint16_t	version;
	uint16_t	reserved;
	uint32_t	nrules;
	struct ng_policy_rule rules[];
};

#define	NG_POLICY_TX_ADD_RULE_TYPE_INFO(atype) {		\
	{ "tx_id",		&ng_parse_uint64_type	},	\
	{ "version",		&ng_parse_uint16_type	},	\
	{ "reserved",		&ng_parse_uint16_type	},	\
	{ "nrules",		&ng_parse_uint32_type	},	\
	{ "rules",		(atype)			},	\
	{ NULL }						\
}

struct ng_policy_tx_add_addr {
	uint64_t	tx_id;
	uint16_t	version;
	uint16_t	reserved;
	uint32_t	naddrs;
	struct ng_policy_addr addrs[];
};

#define	NG_POLICY_TX_ADD_ADDR_TYPE_INFO(atype) {		\
	{ "tx_id",		&ng_parse_uint64_type	},	\
	{ "version",		&ng_parse_uint16_type	},	\
	{ "reserved",		&ng_parse_uint16_type	},	\
	{ "naddrs",		&ng_parse_uint32_type	},	\
	{ "addrs",		(atype)			},	\
	{ NULL }						\
}

struct ng_policy_tx_set_default {
	uint64_t	tx_id;
	uint8_t		default_action;
	uint8_t		reserved0;
	uint16_t	reserved1;
	uint32_t	reserved2;
};

#define	NG_POLICY_TX_SET_DEFAULT_TYPE_INFO {			\
	{ "tx_id",		&ng_parse_uint64_type	},	\
	{ "default_action",	&ng_parse_uint8_type	},	\
	{ "reserved0",		&ng_parse_uint8_type	},	\
	{ "reserved1",		&ng_parse_uint16_type	},	\
	{ "reserved2",		&ng_parse_uint32_type	},	\
	{ NULL }						\
}

/* Optimistic concurrency: the commit applies only if base_generation
   equals the active generation, unless TXC_F_FORCE is set. */
struct ng_policy_tx_commit_req {
	uint64_t	tx_id;
	uint64_t	base_generation;
	uint16_t	version;
	uint16_t	flags;
	uint32_t	reserved;
};

#define	NG_POLICY_TX_COMMIT_REQ_TYPE_INFO {			\
	{ "tx_id",		&ng_parse_uint64_type	},	\
	{ "base_generation",	&ng_parse_uint64_type	},	\
	{ "version",		&ng_parse_uint16_type	},	\
	{ "flags",		&ng_parse_hint16_type	},	\
	{ "reserved",		&ng_parse_uint32_type	},	\
	{ NULL }						\
}

struct ng_policy_tx_commit_resp {
	uint64_t	generation;
	uint64_t	memory;
	uint64_t	build_usec;
	uint64_t	validate_usec;
	uint64_t	commit_usec;
	uint64_t	reclaim_usec;
	uint32_t	nrules;
	uint32_t	naddrs;
};

#define	NG_POLICY_TX_COMMIT_RESP_TYPE_INFO {			\
	{ "generation",		&ng_parse_uint64_type	},	\
	{ "memory",		&ng_parse_uint64_type	},	\
	{ "build_usec",		&ng_parse_uint64_type	},	\
	{ "validate_usec",	&ng_parse_uint64_type	},	\
	{ "commit_usec",	&ng_parse_uint64_type	},	\
	{ "reclaim_usec",	&ng_parse_uint64_type	},	\
	{ "nrules",		&ng_parse_uint32_type	},	\
	{ "naddrs",		&ng_parse_uint32_type	},	\
	{ NULL }						\
}

struct ng_policy_tx_id {
	uint64_t	tx_id;
};

#define	NG_POLICY_TX_ID_TYPE_INFO {				\
	{ "tx_id",		&ng_parse_uint64_type	},	\
	{ NULL }						\
}

struct ng_policy_stats {
	uint64_t	generation;
	uint64_t	packets_total;
	uint64_t	bytes_total;
	uint64_t	allowed_packets;
	uint64_t	allowed_bytes;
	uint64_t	dropped_packets;
	uint64_t	dropped_bytes;
	uint64_t	permissive_violations;
	uint64_t	malformed_packets;
	uint64_t	unsupported_packets;
	uint64_t	fragmented_packets;
	uint64_t	arp_packets;
	uint64_t	unbound_hook_packets;
	uint64_t	no_peer_packets;
	uint64_t	rule_matches;
	uint64_t	default_matches;
	uint64_t	addr_lookups;
	uint64_t	addr_hits;
	uint64_t	commits;
	uint64_t	failed_commits;
	uint64_t	aborts;
	uint64_t	tx_timeouts;
	uint32_t	mode;
	uint32_t	nendpoints;
	uint32_t	nrules;
	uint32_t	naddrs;
	uint32_t	ntx;
	uint32_t	reserved;
	uint64_t	policy_memory;
	uint64_t	tx_memory;
	uint64_t	endpoint_memory;
	uint64_t	addr_memory;
};

#define	NG_POLICY_STATS_TYPE_INFO {				\
	{ "generation",		&ng_parse_uint64_type	},	\
	{ "packets_total",	&ng_parse_uint64_type	},	\
	{ "bytes_total",	&ng_parse_uint64_type	},	\
	{ "allowed_packets",	&ng_parse_uint64_type	},	\
	{ "allowed_bytes",	&ng_parse_uint64_type	},	\
	{ "dropped_packets",	&ng_parse_uint64_type	},	\
	{ "dropped_bytes",	&ng_parse_uint64_type	},	\
	{ "permissive_violations", &ng_parse_uint64_type	},	\
	{ "malformed_packets",	&ng_parse_uint64_type	},	\
	{ "unsupported_packets", &ng_parse_uint64_type	},	\
	{ "fragmented_packets",	&ng_parse_uint64_type	},	\
	{ "arp_packets",	&ng_parse_uint64_type	},	\
	{ "unbound_hook_packets", &ng_parse_uint64_type	},	\
	{ "no_peer_packets",	&ng_parse_uint64_type	},	\
	{ "rule_matches",	&ng_parse_uint64_type	},	\
	{ "default_matches",	&ng_parse_uint64_type	},	\
	{ "addr_lookups",	&ng_parse_uint64_type	},	\
	{ "addr_hits",		&ng_parse_uint64_type	},	\
	{ "commits",		&ng_parse_uint64_type	},	\
	{ "failed_commits",	&ng_parse_uint64_type	},	\
	{ "aborts",		&ng_parse_uint64_type	},	\
	{ "tx_timeouts",	&ng_parse_uint64_type	},	\
	{ "mode",		&ng_parse_uint32_type	},	\
	{ "nendpoints",		&ng_parse_uint32_type	},	\
	{ "nrules",		&ng_parse_uint32_type	},	\
	{ "naddrs",		&ng_parse_uint32_type	},	\
	{ "ntx",		&ng_parse_uint32_type	},	\
	{ "reserved",		&ng_parse_uint32_type	},	\
	{ "policy_memory",	&ng_parse_uint64_type	},	\
	{ "tx_memory",		&ng_parse_uint64_type	},	\
	{ "endpoint_memory",	&ng_parse_uint64_type	},	\
	{ "addr_memory",	&ng_parse_uint64_type	},	\
	{ NULL }						\
}

struct ng_policy_rule_stat {
	struct ng_policy_rule	rule;
	uint64_t		match_packets;
	uint64_t		match_bytes;
	uint32_t		index;
	uint32_t		reserved;
};

#define	NG_POLICY_RULE_STAT_TYPE_INFO(rtype) {			\
	{ "rule",		(rtype)			},	\
	{ "match_packets",	&ng_parse_uint64_type	},	\
	{ "match_bytes",	&ng_parse_uint64_type	},	\
	{ "index",		&ng_parse_uint32_type	},	\
	{ "reserved",		&ng_parse_uint32_type	},	\
	{ NULL }						\
}

struct ng_policy_rule_query {
	uint32_t	start_index;
	uint32_t	max_entries;
};

#define	NG_POLICY_RULE_QUERY_TYPE_INFO {			\
	{ "start_index",	&ng_parse_uint32_type	},	\
	{ "max_entries",	&ng_parse_uint32_type	},	\
	{ NULL }						\
}

struct ng_policy_rule_stats_resp {
	uint64_t	generation;
	uint32_t	total;
	uint32_t	returned;
	uint32_t	next_index;
	uint32_t	reserved;
	struct ng_policy_rule_stat entries[];
};

#define	NG_POLICY_RULE_STATS_RESP_TYPE_INFO(atype) {		\
	{ "generation",		&ng_parse_uint64_type	},	\
	{ "total",		&ng_parse_uint32_type	},	\
	{ "returned",		&ng_parse_uint32_type	},	\
	{ "next_index",		&ng_parse_uint32_type	},	\
	{ "reserved",		&ng_parse_uint32_type	},	\
	{ "entries",		(atype)			},	\
	{ NULL }						\
}

struct ng_policy_reset_req {
	uint32_t	what;		/* 0 = everything */
	uint32_t	endpoint_id;	/* 0 = all endpoints */
};

#define	NG_POLICY_RESET_REQ_TYPE_INFO {				\
	{ "what",		&ng_parse_hint32_type	},	\
	{ "endpoint_id",	&ng_parse_uint32_type	},	\
	{ NULL }						\
}

#endif /* _NETGRAPH_NG_POLICY_MSG_H_ */
