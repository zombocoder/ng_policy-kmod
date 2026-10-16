/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zombocoder <zombocoder@gmail.com>
 *
 * ng_policy test harness - shared declarations.
 */

#ifndef NGP_HARNESS_H
#define NGP_HARNESS_H

#include <sys/types.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include <netgraph/ng_message.h>
#include <netgraph/ng_policy/ng_policy.h>

#define	NGP_MAXFRAME	2048

struct ngp_ctx {
	int	cs;			/* control socket */
	int	ds;			/* data socket */
	char	node[NG_NODESIZ];	/* policy node name */
	char	path[NG_PATHSIZ];	/* "<node>:" */
};

int	ngp_setup(struct ngp_ctx *c);
void	ngp_teardown(struct ngp_ctx *c);

int	ngp_msg(struct ngp_ctx *c, int cmd, const void *arg, size_t arglen);
int	ngp_msg_resp(struct ngp_ctx *c, int cmd, const void *arg, size_t arglen,
	    void *resp, size_t resplen);

int	ngp_hook(struct ngp_ctx *c, const char *sockhook, const char *nodehook);

int	ngp_send(struct ngp_ctx *c, const char *sockhook, const void *f,
	    size_t len);
int	ngp_recv(struct ngp_ctx *c, char *hookbuf, size_t hooklen, void *buf,
	    size_t buflen, int timeout_ms);
void	ngp_drain(struct ngp_ctx *c);

int	ngp_ep_add(struct ngp_ctx *c, uint32_t id, const char *hook,
	    const char *peer, uint32_t flags);
int	ngp_ep_del(struct ngp_ctx *c, uint32_t id);
int	ngp_set_mode(struct ngp_ctx *c, uint32_t mode);
int	ngp_get_stats(struct ngp_ctx *c, struct ng_policy_stats *st);
int	ngp_install(struct ngp_ctx *c, const struct ng_policy_rule *rules,
	    uint32_t nrules, const struct ng_policy_addr *addrs,
	    uint32_t naddrs, uint8_t defact);
int	ngp_begin(struct ngp_ctx *c, struct ng_policy_tx_begin_resp *b,
	    uint32_t timeout);
int	ngp_commit(struct ngp_ctx *c, uint64_t tx_id, uint64_t base,
	    struct ng_policy_tx_commit_resp *r);
int	ngp_setdef(struct ngp_ctx *c, uint64_t tx_id, uint8_t act);

size_t	ngp_eth(uint8_t *b, uint16_t ethertype);
size_t	ngp_tcp(uint8_t *b, uint32_t sip, uint32_t dip, uint16_t sp,
	    uint16_t dp);
size_t	ngp_udp(uint8_t *b, uint32_t sip, uint32_t dip, uint16_t sp,
	    uint16_t dp);
size_t	ngp_icmp(uint8_t *b, uint32_t sip, uint32_t dip, uint8_t type,
	    uint8_t code);
size_t	ngp_arp(uint8_t *b);
size_t	ngp_frag(uint8_t *b, uint32_t sip, uint32_t dip, uint16_t off, int mf);

struct ngp_case {
	const char	*name;
	int		(*fn)(struct ngp_ctx *);
};
extern const struct ngp_case ngp_cases[];
extern const int ngp_ncases;

#define	ASSERT_EQ(a, b) do {						\
	long long _a = (long long)(a), _b = (long long)(b);		\
	if (_a != _b) {							\
		printf("    FAIL %s:%d: %s == %s (%lld != %lld)\n",	\
		    __FILE__, __LINE__, #a, #b, _a, _b);		\
		return (1);						\
	}								\
} while (0)

#define	ASSERT_OK(x)	ASSERT_EQ((x), 0)

#define	ASSERT_ERRNO(x, e) do {						\
	int _r = (x);							\
	if (_r != -1 || errno != (e)) {					\
		printf("    FAIL %s:%d: %s expected errno %d, "		\
		    "got rc %d errno %d\n",				\
		    __FILE__, __LINE__, #x, (e), _r, errno);		\
		return (1);						\
	}								\
} while (0)

#endif /* NGP_HARNESS_H */
