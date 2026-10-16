#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

#include <netgraph.h>

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ngp_harness.h"

static int ngp_seq;

int
ngp_setup(struct ngp_ctx *c)
{

	memset(c, 0, sizeof(*c));
	c->cs = c->ds = -1;
	snprintf(c->node, sizeof(c->node), "ngptest%d_%d", (int)getpid(),
	    ++ngp_seq);
	snprintf(c->path, sizeof(c->path), "%s:", c->node);

	if (NgMkSockNode(NULL, &c->cs, &c->ds) < 0)
		return (-1);
	/*
	 * Create the policy node hanging off a throwaway socket hook.
	 *
	 * The generic NGM_MKPEER/NGM_NAME/NGM_CONNECT messages are
	 * struct-typed for ng_parse's ASCII2BINARY conversion, which on
	 * this kernel requires brace/field="value" syntax -- bare
	 * positional words are rejected with EINVAL.
	 */
	if (NgSendAsciiMsg(c->cs, ".:",
	    "mkpeer { type=\"%s\" ourhook=\"ctl\" peerhook=\"ctl0\" }",
	    NG_POLICY_NODE_TYPE) < 0)
		return (-1);
	if (NgSendAsciiMsg(c->cs, ".:ctl", "name { name=\"%s\" }",
	    c->node) < 0)
		return (-1);
	return (0);
}

void
ngp_teardown(struct ngp_ctx *c)
{

	if (c->cs >= 0) {
		(void)NgSendAsciiMsg(c->cs, c->path, "shutdown");
		close(c->cs);
	}
	if (c->ds >= 0)
		close(c->ds);
	c->cs = c->ds = -1;
}

int
ngp_msg(struct ngp_ctx *c, int cmd, const void *arg, size_t arglen)
{

	if (NgSendMsg(c->cs, c->path, NGM_POLICY_COOKIE, cmd, arg, arglen) < 0)
		return (-1);
	return (0);
}

int
ngp_msg_resp(struct ngp_ctx *c, int cmd, const void *arg, size_t arglen,
    void *resp, size_t resplen)
{
	/*
	 * NG_POLICY_RESP_BYTE_BUDGET (ng_policy.h) is the whole-wire-size
	 * ceiling ng_policy_ep_list()/ng_policy_rule_stats() clamp their
	 * windowed responses to, matching the default net.graph.recvspace
	 * -- so it is also the largest reply any conforming node will ever
	 * hand back on this socket.  A smaller stack buffer here silently
	 * truncates a legitimately large page and corrupts whatever
	 * follows on the stack rather than failing loudly.
	 */
	union {
		struct ng_mesg	m;
		u_char		buf[NG_POLICY_RESP_BYTE_BUDGET];
	} u;
	int token;

	token = NgSendMsg(c->cs, c->path, NGM_POLICY_COOKIE, cmd, arg, arglen);
	if (token < 0)
		return (-1);
	/*
	 * NgSendMsg() returns the token it stamped on this request. A
	 * reply already sitting on the socket ahead of this one's -- left
	 * over from an earlier call whose own wait window it missed -- is
	 * not this request's reply just because it is first in FIFO
	 * order. Keep reading and discard anything whose token does not
	 * match: commit cab0ba4 hit exactly this failure mode (a stale
	 * reply consumed by the wrong caller, misread as "node stopped
	 * responding") in the fuzzer's control drain, and this helper had
	 * the same unguarded assumption -- every one of the 59 tests that
	 * call it relies on this loop rather than on FIFO order alone.
	 */
	for (;;) {
		if (NgRecvMsg(c->cs, &u.m, sizeof(u), NULL) < 0)
			return (-1);
		if ((int)u.m.header.token == token)
			break;
	}
	if (u.m.header.arglen < resplen) {
		errno = EPROTO;
		return (-1);
	}
	memcpy(resp, u.m.data, resplen);
	return (0);
}

int
ngp_hook(struct ngp_ctx *c, const char *sockhook, const char *nodehook)
{

	/* See the note in ngp_setup() about NGM_CONNECT's ASCII syntax. */
	if (NgSendAsciiMsg(c->cs, ".:",
	    "connect { path=\"%s\" ourhook=\"%s\" peerhook=\"%s\" }",
	    c->path, sockhook, nodehook) < 0)
		return (-1);
	return (0);
}

int
ngp_send(struct ngp_ctx *c, const char *sockhook, const void *f, size_t len)
{

	if (NgSendData(c->ds, sockhook, f, len) < 0)
		return (-1);
	return (0);
}

int
ngp_recv(struct ngp_ctx *c, char *hookbuf, size_t hooklen, void *buf,
    size_t buflen, int timeout_ms)
{
	char hook[NG_HOOKSIZ];
	struct timeval tv;
	fd_set rfds;
	int n;

	FD_ZERO(&rfds);
	FD_SET(c->ds, &rfds);
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	n = select(c->ds + 1, &rfds, NULL, NULL, &tv);
	if (n < 0)
		return (-1);
	if (n == 0)
		return (0);
	n = NgRecvData(c->ds, buf, buflen, hook);
	if (n < 0)
		return (-1);
	if (hookbuf != NULL)
		strlcpy(hookbuf, hook, hooklen);
	return (n);
}

void
ngp_drain(struct ngp_ctx *c)
{
	u_char buf[NGP_MAXFRAME];

	while (ngp_recv(c, NULL, 0, buf, sizeof(buf), 0) > 0)
		continue;
}

int
ngp_ep_add(struct ngp_ctx *c, uint32_t id, const char *hook, const char *peer,
    uint32_t flags)
{
	struct ng_policy_endpoint_add a;

	memset(&a, 0, sizeof(a));
	a.endpoint_id = id;
	a.flags = flags;
	strlcpy(a.hook, hook, sizeof(a.hook));
	if (peer != NULL)
		strlcpy(a.peer_hook, peer, sizeof(a.peer_hook));
	return (ngp_msg(c, NGM_POLICY_ENDPOINT_ADD, &a, sizeof(a)));
}

int
ngp_ep_del(struct ngp_ctx *c, uint32_t id)
{
	struct ng_policy_endpoint_del d;

	memset(&d, 0, sizeof(d));
	d.endpoint_id = id;
	return (ngp_msg(c, NGM_POLICY_ENDPOINT_DEL, &d, sizeof(d)));
}

int
ngp_set_mode(struct ngp_ctx *c, uint32_t mode)
{
	struct ng_policy_mode_req r;

	r.mode = mode;
	return (ngp_msg(c, NGM_POLICY_SET_MODE, &r, sizeof(r)));
}

int
ngp_get_stats(struct ngp_ctx *c, struct ng_policy_stats *st)
{

	return (ngp_msg_resp(c, NGM_POLICY_GET_STATS, NULL, 0, st,
	    sizeof(*st)));
}

int
ngp_install(struct ngp_ctx *c, const struct ng_policy_rule *rules,
    uint32_t nrules, const struct ng_policy_addr *addrs, uint32_t naddrs,
    uint8_t defact)
{
	struct ng_policy_tx_begin_req breq;
	struct ng_policy_tx_begin_resp bresp;
	struct ng_policy_tx_commit_req creq;
	struct ng_policy_tx_commit_resp cresp;
	struct ng_policy_tx_set_default sd;
	struct ng_policy_stats st;
	union {
		u_char buf[8192];
		uint64_t align;
	} u;
	size_t len;

	memset(&breq, 0, sizeof(breq));
	if (ngp_msg_resp(c, NGM_POLICY_TX_BEGIN, &breq, sizeof(breq), &bresp,
	    sizeof(bresp)) < 0)
		return (-1);

	if (nrules > 0) {
		struct ng_policy_tx_add_rule *ar = (void *)u.buf;

		len = sizeof(*ar) + nrules * sizeof(rules[0]);
		if (len > sizeof(u.buf)) {
			errno = ENOSPC;
			return (-1);
		}
		memset(ar, 0, sizeof(*ar));
		ar->tx_id = bresp.tx_id;
		ar->nrules = nrules;
		memcpy(ar->rules, rules, nrules * sizeof(rules[0]));
		if (ngp_msg(c, NGM_POLICY_TX_ADD_RULE, ar, len) < 0)
			return (-1);
	}
	if (naddrs > 0) {
		struct ng_policy_tx_add_addr *aa = (void *)u.buf;

		len = sizeof(*aa) + naddrs * sizeof(addrs[0]);
		if (len > sizeof(u.buf)) {
			errno = ENOSPC;
			return (-1);
		}
		memset(aa, 0, sizeof(*aa));
		aa->tx_id = bresp.tx_id;
		aa->naddrs = naddrs;
		memcpy(aa->addrs, addrs, naddrs * sizeof(addrs[0]));
		if (ngp_msg(c, NGM_POLICY_TX_ADD_ADDR, aa, len) < 0)
			return (-1);
	}

	memset(&sd, 0, sizeof(sd));
	sd.tx_id = bresp.tx_id;
	sd.default_action = defact;
	if (ngp_msg(c, NGM_POLICY_TX_SET_DEFAULT, &sd, sizeof(sd)) < 0)
		return (-1);

	if (ngp_get_stats(c, &st) < 0)
		return (-1);
	memset(&creq, 0, sizeof(creq));
	creq.tx_id = bresp.tx_id;
	creq.base_generation = st.generation;
	return (ngp_msg_resp(c, NGM_POLICY_TX_COMMIT, &creq, sizeof(creq),
	    &cresp, sizeof(cresp)));
}

int
ngp_begin(struct ngp_ctx *c, struct ng_policy_tx_begin_resp *b, uint32_t timeout)
{
	struct ng_policy_tx_begin_req req;

	memset(&req, 0, sizeof(req));
	req.timeout = timeout;
	return (ngp_msg_resp(c, NGM_POLICY_TX_BEGIN, &req, sizeof(req), b,
	    sizeof(*b)));
}

int
ngp_commit(struct ngp_ctx *c, uint64_t tx_id, uint64_t base,
    struct ng_policy_tx_commit_resp *r)
{
	struct ng_policy_tx_commit_req req;

	memset(&req, 0, sizeof(req));
	req.tx_id = tx_id;
	req.base_generation = base;
	return (ngp_msg_resp(c, NGM_POLICY_TX_COMMIT, &req, sizeof(req), r,
	    sizeof(*r)));
}

int
ngp_setdef(struct ngp_ctx *c, uint64_t tx_id, uint8_t act)
{
	struct ng_policy_tx_set_default sd;

	memset(&sd, 0, sizeof(sd));
	sd.tx_id = tx_id;
	sd.default_action = act;
	return (ngp_msg(c, NGM_POLICY_TX_SET_DEFAULT, &sd, sizeof(sd)));
}

/*
 * Frame builders.  All addresses and ports are given in host order and
 * converted here.  Checksums are left zero: the node never validates
 * them, and saying so in one place is better than computing them in six.
 */
static const uint8_t ngp_dmac[6] = { 0x02, 0, 0, 0, 0, 0x01 };
static const uint8_t ngp_smac[6] = { 0x02, 0, 0, 0, 0, 0x02 };

size_t
ngp_eth(uint8_t *b, uint16_t ethertype)
{
	struct ether_header *eh = (void *)b;

	memcpy(eh->ether_dhost, ngp_dmac, 6);
	memcpy(eh->ether_shost, ngp_smac, 6);
	eh->ether_type = htons(ethertype);
	return (ETHER_HDR_LEN);
}

static size_t
ngp_ip4(uint8_t *b, uint8_t proto, uint32_t sip, uint32_t dip, size_t payload,
    uint16_t fragoff, int mf)
{
	struct ip *ip = (void *)(b + ETHER_HDR_LEN);
	size_t off = ngp_eth(b, ETHERTYPE_IP);

	memset(ip, 0, sizeof(*ip));
	ip->ip_v = 4;
	ip->ip_hl = sizeof(*ip) >> 2;
	ip->ip_len = htons((uint16_t)(sizeof(*ip) + payload));
	ip->ip_ttl = 64;
	ip->ip_p = proto;
	ip->ip_src.s_addr = htonl(sip);
	ip->ip_dst.s_addr = htonl(dip);
	ip->ip_off = htons((uint16_t)((fragoff >> 3) | (mf ? IP_MF : 0)));
	return (off + sizeof(*ip));
}

size_t
ngp_tcp(uint8_t *b, uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp)
{
	size_t off = ngp_ip4(b, IPPROTO_TCP, sip, dip, sizeof(struct tcphdr),
	    0, 0);
	struct tcphdr *th = (void *)(b + off);

	memset(th, 0, sizeof(*th));
	th->th_sport = htons(sp);
	th->th_dport = htons(dp);
	th->th_off = sizeof(*th) >> 2;
	th->th_flags = TH_SYN;
	return (off + sizeof(*th));
}

size_t
ngp_udp(uint8_t *b, uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp)
{
	size_t off = ngp_ip4(b, IPPROTO_UDP, sip, dip, sizeof(struct udphdr),
	    0, 0);
	struct udphdr *uh = (void *)(b + off);

	memset(uh, 0, sizeof(*uh));
	uh->uh_sport = htons(sp);
	uh->uh_dport = htons(dp);
	uh->uh_ulen = htons(sizeof(*uh));
	return (off + sizeof(*uh));
}

size_t
ngp_icmp(uint8_t *b, uint32_t sip, uint32_t dip, uint8_t type, uint8_t code)
{
	size_t off = ngp_ip4(b, IPPROTO_ICMP, sip, dip, 8, 0, 0);
	uint8_t *ic = b + off;

	memset(ic, 0, 8);
	ic[0] = type;
	ic[1] = code;
	return (off + 8);
}

size_t
ngp_arp(uint8_t *b)
{
	size_t off = ngp_eth(b, ETHERTYPE_ARP);

	memset(b + off, 0, 28);
	b[off + 1] = 1;		/* hardware type Ethernet */
	b[off + 2] = 0x08;	/* protocol type IPv4 */
	b[off + 4] = 6;		/* hardware size */
	b[off + 5] = 4;		/* protocol size */
	b[off + 7] = 1;		/* opcode request */
	return (off + 28);
}

size_t
ngp_frag(uint8_t *b, uint32_t sip, uint32_t dip, uint16_t off, int mf)
{
	size_t hdr = ngp_ip4(b, IPPROTO_TCP, sip, dip, 8, off, mf);

	memset(b + hdr, 0, 8);
	return (hdr + 8);
}
