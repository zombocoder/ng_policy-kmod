/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zombocoder <zombocoder@gmail.com>
 *
 * ng_policy - packet parsing.
 *
 * Extracts only what a policy decision needs.  Never modifies the mbuf,
 * never calls m_pullup, and never reads past m_pkthdr.len.
 */

#include <netgraph/ng_policy/ng_policy_var.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/*
 * Return a pointer to len bytes at offset off.  Zero copy when those
 * bytes are contiguous in the first mbuf, which is the common case;
 * otherwise copy into the caller's scratch buffer.  NULL means the
 * packet is shorter than the caller requires.
 */
static __inline const void *
ngp_at(const struct mbuf *m, int off, int len, void *scratch)
{

	if (__predict_false(off < 0 || len < 0))
		return (NULL);
	if (__predict_false(off + len > m->m_pkthdr.len))
		return (NULL);
	if (__predict_true(!ng_policy_debug_force_copy &&
	    m->m_len >= off + len))
		return (mtod(m, const uint8_t *) + off);
	m_copydata(m, off, len, scratch);
	return (scratch);
}

enum ng_policy_parse_result
ng_policy_parse(struct mbuf *m, struct ng_policy_meta *meta)
{
	union {
		struct ether_header	eh;
		struct ip		ip;
		struct tcphdr		th;
		struct udphdr		uh;
		uint8_t			icmp[4];
	} scratch;
	const struct ether_header *eh;
	const struct ip *ip;
	const struct tcphdr *th;
	const struct udphdr *uh;
	const uint8_t *ic;
	uint16_t ip_off, ip_len;
	int off, hlen;

	eh = ngp_at(m, 0, ETHER_HDR_LEN, &scratch);
	if (eh == NULL)
		return (NG_POLICY_PARSE_MALFORMED);
	meta->ether_type = ntohs(eh->ether_type);
	off = ETHER_HDR_LEN;

	/*
	 * v0.2 adds 802.1Q here by advancing off past each tag and
	 * re-reading the EtherType; until then a tag is unsupported.
	 */
	switch (meta->ether_type) {
	case ETHERTYPE_ARP:
		return (NG_POLICY_PARSE_ARP);
	case ETHERTYPE_IP:
		break;
	default:
		return (NG_POLICY_PARSE_UNSUPPORTED);
	}

	ip = ngp_at(m, off, sizeof(struct ip), &scratch);
	if (ip == NULL)
		return (NG_POLICY_PARSE_MALFORMED);
	if (ip->ip_v != IPVERSION)
		return (NG_POLICY_PARSE_MALFORMED);
	hlen = ip->ip_hl << 2;
	if (hlen < (int)sizeof(struct ip))
		return (NG_POLICY_PARSE_MALFORMED);
	ip_len = ntohs(ip->ip_len);
	if (ip_len < hlen)
		return (NG_POLICY_PARSE_MALFORMED);
	if (off + hlen > m->m_pkthdr.len)
		return (NG_POLICY_PARSE_MALFORMED);

	meta->ip_version = 4;
	meta->protocol = ip->ip_p;
	meta->src_ipv4 = ip->ip_src.s_addr;
	meta->dst_ipv4 = ip->ip_dst.s_addr;
	ip_off = ntohs(ip->ip_off);

	if ((ip_off & IP_OFFMASK) != 0)
		return (NG_POLICY_PARSE_FRAGMENT);
	if ((ip_off & IP_MF) != 0)
		meta->flags |= NGP_META_F_FIRSTFRAG;

	off += hlen;

	/*
	 * ip is dead from here on: it points into the shared scratch
	 * buffer on the non-contiguous path, and the ngp_at() calls below
	 * for the transport header reuse that same buffer.  Everything
	 * needed from the IP header was already copied into *meta above,
	 * so switch on meta->protocol, never on ip->ip_p.
	 */
	switch (meta->protocol) {
	case IPPROTO_TCP:
		if (ip_len - hlen < (int)sizeof(struct tcphdr))
			return (NG_POLICY_PARSE_MALFORMED);
		th = ngp_at(m, off, sizeof(struct tcphdr), &scratch);
		if (th == NULL)
			return (NG_POLICY_PARSE_MALFORMED);
		meta->src_port = ntohs(th->th_sport);
		meta->dst_port = ntohs(th->th_dport);
		break;
	case IPPROTO_UDP:
		if (ip_len - hlen < (int)sizeof(struct udphdr))
			return (NG_POLICY_PARSE_MALFORMED);
		uh = ngp_at(m, off, sizeof(struct udphdr), &scratch);
		if (uh == NULL)
			return (NG_POLICY_PARSE_MALFORMED);
		if (ntohs(uh->uh_ulen) < (int)sizeof(struct udphdr) ||
		    ntohs(uh->uh_ulen) > ip_len - hlen)
			return (NG_POLICY_PARSE_MALFORMED);
		meta->src_port = ntohs(uh->uh_sport);
		meta->dst_port = ntohs(uh->uh_dport);
		break;
	case IPPROTO_ICMP:
		if (ip_len - hlen < 4)
			return (NG_POLICY_PARSE_MALFORMED);
		ic = ngp_at(m, off, 4, &scratch);
		if (ic == NULL)
			return (NG_POLICY_PARSE_MALFORMED);
		meta->icmp_type = ic[0];
		meta->icmp_code = ic[1];
		break;
	default:
		/*
		 * Any other IP protocol parses successfully with zero
		 * ports, so a rule may match it by protocol number.
		 * Waving it through as "unsupported" would let one
		 * configuration knob bypass policy wholesale.
		 */
		break;
	}
	return (NG_POLICY_PARSE_OK);
}
