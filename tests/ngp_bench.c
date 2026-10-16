/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 zombocoder <zombocoder@gmail.com>
 *
 * ng_policy - commit-cost and lookup-cost benchmarks.
 */

/*
 * ng_policy benchmarks.
 *
 * Commit cost is reported with the kernel's own phase timings, which is
 * the only way to separate the time userland spent sending rules from
 * the time the kernel spent building and validating them.
 *
 * Four things about these numbers are not what their field names
 * suggest -- see docs/performance.md for the full explanation of each:
 *
 *   1. reclaim_usec times only the NET_EPOCH_CALL() enqueue, not the
 *      grace period.  Reclamation is asynchronous; its real cost is not
 *      attributable to the commit that triggered it.
 *   2. validate_usec covers only the unlocked duplicate-id scan.  The
 *      locked struct-field and endpoint-reference validation pass
 *      happens earlier, still under the control mutex, and is not
 *      included in this figure.
 *   3. build_usec measures work done with the node's writer claim held
 *      but the control mutex dropped, using M_WAITOK.  A large commit
 *      can therefore sleep (on memory) while still holding off other
 *      writer work on the node; it does not fail the commit, but data
 *      items queue up behind it.
 *   4. The lookup benchmark's absolute numbers are dominated by socket
 *      round-trip overhead in userland and in ng_socket, not by
 *      ng_policy_match().  Only the delta between rule counts is
 *      meaningful.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <netgraph.h>

#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ngp_harness.h"

static uint64_t
usec_now(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000000 + tv.tv_usec);
}

/*
 * Send rules in chunks that fit comfortably in one control message.
 *
 * "Comfortably" is load-bearing: net.graph.maxdgram caps a single
 * netgraph control datagram at 20480 bytes by default (confirmed live
 * on this host with sysctl(8)), and struct ng_policy_rule is 32 bytes,
 * so a naive chunk of 1024 rules (32768 bytes of rules alone, before
 * the ng_mesg and ng_policy_tx_add_rule headers) overflows that limit
 * and NgSendMsg() fails with EMSGSIZE.  512 rules (16384 bytes of
 * rules, ~16440 with headers) leaves comfortable headroom under the
 * default 20480-byte cap.
 */
#define	BENCH_CHUNK	512

static int
bench_commit(struct ngp_ctx *c, uint32_t n)
{
	struct ng_policy_tx_begin_resp b;
	struct ng_policy_tx_commit_resp cr;
	struct ng_policy_tx_add_rule *ar;
	struct ng_policy_stats st;
	uint64_t t_send, t0;
	uint32_t i, chunk;
	size_t bufsz;
	uint8_t *buf;

	bufsz = sizeof(*ar) + BENCH_CHUNK * sizeof(struct ng_policy_rule);
	buf = malloc(bufsz);
	if (buf == NULL)
		return (-1);
	ar = (void *)buf;

	if (ngp_get_stats(c, &st) < 0 || ngp_begin(c, &b, 300) < 0) {
		free(buf);
		return (-1);
	}

	t0 = usec_now();
	for (i = 0; i < n; i += chunk) {
		uint32_t j;

		chunk = (n - i > BENCH_CHUNK) ? BENCH_CHUNK : n - i;
		memset(ar, 0, sizeof(*ar));
		ar->tx_id = b.tx_id;
		ar->nrules = chunk;
		for (j = 0; j < chunk; j++) {
			ar->rules[j].rule_id = i + j + 1;
			ar->rules[j].priority = (uint16_t)((i + j) % 4096);
			ar->rules[j].src_endpoint = 1000 + ((i + j) % 512);
			ar->rules[j].dst_endpoint = 2000 + ((i + j) % 512);
			ar->rules[j].protocol = NG_POLICY_PROTO_TCP;
			ar->rules[j].action = NG_POLICY_ALLOW;
			ar->rules[j].src_port_max = 65535;
			ar->rules[j].dst_port_min = 443;
			ar->rules[j].dst_port_max = 443;
		}
		if (ngp_msg(c, NGM_POLICY_TX_ADD_RULE, ar,
		    sizeof(*ar) + chunk * sizeof(struct ng_policy_rule)) < 0) {
			free(buf);
			ngp_msg(c, NGM_POLICY_TX_ABORT, &b.tx_id,
			    sizeof(b.tx_id));
			return (-1);
		}
	}
	t_send = usec_now() - t0;
	free(buf);

	if (ngp_setdef(c, b.tx_id, NG_POLICY_DROP) < 0 ||
	    ngp_commit(c, b.tx_id, st.generation, &cr) < 0) {
		/*
		 * A failed commit (stale generation, over a limit, etc.)
		 * leaves the transaction open in the kernel rather than
		 * consuming it; abort explicitly so it does not sit around
		 * holding tx_memory until its timeout, and so the next
		 * ngp_begin() in the loop is not competing with a leftover
		 * transaction for net.graph.policy.max_tx.
		 */
		ngp_msg(c, NGM_POLICY_TX_ABORT, &b.tx_id, sizeof(b.tx_id));
		return (-1);
	}

	printf("%8u  %10ju %10ju %10ju %10ju %12ju\n", n,
	    (uintmax_t)t_send, (uintmax_t)cr.validate_usec,
	    (uintmax_t)cr.build_usec, (uintmax_t)cr.commit_usec,
	    (uintmax_t)cr.memory);
	if (n > 0)
		printf("            (build: %ju ns/rule, memory: %ju"
		    " bytes/rule)\n",
		    (uintmax_t)(cr.build_usec * 1000 / n),
		    (uintmax_t)(cr.memory / n));
	return (0);
}

/*
 * Lookup cost, measured as the round trip of sending a frame and
 * reading it back, minus the same round trip with policy disabled.
 * Socket overhead dominates the absolute numbers, so only the delta
 * between rule counts is meaningful; that delta is what the index is
 * supposed to keep flat.
 *
 * At full send speed, NgSendData() can return ENOBUFS for a frame the
 * node already received, matched and counted: the three ENOBUFS return
 * paths in ng_socket.c are all on the *receive* side
 * (sbappendaddr_locked(&so->so_rcv, ...)), triggered when our own
 * userland recv() loop falls behind and the reply backs up in the data
 * socket's receive buffer.  This was established empirically in Task
 * 11 (see the packets_total == sent + sent_enobufs identity in
 * tests/ngp_test.c's test_concurrent_policy_replacement()).  So on
 * ENOBUFS here the send is not retried -- the frame was already
 * processed once -- and it is not tallied as a lost/dropped packet
 * either, since it was not: it is counted separately and the backlog
 * is drained before the loop continues, so it neither truncates the
 * requested iteration count nor silently distorts the timing.
 */
static uint64_t
bench_lookup(struct ngp_ctx *c, uint32_t iters, uint32_t *enobufs)
{
	uint8_t f[NGP_MAXFRAME], out[NGP_MAXFRAME];
	uint64_t t0;
	uint32_t i;
	size_t len;

	*enobufs = 0;
	len = ngp_tcp(f, 0x0a320110, 0x0a320210, 40000, 443);

	/* warm up */
	for (i = 0; i < 100; i++) {
		if (ngp_send(c, "d_ep", f, len) < 0) {
			if (errno == ENOBUFS)
				ngp_drain(c);
			continue;
		}
		(void)ngp_recv(c, NULL, 0, out, sizeof(out), 100);
	}

	t0 = usec_now();
	for (i = 0; i < iters; i++) {
		if (ngp_send(c, "d_ep", f, len) < 0) {
			if (errno != ENOBUFS)
				break;
			(*enobufs)++;
			ngp_drain(c);
			continue;
		}
		(void)ngp_recv(c, NULL, 0, out, sizeof(out), 100);
	}
	return (usec_now() - t0);
}

int
main(void)
{
	static const uint32_t sizes[] = { 100, 1000, 10000, 100000 };
	static const uint32_t lookup_sizes[] = { 0, 10, 100, 1000, 10000 };
	struct ngp_ctx c;
	struct ng_policy_addr a[1];
	size_t k;

	if (ngp_setup(&c) < 0)
		err(1, "ngp_setup");
	if (ngp_hook(&c, "d_ep", "ep-1001") < 0 ||
	    ngp_hook(&c, "d_fab", "fab-1001") < 0 ||
	    ngp_ep_add(&c, 1001, "ep-1001", "fab-1001", 0) < 0)
		err(1, "wiring");

	printf("\ncommit cost (microseconds)\n");
	printf("   rules   userland   validate      build     commit"
	    "       memory\n");
	for (k = 0; k < nitems(sizes); k++)
		if (bench_commit(&c, sizes[k]) < 0)
			warnx("commit of %u rules failed", sizes[k]);

	printf("\nlookup cost, %u round trips (microseconds)\n", 20000);
	memset(a, 0, sizeof(a));
	a[0].ipv4 = htonl(0x0a320210);
	a[0].endpoint_id = 2001;
	for (k = 0; k < nitems(lookup_sizes); k++) {
		struct ng_policy_rule *r;
		uint32_t n = lookup_sizes[k], i, enobufs;
		uint64_t us;

		if (n == 0) {
			if (ngp_install(&c, NULL, 0, a, 1, NG_POLICY_ALLOW) < 0)
				err(1, "install");
			if (ngp_set_mode(&c, NG_POLICY_MODE_DISABLED) < 0)
				err(1, "set_mode");
			us = bench_lookup(&c, 20000, &enobufs);
			printf("%8s  %10ju", "disabled", (uintmax_t)us);
			if (enobufs > 0)
				printf("   (%u ENOBUFS, drained)", enobufs);
			printf("\n");
			if (ngp_set_mode(&c, NG_POLICY_MODE_ENFORCE) < 0)
				err(1, "set_mode");
			continue;
		}
		r = calloc(n, sizeof(*r));
		if (r == NULL)
			err(1, "calloc");
		for (i = 0; i < n; i++) {
			r[i].rule_id = i + 1;
			r[i].priority = (uint16_t)(i % 4096);
			/*
			 * Non-matching rules, so the scan runs its
			 * full length.
			 */
			r[i].src_endpoint = 5000 + i;
			r[i].action = NG_POLICY_DROP;
			r[i].src_port_max = 65535;
			r[i].dst_port_max = 65535;
		}
		/* A final matching rule at the lowest priority. */
		r[n - 1].src_endpoint = 1001;
		r[n - 1].dst_endpoint = 2001;
		r[n - 1].action = NG_POLICY_ALLOW;
		r[n - 1].priority = 65535;

		{
			struct ng_policy_tx_begin_resp b;
			struct ng_policy_tx_commit_resp cr;
			struct ng_policy_tx_add_rule *ar;
			struct ng_policy_stats st;
			struct ng_policy_tx_add_addr *aa;
			uint8_t *buf;
			uint32_t off, chunk;

			buf = malloc(sizeof(*ar) +
			    BENCH_CHUNK * sizeof(*r));
			if (buf == NULL)
				err(1, "malloc");
			ar = (void *)buf;
			if (ngp_get_stats(&c, &st) < 0 ||
			    ngp_begin(&c, &b, 300) < 0)
				err(1, "begin");
			for (off = 0; off < n; off += chunk) {
				chunk = (n - off > BENCH_CHUNK) ?
				    BENCH_CHUNK : n - off;
				memset(ar, 0, sizeof(*ar));
				ar->tx_id = b.tx_id;
				ar->nrules = chunk;
				memcpy(ar->rules, r + off,
				    chunk * sizeof(*r));
				if (ngp_msg(&c, NGM_POLICY_TX_ADD_RULE, ar,
				    sizeof(*ar) + chunk * sizeof(*r)) < 0) {
					free(buf);
					free(r);
					err(1, "add rules");
				}
			}
			aa = (void *)buf;
			memset(aa, 0, sizeof(*aa));
			aa->tx_id = b.tx_id;
			aa->naddrs = 1;
			aa->addrs[0] = a[0];
			if (ngp_msg(&c, NGM_POLICY_TX_ADD_ADDR, aa,
			    sizeof(*aa) + sizeof(a[0])) < 0) {
				free(buf);
				free(r);
				err(1, "add addr");
			}
			if (ngp_setdef(&c, b.tx_id, NG_POLICY_DROP) < 0 ||
			    ngp_commit(&c, b.tx_id, st.generation, &cr) < 0) {
				free(buf);
				free(r);
				err(1, "commit");
			}
			free(buf);
		}
		free(r);

		us = bench_lookup(&c, 20000, &enobufs);
		printf("%8u  %10ju", n, (uintmax_t)us);
		if (enobufs > 0)
			printf("   (%u ENOBUFS, drained)", enobufs);
		printf("\n");
	}

	ngp_teardown(&c);
	return (0);
}
