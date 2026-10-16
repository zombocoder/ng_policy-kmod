/*
 * ng_policy fuzzer.  Drives randomised control messages and randomised
 * frames through a live node.  Success is defined negatively: the
 * kernel must not panic, must not leak, and must keep answering.
 *
 * Usage: ngp_fuzz [seed] [iterations]
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/time.h>

#include <netgraph.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ngp_harness.h"

static uint32_t rng_state;

static uint32_t
rnd(void)
{

	/* xorshift32: tiny, reproducible, good enough to shake a parser. */
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return (rng_state);
}

static uint32_t
rnd_below(uint32_t n)
{

	return (n != 0 ? rnd() % n : 0);
}

/*
 * How long to wait, once, for a reply that might still be in flight
 * before concluding there isn't one.  This control path processes
 * messages synchronously (see the existing harness helpers, which never
 * wait), so any reply is already queued on the socket by the time
 * NgSendMsg() returns; this is a hedge against scheduling jitter, not a
 * real processing delay, so it can be small.  A late reply is never
 * lost even if this window is too short: it sits on the socket and the
 * *next* drain_control() call picks it up on its non-blocking backlog
 * pass.
 */
#define	NGP_DRAIN_WAIT_USEC	300

/*
 * Drain replies from the control socket without ever blocking
 * indefinitely.  Most fuzzed commands produce no reply at all -- the
 * node rejects a bad command or length synchronously and simply never
 * calls NG_RESPOND_MSG -- so a bare, unconditional NgRecvMsg() wedges
 * the fuzzer forever waiting for a reply that will never arrive.
 *
 * "wait" is false when the caller already knows nothing can possibly
 * be queued (the send itself failed, so the node never even saw the
 * message): skip the hedge wait entirely and only check for backlog
 * from an earlier call.
 */
static void
drain_control(struct ngp_ctx *c, int wait)
{
	union {
		struct ng_mesg m;
		u_char buf[16384];
	} u;
	struct timeval tv;
	fd_set rfds;
	int first;

	for (first = 1; ; first = 0) {
		FD_ZERO(&rfds);
		FD_SET(c->cs, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = (first && wait) ? NGP_DRAIN_WAIT_USEC : 0;
		if (select(c->cs + 1, &rfds, NULL, NULL, &tv) <= 0)
			break;
		if (NgRecvMsg(c->cs, &u.m, sizeof(u), NULL) < 0)
			break;
	}
}

/* Send a message with a deliberately arbitrary command, length and body. */
static void
fuzz_control(struct ngp_ctx *c)
{
	static const int cmds[] = {
		NGM_POLICY_GET_CONFIG, NGM_POLICY_SET_CONFIG,
		NGM_POLICY_SET_MODE, NGM_POLICY_ENDPOINT_ADD,
		NGM_POLICY_ENDPOINT_DEL, NGM_POLICY_ENDPOINT_LIST,
		NGM_POLICY_TX_BEGIN, NGM_POLICY_TX_ADD_RULE,
		NGM_POLICY_TX_ADD_ADDR, NGM_POLICY_TX_SET_DEFAULT,
		NGM_POLICY_TX_COMMIT, NGM_POLICY_TX_ABORT,
		NGM_POLICY_GET_STATS, NGM_POLICY_GET_ENDPOINT_STATS,
		NGM_POLICY_GET_RULE_STATS, NGM_POLICY_RESET_STATS,
		99, 0, -1,
	};
	uint8_t buf[512];
	size_t len;
	int cmd, sent;
	size_t i;

	cmd = cmds[rnd_below(nitems(cmds))];
	len = rnd_below(sizeof(buf) + 1);
	for (i = 0; i < len; i++)
		buf[i] = (uint8_t)rnd();
	/*
	 * Half the time, plant a plausible tx_id and a huge count in the
	 * first sixteen bytes, which is where the batched messages keep
	 * the fields whose arithmetic must not overflow.
	 */
	if (len >= 16 && (rnd() & 1) != 0) {
		uint64_t txid = rnd_below(4);
		uint32_t n = (rnd() & 1) ? 0xffffffffu : rnd_below(100000);

		memcpy(buf, &txid, sizeof(txid));
		memcpy(buf + 12, &n, sizeof(n));
	}
	sent = NgSendMsg(c->cs, c->path, NGM_POLICY_COOKIE, cmd, buf, len);
	/*
	 * Drain any reply so the socket buffer cannot fill, without
	 * blocking forever on commands that produce none.  If the send
	 * itself failed, the node never queued the message, so nothing
	 * will ever reply to it -- don't wait, just check for backlog
	 * from an earlier iteration.
	 */
	drain_control(c, sent >= 0);
}

/* Send a frame that is valid-ish, then corrupt it. */
static void
fuzz_frame(struct ngp_ctx *c)
{
	uint8_t f[NGP_MAXFRAME];
	size_t len, i, nmut;

	switch (rnd_below(6)) {
	case 0:
		len = ngp_tcp(f, rnd(), rnd(), rnd(), rnd());
		break;
	case 1:
		len = ngp_udp(f, rnd(), rnd(), rnd(), rnd());
		break;
	case 2:
		len = ngp_icmp(f, rnd(), rnd(), rnd(), rnd());
		break;
	case 3:
		len = ngp_arp(f);
		break;
	case 4:
		len = ngp_frag(f, rnd(), rnd(), rnd_below(8192), rnd() & 1);
		break;
	default:
		len = ngp_eth(f, (uint16_t)rnd());
		{
			size_t extra = rnd_below(64);
			size_t j;

			/*
			 * ngp_eth() only writes its 14-byte header; fill the
			 * extra tail explicitly instead of extending len over
			 * whatever this stack buffer held from the previous
			 * call, which is correlated stale data, not entropy.
			 */
			for (j = 0; j < extra; j++)
				f[len + j] = (uint8_t)rnd();
			len += extra;
		}
		break;
	}
	/* Truncate sometimes: a short frame is the classic parser killer. */
	if ((rnd() & 3) == 0)
		len = rnd_below(len + 1);
	/* Flip a few bytes. */
	nmut = rnd_below(6);
	for (i = 0; i < nmut && len > 0; i++)
		f[rnd_below(len)] = (uint8_t)rnd();

	(void)ngp_send(c, (rnd() & 1) ? "d_ep" : "d_fab", f, len);
	ngp_drain(c);
}

/*
 * How often to check in with the node and print progress.  Kept short
 * (rather than the round number an untimed eyeball might reach for) so
 * that a wedge shows up as missing output within seconds, not after a
 * fifth of the run has silently gone nowhere.
 */
#define	NGP_FUZZ_PROGRESS_EVERY	5000

static double
ngp_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec + ts.tv_nsec / 1e9);
}

int
main(int argc, char **argv)
{
	struct ngp_ctx c;
	struct ng_policy_stats st;
	uint32_t iters, i, last_i;
	double t_start, t_last;

	/*
	 * Redirected to a file (as it will be for any long campaign),
	 * stdio fully-buffers by default and nothing appears until the
	 * process exits cleanly.  That is exactly what made an earlier
	 * wedge indistinguishable from slowness: the process sat blocked
	 * with zero output for the whole run.  Line-buffer so progress
	 * is visible as it happens.
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);

	rng_state = (argc > 1) ? (uint32_t)strtoul(argv[1], NULL, 0) : 12345;
	if (rng_state == 0)
		rng_state = 1;
	iters = (argc > 2) ? (uint32_t)strtoul(argv[2], NULL, 0) : 200000;
	printf("seed %u, %u iterations\n", rng_state, iters);

	if (ngp_setup(&c) < 0)
		err(1, "ngp_setup");
	if (ngp_hook(&c, "d_ep", "ep-1001") < 0 ||
	    ngp_hook(&c, "d_fab", "fab-1001") < 0 ||
	    ngp_ep_add(&c, 1001, "ep-1001", "fab-1001", 0) < 0)
		err(1, "wiring");

	t_start = t_last = ngp_now();
	last_i = 0;
	for (i = 0; i < iters; i++) {
		if ((rnd() & 3) == 0)
			fuzz_control(&c);
		else
			fuzz_frame(&c);
		if ((i % NGP_FUZZ_PROGRESS_EVERY) == 0) {
			double now;
			uint32_t delta;

			/* The node must still be answering. */
			if (ngp_get_stats(&c, &st) < 0)
				err(1, "node stopped responding at %u", i);
			now = ngp_now();
			delta = i - last_i;
			printf("  %u iterations, %ju packets seen, "
			    "%.0f iter/s (avg), %.0f iter/s (recent)\n", i,
			    (uintmax_t)st.packets_total,
			    (now > t_start) ? i / (now - t_start) : 0.0,
			    (delta > 0 && now > t_last) ?
			    delta / (now - t_last) : 0.0);
			t_last = now;
			last_i = i;
		}
	}

	/*
	 * The last fuzz_control() call above may not yet have had its
	 * reply queued when its own drain_control() ran: a reply lands on
	 * the socket in FIFO order, so if it arrives late it would
	 * otherwise be consumed by the GET_STATS call below instead of
	 * the real GET_STATS response, making a live node look dead.
	 * Drain (waiting form) once more before checking in.
	 */
	drain_control(&c, 1);
	if (ngp_get_stats(&c, &st) < 0)
		err(1, "node stopped responding");
	printf("survived: %ju packets, %ju malformed, %ju unsupported\n",
	    (uintmax_t)st.packets_total, (uintmax_t)st.malformed_packets,
	    (uintmax_t)st.unsupported_packets);
	ngp_teardown(&c);
	return (0);
}
