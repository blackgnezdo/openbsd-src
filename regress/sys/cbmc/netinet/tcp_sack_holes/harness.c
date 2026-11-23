/*
 * Harness: the sender's SACK scoreboard.  tcp_del_sackholes() followed by
 * tcp_sack_option() on one tcpcb, as tcp_input_solocked() does, on a
 * scoreboard of 0..MAXHOLES holes that satisfies the invariant below, and
 * a TCP header whose option area holds 0..2 SACK blocks of arbitrary
 * values.  The functional half of netinet/tcp_sack_option (which proves
 * memory safety only, on a scoreboard at fixed distances and one block).
 *
 * Order and what holds between the calls (tcp_input.c):
 *   tcp_input_solocked(): "if (tp->sack_enable) tcp_del_sackholes(tp, th)"
 *   (line 867), then, when the header has options, tcp_dooptions() (line
 *   878), which calls tcp_sack_option() once for every SACK option of the
 *   header (case TCPOPT_SACK, line 2226): possibly several times, each on
 *   the state the previous call left.  Between the two calls nothing
 *   touches snd_una, snd_max or the list: snd_una moves only in the ack
 *   processing below (lines 977, 1141, 1774), snd_max only in tcp_output.
 *   The invariant being preserved by each of the two functions therefore
 *   covers any number of SACK options; the harness drives one option of up
 *   to two blocks.  th_ack: nothing before line 867 constrains it (the
 *   check against snd_una and snd_max is made by tcp_sack_option() itself,
 *   and by tcp_input later), so it is an arbitrary 32 bit value, and
 *   th_flags is arbitrary (tcp_sack_option() wants TH_ACK).
 *
 * Invariant I (sequence numbers compared with SEQ_*, all in the window
 * [snd_una, snd_max], snd_max - snd_una < 2^31):
 *   - holes are ordered and disjoint: h->end < h->next->start (strict, a
 *     gap of at least one SACKed byte lies between two holes);
 *   - snd_una <= h->start, h->start < h->end for every hole except the
 *     head, whose start may equal its end (see FINDINGS 1 below);
 *     h->end <= snd_max;
 *   - h->start <= h->rxmit <= h->end (the code keeps rxmit through
 *     SEQ_MAX(rxmit, start), SEQ_MIN(rxmit, end) and "if rxmit < start
 *     rxmit = start"; the closed bound at end is real: tcp_sack_output
 *     tests SEQ_LT(rxmit, end) for "more to retransmit");
 *   - if the list is not empty: last->end < rcv_lastsack <= snd_max
 *     (so every hole lies in [snd_una, rcv_lastsack)); when it is empty
 *     rcv_lastsack is stale (nothing resets it) and arbitrary;
 *   - snd_numholes equals the length of the list when the list is not
 *     empty.  When it is empty, tcp_timer_freesack() (tcp_timer.c:183) may
 *     have emptied the list without resetting the count: arbitrary in
 *     0..TCP_SACKHOLE_LIMIT, and the first-hole path sets it to 1.  If
 *     the list was not empty before, the count is exact also when the
 *     functions empty it (check_inv(.., exact));
 *   - no hole is leaked, double freed or used after free: model_pool_get
 *     and model_pool_put count the live items of sackhl_pool, which must
 *     equal the length of the list after each call; the items are freed
 *     with CBMC's free, so a listed hole freed is a pointer check failure
 *     in check_inv, and --memory-leak-check (opts) covers the rest after
 *     the teardown at the end of main().  Natively (native.sh) the
 *     replace file does not reach pool_get and pool_put, which common/
 *     stubs_pool.c defines: the live count is not checked there, and the
 *     native leak check and ASan stand in for it.
 *
 * FINDINGS (read in FINDINGS, "SACK handling"), as seen by this target:
 *  1. Zero-length hole.  Real, but only as the head of the list: the
 *     first-hole path of tcp_sack_option() sets start = th_ack, end =
 *     sack.start, and sack.start == th_ack passes every guard before it.
 *     No other path makes a hole with start == end (every other write is
 *     bounded by a strict SEQ_LT / SEQ_GT or by the case analysis of the
 *     walk), and an empty hole only ever exists with no hole behind it
 *     when it is made.  Set EMPTY_HEAD_OK to 0 and the target is
 *     VIOLATED on "empty or inverted hole" (trace: empty list, th_ack ==
 *     sack.start); with 1 the invariant above is VERIFIED.
 *  2. Stale snd_numholes.  Real while the list is empty (tcp_timer_freesack
 *     does not reset it), and then never read: the paths that read it
 *     (the "snd_numholes >= TCP_SACKHOLE_LIMIT" tests) need a non-empty
 *     list, and the first-hole path assigns 1.  The count is exact in
 *     every non-empty list and exact when the functions empty a list that
 *     was exact (VERIFIED).  The harness starts the empty list with a
 *     stale count in 0..TCP_SACKHOLE_LIMIT.
 *  3. rcv_lastsack: the invariant it relies on is the one stated above
 *     (last->end < rcv_lastsack <= snd_max when the list is not empty);
 *     it is established by the first-hole and append paths and kept by
 *     every other write.  It is not "the highest sacked sequence number":
 *     a block that overlaps the end of the last hole and extends past
 *     rcv_lastsack (deleting or trimming the last hole) leaves
 *     rcv_lastsack where it was.
 *
 * Sizes: gaps and hole lengths are 0..65535 (+1) bytes, built by masking
 * (no division); snd_una is any 32 bit value, snd_max - last end up to
 * 2^30, rcv_lastsack stale-arbitrary when the list is empty.  The SACK
 * block values are arbitrary 32 bit values read from the option bytes.
 * t_maxseg is the constant 512 (tcp_mssdflt): it only divides sequence
 * differences into dups, and a symbolic divisor costs the solver most of
 * the time; dups is not asserted.  t_state ESTABLISHED (the code only
 * tests it against LISTEN, which tcp_input panics on).  Not covered:
 * the "snd_numholes >= TCP_SACKHOLE_LIMIT" exits (the limit, 128, is out
 * of reach of a list of at most MAXHOLES + 2 holes) and more than two
 * blocks per call (the real maximum is four).
 *
 * snd_nxt is set to a value in [snd_una, snd_max] as the caller keeps it;
 * neither function reads it.
 */
#include "tcp_input.c"
#include "cbmc_harness.h"

/* CBMC's free for objects of CBMC_NEW (kernel free(9) is kfree here) */
#undef free
void free(void *);
static void
harness_release(void *p)
{
	free(p);
}
#define free kfree

#define EMPTY_HEAD_OK	1	/* 0: see FINDINGS 1 in the comment */

#define MAXHOLES	3	/* before the call */
#define MAXBLOCKS	1
#define MAXLIST		(MAXHOLES + MAXBLOCKS)	/* each block adds one hole */
#define MAXOPT		(2 + MAXBLOCKS * TCPOLEN_SACK)

struct pool sackhl_pool;
static int live;	/* sackhl_pool items outstanding */

/* sackhl_pool items: typed, see README "Adding a target", step 3 */
void *
model_pool_get(struct pool *pp, int flags)
{
	__CPROVER_assert(pp == &sackhl_pool, "pool_get on an unexpected pool");
	__CPROVER_assert(flags == PR_NOWAIT, "pool_get flags");
	if (nondet_bool())
		return (NULL);
	live++;
	return (CBMC_NEW(struct sackhole));
}

void
model_pool_put(struct pool *pp, void *v)
{
	__CPROVER_assert(pp == &sackhl_pool, "pool_put on an unexpected pool");
	__CPROVER_assert(v != NULL, "pool_put of NULL");
	live--;
	harness_release(v);
}

/*
 * Invariant I.  exact: snd_numholes must match also for an empty list.
 * Returns the length of the list.
 */
static int
check_inv(struct tcpcb *tp, int exact)
{
	struct sackhole *h, *last = NULL;
	int n = 0;

	for (h = tp->snd_holes; h != NULL; h = h->next) {
		n++;
		__CPROVER_assert(n <= MAXLIST,
		    "hole list longer than blocks seen, or cyclic");
		if (EMPTY_HEAD_OK && h == tp->snd_holes)
			__CPROVER_assert(SEQ_LEQ(h->start, h->end),
			    "inverted head hole");
		else
			__CPROVER_assert(SEQ_LT(h->start, h->end),
			    "empty or inverted hole");
		__CPROVER_assert(SEQ_GEQ(h->start, tp->snd_una),
		    "hole starts before snd_una");
		__CPROVER_assert(SEQ_LEQ(h->end, tp->snd_max),
		    "hole ends after snd_max");
		__CPROVER_assert(SEQ_GEQ(h->rxmit, h->start),
		    "rxmit before start of hole");
		__CPROVER_assert(SEQ_LEQ(h->rxmit, h->end),
		    "rxmit after end of hole");
		if (h->next != NULL)
			__CPROVER_assert(SEQ_LT(h->end, h->next->start),
			    "holes overlap, touch or are out of order");
		last = h;
	}
	if (last != NULL) {
		__CPROVER_assert(SEQ_LT(last->end, tp->rcv_lastsack),
		    "rcv_lastsack not above the last hole");
		__CPROVER_assert(SEQ_LEQ(tp->rcv_lastsack, tp->snd_max),
		    "rcv_lastsack above snd_max");
	}
	__CPROVER_assert(SEQ_LEQ(tp->snd_una, tp->snd_max),
	    "snd_una above snd_max");
	if (n > 0 || exact)
		__CPROVER_assert(tp->snd_numholes == n,
		    "snd_numholes does not match the hole list");
#ifndef NATIVE_SHIM_H
	/* natively the common pool_get/pool_put run, not the models */
	__CPROVER_assert(live == n, "hole leaked or freed while listed");
#endif
	return (n);
}

/* a value in 0..65535 */
static u_int32_t
rnd(void)
{
	return (nondet_u32() & 0xffff);
}

int
main(void)
{
	struct tcpcb *tp;
	struct tcphdr *th;
	struct sackhole *h, *prev, *next;
	u_char *block, *cp;
	int optlen, k, i, exact;
	u_int32_t off, len, r, d;

	sackhl_pool.pr_size = sizeof(struct sackhole);

	/*
	 * Header and option as one object of constant size, the option
	 * ending exactly at the end of the object: optlen bytes behind the
	 * header, one byte more is outside the object (as in
	 * netinet/tcp_sack_option).  0, 1 or 2 SACK blocks.
	 */
	optlen = 2 + TCPOLEN_SACK * (nondet_uint() % (MAXBLOCKS + 1));
	block = malloc(sizeof(struct tcphdr) + MAXOPT, M_DEVBUF, M_WAITOK);
	th = (struct tcphdr *)(block + (MAXOPT - optlen));
	cp = block + sizeof(struct tcphdr) + (MAXOPT - optlen);
	cp[0] = TCPOPT_SACK;
	cp[1] = optlen;

	tp = CBMC_NEW(struct tcpcb);
	tp->t_state = TCPS_ESTABLISHED;
	tp->t_maxseg = 512;
	tp->sack_enable = nondet_bool() ? 1 : 0;
	tp->snd_una = nondet_u32();

	/* a list of k holes, built by arithmetic from snd_una */
	k = tp->sack_enable ? nondet_uint() % (MAXHOLES + 1) : 0;
	off = 0;
	prev = NULL;
	for (i = 0; i < k; i++) {
		h = CBMC_NEW(struct sackhole);
		live++;
		off += rnd() + (i > 0 ? 1 : 0);	/* gap before; >= 1 between */
		h->start = tp->snd_una + off;
		len = rnd() + ((i > 0 || !EMPTY_HEAD_OK) ? 1 : 0);	/* the head may be empty */
		off += len;
		h->end = tp->snd_una + off;
		r = rnd();
		if (r > len)
			r = len;
		h->rxmit = h->start + r;	/* start <= rxmit <= end */
		h->dups = 1 + (nondet_uint() & 1);
		if (prev == NULL)
			tp->snd_holes = h;
		else
			prev->next = h;
		prev = h;
	}
	if (k > 0) {
		off += rnd() + 1;
		tp->rcv_lastsack = tp->snd_una + off;
		tp->snd_numholes = k;
	} else {
		tp->rcv_lastsack = nondet_u32();	/* stale */
		tp->snd_numholes = nondet_uint() % (TCP_SACKHOLE_LIMIT + 1);
	}
	tp->snd_max = tp->snd_una + off + (nondet_u32() & 0x3fffffff);
	d = tp->snd_max - tp->snd_una;
	r = nondet_u32();
	tp->snd_nxt = tp->snd_una + (r > d ? d : r);
	exact = (k > 0);

	/* tcp_input_solocked() does this before tcp_dooptions() */
	if (tp->sack_enable)
		tcp_del_sackholes(tp, th);
	check_inv(tp, exact);

	tcp_sack_option(tp, th, cp, optlen);
	check_inv(tp, exact);

	/* teardown, as tcp_close() does */
	for (h = tp->snd_holes; h != NULL; h = next) {
		next = h->next;
		pool_put(&sackhl_pool, h);
	}
	tp->snd_holes = NULL;
#ifndef NATIVE_SHIM_H
	__CPROVER_assert(live == 0, "sackhl_pool items outstanding");
#endif
	harness_release(tp);
	free(block, M_DEVBUF, 0);
	return (0);
}
