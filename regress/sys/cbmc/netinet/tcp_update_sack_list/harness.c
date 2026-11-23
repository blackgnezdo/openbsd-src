/*
 * Harness: tcp_update_sack_list() of sys/netinet/tcp_input.c, the
 * receiver's list of SACK blocks to report (RFC 2018), updated after the
 * segment [rcv_laststart, rcv_lastend) arrived out of order.  A target
 * about correctness: the harness states the invariant the list keeps and
 * the result the function must produce, and asserts that the real
 * function preserves the one and delivers the other.
 *
 * Invariant of tp->rcv_numsacks / tp->sackblks[] after the call (INV):
 *   I1  0 <= rcv_numsacks <= MAX_SACK_BLKS (6);
 *   I2  every block i < rcv_numsacks is non-empty, SEQ_LT(start, end),
 *       and above rcv_nxt, SEQ_GT(start, rcv_nxt);
 *   I3  blocks are pairwise separated by a gap, SEQ_LT(end_i, start_j) or
 *       the reverse.  Touching blocks (end_i == start_j) are merged by
 *       the code: its "no overlap" test is SEQ_LT(sack.end, first.start)
 *       || SEQ_GT(sack.start, first.end), so equality overlaps.  A stored
 *       list therefore never holds two touching blocks;
 *   I4  entries at and above rcv_numsacks: all (0, 0) when rcv_numsacks
 *       is 0 (tcp_clean_sackreport), otherwise NOT specified.  The code
 *       only zeroes the entries it discards, then copies temp[] over the
 *       front of the list, so stale copies stay behind the end of a
 *       shortened list.  Nothing reads them.  The pair (0, 0) is the
 *       code's own sentinel for "discarded" inside its loops; a stored
 *       block is never (0, 0) because I2 makes it non-empty.
 * Order: block 0 is the newest segment, the rest in arrival order.
 *
 * Entry state (ENTRY): I1, I3, and per block either start > rcv_nxt
 * ("live") or end <= rcv_nxt ("stale").  rcv_nxt is never strictly
 * inside a block: it moves forward in tcp_reass() over whole queued
 * segments and a block is a union of queued segments; the function itself
 * only tests the end of a block against rcv_nxt.  Stale blocks make the
 * clean-up loop work.  Entries at and above rcv_numsacks are arbitrary.
 * Built by arithmetic, no __CPROVER_assume: the sequence space round
 * rcv_nxt is cut into regions of W = 16 numbers, list position i sits in
 * region i - S (S arbitrary 0..6: the S lowest blocks are below rcv_nxt),
 * and a block is [base + 1, base + 5) or [base + 12, base + 16), so
 * neighbours are at least one apart (never touching) and a stale block
 * can end exactly at rcv_nxt.  The harness asserts ENTRY itself before
 * the call, which checks the construction.
 *
 * Segment: either "old" (rcv_lastend <= rcv_nxt: tcp_reass() or the
 * in-order path moved rcv_nxt past it) or "new" (rcv_laststart > rcv_nxt).
 * A segment with rcv_laststart <= rcv_nxt < rcv_lastend cannot reach the
 * call, see "Caller".  Positions and lengths (SEGMIN .. 64) are symbolic,
 * so every order of the segment's ends against the block ends occurs,
 * touching included.
 *
 * Caller, sys/netinet/tcp_input.c:1945-1977 (tcp_input_solocked), inside
 * "if ((tlen || (tiflags & TH_FIN)) && !TCPS_HAVERCVDFIN)":
 *   laststart = th->th_seq        (1946)
 *   lastend   = th->th_seq + tlen (1947)
 * taken after the trims of 1301-1335 (the segment starts at or after
 * rcv_nxt) and 1357-1378 (it ends inside the window), then either
 * rcv_nxt += tlen (1954, in order, queue empty) or tcp_reass() (1968),
 * which may advance rcv_nxt over queued segments; the call is made only
 * if sack_enable and tcp_reass() did not fail (1976).  So lastend is
 * either <= rcv_nxt at the call, or the segment is above rcv_nxt.
 * tlen can be 0 there: the condition admits a FIN without data, and an
 * out-of-order FIN has th_seq > rcv_nxt, so the call gets
 * rcv_laststart == rcv_lastend > rcv_nxt, and block 0 is then empty
 * (I2 fails; FINDINGS).  SEGMIN is the minimum length: 1 proves INV,
 * 0 admits the empty segment.
 *
 * Postconditions, on the offsets from rcv_nxt (small integers):
 *   P0  INV;
 *   P1  block 0 covers [laststart, lastend) when laststart > rcv_nxt;
 *   P2  a sequence number covered by a live block before the call is
 *       covered by the list after it, except for the oldest block of a
 *       full list that the segment does not touch (the dropped one);
 *   P3  the list is the reference: if the segment is above rcv_nxt,
 *       block 0 is the hull of the segment and every live block that
 *       overlaps or touches it (SEQ_LEQ(start, lastend) && SEQ_GEQ(end,
 *       laststart)); behind it come old blocks the segment does not
 *       touch, unchanged, in order; the count is 1 + the untouched live
 *       blocks, cut at MAX_SACK_BLKS (only the oldest is dropped); if
 *       the segment is old, the list is the live blocks.
 *
 * Sizes: rcv_nxt is the constant -16 (0xfffffff0): the code only
 * compares sequence numbers by difference and tests a block against
 * (0, 0), so what matters is where the wrap and zero fall relative to
 * the blocks; with -16 both fall inside the live blocks (zero at
 * offset 16, the region boundary).  An arbitrary or 256-valued rcv_nxt
 * made every check time out (250 s, 80,000 variables) where the constant
 * solves in 11 s.  The list is in the order of sequence space (oldest
 * block lowest): swapping two neighbours made the checks time out as
 * well (200 s).  Not covered: other rcv_nxt, lists whose arrival order
 * differs from their order in sequence space (the merge of non-neighbours
 * with a block between that stays, the shift of a list with holes),
 * blocks longer than 4 or at other distances than 11, sequence space
 * differences of 2^31 and more.
 */
#include "tcp_input.c"
#include "cbmc_harness.h"

#ifndef SEGMIN
#define SEGMIN	1
#endif
#define W	16u

/* INV (exit_state) or ENTRY (otherwise) */
static void
check_list(const struct tcpcb *tp, int exit_state)
{
	const struct sackblk *a, *b;
	int i, j;

	__CPROVER_assert(tp->rcv_numsacks >= 0 &&
	    tp->rcv_numsacks <= MAX_SACK_BLKS, "I1: rcv_numsacks in range");
	for (i = 0; i < tp->rcv_numsacks && i < MAX_SACK_BLKS; i++) {
		a = &tp->sackblks[i];
		__CPROVER_assert(SEQ_LT(a->start, a->end),
		    "I2: block is empty or inverted");
		if (exit_state)
			__CPROVER_assert(SEQ_GT(a->start, tp->rcv_nxt),
			    "I2: block not above rcv_nxt");
		else
			__CPROVER_assert(SEQ_GT(a->start, tp->rcv_nxt) ||
			    SEQ_LEQ(a->end, tp->rcv_nxt),
			    "ENTRY: rcv_nxt inside a block");
		for (j = i + 1; j < tp->rcv_numsacks && j < MAX_SACK_BLKS;
		    j++) {
			b = &tp->sackblks[j];
			__CPROVER_assert(SEQ_LT(a->end, b->start) ||
			    SEQ_LT(b->end, a->start),
			    "I3: blocks overlap or touch");
		}
	}
	if (tp->rcv_numsacks == 0 && exit_state)
		for (i = 0; i < MAX_SACK_BLKS; i++)
			__CPROVER_assert(tp->sackblks[i].start == 0 &&
			    tp->sackblks[i].end == 0,
			    "I4: entry not zero in an empty list");
}

int
main(void)
{
	struct tcpcb *tp;
	int bs[MAX_SACK_BLKS], be[MAX_SACK_BLKS];	/* old blocks, offsets */
	int keep[MAX_SACK_BLKS];
	int n, nstale, nkeep = 0, nexp, o, i, j, k, f, t, merged = 0, found;
	int above, live, pick, ls, le, hs, he, xo, so, eo;
	tcp_seq laststart, lastend;
	u_int len;

	tp = CBMC_NEW(struct tcpcb);
	tp->rcv_nxt = (tcp_seq)-16;	/* see "Sizes" */

	n = nondet_uint() % (MAX_SACK_BLKS + 1);
	nstale = nondet_uint() % (MAX_SACK_BLKS + 1);
	for (i = 0; i < MAX_SACK_BLKS; i++) {
		bs[i] = be[i] = 0;
		if (i < n) {
			f = nondet_bool() ? 1 : 12;
			bs[i] = (i - nstale) * (int)W + f;
			be[i] = bs[i] + 4;
			tp->sackblks[i].start = tp->rcv_nxt + bs[i];
			tp->sackblks[i].end = tp->rcv_nxt + be[i];
		} else {
			/* behind the end of the list: anything */
			tp->sackblks[i].start = nondet_u32();
			tp->sackblks[i].end = nondet_u32();
		}
	}
	tp->rcv_numsacks = n;
	check_list(tp, 0);	/* ENTRY holds by construction */

	/* the segment, as offsets from rcv_nxt and as sequence numbers */
	len = SEGMIN + (nondet_uint() & (4 * W - 1));
	if (nondet_bool()) {
		ls = 1 + (nondet_uint() & (8 * W - 1));
		le = ls + len;
	} else {
		le = -(int)(nondet_uint() & (4 * W - 1));
		ls = le - len;
	}
	laststart = tp->rcv_nxt + ls;
	lastend = tp->rcv_nxt + le;

	/*
	 * Reference, on the offsets (small integers, no wrap-around to
	 * reason about) and without indexing by a symbolic value: keep[k]
	 * is "old block k stays in the list unchanged".
	 */
	above = ls > 0;
	o = above ? 1 : 0;
	hs = ls;
	he = le;
	for (k = 0; k < MAX_SACK_BLKS; k++) {
		live = k < n && be[k] > 0;
		t = above && bs[k] <= le && be[k] >= ls;
		keep[k] = live && !t;
		nkeep += keep[k];
		if (live && t) {
			merged = 1;
			if (bs[k] < hs)
				hs = bs[k];
			if (be[k] > he)
				he = be[k];
		}
	}
	nexp = o + nkeep;
	if (nexp > MAX_SACK_BLKS)
		nexp = MAX_SACK_BLKS;
	/* a point of a live block, for P2 */
	pick = nondet_uint() % MAX_SACK_BLKS;
	xo = 0;
	live = 0;
	for (k = 0; k < MAX_SACK_BLKS; k++)
		if (k == pick && k < n && be[k] > 0) {
			xo = bs[k] + (nondet_u32() & 3);
			live = xo < be[k];
		}

	tcp_update_sack_list(tp, laststart, lastend);

	check_list(tp, 1);				/* P0 */
	if (above) {					/* P1 */
		__CPROVER_assert(tp->rcv_numsacks >= 1,
		    "P1: no block for the new segment");
		__CPROVER_assert(SEQ_LEQ(tp->sackblks[0].start, laststart) &&
		    SEQ_GEQ(tp->sackblks[0].end, lastend),
		    "P1: block 0 does not cover the segment");
	}
	/* P2: not for the oldest live block of a full list, if dropped */
	if (live && !(above && !merged && nkeep == MAX_SACK_BLKS &&
	    pick == MAX_SACK_BLKS - 1)) {
		found = 0;
		for (j = 0; j < MAX_SACK_BLKS && j < tp->rcv_numsacks; j++) {
			so = (int)(tp->sackblks[j].start - tp->rcv_nxt);
			eo = (int)(tp->sackblks[j].end - tp->rcv_nxt);
			if (so <= xo && xo < eo)
				found = 1;
		}
		__CPROVER_assert(found,
		    "P2: a received number is lost from the list");
	}
	__CPROVER_assert(tp->rcv_numsacks == nexp,	/* P3 */
	    "P3: wrong number of blocks");
	if (above && tp->rcv_numsacks >= 1)
		__CPROVER_assert(
		    (int)(tp->sackblks[0].start - tp->rcv_nxt) == hs &&
		    (int)(tp->sackblks[0].end - tp->rcv_nxt) == he,
		    "P3: block 0 is not the hull");
	/*
	 * P3, rest of the list: each block behind block 0 is an old block
	 * the segment does not touch, and the order is kept (ascending, as
	 * the entry list is).  With the count and P2 this is the reference:
	 * the exact match block by block, with ranks, did not finish.
	 */
	for (j = o; j < MAX_SACK_BLKS && j < tp->rcv_numsacks; j++) {
		so = (int)(tp->sackblks[j].start - tp->rcv_nxt);
		eo = (int)(tp->sackblks[j].end - tp->rcv_nxt);
		found = 0;
		for (k = 0; k < MAX_SACK_BLKS; k++)
			if (keep[k] && so == bs[k] && eo == be[k])
				found = 1;
		__CPROVER_assert(found,
		    "P3: block is not an unchanged old block");
		if (j > o && j < tp->rcv_numsacks)
			__CPROVER_assert(SEQ_LT(tp->sackblks[j - 1].start,
			    tp->sackblks[j].start),
			    "P3: order of the old blocks not kept");
	}
	return (0);
}
