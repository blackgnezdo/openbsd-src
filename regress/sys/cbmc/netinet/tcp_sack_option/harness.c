/*
 * Harness: tcp_sack_option() on an arbitrary SACK option and a connection
 * state with 0..MAXHOLES holes.  The SACK half of the split whose walk
 * half is netinet/tcp_dooptions (there tcp_sack_option is a model that
 * asserts the contract used here).
 *
 * Properties: no read outside the option (heap object of exactly optlen
 * bytes behind the header), the hole list is never indexed or followed
 * outside the objects of the list, no freed hole is touched, the loops
 * terminate, and afterwards the list is ordered, non-overlapping and
 * inside [snd_una, snd_max] with snd_numholes matching it (check_holes).
 *
 * Contract from tcp_dooptions() (assumed here, asserted by the model in
 * the walk target): cp[0] == TCPOPT_SACK, cp[1] == optlen, 2 <= optlen <=
 * 40 (cnt <= 40), [cp, cp + optlen) readable; th is the TCP header
 * (th_flags, th_ack arbitrary: the function checks both).  tcp_dooptions
 * gets tp from tcp_input_solocked() or syn_cache_add().  From
 * syn_cache_add() (pure SYN, no ACK) tcp_sack_option returns at the ACK
 * test; that site is not modelled here.  tcp_input_solocked() calls
 * tcp_del_sackholes() just before tcp_dooptions(); the harness does too.
 *
 * State of tp, and where the kernel establishes it:
 *   t_state not CLOSED and not LISTEN: tcp_input drops CLOSED, panics on
 *	LISTEN.  The harness uses ESTABLISHED, see "Sizes".
 *   t_maxseg != 0: tcp_newtcpcb() sets it to tcp_mssdflt, tcp_mss() keeps
 *	it >= 64; tcp_sack_option() panics ("Should never happen") on 0.
 *	The harness uses 512, see "Sizes".
 *   snd_max - snd_una in 0..2^31-1 (sequence space order): snd_max never
 *	moves back, snd_una only moves to acks in [snd_una, snd_max].
 *   sack_enable 0 or 1; no holes unless sack_enable (holes are only made
 *	by tcp_sack_option(), which returns when !sack_enable).
 *   hole list: 0..MAXHOLES holes in tcp_seq space (fixed distances from
 *	snd_una in the harness)
 *	snd_una <= h0.start < h0.end < h1.start < h1.end < rcv_lastsack
 *	<= snd_max, dups in 1..tcprexmtthresh (harness: 1), start <= rxmit <= end
 *	(harness: rxmit == start).  See
 *	the check_holes() comment for the places in tcp_sack_option() that
 *	establish these; start >= snd_una by tcp_del_sackholes().
 *   snd_numholes == length of the list when the list is not empty.  When
 *	it is empty snd_numholes is arbitrary in 0..TCP_SACKHOLE_LIMIT:
 *	tcp_timer_freesack() empties the list without resetting the count
 *	(the first-hole path of tcp_sack_option() sets it to 1 again).
 *   everything else of tp is zero.
 *
 * Environment models: pool_get(&sackhl_pool, PR_NOWAIT) returns a typed
 * hole or fails; tcpstat_inc (statistics) has no body.
 *
 * Sizes: MAXOPT = 10: one SACK block (the real maximum is 40: four
 * blocks).  MAXHOLES = 2 holes before the call, so one block meets every
 * position in a list of two (head, tail, between) and may add one more.
 * Larger configurations did not finish within the time limit: 40 bytes,
 * 2 holes: cover run timeout at 4.7 million SAT variables; 18 bytes,
 * 2 holes: 1.7 million variables in the check run, timeout.
 * TCP_SACKHOLE_LIMIT (128) cannot be reached with that, the
 * "snd_numholes >= TCP_SACKHOLE_LIMIT" exits are not covered.  Not covered
 * either: two blocks in one call (state left by the first block).
 * The hole boundaries are fixed distances from snd_una (H0_START ...
 * SND_MAX: 16, 32, 48, 64, rcv_lastsack 48 or 80, snd_max 96), snd_una
 * itself is arbitrary.  The code only compares sequence numbers, and the
 * option values and th_ack are arbitrary 32-bit values, so every order of
 * a block's start and end and of th_ack against the boundaries occurs;
 * boundaries at other distances give the same orders.  Symbolic
 * boundaries (sorted, with gaps) made the postcondition proofs time out.
 * Not covered: boundaries that are adjacent (end + 1 == next start).
 * The head hole is empty (start == end) or not.
 * To keep the solver within the time limit t_state is ESTABLISHED (the
 * code only tests it against LISTEN in tcp_del_sackholes), dups is 1 and
 * rxmit is start in the initial holes (both are only written or compared
 * by the code, never used as an index or pointer; rxmit is not asserted).
 * t_maxseg is the constant 512 (tcp_mssdflt) instead of any non-zero
 * value: it only divides sequence differences into dups (the divisions
 * with a symbolic divisor cost most of the solver time), dups is not used
 * for any index or pointer.  Not covered: t_maxseg other than 512.
 */
#include "tcp_input.c"
#include "cbmc_harness.h"


#define MAXOPT		10
#define MAXHOLES	2
/* offsets from snd_una, see "Sizes" */
#define H0_START	16
#define H0_END		32
#define H1_START	48
#define H1_END		64
#define LASTSACK1	48	/* rcv_lastsack with one hole */
#define LASTSACK2	80	/* with two */
#define SND_MAX		96

struct pool sackhl_pool;

/* sackhl_pool items: typed, see README "Adding a target", step 3 */
void *
model_pool_get(struct pool *pp, int flags)
{
	__CPROVER_assert(pp == &sackhl_pool, "pool_get on an unexpected pool");
	__CPROVER_assert(flags == PR_NOWAIT, "pool_get flags");
	if (nondet_bool())
		return (NULL);
	return (CBMC_NEW(struct sackhole));
}

/*
 * Postcondition.  A hole may be empty (start == end): the first-hole path
 * of tcp_sack_option() sets start = th_ack, end = sack.start, and the
 * checks before it accept sack.start == th_ack (SEQ_LT(sack.start,
 * th_ack) and SEQ_LT(sack.start, snd_una) only reject smaller values).  A
 * peer sends it as a SACK block that starts at the cumulative ack.  Every
 * other way to make or change a hole keeps start < end, and the empty hole
 * is the head of the list (made when the list was empty).  The check is
 * therefore start <= end here, and the generator of main() makes the head
 * hole empty too.
 */
static void
check_holes(struct tcpcb *tp)
{
	struct sackhole *h;
	int n = 0;

	for (h = tp->snd_holes; h != NULL; h = h->next) {
		n++;
		__CPROVER_assert(n <= MAXHOLES + MAXOPT / TCPOLEN_SACK,
		    "hole list longer than blocks seen, or cyclic");
		__CPROVER_assert(SEQ_LEQ(h->start, h->end),
		    "inverted hole");
		__CPROVER_assert(SEQ_GEQ(h->start, tp->snd_una),
		    "hole starts before snd_una");
		__CPROVER_assert(SEQ_LEQ(h->end, tp->snd_max),
		    "hole ends after snd_max");
		if (h->next != NULL)
			__CPROVER_assert(SEQ_LT(h->end, h->next->start),
			    "holes overlap or are out of order");
	}
	if (tp->snd_holes != NULL)
		__CPROVER_assert(tp->snd_numholes == n,
		    "snd_numholes does not match the hole list");
}

int
main(void)
{
	struct tcpcb *tp;
	struct tcphdr *th;
	u_char *block, *cp;
	int optlen, k;

	sackhl_pool.pr_size = sizeof(struct sackhole);

	/*
	 * Header and option as one object of constant size, the option
	 * ending exactly at the end of the object (an object of symbolic
	 * size is expensive for the solver): optlen bytes behind the
	 * header, one byte more is outside the object.
	 */
	optlen = 2 + nondet_uint() % (MAXOPT - 1);
	block = malloc(sizeof(struct tcphdr) + MAXOPT, M_DEVBUF, M_WAITOK);
	th = (struct tcphdr *)(block + (MAXOPT - optlen));
	cp = block + sizeof(struct tcphdr) + (MAXOPT - optlen);
	cp[0] = TCPOPT_SACK;
	cp[1] = optlen;

	tp = CBMC_NEW(struct tcpcb);
	tp->t_state = TCPS_ESTABLISHED;	/* see "Sizes" */
	tp->t_maxseg = 512;	/* tcp_mssdflt; see "Sizes" */
	tp->sack_enable = nondet_bool() ? 1 : 0;
	tp->snd_una = nondet_u32();
	tp->snd_max = tp->snd_una + SND_MAX;
	tp->snd_numholes = nondet_uint() % (TCP_SACKHOLE_LIMIT + 1);
	tp->rcv_lastsack = nondet_u32();

	k = tp->sack_enable ? nondet_uint() % (MAXHOLES + 1) : 0;
	if (k > 0) {
		struct sackhole *h0, *h1;

		h0 = CBMC_NEW(struct sackhole);
		h0->start = tp->snd_una + H0_START;
		h0->end = nondet_bool() ? h0->start : tp->snd_una + H0_END;
		h0->dups = 1;
		h0->rxmit = h0->start;
		tp->snd_holes = h0;
		tp->rcv_lastsack = tp->snd_una + LASTSACK1;
		if (k > 1) {
			h1 = CBMC_NEW(struct sackhole);
			h1->start = tp->snd_una + H1_START;
			h1->end = tp->snd_una + H1_END;
			h1->dups = 1;
			h1->rxmit = h1->start;
			h0->next = h1;
			tp->rcv_lastsack = tp->snd_una + LASTSACK2;
		}
		tp->snd_numholes = k;
	}
	/* tcp_input_solocked() does this before tcp_dooptions() */
	if (tp->sack_enable)
		tcp_del_sackholes(tp, th);

	tcp_sack_option(tp, th, cp, optlen);

	check_holes(tp);
	return (0);
}
