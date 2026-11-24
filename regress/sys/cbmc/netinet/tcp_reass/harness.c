/*
 * Harness: tcp_reass() of sys/netinet/tcp_input.c, with the tcp_flush_queue()
 * it ends in, on a reassembly queue of 0..2 entries and one new segment, on
 * the mbuf contract models (common/mbufcontract.h).
 *
 * What the code does: tcp_reass() takes a queue entry from tcpqe_pool (on
 * failure it drops the segment and the queue, or reuses the last entry when
 * the segment is the next in sequence), finds the entry q that starts after
 * the new segment and its predecessor p, trims the head of the new segment
 * by what p already holds (or drops the segment if p holds all of it), trims
 * or dequeues the entries the new segment overlaps, inserts the entry, and,
 * if the segment starts at rcv_nxt, tcp_flush_queue() hands every entry that
 * continues at rcv_nxt to the socket buffer (sbappendstream) and advances
 * rcv_nxt.  What is stored: th_seq (first sequence number held), th_reseqlen
 * (= th_urp, the number of data bytes held, FIN not counted) in the entry's
 * struct tcphdr, and the mbuf chain; tcpqe_tcp points at the header.
 *
 * Caller contract, tcp_input_solocked() in sys/netinet/tcp_input.c:
 *   - th points into the first mbuf, before the data: th = ip6_exthdr_get()
 *     (433, 519) is contiguous in the first mbuf and m_adj(m, hdroptlen)
 *     (1967) only advances m_data past it (hdroptlen = iphlen + off, 1074,
 *     plus the head duplicate bytes, 1331), the header stays in the
 *     buffer; the mbuf stays on the chain, so th lives as long as the
 *     chain does.  Here: the first mbuf's buffer is a struct seg (header,
 *     then 8 data bytes, the data ending at the end of the object).
 *   - tlen is the number of data bytes of the chain: tlen = m_pkthdr.len -
 *     iphlen (441) - off (517), and every later reduction of tlen comes
 *     with an m_adj of the same size: 1221/1222 (m_adj(m, -todrop)), 1331-
 *     1333 (hdroptlen += todrop, dropped by the m_adj at 1967), 1377-1379.
 *     So after 1967: m_pkthdr.len == sum of m_len == tlen, 0 <= tlen.
 *   - th_seq >= rcv_nxt (sequence order): 1280-1334 trim a segment that
 *     starts below rcv_nxt to start at rcv_nxt (or empty it, then
 *     (tlen || FIN) at 1945 is false and tcp_reass is not called).
 *     The harness uses th_seq - rcv_nxt in 0..NMAX-1, rcv_nxt arbitrary.
 *   - tcp_reass is called (1968) when not (th_seq == rcv_nxt && queue
 *     empty && ESTABLISHED) (1950); the harness also lets that case in.
 *   - tcp_reass owns m: it is queued or freed.  th_urp (th_reseqlen)
 *     holds the urgent pointer, arbitrary, tcp_reass overwrites it (283).
 *   - t_state >= ESTABLISHED and < TIME_WAIT (1945: HAVERCVDFIN false;
 *     the ACK step before it moved SYN_RECEIVED to ESTABLISHED).
 *   - the end of the segment is inside the window: not read by tcp_reass,
 *     not modelled.
 *
 * Queue invariant (check_queue, asserted before and after the call):
 *   entries in sequence order, no two overlap: (th_seq + th_reseqlen) of
 *   an entry <= th_seq of the next, in sequence (int) arithmetic.  An
 *   entry may be empty (th_reseqlen 0: a FIN without data; the code makes
 *   one when tlen == 0), so two entries may have the same th_seq.  Every
 *   entry has th_seq above rcv_nxt (strictly; after a delivery that
 *   ended in a FIN, tcp_flush_queue stops and the head may sit at rcv_nxt:
 *   then >=).  th_reseqlen equals the length of the mbuf chain
 *   (m_pkthdr.len = sum of m_len); tcpqe_tcp is the header in the first
 *   mbuf's buffer.  The queue before the call is built by arithmetic to
 *   satisfy it, and the generated queue is checked.
 *
 * Delivery and coverage: every segment carries content that names its
 * position: the byte at stream position x holds (u_char)(x - rcv_nxt0)
 * (retransmitted bytes are equal, as in TCP; positions stay below 64).  One
 * tracked position T (arbitrary, 0..TMAX-1) is followed: the stream
 * positions covered by the segments are preserved by tcp_reass (trims only
 * remove what another entry holds), so after the call T is either
 * delivered (T < new rcv_nxt - old rcv_nxt) or in exactly one remaining
 * entry, and exactly when some segment of the input covered it.  If T is
 * delivered, the byte of the chain given to the socket buffer at that
 * offset must be the byte of position T (check_byte; for a position left
 * in an entry the byte is NOT checked: that cost 130 s of the check phase
 * and the length equalities below tie each trim's m_adj to th_seq and
 * th_reseqlen).  The socket buffer model
 * checks that each chain it gets starts at th_seq == rcv_nxt0 + bytes
 * delivered so far, is a well formed chain whose length is its th_reseqlen,
 * and frees it.  Afterwards the bytes delivered are exactly
 * [rcv_nxt0, rcv_nxt): rcv_nxt advanced by the delivered length, the
 * chains were contiguous from rcv_nxt0, and the remaining head is above
 * rcv_nxt (nothing deliverable is left behind).  FIN: the return value is
 * TH_FIN exactly when the last chain delivered came from an entry with FIN
 * (if the socket buffer is not closed to receive: with SS_CANTRCVMORE the
 * entries are freed by tcp_flush_queue and only the lengths are checked).
 *
 * pool_get failure: the model fails arbitrarily.  Then the code either
 * reuses the last entry (queue not empty and th_seq == rcv_nxt: the last
 * entry's data is gone, coverage excludes it) or flushes the queue and
 * frees the segment and returns -1; the harness checks both, and that
 * a SACK report is cleaned (rcv_numsacks 0 when sack_enable).
 *
 * Queue limit (tcp_reass top, upstream a57fe03c6): t_segqlen counts the
 * entries; a segment not at rcv_nxt is dropped (m_freem, -1) when
 * t_segqlen >= max(TCP_REASS_MAXQLEN, sb_hiwat / 1024).  A queue of 100
 * entries is not built: t_segqlen is n + extra, extra 0 or arbitrary,
 * standing for entries beyond the modelled ones (their walk is not
 * covered).  Asserted: when the limit applies, the segment is dropped,
 * -1 is returned and the queue, t_segqlen and rcv_nxt are unchanged
 * and pool_get is not called; otherwise t_segqlen is the queue length
 * plus extra after the call, 0 after a flush.  sb_hiwat is arbitrary.
 *
 * Leaks: --memory-leak-check, free checks: the harness frees what is
 * left with tcp_freeq (real, from tcp_subr.c) and the tcpcb.
 *
 * Models: mbuf library = the contract models (m_adj, m_freem, ... as the
 * net/mbuf_* targets prove them; the head is trimmed, nothing is copied);
 * pool_get(&tcpqe_pool) = typed entry or failure (a macro renames the call:
 * natively replace does not reach pool_get); pool_put = common model
 * (free with the size check); sbappendstream = the model above;
 * mtx_enter/mtx_leave = owner tracking.  No body (NOBODY line): sorwakeup
 * (wakes the reader), tcpstat_inc, tcpstat_add, tcpstat_pkt (statistics).
 *
 * Bounds, as built: segments 0..8 data bytes in one or two mbufs (first
 * of arbitrary length, zero allowed); queue 0..2 entries; first entry at
 * 1..E0MAX above rcv_nxt, gap to the next 0..GAP; new segment 0..NMAX-1
 * above rcv_nxt; tracked position 0..TMAX-1; rcv_nxt arbitrary 32 bit, so
 * all sequence comparisons wrap.
 */
#define MC_MAXLEN	8
#include "mbufcontract.h"

/*
 * pool_get -> model_pool_get by macro, not by the replace file: natively the
 * common pool_get (a model file) is never replaced, and its M_NOWAIT
 * failures would not be seen by pool_failed.
 */
#include <sys/pool.h>
#define pool_get(pp, flags)	model_pool_get(pp, flags)
void *model_pool_get(struct pool *, int);

#include "tcp_input.c"
#include "tcp_subr.c"

#define SEGMAX	8	/* data bytes of a segment, = MC_MAXLEN */
#define E0MAX	6	/* first entry starts 1..6 above rcv_nxt */
#define GAP	5	/* gap between entries 0..5 */
#define NMAX	21	/* new segment starts 0..20 above rcv_nxt */
#define TMAX	32	/* tracked position */

/* first mbuf's buffer: the TCP header, then the data, ending the object */
struct seg {
	struct tcphdr	th;
	u_char		data[SEGMAX];
};

static struct socket model_so;
static struct inpcb model_inp;

static tcp_seq base;		/* rcv_nxt before the call */
static int track;		/* the tracked stream position */
static int cantrcvmore;
static int pool_failed;
static int qlen;		/* entries counted by check_queue */
static u_int dl_len;		/* bytes given to the socket buffer */
static int dl_n;		/* chains given to it */
static int dl_fin;		/* FIN of the last chain */

/* a queue entry or the new segment: header in the buffer, content */
static struct mbuf *
seg_new(int off, int len, int fin, struct tcphdr **thp)
{
	struct mbuf *m, *m2 = NULL;
	struct seg *s;
	u_char *p1, *p2 = NULL;
	int first, k;

	first = nondet_bool() ? len : mc_upto(len);
	m = CBMC_NEW(struct mbuf);
	s = CBMC_NEW(struct seg);
	m->m_type = MT_DATA;
	m->m_flags = M_PKTHDR;
	m->m_next = NULL;	/* natively CBMC_NEW memory is not zero */
	m->m_nextpkt = NULL;
	MC_BUF(m) = (caddr_t)s;
	m->m_data = (caddr_t)s->data + (SEGMAX - first);
	m->m_len = first;
	m->m_pkthdr.len = len;
	if (first < len) {
		m2 = mc_seg(len - first);
		m->m_next = m2;
		p2 = mtod(m2, u_char *);
	}
	p1 = mtod(m, u_char *);
	for (k = 0; k < SEGMAX; k++) {
		if (k < first)
			p1[k] = (u_char)(off + k);
		else if (k < len)
			p2[k - first] = (u_char)(off + k);
	}
	s->th.th_seq = base + off;
	s->th.th_flags = fin ? TH_FIN : 0;
	*thp = &s->th;
	return (m);
}

static void
enqueue(struct tcpcb *tp, int off, int len)
{
	struct tcpqent *e;
	struct tcphdr *th;
	struct mbuf *m;

	m = seg_new(off, len, nondet_bool(), &th);
	th->th_reseqlen = len;
	e = CBMC_NEW(struct tcpqent);
	e->tcpqe_tcp = th;
	e->tcpqe_m = m;
	TAILQ_INSERT_TAIL(&tp->t_segq, e, tcpqe_q);
}

/* byte j of the chain is the byte of position track */
static void
check_byte(struct mbuf *m, int j)
{
	u_char b;

	if (j < m->m_len)
		b = mtod(m, u_char *)[j];
	else
		b = mtod(m->m_next, u_char *)[j - m->m_len];
	__CPROVER_assert(b == (u_char)track, "tracked byte is not its position's");
}

/*
 * The queue invariant.  *found counts the entries that hold position
 * track.  head_eq: the head may be at rcv_nxt (a FIN was delivered).
 */
static void
check_queue(struct tcpcb *tp, int head_eq, int *found)
{
	struct tcpqent *q, *nq;
	struct tcphdr *th;
	int n = 0, rel, j;

	*found = 0;
	qlen = 0;
	for (q = TAILQ_FIRST(&tp->t_segq); q != NULL; q = nq) {
		n++;
		qlen = n;
		__CPROVER_assert(n <= 3, "queue too long or cyclic");
		th = q->tcpqe_tcp;
		__CPROVER_assert(th == (struct tcphdr *)MC_BUF(q->tcpqe_m),
		    "tcpqe_tcp is not the header of the entry's mbuf");
		rel = (int)(th->th_seq - tp->rcv_nxt);
		if (head_eq)
			__CPROVER_assert(rel >= 0, "entry below rcv_nxt");
		else
			__CPROVER_assert(rel > 0, "entry at or below rcv_nxt");
		mc_check(q->tcpqe_m);
		__CPROVER_assert(q->tcpqe_m->m_flags & M_PKTHDR,
		    "entry without packet header");
		__CPROVER_assert(th->th_reseqlen == mc_total(q->tcpqe_m),
		    "th_reseqlen is not the length of the chain");
		nq = TAILQ_NEXT(q, tcpqe_q);
		if (nq != NULL)
			__CPROVER_assert((int)(nq->tcpqe_tcp->th_seq -
			    (th->th_seq + th->th_reseqlen)) >= 0,
			    "entries overlap or are out of order");
		j = track - (int)(th->th_seq - base);
		if (j >= 0 && j < th->th_reseqlen) {
			(*found)++;
		}
	}
}

/* sequence range [off, off + len) holds position track */
static int
covers(int off, int len)
{
	return (len > 0 && off <= track && track < off + len);
}

void *
model_pool_get(struct pool *pp, int flags)
{
	__CPROVER_assert(pp == &tcpqe_pool, "pool_get on an unexpected pool");
	__CPROVER_assert(flags == PR_NOWAIT, "pool_get flags");
	if (nondet_bool()) {
		pool_failed = 1;
		return (NULL);
	}
	return (CBMC_NEW(struct tcpqent));
}

/* the socket buffer: takes the chain and frees it */
void
model_sbappendstream(struct sockbuf *sb, struct mbuf *m)
{
	struct tcphdr *th;
	int len, j;

	__CPROVER_assert(sb == &model_so.so_rcv, "sbappendstream: socket buffer");
	__CPROVER_assert(mtx_owner(&sb->sb_mtx) == mtx_curcpu(),
	    "sbappendstream: sb_mtx held");
	__CPROVER_assert(!cantrcvmore, "appended although SS_CANTRCVMORE");
	__CPROVER_assert(m != NULL && (m->m_flags & M_PKTHDR),
	    "sbappendstream: packet header");
	__CPROVER_assert(m->m_nextpkt == NULL, "sbappendstream: m_nextpkt");
	mc_check(m);
	th = (struct tcphdr *)MC_BUF(m);
	len = mc_total(m);
	__CPROVER_assert(th->th_seq == base + dl_len,
	    "delivered chain does not continue the stream");
	__CPROVER_assert(th->th_reseqlen == len,
	    "delivered chain is not th_reseqlen long");
	j = track - (int)dl_len;
	if (j >= 0 && j < len)
		check_byte(m, j);
	dl_fin = (th->th_flags & TH_FIN) != 0;
	dl_len += len;
	dl_n++;
	m_freem(m);
}

void
model_mtx_enter(struct mutex *mtx)
{
	__CPROVER_assert(mtx->mtx_owner == 0, "mtx_enter: not held");
	mtx->mtx_owner = mtx_curcpu();
}

void
model_mtx_leave(struct mutex *mtx)
{
	__CPROVER_assert(mtx_owner(mtx) == mtx_curcpu(), "mtx_leave: held");
	mtx->mtx_owner = 0;
}

int
main(void)
{
	struct tcpcb *tp;
	struct tcphdr *th;
	struct mbuf *m;
	int n, o0, l0, o1, l1, no, nl, tlen, ret, found, delta, reuse, covb;
	u_int extra, qlimit, hiwat;
	struct tcpqent *e0, *e1;

	tcpqe_pool.pr_size = sizeof(struct tcpqent);
	model_inp.inp_socket = &model_so;
	cantrcvmore = nondet_bool();
	model_so.so_rcv.sb_state = cantrcvmore ? SS_CANTRCVMORE : 0;
	base = nondet_u32();
	track = mc_upto(TMAX - 1);

	tp = CBMC_NEW(struct tcpcb);
	TAILQ_INIT(&tp->t_segq);
	tp->t_inpcb = &model_inp;
	tp->t_state = TCPS_ESTABLISHED + mc_upto(TCPS_TIME_WAIT -
	    TCPS_ESTABLISHED - 1);
	tp->rcv_nxt = base;
	tp->sack_enable = nondet_bool() ? 1 : 0;
	tp->rcv_numsacks = nondet_bool() ? 0 : 1 + mc_upto(MAX_SACK_BLKS - 1);

	/* a queue that satisfies the invariant, by arithmetic */
	n = mc_upto(2);
	o0 = 1 + mc_upto(E0MAX - 1);
	l0 = mc_upto(SEGMAX);
	o1 = o0 + l0 + mc_upto(GAP);
	l1 = mc_upto(SEGMAX);
	if (n >= 1)
		enqueue(tp, o0, l0);
	if (n >= 2)
		enqueue(tp, o1, l1);
	check_queue(tp, 0, &found);
	e0 = TAILQ_FIRST(&tp->t_segq);
	e1 = e0 != NULL ? TAILQ_NEXT(e0, tcpqe_q) : NULL;

	/* the counter and the limit: entries beyond the modelled ones */
	hiwat = nondet_uint();
	model_so.so_rcv.sb_hiwat = hiwat;
	extra = nondet_bool() ? 0 : (nondet_uint() & 0x7fffffff);
	tp->t_segqlen = n + extra;
	qlimit = hiwat / 1024 > TCP_REASS_MAXQLEN ? hiwat / 1024 :
	    TCP_REASS_MAXQLEN;

	/* the new segment, as tcp_input_solocked() leaves it */
	no = mc_upto(NMAX - 1);
	nl = mc_upto(SEGMAX);
	m = seg_new(no, nl, nondet_bool(), &th);
	th->th_urp = nondet_ushort();
	tlen = nl;

	ret = tcp_reass(tp, th, m, &tlen);

	if (n + extra >= qlimit && no != 0) {
		__CPROVER_assert(ret == -1, "full queue: not -1");
		__CPROVER_assert(!pool_failed, "full queue: pool_get called");
		__CPROVER_assert(TAILQ_FIRST(&tp->t_segq) == e0 &&
		    (e0 == NULL || TAILQ_NEXT(e0, tcpqe_q) == e1),
		    "full queue: queue changed");
		__CPROVER_assert(tp->t_segqlen == n + extra,
		    "full queue: t_segqlen changed");
		__CPROVER_assert(tp->rcv_nxt == base && dl_n == 0,
		    "full queue: data delivered");
		check_queue(tp, 0, &found);
		goto done;
	}
	reuse = pool_failed && n > 0 && no == 0;
	if (pool_failed && !reuse) {
		__CPROVER_assert(ret == -1, "dropped segment: not -1");
		__CPROVER_assert(TAILQ_EMPTY(&tp->t_segq),
		    "queue not flushed after pool_get failure");
		__CPROVER_assert(tp->rcv_nxt == base, "rcv_nxt moved");
		__CPROVER_assert(dl_n == 0, "data delivered after pool failure");
		__CPROVER_assert(tp->t_segqlen == 0,
		    "t_segqlen not 0 after the flush");
	} else {
		__CPROVER_assert(ret == 0 || ret == TH_FIN, "return value");
		delta = (int)(tp->rcv_nxt - base);
		__CPROVER_assert(delta >= 0 && delta <= 3 * SEGMAX,
		    "rcv_nxt advanced by more than the segments hold");
		if (cantrcvmore)
			__CPROVER_assert(dl_n == 0, "appended: SS_CANTRCVMORE");
		else {
			__CPROVER_assert(delta == (int)dl_len,
			    "rcv_nxt advanced by other than the delivered length");
			__CPROVER_assert(ret == (dl_n > 0 && dl_fin ? TH_FIN : 0),
			    "FIN returned for a chain without FIN or not at all");
		}
		check_queue(tp, ret == TH_FIN, &found);
		__CPROVER_assert(tp->t_segqlen == qlen + extra,
		    "t_segqlen is not the queue length");
		/* the positions held are conserved */
		covb = covers(no, nl) ||
		    (n >= 1 && !(reuse && n == 1) && covers(o0, l0)) ||
		    (n >= 2 && !(reuse && n == 2) && covers(o1, l1));
		__CPROVER_assert(found <= 1, "position held twice");
		__CPROVER_assert(!(track < delta && found),
		    "delivered position still queued");
		__CPROVER_assert(covb == (track < delta || found == 1),
		    "position held before is lost, or invented");
	}
done:
	if (pool_failed && tp->sack_enable)
		__CPROVER_assert(tp->rcv_numsacks == 0,
		    "SACK report not cleaned after pool failure");

	tcp_freeq(tp);
	mc_release(tp);
	return (0);
}
