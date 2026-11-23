/*
 * tcp_pulloutofband(so, urgent, m, off) of sys/netinet/tcp_input.c on a
 * chain of arbitrary segmentation, followed by the caller's next step
 * m_adj(m, off) (the real one).
 *
 * Caller (tcp_input.c, tcp_input_solocked):
 *   1878  the call needs (tiflags & TH_URG) && th->th_urp (urgent >= 1);
 *   1925  th->th_urp <= (u_int16_t)tlen and SO_OOBINLINE clear, then
 *   1926  tcp_pulloutofband(so, th->th_urp, m, hdroptlen).
 *   tlen is the payload length left after the header (441, 517) and the
 *   trims: head 1331-1333 (hdroptlen += todrop, tlen -= todrop, th_urp
 *   lowered or URG cleared 1334-1339), tail 1219-1221 and 1357-1377
 *   (m_adj(m, -todrop), tlen -= todrop).  hdroptlen = iphlen + th_off*4
 *   (1074) + head todrop, so m_pkthdr.len == hdroptlen + tlen on entry
 *   (m_adj keeps m_pkthdr.len in step) and
 *       off + urgent - 1 <= hdroptlen + tlen - 1 < chain length.
 *   Hence: 0 <= off < plen, 1 <= urgent <= plen - off, and the panic at
 *   the end is reachable only if urgent > plen - off, i.e. th_urp past
 *   the data (1925 forbids it).  The harness generates exactly that
 *   range: plen in 1..MAXLEN, off in 0..plen-1 (a superset of the
 *   caller's off >= 40 for IPv4), urgent in 1..plen-off.  m is the whole
 *   packet from the IP header on, M_PKTHDR on the first mbuf,
 *   m_pkthdr.len == sum of m_len, mbufs of any m_len (also 0).
 *   so: so_pcb is the inpcb, inp_ppcb the tcpcb (sototcpcb).
 *
 * Asserted (exact effect): no panic; tp->t_iobc is the byte that was at
 * packet offset k = off + urgent - 1 and TCPOOB_HAVEDATA is set (the
 * other t_oobflags bits unchanged); one byte at an arbitrary offset is
 * followed (MEMCPY_TRACK): at offset < k it is still where it was, at
 * offset > k it is now at offset - 1 (the byte at k is gone); the sum of
 * m_len drops by exactly 1, the chain keeps its mbufs.
 *
 * Not asserted: m_pkthdr.len == sum of m_len.  The function leaves
 * m_pkthdr.len unchanged ("still reflected in the segment length");
 * the harness asserts that fact (m_pkthdr.len == plen, one more than
 * the chain) and, after the caller's next step m_adj(m, off), that the
 * head trim takes all of off bytes (m_pkthdr.len == plen - off, sum of
 * m_len == plen - 1 - off) and keeps the bytes in place.  See the
 * README entry: nothing after that reads m_pkthdr.len of this chain.
 *
 * Bounds: up to 2 mbufs, internal or 2k clusters, possibly read-only;
 * packets up to MAXLEN = 24 bytes.  The socket, inpcb and tcpcb are
 * objects with every field zero except t_iobc and t_oobflags, which are
 * arbitrary.
 */
#define MAXLEN	24
#define MBUFKIT_MEMTRACK 1	/* stubflags: -DMEMCPY_TRACK */
#define MBUFKIT_MAXLEN MAXLEN
#include "mbufkit.h"
#include "tcp_input.c"

static struct socket so_;	/* static: zeroed, not a leak candidate */
static struct inpcb inp_;
static struct tcpcb tp_;

int
main(void)
{
	struct mbuf *m;
	struct mbufkit_byte b;
	struct socket *so;
	struct inpcb *inp;
	struct tcpcb *tp;
	int plen, off, k, nmbuf, v0;
	u_int urgent;
	char flags0;

	mbufkit_init();

	so = &so_;
	inp = &inp_;
	tp = &tp_;
	so->so_pcb = inp;
	inp->inp_ppcb = (caddr_t)tp;
	tp->t_iobc = nondet_char();
	tp->t_oobflags = nondet_char();
	flags0 = tp->t_oobflags;

	plen = 1 + mbufkit_upto(MAXLEN - 1);
	off = mbufkit_upto(plen - 1);
	urgent = 1 + mbufkit_upto(plen - off - 1);
	k = off + urgent - 1;

	m = mbufkit_build(plen, MBUFKIT_ANY);
	nmbuf = mbufkit_count(m);
	v0 = mbufkit_byte(m, k);
	mbufkit_track(&b, m);

	tcp_pulloutofband(so, urgent, m, off);

	__CPROVER_assert(v0 >= 0 && tp->t_iobc == (char)v0,
	    "pulloutofband: t_iobc is the byte at off + urgent - 1");
	__CPROVER_assert(tp->t_oobflags == (char)(flags0 | TCPOOB_HAVEDATA),
	    "pulloutofband: TCPOOB_HAVEDATA set, no other flag changed");
	__CPROVER_assert(mbufkit_count(m) == nmbuf,
	    "pulloutofband: the chain keeps its mbufs");
	__CPROVER_assert(mbufkit_len(m) == plen - 1,
	    "pulloutofband: sum of m_len drops by exactly 1");
	if (b.off >= 0 && b.off < k)
		__CPROVER_assert(mbufkit_same(&b, mbufkit_ptr(m, b.off)),
		    "pulloutofband: bytes before the urgent byte stay");
	if (b.off > k)
		__CPROVER_assert(mbufkit_same(&b, mbufkit_ptr(m, b.off - 1)),
		    "pulloutofband: bytes after the urgent byte move down by one");
	__CPROVER_assert(m->m_pkthdr.len == plen,
	    "pulloutofband: m_pkthdr.len is left unchanged");

	/* the caller's next step: tcp_input.c 1960 / 1967 */
	m_adj(m, off);

	__CPROVER_assert(m->m_pkthdr.len == plen - off,
	    "m_adj after: head trim takes all of off");
	__CPROVER_assert(mbufkit_len(m) == plen - 1 - off,
	    "m_adj after: sum of m_len is plen - 1 - off");
	__CPROVER_assert(m->m_pkthdr.len - mbufkit_len(m) == 1,
	    "m_adj after: m_pkthdr.len exceeds the chain by exactly 1");
	if (b.off >= off && b.off < k)
		__CPROVER_assert(mbufkit_same(&b, mbufkit_ptr(m, b.off - off)),
		    "m_adj after: bytes before the urgent byte in place");
	if (b.off > k)
		__CPROVER_assert(mbufkit_same(&b,
		    mbufkit_ptr(m, b.off - 1 - off)),
		    "m_adj after: bytes after the urgent byte in place");
	mbufkit_free(m);
	return (0);
}
