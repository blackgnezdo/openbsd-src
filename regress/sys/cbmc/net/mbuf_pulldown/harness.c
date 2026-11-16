/*
 * m_pulldown(m, off, len, offp) on a packet of arbitrary segmentation
 * and content.
 *
 * Contract (comment above m_pulldown; callers IP6_EXTHDR_GET in
 * netinet/ip6.h, if_pppoe.c, bfd.c, raw_ip6.c): m is a well-formed
 * packet chain; 0 <= off and 0 <= len, and off + len may exceed the
 * packet: if_pppoe.c passes a tag length read from the packet (also 0)
 * at an offset up to the packet length.  Every caller in the tree passes
 * offp (grep m_pulldown): offp == NULL is not covered.  On NULL the
 * whole chain has been freed.  Otherwise the result n is an mbuf of the
 * chain m, and bytes [off, off + len) of the packet are contiguous at
 * mtod(n) + *offp.
 *
 * Asserted: NULL only if off + len exceeds the packet or an allocation
 * failed (CBMC only); on success n is on the chain, n->m_len >= *offp +
 * len, the chain is well formed, its length is unchanged, every byte is
 * where it was in the packet, and packet byte off + k is at mtod(n) +
 * *offp + k; no leak.  Content is followed for one byte at an arbitrary
 * offset (MBUFKIT_MEMTRACK).
 *
 * The content assertions are checked by net/mbuf_pulldown_prefix,
 * _range and _tail, which include this file with CONTENT 1, 2 and 3:
 * together they took the solver over 150 s.  Memory safety and leaks
 * are checked by all four.
 *
 * Bounds: up to 2 mbufs (MBUFKIT_MAXSEG), internal or 2k clusters,
 * possibly read-only; packet, off and len up to MAXLEN = MLEN + 8, so
 * that the new mbuf of the last case needs a cluster (len > MLEN).
 */
#ifndef CONTENT
#define CONTENT	0	/* 0: all but content; 1, 2, 3: content */
#endif
#ifndef BUILD
#define BUILD	MBUFKIT_ANY
#endif
#ifndef MAXLEN
#define MAXLEN	(MLEN + 8)
#endif
#define MBUFKIT_MEMTRACK 1	/* stubflags: -DMEMCPY_TRACK */
#define MBUFKIT_MAXLEN MAXLEN
#define MBUFKIT_MAXCHAIN 3	/* m_pulldown adds at most one mbuf */
#include "mbufkit.h"

int
main(void)
{
	struct mbuf *m, *n, *x;
	struct mbufkit_byte b;
	int plen, off, len, noff, *offp, o, i, dup1;

	mbufkit_init();
	plen = mbufkit_upto(MAXLEN);
	off = mbufkit_upto(MAXLEN);
	len = mbufkit_upto(MAXLEN);
	offp = &noff;
	m = mbufkit_build(plen, BUILD);
	/*
	 * CONTENT 1: a byte before off, 2: a byte in the range, 3: a byte
	 * after it (split for solver time); 0: none checked.
	 */
	if (CONTENT == 1)
		mbufkit_track_off(&b, m, off > 0 ? mbufkit_upto(off - 1) : -1);
	else if (CONTENT == 3)
		mbufkit_track_off(&b, m, off + len < plen ? off + len +
		    mbufkit_upto(plen - off - len - 1) : -1);
	else if (CONTENT == 2)
		mbufkit_track_off(&b, m, len > 0 && off + len <= plen ?
		    off + mbufkit_upto(len - 1) : -1);
	else
		mbufkit_track(&b, m);

	/*
	 * Known deviation (net/mbuf_pulldown_dup1, README): with off 0 and
	 * the range inside a read-only first mbuf, m_dup1() gives the new
	 * second mbuf a copy of the packet header.  Tolerated here so that
	 * this target checks everything else.
	 */
	dup1 = off == 0 && (m->m_len > 0 || m->m_next == NULL) &&
	    M_READONLY(m) && len <= m->m_len;

	n = m_pulldown(m, off, len, offp);
	if (n == NULL) {
		__CPROVER_assert(CONTENT || off + len > plen ||
		    MBUFKIT_FAILED(),
		    "m_pulldown: NULL only for a short packet or no memory");
		return (0);
	}
	o = *offp;
	if (!CONTENT) {
		__CPROVER_assert(off + len <= plen,
		    "m_pulldown: success only if the range is in the packet");
		for (x = m, i = 0; x != NULL && x != n &&
		    i < MBUFKIT_MAXCHAIN; i++)
			x = x->m_next;
		__CPROVER_assert(x == n, "m_pulldown: result is on the chain");
		__CPROVER_assert(o >= 0 && n->m_len >= o + len,
		    "m_pulldown: range contiguous in the result");
		mbufkit_check_chain(m, dup1 ? MBUFKIT_CHK_HDR2 : 0);
		__CPROVER_assert(m->m_pkthdr.len == plen,
		    "m_pulldown: packet length unchanged");
	} else {
		__CPROVER_assert(mbufkit_same(&b, mbufkit_ptr(m, b.off)),
		    "m_pulldown: content unchanged");
		if (CONTENT == 2 && b.off >= 0)
			__CPROVER_assert(mbufkit_same(&b,
			    mtod(n, u_char *) + o + (b.off - off)),
			    "m_pulldown: range at mtod(n) + *offp");
	}
	mbufkit_free(m);
	return (0);
}
