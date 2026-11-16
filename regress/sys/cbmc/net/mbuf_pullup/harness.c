/*
 * m_pullup(m, len) on a packet of arbitrary segmentation and content.
 *
 * Contract (comment above m_pullup; callers such as ip_input.c,
 * if_ether.c, ip_icmp.c, if_gif.c): m is a well-formed packet chain,
 * 0 <= len; len may exceed the packet (callers rely on NULL then).  On
 * NULL the chain has been freed.  Otherwise the first mbuf holds at
 * least len contiguous bytes and the chain is the same packet.
 *
 * Asserted: NULL only if len exceeds the packet or an allocation failed
 * (CBMC only, see MBUFKIT_FAILED); on success a well-formed chain,
 * m_len >= len in the first mbuf, total length and every byte unchanged;
 * no leak either way.
 *
 * Content: one byte at an arbitrary offset is followed through the
 * copies (MBUFKIT_MEMTRACK, stubflags -DMEMCPY_TRACK); it must be at
 * the same packet offset afterwards.
 *
 * Bounds: up to 2 mbufs (MBUFKIT_MAXSEG; 3 took the solver over 150 s),
 * each internal or a 2k cluster, possibly read-only; packets and len up to
 * MAXLEN = MHLEN + 8 bytes: the new-mbuf path needs len > MHLEN - adj
 * for a writable first mbuf (or a read-only one, which the builder
 * makes), the cluster path len + adj > MHLEN.
 */
#define MAXLEN	(MHLEN + 8)
#define MBUFKIT_MEMTRACK 1	/* stubflags: -DMEMCPY_TRACK */
#define MBUFKIT_MAXLEN MAXLEN
#include "mbufkit.h"


int
main(void)
{
	struct mbuf *m;
	struct mbufkit_byte b;
	int plen, len;

	mbufkit_init();
	plen = mbufkit_upto(MAXLEN);
	len = mbufkit_upto(MAXLEN);
	m = mbufkit_build(plen, MBUFKIT_ANY);
	mbufkit_track(&b, m);

	m = m_pullup(m, len);
	if (m == NULL) {
		__CPROVER_assert(len > plen || MBUFKIT_FAILED(),
		    "m_pullup: NULL only for a short packet or no memory");
		return (0);
	}
	mbufkit_check(m);
	__CPROVER_assert(len <= plen, "m_pullup: success only if len fits");
	__CPROVER_assert(m->m_len >= len, "m_pullup: len bytes contiguous");
	__CPROVER_assert(m->m_pkthdr.len == plen,
	    "m_pullup: packet length unchanged");
	__CPROVER_assert(mbufkit_same(&b, mbufkit_ptr(m, b.off)),
	    "m_pullup: content unchanged");
	mbufkit_free(m);
	return (0);
}
