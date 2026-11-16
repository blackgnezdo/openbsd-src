/*
 * m_split(m0, len0, wait) on a packet of arbitrary segmentation and
 * content.
 *
 * Contract (comment above m_split: "In case of failure, it returns NULL
 * and attempts to restore the chain to its original state"; callers
 * pf.c pf_refragment/... (ipoff2), uipc_socket.c soreceive (oobmark)):
 * m0 is a well-formed packet chain, 0 <= len0; wait is M_WAIT or
 * M_DONTWAIT.  len0 may exceed the packet (NULL then).
 *
 * Asserted: NULL only if len0 exceeds the packet or an allocation failed
 * (CBMC only); after NULL the chain is intact: well formed, same length,
 * same bytes.  Otherwise m0 holds the first len0 bytes and the result the
 * rest, both well-formed packets (m_pkthdr.len len0 and plen - len0),
 * and their concatenation is the original packet (one byte at an
 * arbitrary offset followed, MBUFKIT_MEMTRACK); no leak, clusters shared
 * by the two halves are reference counted (MBUFKIT_REFS).
 *
 * Bounds differ by engine.  CBMC: up to 2 mbufs with internal storage,
 * packets up to 24 bytes: the copy path, the remain == 0 path and
 * allocation failure.  Clusters (m_extref, a shared cluster freed by
 * reference count) made the formula explode even with one segment
 * (9.4 million variables, symex 35-45 s; README, "mbuf kit"), and the
 * recursive case needs an internal mbuf holding more than MHLEN bytes
 * after the split point.  Natively (native.sh): up to 2 mbufs, internal
 * or clusters, possibly read-only, packets up to MHLEN + 8, which
 * reaches both.
 */
#ifdef NATIVE_SHIM_H
#define MAXLEN	(MHLEN + 8)
#define BUILD	MBUFKIT_ANY
#else
#define MAXLEN	24
#define BUILD	MBUFKIT_PLAIN
#endif
#define MBUFKIT_MEMTRACK 1	/* stubflags: -DMEMCPY_TRACK */
#define MBUFKIT_MAXLEN MAXLEN
#define MBUFKIT_REFS	1
#include "mbufkit.h"

int
main(void)
{
	struct mbuf *m, *n;
	struct mbufkit_byte b;
	int plen, len0, wait;

	mbufkit_init();
	plen = mbufkit_upto(MAXLEN);
	len0 = mbufkit_upto(MAXLEN);
	wait = nondet_bool() ? M_WAIT : M_DONTWAIT;
	m = mbufkit_build(plen, BUILD);
	mbufkit_track(&b, m);

	n = m_split(m, len0, wait);

	if (n == NULL) {
		__CPROVER_assert(len0 > plen || MBUFKIT_FAILED(),
		    "m_split: NULL only for a short packet or no memory");
		mbufkit_check(m);
		__CPROVER_assert(m->m_pkthdr.len == plen,
		    "m_split: failure leaves the length");
		__CPROVER_assert(mbufkit_same(&b, mbufkit_ptr(m, b.off)),
		    "m_split: failure leaves the content");
		mbufkit_free(m);
		return (0);
	}
	__CPROVER_assert(len0 <= plen, "m_split: success only if len0 fits");
	mbufkit_check(m);
	mbufkit_check(n);
	__CPROVER_assert(m->m_pkthdr.len == len0,
	    "m_split: head has len0 bytes");
	__CPROVER_assert(n->m_pkthdr.len == plen - len0,
	    "m_split: tail has the rest");
	if (b.off >= 0 && b.off < len0)
		__CPROVER_assert(mbufkit_same(&b, mbufkit_ptr(m, b.off)),
		    "m_split: head bytes in place");
	if (b.off >= len0)
		__CPROVER_assert(mbufkit_same(&b, mbufkit_ptr(n, b.off - len0)),
		    "m_split: tail bytes in place");
	mbufkit_free(m);
	mbufkit_free(n);
	return (0);
}
