/*
 * m_adj(m, req_len) on a packet of arbitrary segmentation and content.
 *
 * Contract (comment-free; callers ip_input.c, ip6_input.c, if_pppoe.c,
 * ether_input, tcp_input.c): m is a well-formed packet chain or NULL;
 * req_len > 0 trims from the head, < 0 from the tail, and |req_len| may
 * exceed the packet: if_pppoe.c passes off + plen - m_pkthdr.len with
 * plen from the packet.  req_len is generated in
 * [-(MAXLEN + 2), MAXLEN + 2]; INT_MIN is not (no caller can pass it).
 *
 * Asserted: m_pkthdr.len is max(plen - |req_len|, 0), the chain is
 * well formed (m_pkthdr.len is the sum of m_len), the remaining bytes
 * are the packet's bytes [req_len, plen) (head trim) or [0, plen +
 * req_len) (tail trim) at their new offsets (one byte at an arbitrary
 * offset followed, MBUFKIT_MEMTRACK; m_adj copies nothing, so it must
 * be the very same byte), no leak.
 *
 * Bounds: up to 2 mbufs, internal or 2k clusters, possibly read-only;
 * packets up to MAXLEN = 24 bytes.
 */
#define MAXLEN	24
#define MBUFKIT_MEMTRACK 1	/* stubflags: -DMEMCPY_TRACK */
#define MBUFKIT_MAXLEN MAXLEN
#include "mbufkit.h"

int
main(void)
{
	struct mbuf *m;
	struct mbufkit_byte b;
	int plen, req, nlen;

	mbufkit_init();
	plen = mbufkit_upto(MAXLEN);
	req = mbufkit_upto(2 * (MAXLEN + 2)) - (MAXLEN + 2);
	m = mbufkit_build(plen, MBUFKIT_ANY);
	mbufkit_track(&b, m);

	m_adj(m, req);

	nlen = plen - (req < 0 ? -req : req);
	if (nlen < 0)
		nlen = 0;
	mbufkit_check(m);
	__CPROVER_assert(m->m_pkthdr.len == nlen,
	    "m_adj: length is max(plen - |req_len|, 0)");
	if (req >= 0 && b.off >= req)
		__CPROVER_assert(mbufkit_same(&b, mbufkit_ptr(m, b.off - req)),
		    "m_adj: head trim keeps the rest");
	if (req < 0 && b.off >= 0 && b.off < nlen)
		__CPROVER_assert(mbufkit_same(&b, mbufkit_ptr(m, b.off)),
		    "m_adj: tail trim keeps the rest");
	mbufkit_free(m);
	m_adj(NULL, req);	/* NULL is accepted */
	return (0);
}
