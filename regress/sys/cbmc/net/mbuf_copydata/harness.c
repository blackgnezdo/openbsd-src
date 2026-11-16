/*
 * m_copydata(m, off, len, buf) on a packet of arbitrary segmentation
 * and content.
 *
 * Contract (comment above m_copydata; it panics otherwise): m is a
 * well-formed chain, 0 <= off, 0 <= len and off + len <= the packet
 * length; buf has room for len bytes.  Callers check the packet length
 * first (tcp_input.c, ip_icmp.c, pf.c pf_pull_hdr, if_pppoe.c), so only
 * arguments inside the packet are generated: off arbitrary in
 * [0, plen], len arbitrary in [0, plen - off].
 *
 * Asserted: no access outside buf (buf is a heap object of exactly len
 * bytes: any byte written before or after it is an out-of-bounds write,
 * under CBMC and under ASan, which is what canary bytes would detect),
 * buf[k] is packet byte off + k (followed for one byte at an arbitrary
 * offset of the range, MBUFKIT_MEMTRACK), the chain is unchanged and
 * well formed, no panic, no leak.
 *
 * Bounds: up to 2 mbufs, internal or 2k clusters, possibly read-only;
 * packets up to MAXLEN = 40 bytes.
 */
#define MAXLEN	40
#define MBUFKIT_MEMTRACK 1	/* stubflags: -DMEMCPY_TRACK */
#define MBUFKIT_MAXLEN MAXLEN
#include "mbufkit.h"

int
main(void)
{
	struct mbuf *m;
	struct mbufkit_byte b;
	u_char *buf;
	int plen, off, len;

	mbufkit_init();
	plen = mbufkit_upto(MAXLEN);
	off = mbufkit_upto(plen);
	len = mbufkit_upto(plen - off);
	m = mbufkit_build(plen, MBUFKIT_ANY);
	mbufkit_track_off(&b, m, len > 0 ? off + mbufkit_upto(len - 1) : -1);
	buf = malloc(len > 0 ? len : 1, M_TEMP, M_WAITOK);

	m_copydata(m, off, len, buf);

	if (len > 0)
		__CPROVER_assert(mbufkit_same(&b, buf + (b.off - off)),
		    "m_copydata: buf[k] is packet byte off + k");
	mbufkit_check(m);
	__CPROVER_assert(m->m_pkthdr.len == plen,
	    "m_copydata: chain unchanged");
	free(buf, M_TEMP, len > 0 ? len : 1);
	mbufkit_free(m);
	return (0);
}
