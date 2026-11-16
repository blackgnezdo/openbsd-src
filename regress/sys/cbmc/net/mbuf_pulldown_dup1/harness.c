/*
 * Finding, FIXED: m_pulldown(m, 0, len, &off) with len <= m->m_len and
 * a read-only first mbuf (a cluster shared after m_copym, or external
 * storage without M_EXTWR) takes the m_dup1() path.  m_dup1(n, 0, ...)
 * saw off == 0 and M_PKTHDR on n and allocated the copy with MGETHDR
 * and m_dup_pkthdr(), but the copy is inserted as n's successor: the
 * chain then had M_PKTHDR (and a second copy of the packet header and
 * its tags) on its second mbuf.
 *
 * In-tree caller with off 0: net/bfd.c bfd_input(), twice.  The chain
 * was otherwise intact (no leak, no unsafe access; net/mbuf_pulldown
 * checks the rest with this case tolerated).  Fix: m_dup1() never
 * copies the header (its only caller inserts the copy behind n); it
 * always uses MGET and MLEN, and a cluster for len > MLEN.
 *
 * VERIFIED on the current tree.  The mutant keeps the finding: with
 * CBMC_OVERRIDE_DIR=net/mbuf_pulldown_dup1/mutant (the pre-fix
 * uipc_mbuf2.c) the result is VIOLATED, "M_PKTHDR only on the first
 * mbuf".
 *
 * Bounds: one mbuf of up to 16 bytes, possibly a read-only cluster.
 */
#define MBUFKIT_MEMTRACK 1	/* stubflags: -DMEMCPY_TRACK */
#define MBUFKIT_MAXSEG	1
#define MBUFKIT_MAXLEN	16
#include "mbufkit.h"

int
main(void)
{
	struct mbuf *m, *n;
	int plen, len, noff;

	mbufkit_init();
	plen = mbufkit_upto(MBUFKIT_MAXLEN);
	len = mbufkit_upto(plen);
	m = mbufkit_build(plen, MBUFKIT_ANY);
	n = m_pulldown(m, 0, len, &noff);
	if (n == NULL)
		return (0);
	mbufkit_check(m);
	mbufkit_free(m);
	return (0);
}
