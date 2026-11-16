/*
 * Worked example of a packet parser target (README, "Writing a packet
 * parser target"): tlv_parse() of parser/tlv.c on a packet of arbitrary
 * content and segmentation, built with the mbuf kit.
 *
 * Contract of tlv_parse (as its callers would have it): *mp is a
 * well-formed packet chain, 0 <= off; on return *mp is NULL (freed) or
 * a well-formed chain the caller frees.
 *
 * Asserted: memory safety of the parser and of the mbuf code it calls
 * (real m_pullup, m_copydata), no panic (m_copydata panics on a range
 * outside the packet), the chain is well formed afterwards, no leak.
 * Bug variant: mutant/tlv.c drops the length check (VIOLATED: m_copydata
 * panics on a range beyond the packet):
 *	CBMC_OVERRIDE_DIR=$PWD/net/mbuf_example_parser/mutant \
 *	    sh cbmc.sh net/mbuf_example_parser
 * tlv.c is in a subdirectory and listed in "included": #include "tlv.c"
 * must find the staged copy (which CBMC_OVERRIDE_DIR replaces), not a
 * file next to harness.c.
 *
 * stubflags -DMEMCPY_TRACK keeps the copies cheap; it also means that
 * the bytes m_copydata() hands the parser are arbitrary values, not the
 * packet's.  That is fine here: the content is arbitrary anyway and the
 * parser never reads the same byte twice.
 *
 * Bounds: up to 2 mbufs, internal or 2k clusters, possibly read-only;
 * packets up to MAXLEN = 24 bytes.
 */
#define MAXLEN	24
#define MBUFKIT_MAXLEN MAXLEN
#include "mbufkit.h"

#include "tlv.c"

int
main(void)
{
	struct mbuf *m;
	int off;

	mbufkit_init();
	m = mbufkit_build(mbufkit_upto(MAXLEN), MBUFKIT_ANY);
	off = mbufkit_upto(MAXLEN);

	(void)tlv_parse(&m, off);

	if (m != NULL) {
		mbufkit_check(m);
		mbufkit_free(m);
	}
	return (0);
}
