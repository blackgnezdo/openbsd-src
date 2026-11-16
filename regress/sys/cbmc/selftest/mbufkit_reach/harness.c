/*
 * The mbuf kit's builder makes chains of every shape the bounds allow:
 * each assertion below claims a shape cannot occur and must FAIL (the
 * counterexample is a chain of that shape).  The chains are well formed
 * (mbufkit_check must not fail).
 */
#define MBUFKIT_MAXLEN	16
#include "mbufkit.h"

int
main(void)
{
	struct mbuf *m;
	int n;

	mbufkit_init();
	m = mbufkit_build(mbufkit_upto(16), MBUFKIT_ANY);
#include <anchor.inc>
	mbufkit_check(m);
	n = mbufkit_count(m);
	__CPROVER_assert(n != 1, "reach: one segment");
	__CPROVER_assert(!(n == 2 && m->m_len > 0 && m->m_len < 4 &&
	    m->m_next->m_len > 0), "reach: two segments, split in the first 4 bytes");
	__CPROVER_assert(!(m->m_flags & M_EXT) &&
	    !(n == 2 && (m->m_next->m_flags & M_EXT)), "reach: a cluster");
	__CPROVER_assert(!(n == 2 && (m->m_next->m_flags & M_EXT) &&
	    !(m->m_next->m_flags & M_EXTWR)), "reach: a read-only cluster");
	__CPROVER_assert(!(n == 2 && m->m_len == 0), "reach: an empty first mbuf");
	__CPROVER_assert(!(m->m_data != m->m_pktdat && !(m->m_flags & M_EXT)),
	    "reach: leading space");
	mbufkit_free(m);
	return (0);
}
