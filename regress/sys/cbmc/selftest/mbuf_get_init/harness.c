/*
 * m_get(M_WAIT) returns a zeroed mbuf of the requested type with
 * m_data at the internal data area, no chain and no cluster.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>

int
main(void)
{
	struct mbuf *m;

	m = m_get(M_WAIT, MT_DATA);
#include <anchor.inc>
	__CPROVER_assert(m != NULL, "m_get(M_WAIT) not NULL");
	__CPROVER_assert(m->m_type == MT_DATA, "type");
	__CPROVER_assert(m->m_data == m->m_dat, "m_data");
	__CPROVER_assert(m->m_len == 0 && m->m_next == NULL &&
	    m->m_nextpkt == NULL, "empty, unchained");
	__CPROVER_assert((m->m_flags & M_EXT) == 0, "no cluster");
	m_freem(m);
	return (0);
}
