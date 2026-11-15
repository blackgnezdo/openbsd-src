/*
 * MCLGET(m, M_WAIT) always yields a cluster: M_EXT is set and all
 * MCLBYTES bytes at m_data are writable.
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
	MCLGET(m, M_WAIT);
#include <anchor.inc>
	__CPROVER_assert(m->m_flags & M_EXT, "cluster attached");
	memset(mtod(m, char *), 0, MCLBYTES);
	m_freem(m);
	return (0);
}
