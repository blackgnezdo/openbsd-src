/*
 * MCLGET(m, M_DONTWAIT) may leave the mbuf without a cluster: code that
 * assumes M_EXT after it is reported.
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
	MCLGET(m, M_DONTWAIT);
#include <anchor.inc>
	__CPROVER_assert(m->m_flags & M_EXT, "cluster attached");
	m_freem(m);
	return (0);
}
