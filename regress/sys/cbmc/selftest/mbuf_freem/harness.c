/*
 * m_freem() releases a whole chain, clusters included: three mbufs,
 * the middle one with a cluster, no leak.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>

int
main(void)
{
	struct mbuf *a, *b, *c;

	a = m_get(M_WAIT, MT_DATA);
	b = m_get(M_WAIT, MT_DATA);
	c = m_get(M_WAIT, MT_DATA);
	MCLGET(b, M_WAIT);
	a->m_next = b;
	b->m_next = c;
#include <anchor.inc>
	m_freem(a);
	return (0);
}
