/*
 * Counterpart of mbuf_freem: the same chain without m_freem() is a
 * leak.
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
	return (0);
}
