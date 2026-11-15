/*
 * m_get(M_DONTWAIT) may fail: using the result unchecked is reported.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>

int
main(void)
{
	struct mbuf *m;

	m = m_get(M_DONTWAIT, MT_DATA);
#include <anchor.inc>
	m->m_len = 0;
	m_freem(m);
	return (0);
}
