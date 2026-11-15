/*
 * An mbuf from m_get() (stubs_mbuf.c) holds MLEN bytes of data at
 * mtod(): writing all of them is in bounds.
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
	memset(mtod(m, char *), 0, MLEN);
	m_freem(m);
	return (0);
}
