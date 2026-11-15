/*
 * One byte more than MLEN does not fit into the mbuf's own data area.
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
	memset(mtod(m, char *), 0, MLEN + 1);
	m_freem(m);
	return (0);
}
