/*
 * One byte more than MCLBYTES does not fit into the cluster.
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
	memset(mtod(m, char *), 0, MCLBYTES + 1);
	m_freem(m);
	return (0);
}
