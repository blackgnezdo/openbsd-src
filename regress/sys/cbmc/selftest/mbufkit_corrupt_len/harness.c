/*
 * mbufkit_check rejects a chain whose m_pkthdr.len is not the sum of
 * m_len (one more byte claimed in the last mbuf than the header says).
 */
#define MBUFKIT_MAXLEN	16
#include "mbufkit.h"

int
main(void)
{
	struct mbuf *m, *l;

	mbufkit_init();
	m = mbufkit_build(mbufkit_upto(8), MBUFKIT_PLAIN);
	for (l = m; l->m_next != NULL; l = l->m_next)
		;
	l->m_len++;		/* storage has room: only the sum is wrong */
#include <anchor.inc>
	mbufkit_check(m);
	mbufkit_free(m);
	return (0);
}
