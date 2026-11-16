/*
 * mbufkit_check rejects an mbuf whose data runs past its storage: the
 * first mbuf's m_data moved to the last byte of m_pktdat with m_len and
 * m_pkthdr.len kept consistent.
 */
#define MBUFKIT_MAXLEN	16
#include "mbufkit.h"

int
main(void)
{
	struct mbuf *m;

	mbufkit_init();
	m = mbufkit_build(2 + mbufkit_upto(6), MBUFKIT_PLAIN);
	if (m->m_len >= 2)
		m->m_data = m->m_pktdat + MHLEN - 1;
#include <anchor.inc>
	mbufkit_check(m);
	mbufkit_free(m);
	return (0);
}
