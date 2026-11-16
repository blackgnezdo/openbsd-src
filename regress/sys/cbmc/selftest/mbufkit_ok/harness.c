/*
 * Counterpart of mbufkit_leak and the corrupt tests: a built chain is
 * well formed, m_freem() (mbufkit_free) releases all of it, the byte
 * probes agree with the chain.
 */
#define MBUFKIT_MAXLEN	16
#include "mbufkit.h"

int
main(void)
{
	struct mbuf *m;
	struct mbufkit_byte b;

	mbufkit_init();
	m = mbufkit_build(mbufkit_upto(16), MBUFKIT_ANY);
	mbufkit_track(&b, m);
#include <anchor.inc>
	mbufkit_check(m);
	__CPROVER_assert(mbufkit_same(&b, mbufkit_ptr(m, b.off)),
	    "probe finds the tracked byte");
	__CPROVER_assert(b.off < 0 || mbufkit_byte(m, b.off) == b.val,
	    "probe value");
	mbufkit_free(m);
	return (0);
}
