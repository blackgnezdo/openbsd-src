/*
 * memcmp (sys/systm.h: __builtin_memcmp) has a body: 0 for equal
 * regions, the sign of the first difference otherwise.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include "cbmc_harness.h"

int
main(void)
{
	unsigned char a[4], b[4];
	int i = nondet_uint() % 4, r;

	a[0] = b[0]; a[1] = b[1]; a[2] = b[2]; a[3] = b[3];
	a[i] = nondet_uchar();
#include <anchor.inc>
	r = memcmp(a, b, 4);
	__CPROVER_assert((r == 0) == (a[i] == b[i]), "memcmp: 0 iff equal");
	__CPROVER_assert(r == 0 || (r < 0) == (a[i] < b[i]),
	    "memcmp: sign of the first difference");
	return (0);
}
