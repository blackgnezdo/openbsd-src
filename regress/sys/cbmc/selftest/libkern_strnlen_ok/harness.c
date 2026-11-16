/*
 * strnlen has a body: the length of a string terminated at an arbitrary
 * k, bounded by maxlen, is min(k, maxlen).
 */
#include <sys/param.h>
#include <sys/systm.h>
#include "cbmc_harness.h"

int
main(void)
{
	char s[8];
	size_t k = nondet_uint() % 8, max = nondet_uint() % 9, i;

	for (i = 0; i < 8; i++)
		s[i] = i < k ? 'a' : 0;
#include <anchor.inc>
	__CPROVER_assert(strnlen(s, max) == (k < max ? k : max),
	    "strnlen is min(k, maxlen)");
	return (0);
}
