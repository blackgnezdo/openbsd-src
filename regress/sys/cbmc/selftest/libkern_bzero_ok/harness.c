/*
 * bzero (sys/systm.h: __builtin_bzero) has a body (common/
 * stubs_libkern.c): it zeroes exactly n bytes and nothing after them.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include "cbmc_harness.h"

int
main(void)
{
	char buf[8];
	size_t n = nondet_uint() % 9, i = nondet_uint() % 8;

	buf[i] = 1;
#include <anchor.inc>
	bzero(buf, n);
	__CPROVER_assert(i >= n || buf[i] == 0, "bzero zeroes [0, n)");
	__CPROVER_assert(i < n || buf[i] == 1, "bzero leaves the rest");
	return (0);
}
