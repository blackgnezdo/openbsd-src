/*
 * min() and friends come from lib/libkern as inline functions in a
 * header and must keep their bodies when used by a kernel file (lib.c
 * calls them from kept wrappers): a stripped body returns arbitrary
 * values.  Arguments tell signed from unsigned and 32 from 64 bits.
 */
#define CHECK(e)	__CPROVER_assert((e), #e)
#define U	(unsigned long)

unsigned long w_min(unsigned long, unsigned long);
unsigned long w_max(unsigned long, unsigned long);
long w_imin(long, long), w_imax(long, long);
long w_lmin(long, long), w_lmax(long, long);
unsigned long w_ulmin(unsigned long, unsigned long);
unsigned long w_ulmax(unsigned long, unsigned long);

int
main(void)
{
#include <anchor.inc>
	CHECK(w_min(3, 5) == 3);
	CHECK(w_max(3, 5) == 5);
	CHECK(w_min(0xffffffffUL, 1) == 1);	/* unsigned */
	CHECK(w_max(0xffffffffUL, 1) == 0xffffffffUL);
	CHECK(w_min((1UL << 32) + 1, 5) == 1);	/* u_int truncates */
	CHECK(w_max((1UL << 32) + 1, 5) == 5);
	CHECK(w_imin(-1, 1) == -1);		/* signed */
	CHECK(w_imax(-1, 1) == 1);
	CHECK(w_imin(7, 2) == 2);
	CHECK(w_imax(7, 2) == 7);
	CHECK(w_imin((1L << 32) + 1, 5) == 1);	/* int truncates */
	CHECK(w_lmin(-1, 1) == -1);
	CHECK(w_lmax(-1, 1) == 1);
	CHECK(w_lmin(-(1L << 40), 7) == -(1L << 40));	/* 64 bits */
	CHECK(w_lmax(1L << 40, 7) == 1L << 40);
	CHECK(w_ulmin(U -1, 1) == 1);		/* unsigned long */
	CHECK(w_ulmax(U -1, 1) == U -1);
	CHECK(w_ulmin(1UL << 40, 7) == 7);
	CHECK(w_ulmax(1UL << 40, 7) == 1UL << 40);
	return (0);
}
