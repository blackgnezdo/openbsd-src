/*
 * A failing KASSERT is reported: goto-cc turns the __assert call of
 * libkern.h (DIAGNOSTIC) into an assertion.  Unlike panic(9) it does
 * not end the path; a holding one is silent.
 */
#include <sys/param.h>
#include <sys/systm.h>

int
main(void)
{
	int x = nondet_int();

#include <anchor.inc>
	KASSERT(1);
	KASSERT(x != 0);
	__CPROVER_assert(x != 0, "after KASSERT");
	return (0);
}
