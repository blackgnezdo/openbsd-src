/*
 * panic(9) ends the path: it is reported, and nothing after it runs
 * (the assertion behind it must not show up as a second failure).
 */
#include <sys/param.h>
#include <sys/systm.h>

int
main(void)
{
#include <anchor.inc>
	panic("selftest");
	__CPROVER_assert(0, "after panic");
	return (0);
}
