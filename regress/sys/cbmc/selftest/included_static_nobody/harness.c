/*
 * Documented contract (cbmc.sh header): a function listed in nobody has
 * its body removed and returns an unconstrained value.  st_twice is
 * static in an included file and listed in nobody, so the assertion
 * must fail.
 */
#include <incl_static.c>

int
main(void)
{
#include <anchor.inc>
	__CPROVER_assert(st_twice(21) == 42, "st_twice(21) == 42");
	return (0);
}
