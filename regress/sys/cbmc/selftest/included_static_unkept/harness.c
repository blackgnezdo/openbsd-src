/*
 * Documented contract (README, cbmc.sh): a function that is not listed
 * in keep loses its body.  st_twice is static in an included file and
 * not in keep, so its result is arbitrary and the assertion must fail.
 * (cbmc.sh keeps every function of harness.o, included files too.)
 */
#include <incl_static.c>

int
main(void)
{
#include <anchor.inc>
	__CPROVER_assert(st_twice(21) == 42, "st_twice(21) == 42");
	return (0);
}
