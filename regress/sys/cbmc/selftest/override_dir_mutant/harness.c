/*
 * CBMC_OVERRIDE_DIR (set by "env") replaces lib.c, matched by basename,
 * with a copy whose f() returns 2: the assertion must now fail.
 */
int f(void);

int
main(void)
{
#include <anchor.inc>
	__CPROVER_assert(f() == 1, "f() == 1");
	return (0);
}
