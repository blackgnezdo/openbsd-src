/*
 * Without CBMC_OVERRIDE_DIR the tree's f() is used: f() == 1.  The
 * same harness is run with an override in override_dir_mutant.
 */
int f(void);

int
main(void)
{
#include <anchor.inc>
	__CPROVER_assert(f() == 1, "f() == 1");
	return (0);
}
