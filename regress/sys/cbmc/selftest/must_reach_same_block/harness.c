/*
 * must_reach anchor in an included file, on a line that cbmc's
 * coverage report lists second in a block (after a line of harness.c).
 * The statement is reached, so the result must be VERIFIED, not
 * VACUOUS.
 */
int
main(void)
{
	int x = 1;

#include <anchor_flat.inc>
	__CPROVER_assert(x == 1, "x == 1");
	return (0);
}
