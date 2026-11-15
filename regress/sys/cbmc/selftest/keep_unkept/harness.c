/*
 * A function that is not listed in keep loses its body and returns an
 * arbitrary value, so the assertion f() == 7 must fail.  Documents the
 * default for every function outside keep.
 */
int f(void);

int
main(void)
{
#include <anchor.inc>
	__CPROVER_assert(f() == 7, "f() == 7");
	return (0);
}
