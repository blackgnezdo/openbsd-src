/*
 * A static inline function defined in a header (cbmc.sh decides by the
 * file name ending in .h) and not listed in keep keeps its body, like
 * min() and max() from libkern.  Only lib.c includes the header, so the
 * function is not part of the harness object, which is kept anyway.
 */
int wrap_add(int, int);

int
main(void)
{
#include <anchor.inc>
	__CPROVER_assert(wrap_add(2, 3) == 5, "wrap_add(2, 3) == 5");
	return (0);
}
