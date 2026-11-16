/* memcmp over equal bytes past the end of the shorter object. */
#include <sys/param.h>
#include <sys/systm.h>
#include "cbmc_harness.h"

int
main(void)
{
	char a[4] = "abc", b[8] = "abc";
	volatile int r;

#include <anchor.inc>
	r = memcmp(a, b, 8);
	return (0);
}
