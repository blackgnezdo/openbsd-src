/* strlcpy with dsize larger than dst writes past dst. */
#include <sys/param.h>
#include <sys/systm.h>
#include "cbmc_harness.h"

int
main(void)
{
	char src[8] = "abcdefg", dst[4];

#include <anchor.inc>
	(void)strlcpy(dst, src, sizeof(src));
	return (0);
}
