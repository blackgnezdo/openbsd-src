/*
 * strlcpy has a body: it returns strlen(src), and for dsize > 0 dst is
 * terminated within dsize bytes and holds the first min(k, dsize - 1)
 * bytes of src.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include "cbmc_harness.h"

int
main(void)
{
	char src[8], dst[8];
	size_t k = nondet_uint() % 8, d = nondet_uint() % 9, i, r;

	for (i = 0; i < 8; i++)
		src[i] = i < k ? 'a' + i : 0;
	dst[7] = 'z';
#include <anchor.inc>
	r = strlcpy(dst, src, d);
	__CPROVER_assert(r == k, "strlcpy returns strlen(src)");
	i = nondet_uint() % 8;
	if (d > 0) {
		size_t c = k < d - 1 ? k : d - 1;
		__CPROVER_assert(dst[c] == 0, "strlcpy terminates dst");
		__CPROVER_assert(i >= c || dst[i] == src[i],
		    "strlcpy copies the prefix");
	}
	return (0);
}
