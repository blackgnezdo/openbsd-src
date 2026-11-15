/*
 * -DMEMCPY_HAVOC: an in-bounds copy stores arbitrary bytes, so the
 * destination is NOT guaranteed to equal the source (counterpart of
 * memcpy_ok, which is VERIFIED).  No bounds failure may be reported.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	unsigned char *src, *dst;

	src = malloc(8, M_TEMP, M_WAITOK);
	dst = malloc(8, M_TEMP, M_WAITOK);
#include <anchor.inc>
	memcpy(dst, src, 8);
	__CPROVER_assert(dst[3] == src[3], "havoc memcpy copied byte");
	free(dst, M_TEMP, 8);
	free(src, M_TEMP, 8);
	return (0);
}
