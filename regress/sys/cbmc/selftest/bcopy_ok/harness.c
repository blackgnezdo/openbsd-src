/*
 * bcopy(src, dst, n) through the kernel macro: argument order is source
 * first, and the bytes must arrive.  Pins down the "bcopy had no body,
 * copy silently skipped" defect.  Needs --unwindset __builtin_bcopy.0.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	unsigned char *src, *dst;
	int i;

	src = malloc(8, M_TEMP, M_WAITOK);
	dst = malloc(8, M_TEMP, M_WAITOK);
#include <anchor.inc>
	bcopy(src, dst, 8);
	for (i = 0; i < 8; i++)
		__CPROVER_assert(dst[i] == src[i], "bcopy copied byte");
	free(dst, M_TEMP, 8);
	free(src, M_TEMP, 8);
	return (0);
}
