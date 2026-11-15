/*
 * memcpy via the kernel macro (sys/systm.h -> __builtin_memcpy) must
 * perform the copy: after an in-bounds copy the bytes are equal.  Pins
 * down the "memcpy had no body, copy silently skipped" defect.
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
	memcpy(dst, src, 8);
	for (i = 0; i < 8; i++)
		__CPROVER_assert(dst[i] == src[i], "memcpy copied byte");
	free(dst, M_TEMP, 8);
	free(src, M_TEMP, 8);
	return (0);
}
