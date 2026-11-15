/*
 * bcopy of 16 bytes into an 8-byte allocation: the byte loop must write
 * out of bounds and be reported.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	char *src, *dst;

	src = malloc(16, M_TEMP, M_WAITOK);
	dst = malloc(8, M_TEMP, M_WAITOK);
#include <anchor.inc>
	bcopy(src, dst, 16);
	free(dst, M_TEMP, 8);
	free(src, M_TEMP, 16);
	return (0);
}
