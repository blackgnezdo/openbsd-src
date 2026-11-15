/*
 * -DMEMCPY_HAVOC (stubflags): the havoc variant of memcpy still checks
 * the destination region.
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
	memcpy(dst, src, 16);
	free(dst, M_TEMP, 8);
	free(src, M_TEMP, 16);
	return (0);
}
