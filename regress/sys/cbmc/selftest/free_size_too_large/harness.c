/*
 * free(9) with a size far above the allocation: DIAGNOSTIC kernels
 * panic ("free: size too large").  The model's kfree ignores the size.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	char *p;

	p = malloc(8, M_TEMP, M_WAITOK);
#include <anchor.inc>
	free(p, M_TEMP, 4096);
	return (0);
}
