/*
 * free(9) with a size at most half of the allocation's bucket:
 * DIAGNOSTIC kernels panic ("free: size too small").  The model's
 * kfree ignores the size.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	char *p;

	p = malloc(4096, M_TEMP, M_WAITOK);
#include <anchor.inc>
	free(p, M_TEMP, 16);
	return (0);
}
