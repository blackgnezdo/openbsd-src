/*
 * mallocarray(9) allocates exactly nmemb * size bytes: one byte past
 * is out of bounds.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	volatile char *p;

#include <anchor.inc>
	p = mallocarray(4, 3, M_TEMP, M_WAITOK);
	p[12] = 1;
	free((void *)p, M_TEMP, 12);
	return (0);
}
