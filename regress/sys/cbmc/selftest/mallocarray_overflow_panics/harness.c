/*
 * mallocarray(9): nmemb * size overflows size_t; without M_CANFAIL
 * the kernel panics.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	char *p;

#include <anchor.inc>
	p = mallocarray((size_t)-1 / 2 + 2, 2, M_TEMP, M_WAITOK);
	free(p, M_TEMP, 0);
	return (0);
}
