/*
 * mallocarray(9) without overflow allocates nmemb * size bytes: the
 * last byte is writable, and M_ZERO is honoured.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	char *p;

#include <anchor.inc>
	p = mallocarray(4, 3, M_TEMP, M_WAITOK | M_ZERO);
	__CPROVER_assert(p[11] == 0, "mallocarray M_ZERO");
	p[11] = 1;
	free(p, M_TEMP, 12);
	return (0);
}
