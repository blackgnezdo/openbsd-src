/*
 * mallocarray(9): the same overflow with M_CANFAIL returns NULL.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	char *p;

#include <anchor.inc>
	p = mallocarray((size_t)-1 / 2 + 2, 2, M_TEMP, M_WAITOK | M_CANFAIL);
	__CPROVER_assert(p == NULL, "overflow with M_CANFAIL is NULL");
	free(p, M_TEMP, 0);
	return (0);
}
