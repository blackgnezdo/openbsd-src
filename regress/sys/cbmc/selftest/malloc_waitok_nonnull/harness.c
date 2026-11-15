/*
 * M_WAITOK allocations do not fail: the result is not NULL.
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
	__CPROVER_assert(p != NULL, "M_WAITOK result not NULL");
	free(p, M_TEMP, 8);
	return (0);
}
