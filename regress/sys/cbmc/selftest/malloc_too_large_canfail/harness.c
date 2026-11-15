/*
 * Same request with M_CANFAIL does not panic but returns NULL.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	char *p;

#include <anchor.inc>
	p = malloc(1UL << 30, M_TEMP, M_WAITOK | M_CANFAIL);
	__CPROVER_assert(p == NULL, "too large with M_CANFAIL is NULL");
	free(p, M_TEMP, 1UL << 30);
	return (0);
}
