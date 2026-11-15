/*
 * Counterpart of malloc_zero: without M_ZERO the memory is arbitrary,
 * so an assertion that it is zero must fail.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	unsigned char *p;

	p = malloc(8, M_TEMP, M_WAITOK);
#include <anchor.inc>
	__CPROVER_assert(p[0] == 0, "M_NOZERO memory is zero");
	free(p, M_TEMP, 8);
	return (0);
}
