/*
 * malloc(9) with M_ZERO must return memory that reads as zero (the
 * model uses calloc).  Pins down the M_ZERO flag mapping.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	unsigned char *p;
	int i;

	p = malloc(8, M_TEMP, M_WAITOK | M_ZERO);
#include <anchor.inc>
	for (i = 0; i < 8; i++)
		__CPROVER_assert(p[i] == 0, "M_ZERO memory reads as zero");
	free(p, M_TEMP, 8);
	return (0);
}
