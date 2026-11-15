/*
 * M_NOWAIT allocations may fail: storing through the result without a
 * NULL check must be reported.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	volatile char *p;

	p = malloc(8, M_TEMP, M_NOWAIT);
#include <anchor.inc>
	p[0] = 1;
	free((void *)p, M_TEMP, 8);
	return (0);
}
