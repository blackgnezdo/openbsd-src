/*
 * Reading memory after free(9) must be reported (the free model maps
 * to CBMC's free, which kills the object).
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	volatile unsigned char *p, c;

	p = malloc(8, M_TEMP, M_WAITOK);
	free((void *)p, M_TEMP, 8);
#include <anchor.inc>
	c = p[0];
	return (c);
}
