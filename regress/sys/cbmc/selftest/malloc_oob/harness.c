/*
 * An access one byte past an 8-byte allocation must be reported.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	volatile char *p;

	p = malloc(8, M_TEMP, M_WAITOK);
#include <anchor.inc>
	p[8] = 1;
	free((void *)p, M_TEMP, 8);
	return (0);
}
