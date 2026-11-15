/*
 * Counterpart of leak: the same code with the free is clean.
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
	p[0] = 1;
	free(p, M_TEMP, 8);
	return (0);
}
