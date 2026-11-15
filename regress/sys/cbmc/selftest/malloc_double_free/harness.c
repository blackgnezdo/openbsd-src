/*
 * free(9) of the same pointer twice must be reported.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	char *p;

	p = malloc(8, M_TEMP, M_WAITOK);
	free(p, M_TEMP, 8);
#include <anchor.inc>
	free(p, M_TEMP, 8);
	return (0);
}
