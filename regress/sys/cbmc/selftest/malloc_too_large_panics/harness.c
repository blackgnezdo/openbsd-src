/*
 * malloc(9) above its size limit (65535 pages) without M_CANFAIL
 * panics; the model reports that as "panic reached".
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	char *p;

#include <anchor.inc>
	p = malloc(1UL << 30, M_TEMP, M_WAITOK);
	free(p, M_TEMP, 1UL << 30);
	return (0);
}
