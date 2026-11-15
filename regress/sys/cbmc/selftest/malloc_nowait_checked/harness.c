/*
 * Counterpart of malloc_nowait_unchecked: with the NULL check the
 * program is clean, and both outcomes (NULL, memory) are reachable
 * (one anchor per branch).
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
	volatile char *p;

	p = malloc(8, M_TEMP, M_NOWAIT);
	if (p == NULL) {
#include <anchor.inc>
		return (0);
	}
#include <anchor2.inc>
	p[0] = 1;
	free((void *)p, M_TEMP, 8);
	return (0);
}
