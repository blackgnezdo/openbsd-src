/*
 * free(9) of NULL is a no-op.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

int
main(void)
{
#include <anchor.inc>
	free(NULL, M_TEMP, 0);
	return (0);
}
