/*
 * copyout(9) of more bytes than the kernel buffer holds would leak
 * adjacent kernel memory: reported.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/malloc.h>

unsigned long nondet_ulong(void);

int
main(void)
{
	char *buf;

	buf = malloc(8, M_TEMP, M_WAITOK | M_ZERO);
#include <anchor.inc>
	(void)copyout(buf, (void *)nondet_ulong(), 16);
	free(buf, M_TEMP, 8);
	return (0);
}
