/*
 * copyin(9) of more bytes than the kernel buffer holds is reported.
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

	buf = malloc(8, M_TEMP, M_WAITOK);
#include <anchor.inc>
	(void)copyin((const void *)nondet_ulong(), buf, 16);
	free(buf, M_TEMP, 8);
	return (0);
}
