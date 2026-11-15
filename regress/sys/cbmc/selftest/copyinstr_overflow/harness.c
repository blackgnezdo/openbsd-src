/*
 * copyinstr(9) with a length larger than the kernel buffer is
 * reported.
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
	size_t done;

	buf = malloc(8, M_TEMP, M_WAITOK);
#include <anchor.inc>
	(void)copyinstr((const void *)nondet_ulong(), buf, 16, &done);
	free(buf, M_TEMP, 8);
	return (0);
}
