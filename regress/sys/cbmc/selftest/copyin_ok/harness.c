/*
 * copyin(9) into a kernel buffer of exactly the copied length is fine,
 * and the result is 0 or EFAULT, nothing else.
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
	int error;

	buf = malloc(16, M_TEMP, M_WAITOK);
	error = copyin((const void *)nondet_ulong(), buf, 16);
	__CPROVER_assert(error == 0 || error == EFAULT, "copyin result");
	if (error == 0) {
#include <anchor.inc>
		buf[15] = 1;
	}
	free(buf, M_TEMP, 16);
	return (0);
}
