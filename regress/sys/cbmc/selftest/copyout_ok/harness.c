/*
 * copyout(9) from a readable kernel buffer is fine; result 0 or EFAULT.
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

	buf = malloc(16, M_TEMP, M_WAITOK | M_ZERO);
#include <anchor.inc>
	error = copyout(buf, (void *)nondet_ulong(), 16);
	__CPROVER_assert(error == 0 || error == EFAULT, "copyout result");
	free(buf, M_TEMP, 16);
	return (0);
}
