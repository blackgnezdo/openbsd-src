/*
 * A successful copyin(9) delivers arbitrary bytes: a buffer cleared
 * beforehand must not be assumed to stay clear.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/malloc.h>

unsigned long nondet_ulong(void);

int
main(void)
{
	char buf[16];
	int error;

	memset(buf, 0, sizeof(buf));
	error = copyin((const void *)nondet_ulong(), buf, 16);
	if (error == 0) {
#include <anchor.inc>
		__CPROVER_assert(buf[0] == 0, "copyin leaves buffer as it was");
	}
	return (0);
}
