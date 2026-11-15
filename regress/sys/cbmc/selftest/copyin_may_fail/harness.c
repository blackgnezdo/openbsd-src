/*
 * Any copyin(9) may fail: asserting that it succeeds must be refuted.
 * Code that ignores the return value is therefore found by checks on
 * the data it uses.
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

#include <anchor.inc>
	error = copyin((const void *)nondet_ulong(), buf, 16);
	__CPROVER_assert(error == 0, "copyin cannot fail");
	return (0);
}
