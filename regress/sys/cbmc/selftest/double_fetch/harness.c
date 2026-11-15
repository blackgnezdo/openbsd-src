/*
 * Two copyin(9) calls from the same user address yield independent
 * bytes (user memory may change in between): comparing them must be
 * refuted.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/malloc.h>

unsigned long nondet_ulong(void);

int
main(void)
{
	const void *uaddr = (const void *)nondet_ulong();
	int a, b;

	if (copyin(uaddr, &a, sizeof(a)) != 0 ||
	    copyin(uaddr, &b, sizeof(b)) != 0)
		return (0);
#include <anchor.inc>
	__CPROVER_assert(a == b, "double fetch");
	return (0);
}
