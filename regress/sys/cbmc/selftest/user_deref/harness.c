/*
 * A user address is not an object of the model: dereferencing it
 * directly instead of through copyin(9) is reported.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/malloc.h>

unsigned long nondet_ulong(void);

int
main(void)
{
	volatile char *uaddr = (volatile char *)nondet_ulong();
	char c;

#include <anchor.inc>
	c = *uaddr;
	return (c);
}
