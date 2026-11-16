/* strnlen with maxlen beyond an unterminated object reads past it. */
#include <sys/param.h>
#include <sys/systm.h>
#include "cbmc_harness.h"

int
main(void)
{
	char s[4] = { 'a', 'b', 'c', 'd' };
	volatile size_t n;

#include <anchor.inc>
	n = strnlen(s, 8);
	return (0);
}
