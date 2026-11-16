/* bzero one byte past the end of the object is reported. */
#include <sys/param.h>
#include <sys/systm.h>
#include "cbmc_harness.h"

int
main(void)
{
	char buf[8];

#include <anchor.inc>
	bzero(buf, sizeof(buf) + 1);
	return (0);
}
