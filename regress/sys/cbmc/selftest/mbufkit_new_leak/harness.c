/*
 * An object made with CBMC_NEW and never freed is a leak.  The mbuf kit
 * allocates every mbuf and cluster this way; before CBMC_NEW recorded
 * its objects for --memory-leak-check, a dropped chain went unnoticed.
 */
#include <sys/param.h>
#include "cbmc_harness.h"

struct obj {
	int	a;
};

int
main(void)
{
	struct obj *p = CBMC_NEW(struct obj);

#include <anchor.inc>
	p->a = 1;
	return (0);
}
