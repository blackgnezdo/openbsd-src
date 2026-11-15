/*
 * Counterpart of pool_zero: without PR_ZERO the item is arbitrary.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/pool.h>

static struct pool pp;

int
main(void)
{
	unsigned char *p;

	pp.pr_size = 8;
	p = pool_get(&pp, PR_WAITOK);
#include <anchor.inc>
	__CPROVER_assert(p[0] == 0, "item is zero");
	pool_put(&pp, p);
	return (0);
}
