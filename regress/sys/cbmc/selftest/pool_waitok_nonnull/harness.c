/*
 * PR_WAITOK pool_get(9) does not fail.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/pool.h>

static struct pool pp;

int
main(void)
{
	void *p;

	pp.pr_size = 8;
	p = pool_get(&pp, PR_WAITOK);
#include <anchor.inc>
	__CPROVER_assert(p != NULL, "PR_WAITOK item not NULL");
	pool_put(&pp, p);
	return (0);
}
