/*
 * pool_put(9) of the same item twice is reported.
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
	pool_put(&pp, p);
#include <anchor.inc>
	pool_put(&pp, p);
	return (0);
}
