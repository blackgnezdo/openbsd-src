/*
 * PR_NOWAIT pool_get(9) may fail: using the result unchecked is
 * reported.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/pool.h>

static struct pool pp;

int
main(void)
{
	volatile unsigned char *p;

	pp.pr_size = 8;
	p = pool_get(&pp, PR_NOWAIT);
#include <anchor.inc>
	p[0] = 1;
	pool_put(&pp, (void *)p);
	return (0);
}
