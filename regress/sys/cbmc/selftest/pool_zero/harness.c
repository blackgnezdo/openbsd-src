/*
 * pool_get(9) with PR_ZERO returns zeroed memory of pr_size bytes
 * (stubs_pool.c maps the flag to M_ZERO).
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
	int i;

	pp.pr_size = 8;
	p = pool_get(&pp, PR_WAITOK | PR_ZERO);
#include <anchor.inc>
	for (i = 0; i < 8; i++)
		__CPROVER_assert(p[i] == 0, "PR_ZERO item reads as zero");
	pool_put(&pp, p);
	return (0);
}
