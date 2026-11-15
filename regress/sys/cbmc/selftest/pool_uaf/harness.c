/*
 * Reading a pool item after pool_put(9) is reported.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/pool.h>

static struct pool pp;

int
main(void)
{
	volatile unsigned char *p, c;

	pp.pr_size = 8;
	p = pool_get(&pp, PR_WAITOK);
	pool_put(&pp, (void *)p);
#include <anchor.inc>
	c = p[0];
	return (c);
}
