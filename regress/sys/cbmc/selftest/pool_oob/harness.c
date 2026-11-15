/*
 * A pool item is exactly pr_size bytes: the byte at offset pr_size is the
 * first one outside it.
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
	p = pool_get(&pp, PR_WAITOK);
#include <anchor.inc>
	p[8] = 1;
	pool_put(&pp, (void *)p);
	return (0);
}
