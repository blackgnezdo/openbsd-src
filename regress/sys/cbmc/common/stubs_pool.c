/* pool(9) model on top of the malloc(9) model.  Built with kernel headers.
 * The harness must set pr_size of every pool it uses. */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/pool.h>

void *
pool_get(struct pool *pp, int flags)
{
	int mflags = 0;

	if (flags & PR_NOWAIT)
		mflags |= M_NOWAIT;
	if (flags & PR_ZERO)
		mflags |= M_ZERO;
	return malloc(pp->pr_size, M_TEMP, mflags);
}

void
pool_put(struct pool *pp, void *v)
{
	free(v, M_TEMP, pp->pr_size);
}
