/* Allocator model.  Built WITHOUT kernel headers and without -Dmalloc=...,
 * so malloc/calloc/free here are CBMC's built-in heap model. */
#include <stdlib.h>
#define M_NOWAIT 0x0002
#define M_ZERO   0x0008
_Bool nondet_bool(void);
void *kmalloc(size_t size, int type, int flags)
{
	if ((flags & M_NOWAIT) && nondet_bool())
		return NULL;
	return (flags & M_ZERO) ? calloc(1, size) : malloc(size);
}
void kfree(void *p, int type, size_t size)
{
	free(p);
}
