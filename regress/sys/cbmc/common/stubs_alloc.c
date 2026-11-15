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

/*
 * CBMC has no model for bcopy.  A byte loop is used because CBMC's memmove
 * with a symbolic length is very expensive; targets that call bcopy must
 * bound the loop with --unwindset __builtin_bcopy.0:N.
 */
void __builtin_bcopy(const void *src, void *dst, size_t n)
{
	const unsigned char *s = src;
	unsigned char *d = dst;

	for (size_t i = 0; i < n; i++)
		d[i] = s[i];
}
