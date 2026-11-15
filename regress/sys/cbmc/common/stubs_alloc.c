/* Allocator model.  Built WITHOUT kernel headers and without -Dmalloc=...,
 * so malloc/calloc/free here are CBMC's built-in heap model. */
#include <stdlib.h>
#define M_NOWAIT 0x0002
#define M_ZERO   0x0008
_Bool nondet_bool(void);
#define M_CANFAIL 0x0004
#define MALLOC_MAX (65535UL * 4096)	/* kern_malloc.c: 65535 * PAGE_SIZE */
void panic(const char *, ...);
void *kmalloc(size_t size, int type, int flags)
{
	if (size > MALLOC_MAX) {
		if (flags & M_CANFAIL)
			return NULL;
		panic("malloc: allocation too large");
	}
	if ((flags & M_NOWAIT) && nondet_bool())
		return NULL;
	return (flags & M_ZERO) ? calloc(1, size) : malloc(size);
}
void *mallocarray(size_t nmemb, size_t size, int type, int flags)
{
	if (size != 0 && nmemb > (size_t)-1 / size) {
		if (flags & M_CANFAIL)
			return NULL;
		panic("mallocarray: overflow");
	}
	return kmalloc(nmemb * size, type, flags);
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

/*
 * panic(9) does not return.  Reaching it is reported: a panic that on-disk
 * or device-supplied data can trigger is a finding.
 */
void panic(const char *fmt, ...)
{
	__CPROVER_assert(0, "panic reached");
	__CPROVER_assume(0);
}

/*
 * The kernel maps memcpy and memmove to the compiler builtins, for which
 * CBMC supplies no body after goto-cc.  Route them to CBMC's own models,
 * which check that both regions are valid.
 */
#include <string.h>
void *__builtin_memcpy(void *dst, const void *src, size_t n)
{
#ifdef MEMCPY_HAVOC
	/*
	 * Cheaper model for targets where CBMC's memcpy with a symbolic
	 * length is too expensive: both regions are checked, but the
	 * destination receives arbitrary bytes instead of the source's.
	 * Only sound where nothing later depends on the copied values
	 * being equal to the source.
	 */
	__CPROVER_precondition(__CPROVER_r_ok(src, n),
	    "memcpy source region readable");
	__CPROVER_precondition(__CPROVER_w_ok(dst, n),
	    "memcpy destination region writeable");
	if (n > 0)
		__CPROVER_havoc_slice(dst, n);
	return dst;
#else
	return memcpy(dst, src, n);
#endif
}
void *__builtin_memmove(void *dst, const void *src, size_t n)
{
	return memmove(dst, src, n);
}
