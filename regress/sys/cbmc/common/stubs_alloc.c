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
/*
 * free(9) under DIAGNOSTIC (kern_malloc.c) panics when the size passed is
 * non-zero and larger than the allocation's bucket, or when the bucket is
 * larger than MINALLOCSIZE and the size is at most half of it.  The bucket
 * is the allocation size rounded up to a power of two (at least 16), or to
 * whole pages above MAXALLOCSAVE (two pages).  Size 0 means "unknown".
 * The allocation size is that of the object p points to: CBMC's heap
 * object, or one made by __CPROVER_allocate (typed allocations, pool items).
 */
#define PAGE_SIZE_ 4096UL
#define MINALLOCSIZE_ 16UL
#define MAXALLOCSAVE_ (2 * PAGE_SIZE_)
void kfree(void *p, int type, size_t size)
{
	size_t alloc, b;

	if (p == NULL)
		return;
	alloc = __CPROVER_OBJECT_SIZE(p);
	b = MINALLOCSIZE_;
	/* 16 doubled up to 8192; no loop, targets set their own unwind bounds */
#define STEP_ if (b < alloc) b <<= 1;
	STEP_ STEP_ STEP_ STEP_ STEP_ STEP_ STEP_ STEP_ STEP_
#undef STEP_
	if (alloc > MAXALLOCSAVE_)
		b = (alloc + PAGE_SIZE_ - 1) & ~(PAGE_SIZE_ - 1);
	__CPROVER_assert(size == 0 || size <= b, "free: size too large");
	__CPROVER_assert(size == 0 || b <= MINALLOCSIZE_ || size > b / 2,
	    "free: size too small");
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
/*
 * -DMEMCPY_BYTELOOP (stubflags): memcpy and memmove are byte loops that
 * check both regions, like bcopy; bound them with --unwindset
 * __builtin_memcpy.0:N, __builtin_memmove.0:N, __builtin_memmove.1:N.
 * For targets that copy into and out of the data area of a structure
 * (mbufs: m_dat inside struct mbuf): CBMC's own models replace the
 * whole object at a symbolic offset, after which every field read of
 * that object is very expensive to execute symbolically.
 */
/*
 * -DMEMCPY_TRACK (stubflags): memcpy and memmove check both regions and
 * follow one byte, but store nothing.  For data inside structures
 * (mbufs: m_dat inside struct mbuf): a byte written at a symbolic offset
 * into a structure turns every later field read of that object into
 * byte operations, pointers read back lose their targets, and the
 * formula explodes (CBMC's own memmove: over three million variables
 * for one call into one mbuf).
 *
 * The harness names one byte: __memtrack_loc[0] = its address
 * (common/mbufkit.h, mbufkit_track()).  The model keeps the set of
 * locations that hold a copy of that byte, at most two: a copy whose
 * source region contains a tracked location adds the corresponding
 * destination location; a tracked location inside the destination that
 * receives no copy of the byte leaves the set.  "Byte p of the result is
 * the tracked byte" is then a pointer comparison: p is in the set
 * (mbufkit_same()).  Destination bytes keep their old content, so the
 * values code reads after a copy are not the source's: use this only
 * where control flow does not depend on copied bytes (the mbuf
 * library), and where all data moves through memcpy/memmove (not bcopy
 * or direct stores).  Copies of at most MEMTRACK_REAL bytes (default 0;
 * a constant) are also performed, for small structures copied with
 * memcpy (m_defrag copies struct mbuf_ext).  Natively (native.sh) the
 * copy is always real and mbufkit_same() compares values.
 */
#if defined(MEMCPY_TRACK) && !defined(NATIVE_SHIM_H)
#ifndef MEMTRACK_REAL
#define MEMTRACK_REAL	0
#endif
/* Macros, not functions: cbmc.sh keeps only the bodies of the fixed
 * model names (__builtin_memcpy, __builtin_memmove) in this file. */
const unsigned char *__memtrack_loc[2];

/* p inside [base, base + n) */
#define MEMTRACK_IN(p, base, n)						\
	((p) != 0 && __CPROVER_same_object((p), (base)) &&		\
	    __CPROVER_POINTER_OFFSET(p) >= __CPROVER_POINTER_OFFSET(base) && \
	    (size_t)(__CPROVER_POINTER_OFFSET(p) -			\
	    __CPROVER_POINTER_OFFSET(base)) < (n))

/* p - base for p inside base's object, without CBMC's address model */
#define MEMTRACK_OFF(p, base)						\
	(__CPROVER_POINTER_OFFSET(p) - __CPROVER_POINTER_OFFSET(base))

#define MEMTRACK_COPY(dst, src, len) do {				\
	unsigned char *d_ = (dst);					\
	const unsigned char *s_ = (src);				\
	size_t n_ = (len);						\
	const unsigned char *l0 = __memtrack_loc[0];			\
	const unsigned char *l1 = __memtrack_loc[1];			\
	const unsigned char *n0, *n1;					\
	if (MEMTRACK_REAL > 0 && n_ <= MEMTRACK_REAL) {			\
		unsigned char t_[MEMTRACK_REAL > 0 ? MEMTRACK_REAL : 1]; \
		for (int i_ = 0; i_ < MEMTRACK_REAL; i_++)		\
			if ((size_t)i_ < n_)				\
				t_[i_] = s_[i_];			\
		for (int i_ = 0; i_ < MEMTRACK_REAL; i_++)		\
			if ((size_t)i_ < n_)				\
				d_[i_] = t_[i_];			\
	}								\
	/* copies of the tracked byte this copy produces */		\
	n0 = MEMTRACK_IN(l0, s_, n_) ? d_ + MEMTRACK_OFF(l0, s_) : 0;	\
	n1 = MEMTRACK_IN(l1, s_, n_) ? d_ + MEMTRACK_OFF(l1, s_) : 0;	\
	/* tracked locations in the destination are overwritten */	\
	if (MEMTRACK_IN(l0, d_, n_))					\
		l0 = 0;							\
	if (MEMTRACK_IN(l1, d_, n_))					\
		l1 = 0;							\
	/* new set: surviving old locations, then new ones */		\
	if (l0 == 0) { l0 = l1; l1 = 0; }				\
	if (n0 == 0) { n0 = n1; n1 = 0; }				\
	if (l0 == 0) { l0 = n0; n0 = n1; n1 = 0; }			\
	else if (l1 == 0) { l1 = n0; n0 = n1; n1 = 0; }			\
	__CPROVER_assert(n0 == 0,					\
	    "memtrack: more than two copies of the tracked byte");	\
	__memtrack_loc[0] = l0;						\
	__memtrack_loc[1] = l1;						\
} while (0)
#endif

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
#elif defined(MEMCPY_TRACK) && !defined(NATIVE_SHIM_H)
	__CPROVER_precondition(__CPROVER_r_ok(src, n),
	    "memcpy source region readable");
	__CPROVER_precondition(__CPROVER_w_ok(dst, n),
	    "memcpy destination region writeable");
	MEMTRACK_COPY(dst, src, n);
	return dst;
#elif defined(MEMCPY_BYTELOOP)
	unsigned char *d = dst;
	const unsigned char *s = src;

	__CPROVER_precondition(__CPROVER_r_ok(src, n),
	    "memcpy source region readable");
	__CPROVER_precondition(__CPROVER_w_ok(dst, n),
	    "memcpy destination region writeable");
	for (size_t i = 0; i < n; i++)
		d[i] = s[i];
	return dst;
#else
	return memcpy(dst, src, n);
#endif
}
void *__builtin_memmove(void *dst, const void *src, size_t n)
{
#if defined(MEMCPY_TRACK) && !defined(NATIVE_SHIM_H)
	__CPROVER_precondition(__CPROVER_r_ok(src, n),
	    "memmove source region readable");
	__CPROVER_precondition(__CPROVER_w_ok(dst, n),
	    "memmove destination region writeable");
	MEMTRACK_COPY(dst, src, n);
	return dst;
#elif defined(MEMCPY_BYTELOOP)
	unsigned char *d = dst;
	const unsigned char *s = src;

	__CPROVER_precondition(__CPROVER_r_ok(src, n),
	    "memmove source region readable");
	__CPROVER_precondition(__CPROVER_w_ok(dst, n),
	    "memmove destination region writeable");
	if (d <= s) {
		for (size_t i = 0; i < n; i++)
			d[i] = s[i];
	} else {
		for (size_t i = n; i > 0; i--)
			d[i - 1] = s[i - 1];
	}
	return dst;
#else
	return memmove(dst, src, n);
#endif
}

/* libkern string and bit functions (no bodies otherwise) */
#include "stubs_libkern.c"
