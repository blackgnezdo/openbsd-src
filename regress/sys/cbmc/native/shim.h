/*
 * Native stand-ins for the CBMC primitives.  Force-included (gcc -E
 * -include) into every translation unit native.sh builds: kernel files,
 * harness and common models.  Kernel units are built with -nostdinc, so
 * this header includes nothing and uses only builtin types.
 * The functions are in native/runtime.c.
 */
#ifndef NATIVE_SHIM_H
#define NATIVE_SHIM_H

void __native_assert_fail(const char *, const char *, int, const char *);
void __native_assume_fail(void) __attribute__((__noreturn__));
int __native_region_ok(const void *, unsigned long, int, const char *);
void __native_havoc(void *, unsigned long);
void *__native_allocate(unsigned long, int);
unsigned long __native_object_size(const void *);

#define __CPROVER_assert(c, msg) \
	((c) ? (void)0 : __native_assert_fail((msg), __FILE__, __LINE__, __func__))
#define __CPROVER_precondition(c, msg)	__CPROVER_assert(c, msg)
#define __CPROVER_assume(c) \
	((c) ? (void)0 : __native_assume_fail())
/* the function name lets the MSan build check initialisation in copyout */
#define __CPROVER_r_ok(p, n)	__native_region_ok((p), (n), 0, __func__)
#define __CPROVER_w_ok(p, n)	__native_region_ok((p), (n), 1, __func__)
#define __CPROVER_havoc_slice(p, n)	__native_havoc((p), (n))
#define __CPROVER_allocate(n, z)	__native_allocate((n), (z))
/* heap objects only: the size the allocator recorded for p's chunk */
#define __CPROVER_OBJECT_SIZE(p)	__native_object_size(p)

/*
 * common/stubs_alloc.c defines bodies for __builtin_bcopy, __builtin_memcpy
 * and __builtin_memmove, which clang does not accept as function names and
 * would otherwise expand itself.  Renaming them in every unit routes the
 * kernel's bcopy/memcpy/memmove macros (sys/systm.h) to those models, as
 * under CBMC.  memset, bzero and memcmp stay compiler builtins (libc,
 * checked by the sanitizer), as CBMC uses its own library for them.
 */
void __cbmc_model_bcopy(const void *, void *, unsigned long);
void *__cbmc_model_memcpy(void *, const void *, unsigned long);
void *__cbmc_model_memmove(void *, const void *, unsigned long);
#define __builtin_bcopy		__cbmc_model_bcopy

/* zeroed allocations must not take heap content from the input (runtime.c) */
#define calloc	__native_calloc
#define __builtin_memcpy	__cbmc_model_memcpy
#define __builtin_memmove	__cbmc_model_memmove

#endif
