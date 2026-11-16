/*
 * Helpers for harness.c.  Optional: #include "cbmc_harness.h" (common/ is
 * on the include path of harness.c).
 *
 * CBMC_NEW(type), CBMC_NEW_ARRAY(type, n)
 *	A zeroed object, or array of n objects, with its real type.  Use
 *	them for every object the code under test reaches through a table,
 *	a list or a pointer that may refer to several objects, and in
 *	pool_get/malloc models that replace the common ones (replace file).
 *	The common malloc and pool models return untyped byte arrays, and a
 *	field access through a pointer that may refer to several of those is
 *	encoded byte by byte, which makes the solver very slow (README,
 *	"Adding a target").  Objects that stay behind a single pointer
 *	(a softc on the stack, a static struct) need no such care.
 *	The objects are on CBMC's heap: the code under test may free them,
 *	and --memory-leak-check sees them.  NEW_ARRAY takes a constant n
 *	when the object is part of a table of known size.
 *
 * nondet_*()
 *	Unconstrained values of the named type.  Bound them with arithmetic
 *	(nondet_uint() % N), not with __CPROVER_assume.
 */
#ifndef CBMC_HARNESS_H
#define CBMC_HARNESS_H

/* no <stddef.h>: harness.c is built with -nostdinc */
#define CBMC_SIZE_T_ __typeof__(sizeof(0))

/*
 * __CPROVER_allocate does not take part in --memory-leak-check (CBMC's
 * malloc records each object in __CPROVER_memory_leak; free clears it):
 * CBMC_LEAK_RECORD_ does the same for objects made here.  Statement
 * expressions keep sizeof(type) at the __CPROVER_allocate call, which is
 * where CBMC takes the object's type from.  Natively the sanitizer
 * hooks see every allocation already.
 */
#ifdef NATIVE_SHIM_H
#define CBMC_LEAK_RECORD_(p)	((void)0)
#else
extern void *__CPROVER_memory_leak;
_Bool nondet_bool(void);
#define CBMC_LEAK_RECORD_(p)	(__CPROVER_memory_leak = nondet_bool() ? \
	(void *)(p) : __CPROVER_memory_leak)
#endif
#define CBMC_NEW(type) ({						\
	type *cbmc_p_ = (type *)__CPROVER_allocate(sizeof(type), 1);	\
	CBMC_LEAK_RECORD_(cbmc_p_);					\
	cbmc_p_;							\
})
#define CBMC_NEW_ARRAY(type, n) ({					\
	type *cbmc_p_ = (type *)__CPROVER_allocate(sizeof(type) *	\
	    (CBMC_SIZE_T_)(n), 1);					\
	CBMC_LEAK_RECORD_(cbmc_p_);					\
	cbmc_p_;							\
})

_Bool nondet_bool(void);
char nondet_char(void);
signed char nondet_schar(void);
unsigned char nondet_uchar(void);
short nondet_short(void);
unsigned short nondet_ushort(void);
int nondet_int(void);
unsigned int nondet_uint(void);
long nondet_long(void);
unsigned long nondet_ulong(void);
long long nondet_longlong(void);
unsigned long long nondet_ulonglong(void);
CBMC_SIZE_T_ nondet_size_t(void);
unsigned char nondet_u8(void);
unsigned short nondet_u16(void);
unsigned int nondet_u32(void);
unsigned long long nondet_u64(void);

#endif
