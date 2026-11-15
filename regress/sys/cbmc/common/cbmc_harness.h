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

#define CBMC_NEW(type)	((type *)__CPROVER_allocate(sizeof(type), 1))
#define CBMC_NEW_ARRAY(type, n) \
	((type *)__CPROVER_allocate(sizeof(type) * (CBMC_SIZE_T_)(n), 1))

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
