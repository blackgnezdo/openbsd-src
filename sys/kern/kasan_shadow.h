/*	$OpenBSD$	*/

/*
 * KASAN shadow encoding, free of kernel dependencies so subr_kasan.c and
 * the userspace harness (kasan_shadow_test.c) share one implementation.
 *
 * The includer supplies kasan_addr_to_shad(vaddr_t), mapping an address to
 * its one-byte shadow cell.  Each cell covers KASAN_SHADOW_SCALE_SIZE bytes:
 *	0		all bytes valid
 *	1..SCALE_SIZE	that many leading bytes valid (partial granule)
 *	0xFx		poisoned; value identifies the redzone kind
 */

#ifndef _KERN_KASAN_SHADOW_H_
#define _KERN_KASAN_SHADOW_H_

#ifndef KASAN_SHADOW_SCALE_SHIFT
#define KASAN_SHADOW_SCALE_SHIFT	3
#endif
#ifndef KASAN_SHADOW_SCALE_SIZE
#define KASAN_SHADOW_SCALE_SIZE		(1UL << KASAN_SHADOW_SCALE_SHIFT)
#endif
#ifndef KASAN_SHADOW_MASK
#define KASAN_SHADOW_MASK		(KASAN_SHADOW_SCALE_SIZE - 1)
#endif

#define KASAN_ADDR_CROSSES_SCALE_BOUNDARY(addr, size)			\
	(((addr) >> KASAN_SHADOW_SCALE_SHIFT) !=			\
	    (((addr) + (size) - 1) >> KASAN_SHADOW_SCALE_SHIFT))

/*
 * Offset of the redzone after a 'size'-byte object.  A trailing partial
 * granule is encoded in its valid cell, so the redzone can only begin at
 * the next granule boundary; the poisoning path requires that alignment.
 */
static inline size_t
kasan_redzone_start(size_t size)
{
	return (size + KASAN_SHADOW_MASK) & ~(size_t)KASAN_SHADOW_MASK;
}

static inline void
kasan_shadow_1byte_markvalid(vaddr_t addr)
{
	uint8_t *byte = kasan_addr_to_shad(addr);
	uint8_t last = (addr & KASAN_SHADOW_MASK) + 1;

	*byte = last;
}

/* Fill the shadow for [addr, addr + size); addr and size granule-aligned. */
static inline void
kasan_shadow_memset(vaddr_t addr, size_t size, uint8_t val)
{
	uint8_t *shad = kasan_addr_to_shad(addr);

	__builtin_memset(shad, val, size >> KASAN_SHADOW_SCALE_SHIFT);
}

/*
 * Cells are signed: redzone codes (0xF1..0xFB) are negative, so a positive
 * 'last' never compares <= them.  int8_t at every width is load-bearing;
 * an unsigned cell makes redzone accesses read as valid.
 */
static inline int
kasan_shadow_1byte_isvalid(vaddr_t addr)
{
	int8_t *byte = (int8_t *)kasan_addr_to_shad(addr);
	int8_t last = (addr & KASAN_SHADOW_MASK) + 1;

	return (*byte == 0 || last <= *byte);
}

static inline int
kasan_shadow_2byte_isvalid(vaddr_t addr)
{
	int8_t *byte, last;

	if (KASAN_ADDR_CROSSES_SCALE_BOUNDARY(addr, 2)) {
		return (kasan_shadow_1byte_isvalid(addr) &&
		    kasan_shadow_1byte_isvalid(addr + 1));
	}

	byte = (int8_t *)kasan_addr_to_shad(addr);
	last = ((addr + 1) & KASAN_SHADOW_MASK) + 1;

	return (*byte == 0 || last <= *byte);
}

static inline int
kasan_shadow_4byte_isvalid(vaddr_t addr)
{
	int8_t *byte, last;

	if (KASAN_ADDR_CROSSES_SCALE_BOUNDARY(addr, 4)) {
		return (kasan_shadow_2byte_isvalid(addr) &&
		    kasan_shadow_2byte_isvalid(addr + 2));
	}

	byte = (int8_t *)kasan_addr_to_shad(addr);
	last = ((addr + 3) & KASAN_SHADOW_MASK) + 1;

	return (*byte == 0 || last <= *byte);
}

static inline int
kasan_shadow_8byte_isvalid(vaddr_t addr)
{
	int8_t *byte, last;

	if (KASAN_ADDR_CROSSES_SCALE_BOUNDARY(addr, 8)) {
		return (kasan_shadow_4byte_isvalid(addr) &&
		    kasan_shadow_4byte_isvalid(addr + 4));
	}

	byte = (int8_t *)kasan_addr_to_shad(addr);
	last = ((addr + 7) & KASAN_SHADOW_MASK) + 1;

	return (*byte == 0 || last <= *byte);
}

static inline int
kasan_shadow_Nbyte_isvalid(vaddr_t addr, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		if (!kasan_shadow_1byte_isvalid(addr + i))
			return 0;
	}

	return 1;
}

#endif /* !_KERN_KASAN_SHADOW_H_ */
