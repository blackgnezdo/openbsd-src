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

/*
 * Mark [addr, addr + size) valid; addr must be granule-aligned.  Writes each
 * shadow cell exactly once, to its final extent (8 for a full granule, the
 * remainder for a trailing partial one).
 *
 * This must NOT walk a cell 1->2->...->8 byte by byte: kasan_alloc() re-marks
 * an already-valid object on every reuse (e.g. pool_get()), and on another CPU
 * a concurrent kasan_shadow_*_isvalid() reading the same, still-valid granule
 * could observe a partial intermediate count and wrongly report the access
 * out of bounds.  A single store never dips below the final extent, so a
 * reader sees either the old or the new fully-valid value.  (Seen in the wild
 * as the amap_chunk_get / amap_lookups "shadow 0x08: valid" MP false-positive
 * panics.)
 */
static inline void
kasan_shadow_markvalid(vaddr_t addr, size_t size)
{
	uint8_t *shad = kasan_addr_to_shad(addr);
	size_t full = size >> KASAN_SHADOW_SCALE_SHIFT;
	size_t rem = size & KASAN_SHADOW_MASK;

	if (full != 0)
		__builtin_memset(shad, KASAN_SHADOW_SCALE_SIZE, full);
	if (rem != 0)
		shad[full] = rem;
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

#define KASAN_DUMP_CELLS	16	/* shadow cells per dump row */
#define KASAN_DUMP_ROWS		5

/*
 * Print the shadow cells around a faulting address, the guilty cell
 * bracketed, so the poison pattern across the whole object is visible at a
 * glance (freed body vs trailing redzone vs partial granule).  [lo, hi) is
 * the surrounding range with readable shadow; rows never stray outside it.
 * lo must be granule-aligned.  The row prefix is the covered VA, not the
 * shadow address.
 */
static inline void
kasan_shadow_dump(vaddr_t bad, vaddr_t lo, vaddr_t hi,
    int (*pr)(const char *, ...))
{
	const vaddr_t rowbytes = KASAN_DUMP_CELLS * KASAN_SHADOW_SCALE_SIZE;
	vaddr_t badva = bad & ~(vaddr_t)KASAN_SHADOW_MASK;
	vaddr_t start, end, row, va;
	int guilty;

	/* Center the window on the guilty cell's row, clamped to [lo, hi). */
	start = bad & ~(rowbytes - 1);
	if (start >= lo && start - lo >= (KASAN_DUMP_ROWS / 2) * rowbytes)
		start -= (KASAN_DUMP_ROWS / 2) * rowbytes;
	else
		start = lo;
	end = start + KASAN_DUMP_ROWS * rowbytes;
	if (end > hi || end < start)
		end = hi;

	pr("KASAN: shadow of 0x%lx..0x%lx (1 cell = %lu bytes):\n",
	    (unsigned long)start, (unsigned long)end,
	    (unsigned long)KASAN_SHADOW_SCALE_SIZE);
	for (row = start; row < end; row += rowbytes) {
		pr("%s0x%016lx:", (badva - row < rowbytes) ? ">" : " ",
		    (unsigned long)row);
		guilty = 0;
		for (va = row; va < row + rowbytes && va < end;
		    va += KASAN_SHADOW_SCALE_SIZE) {
			pr("%s%02x", (va == badva) ? "[" : (guilty ? "]" : " "),
			    (uint8_t)*kasan_addr_to_shad(va));
			guilty = (va == badva);
		}
		pr("%s\n", guilty ? "]" : "");
	}
}

#endif /* !_KERN_KASAN_SHADOW_H_ */
