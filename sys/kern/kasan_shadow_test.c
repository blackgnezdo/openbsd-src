/*	$OpenBSD$	*/

/*
 * Host-side tests for the shadow encoding in kern/kasan_shadow.h, so the
 * algorithm can be checked without booting a KASAN kernel:
 *
 *	cc -o kasan_shadow_test kasan_shadow_test.c && ./kasan_shadow_test
 *
 * Invariants worth pinning: the redzone must start past an object's partial
 * granule (else the poisoning path gets an unaligned address), and shadow
 * comparisons must be signed at every width (else redzone reads pass).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef uintptr_t vaddr_t;

/* Redzone code, mirrors KASAN_MEMORY_REDZONE in <sys/kasan.h>. */
#define TEST_REDZONE	0xFB

/* Modeled memory + shadow; kasan_shadow.h builds on kasan_addr_to_shad(). */
#define MEM_BASE	((vaddr_t)0x10000000)
#define MEM_BYTES	(1UL << 20)		/* 1 MiB modeled */
static uint8_t shadow[MEM_BYTES >> 3];

static inline uint8_t *
kasan_addr_to_shad(vaddr_t va)
{
	return &shadow[(va - MEM_BASE) >> 3];
}

#include "kasan_shadow.h"

static int failures;

#define CHECK(cond, ...) do {						\
	if (!(cond)) {							\
		failures++;						\
		printf("FAIL %s:%d: ", __func__, __LINE__);		\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)

/* 0xFF reads as valid at any width, matching freshly mapped shadow pages. */
static void
shadow_reset(void)
{
	memset(shadow, 0xFF, sizeof(shadow));
}

/* Same marking as kasan_alloc()+kasan_markmem(), via the shared primitives. */
static void
mark_alloc(vaddr_t addr, size_t size, size_t redzone)
{
	size_t rzbeg = kasan_redzone_start(size);

	kasan_shadow_memset(addr + rzbeg, redzone - rzbeg, TEST_REDZONE);
	kasan_shadow_markvalid(addr, size);
}

/* kasan_add_redzone(): round to a granule, then add one redzone granule. */
static size_t
add_redzone(size_t size)
{
	return kasan_redzone_start(size) + KASAN_SHADOW_SCALE_SIZE;
}

static void
test_redzone_start(void)
{
	CHECK(kasan_redzone_start(0) == 0, "rz(0)=%zu", kasan_redzone_start(0));
	CHECK(kasan_redzone_start(1) == 8, "rz(1)=%zu", kasan_redzone_start(1));
	CHECK(kasan_redzone_start(8) == 8, "rz(8)=%zu", kasan_redzone_start(8));
	CHECK(kasan_redzone_start(9) == 16, "rz(9)=%zu", kasan_redzone_start(9));
	CHECK(kasan_redzone_start(16) == 16, "rz(16)=%zu",
	    kasan_redzone_start(16));
	CHECK(kasan_redzone_start(4105) == 4112, "rz(4105)=%zu",
	    kasan_redzone_start(4105));
}

static void
test_aligned_alloc(void)
{
	vaddr_t base = MEM_BASE + 0x800;
	size_t size = 64, redz = add_redzone(64);	/* 64 + 8 */
	size_t i;

	shadow_reset();
	mark_alloc(base, size, redz);

	for (i = 0; i < size; i++)
		CHECK(kasan_shadow_1byte_isvalid(base + i), "byte %zu valid", i);
	for (i = size; i < redz; i++)
		CHECK(!kasan_shadow_1byte_isvalid(base + i),
		    "redzone byte %zu invalid", i);
}

static void
test_partial_granule_alloc(void)
{
	vaddr_t base = MEM_BASE + 0x4000;
	size_t size = 4105;			/* not granule-aligned */
	size_t redz = add_redzone(size);	/* 4112 + 8 = 4120 */
	size_t i;

	CHECK(redz == 4120, "redz=%zu", redz);

	shadow_reset();
	mark_alloc(base, size, redz);

	/* In-bounds, including the lone valid byte of the last granule. */
	for (i = 0; i < size; i++)
		CHECK(kasan_shadow_1byte_isvalid(base + i),
		    "in-bounds byte %zu valid", i);

	/* Remainder of the partial granule and the redzone are out of bounds. */
	for (i = size; i < redz; i++)
		CHECK(!kasan_shadow_1byte_isvalid(base + i),
		    "out-of-bounds byte %zu invalid", i);

	/* Partial cell counts one valid byte; next cell is the redzone. */
	CHECK(*kasan_addr_to_shad(base + 4104) == 1, "partial cell=%d",
	    *kasan_addr_to_shad(base + 4104));
	CHECK((uint8_t)*kasan_addr_to_shad(base + 4112) == TEST_REDZONE,
	    "redzone cell=0x%02x", *kasan_addr_to_shad(base + 4112));
}

static void
test_redzone_detected_all_widths(void)
{
	vaddr_t base = MEM_BASE + 0x8000;
	size_t size = 16, redz = add_redzone(16);	/* redzone at [16,24) */

	shadow_reset();
	mark_alloc(base, size, redz);

	/* Every width must flag a read sitting in the redzone. */
	CHECK(!kasan_shadow_1byte_isvalid(base + 16), "1-byte redzone read");
	CHECK(!kasan_shadow_2byte_isvalid(base + 16), "2-byte redzone read");
	CHECK(!kasan_shadow_4byte_isvalid(base + 16), "4-byte redzone read");
	CHECK(!kasan_shadow_8byte_isvalid(base + 16), "8-byte redzone read");
	CHECK(!kasan_shadow_Nbyte_isvalid(base + 16, 5), "N-byte redzone read");

	/* In-bounds reads pass. */
	CHECK(kasan_shadow_1byte_isvalid(base + 0), "1-byte in-bounds");
	CHECK(kasan_shadow_8byte_isvalid(base + 8), "8-byte in-bounds");
	CHECK(kasan_shadow_Nbyte_isvalid(base + 0, 16), "N-byte in-bounds");
}

static void
test_boundary_crossing(void)
{
	vaddr_t base = MEM_BASE + 0xC000;
	size_t size = 16, redz = add_redzone(16);	/* valid [0,16) */

	shadow_reset();
	mark_alloc(base, size, redz);

	/* Width that straddles into the redzone is flagged; one that doesn't isn't. */
	CHECK(!kasan_shadow_8byte_isvalid(base + 12), "straddling 8-byte read");
	CHECK(kasan_shadow_4byte_isvalid(base + 12), "in-bounds 4-byte read");
}

/*
 * kasan_alloc() re-marks an already-valid object valid on every reuse
 * (pool_get() -> kasan_alloc()).  If that marking walks a granule's shadow
 * cell 1->2->...->8 one byte at a time, another CPU reading the same,
 * already-valid granule can observe a partial intermediate count and
 * false-positive -- the amap_chunk_get / amap_lookups "shadow 0x08: valid"
 * MP panics.  Model both markings with a per-store observer and a concurrent
 * in-bounds reader: the single-store-per-granule marking keeps the granule
 * valid throughout; the byte-by-byte one transiently does not.
 */
static vaddr_t race_base;
static int race_reader_failed;

static void
race_reader(void)
{
	/* An already-valid 8-byte object: an in-bounds read must stay valid. */
	if (!kasan_shadow_8byte_isvalid(race_base))
		race_reader_failed = 1;
}

static void
noop_observer(void)
{
}

/* The old marking: one store per byte, observed after each store. */
static void
mark_bytewise_observed(vaddr_t addr, size_t size, void (*obs)(void))
{
	size_t i;

	for (i = 0; i < size; i++) {
		kasan_shadow_1byte_markvalid(addr + i);
		obs();
	}
}

/* The new marking: one store per granule, observed after each store. */
static void
mark_collapsed_observed(vaddr_t addr, size_t size, void (*obs)(void))
{
	uint8_t *shad = kasan_addr_to_shad(addr);
	size_t full = size >> KASAN_SHADOW_SCALE_SHIFT;
	size_t rem = size & KASAN_SHADOW_MASK;
	size_t g;

	for (g = 0; g < full; g++) {
		shad[g] = KASAN_SHADOW_SCALE_SIZE;
		obs();
	}
	if (rem != 0) {
		shad[full] = rem;
		obs();
	}
}

static void
test_remark_race(void)
{
	race_base = MEM_BASE + 0x30000;

	shadow_reset();
	kasan_shadow_markvalid(race_base, 8);	/* object already fully valid */

	/* Collapsed re-mark: the concurrent reader never observes a dip. */
	race_reader_failed = 0;
	mark_collapsed_observed(race_base, 8, race_reader);
	CHECK(!race_reader_failed,
	    "single-store re-mark keeps the granule valid throughout");

	/* Byte-by-byte re-mark WOULD dip -- documents the bug being fixed. */
	shadow_reset();
	kasan_shadow_markvalid(race_base, 8);
	race_reader_failed = 0;
	mark_bytewise_observed(race_base, 8, race_reader);
	CHECK(race_reader_failed,
	    "byte-by-byte re-mark transiently reads invalid (the MP bug)");
}

/*
 * The collapse must not change any final shadow state: sweep sizes across
 * granule boundaries and assert the single-store marking matches the old
 * byte-by-byte result cell for cell.
 */
static void
test_markvalid_equivalence(void)
{
	static uint8_t bytewise[MEM_BYTES >> 3];
	vaddr_t base = MEM_BASE + 0x40000;
	size_t sizes[] = { 1, 7, 8, 9, 15, 16, 17, 63, 64, 65, 200 };
	size_t s, off, ncells;

	for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
		for (off = 0; off < 4; off++) {
			vaddr_t a = base + off * 8;	/* granule-aligned */

			shadow_reset();
			mark_bytewise_observed(a, sizes[s], noop_observer);
			memcpy(bytewise, shadow, sizeof(shadow));

			shadow_reset();
			kasan_shadow_markvalid(a, sizes[s]);

			ncells = sizeof(shadow);
			CHECK(memcmp(bytewise, shadow, ncells) == 0,
			    "size %zu off %zu: collapsed shadow != byte-by-byte",
			    sizes[s], off);
		}
	}
}

int
main(void)
{
	test_redzone_start();
	test_aligned_alloc();
	test_partial_granule_alloc();
	test_redzone_detected_all_widths();
	test_boundary_crossing();
	test_remark_race();
	test_markvalid_equivalence();

	if (failures == 0) {
		printf("kasan_shadow_test: all tests passed\n");
		return 0;
	}
	printf("kasan_shadow_test: %d failure(s)\n", failures);
	return 1;
}
