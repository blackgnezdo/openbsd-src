/*	$OpenBSD$	*/

/*
 * KASAN self-test suite.  Positive cases exercise valid allocator traffic and
 * must run clean (a report there is a false positive); negative cases each
 * perform exactly ONE out-of-bounds / use-after-free access and must trip the
 * matching KASAN report (a case with no report is a FALSE NEGATIVE -- the thing
 * we guard against).  Built only with "option KASAN_TEST" (config
 * arch/amd64/conf/KASAN_TEST), which also implies "option KASAN".
 *
 * Unlike a real bug, every deliberate access here is a tiny overrun into
 * mapped, owned memory (the adjacent heap/pool redzone, a freed-but-still-
 * mapped object, or the compiler's stack/global redzone padding), so the report
 * path can record the fault and RETURN instead of panicking and the whole suite
 * runs in a single boot.  See subr_kasan.c kasan_shadow_check()'s KASAN_TEST
 * branch.  This continue-after-report behaviour is test-only and never enabled
 * in a production KASAN kernel.
 *
 * The suite is driven and verified by an external gdb harness that boots this
 * kernel once under the qemu gdb stub and breaks on kasan_test_caseend() to
 * read kasan_cur/kasan_test_fired/kasan_last_* and compare against each case's
 * expectation in kasan_tests[].  The same kernel also works without gdb: it
 * prints every report and MISS/false-positive line, then exits via
 * vmkill_now().
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/pool.h>

#include <uvm/uvm_extern.h>
#include <machine/vmparam.h>

#ifdef KASAN_TEST

#include <sys/kasan.h>

extern void vmkill_now(void);		/* amd64 db_interface.c; test-only */

/*
 * Result of the most recent report, written by kasan_report() (subr_kasan.c)
 * and read by the gdb harness at the kasan_test_caseend() breakpoint.
 * kasan_cur is the case being run; kasan_test_fired distinguishes a HIT from a
 * MISS within one case.
 */
volatile int kasan_cur = -1;
volatile int kasan_test_fired;
volatile int kasan_last_op;
volatile uint8_t kasan_last_code;
volatile size_t kasan_last_size;
volatile unsigned long kasan_last_addr;

/*
 * Cold marker functions: empty, never inlined, never optimized away.  The
 * harness sets a gdb breakpoint on kasan_test_caseend (hit once per case, with
 * kasan_cur/kasan_test_fired/kasan_last_* holding that case's result) and on
 * kasan_test_complete.  Without gdb attached they are cheap no-ops, so the
 * battery still runs to completion on the console.
 */
void __attribute__((noinline))
kasan_test_caseend(void)
{
	__asm volatile("" ::: "memory");	/* one case finished */
}

void __attribute__((noinline))
kasan_test_complete(void)
{
	__asm volatile("" ::: "memory");	/* battery done */
}

/*
 * Positive test: drive malloc/free across bucket sizes and fragmentation
 * patterns (powers of two, just under/over powers of two, random sizes,
 * interleaved frees) with a deterministic LCG so failures reproduce.
 * Every allocation is touched at both ends; M_ZERO covers full writes.
 */

/* Test parameters */
static const int NUM_ITERATIONS = 50;
static const int MAX_LIVE_ALLOCS = 32;
static const size_t MIN_SIZE = 16;
static const size_t MAX_SIZE = (1 << 20);  /* 1MB */

static inline uint32_t rand_next(uint32_t *s) {
	*s = *s * 1103515245 + 12345;
	return *s;
}

static inline uint32_t rand_range(uint32_t *s, uint32_t min, uint32_t max) {
	return (rand_next(s) % (max - min + 1)) + min;
}

/* Track live allocations, too large for stack */
static struct alloc_entry {
	void *ptr;
	size_t size;
	int active;
} allocs[MAX_LIVE_ALLOCS];
static void *small_ptrs[256];
static size_t small_sizes[256];

static void
malloc_test(void)
{
	const int TYPE = M_PF;

	/* Simple linear congruential generator for deterministic behavior */
	uint32_t seed = 0xcafebabe;  /* Adjust this seed as needed */

	int i, j;
	int total_allocs = 0;
	int total_frees = 0;

	for (i = 0; i < MAX_LIVE_ALLOCS; i++) {
		allocs[i] = (struct alloc_entry){
			.ptr = NULL,
			.size = 0,
			.active = 0
		};
	}

	printf("malloc_test: starting with seed 0x%x\n", seed);

	/* Phase 1: Power-of-two allocations with increasing sizes */
	printf("\n=== Phase 1: Power-of-two allocations ===\n");
	for (i = 4; i <= 19; i++) {
		size_t size = 1 << i;
		void *p = malloc(size, TYPE, M_ZERO | M_WAITOK);
		printf("pow2: size=%zu ptr=%p\n", size, p);

		/* Write pattern to detect corruption */
		if (p) {
			*(uint32_t *)p = 0xfeed0000 | i;
			*(uint32_t *)((char *)p + size - sizeof(uint32_t)) = 0xbeef0000 | i;
		}

		free(p, TYPE, size);
		total_allocs++;
		total_frees++;
	}

	/* Phase 2: Random sized allocations with fragmentation */
	printf("\n=== Phase 2: Random allocations with fragmentation ===\n");
	for (i = 0; i < NUM_ITERATIONS; i++) {
		int action = rand_range(&seed, 0, 100);

		if (action < 70) {  /* 70% chance to allocate */
			/* Find free slot */
			int slot = -1;
			for (j = 0; j < MAX_LIVE_ALLOCS; j++) {
				if (!allocs[j].active) {
					slot = j;
					break;
				}
			}

			if (slot >= 0) {
				/* Generate interesting sizes */
				size_t base_size;
				int size_type = rand_range(&seed, 0, 3);

				switch (size_type) {
				case 0:  /* Power of two */
					base_size = 1 << rand_range(&seed, 4, 17);
					break;
				case 1:  /* Just below power of two */
					{
						uint32_t shift = rand_range(&seed, 5, 17);
						uint32_t subtract = rand_range(&seed, 1, 16);
						base_size = (1 << shift) - subtract;
					}
					break;
				case 2:  /* Just above power of two */
					{
						uint32_t shift = rand_range(&seed, 4, 16);
						uint32_t add = rand_range(&seed, 1, 16);
						base_size = (1 << shift) + add;
					}
					break;
				default:  /* Random */
					base_size = rand_range(&seed, MIN_SIZE, MAX_SIZE/4);
					break;
				}

				allocs[slot].size = base_size;
				allocs[slot].ptr = malloc(base_size, TYPE, M_ZERO | M_WAITOK);
				allocs[slot].active = 1;
				total_allocs++;

				printf("alloc[%d]: size=%zu ptr=%p\n",
				       slot, base_size, allocs[slot].ptr);
			}
		} else {  /* 30% chance to free */
			/* Free random active allocation */
			int active_count = 0;
			for (j = 0; j < MAX_LIVE_ALLOCS; j++) {
				if (allocs[j].active)
					active_count++;
			}

			if (active_count > 0) {
				int target = rand_range(&seed, 0, active_count - 1);
				for (j = 0; j < MAX_LIVE_ALLOCS; j++) {
					if (allocs[j].active) {
						if (target == 0) {
							printf("free[%d]: size=%zu ptr=%p\n",
							       j, allocs[j].size, allocs[j].ptr);
							free(allocs[j].ptr, TYPE, allocs[j].size);
							allocs[j].active = 0;
							total_frees++;
							break;
						}
						target--;
					}
				}
			}
		}
	}

	/* Phase 3: Stress test with many small allocations */
	printf("\n=== Phase 3: Small allocation stress test ===\n");

	for (i = 0; i < 256; i++) {
		small_sizes[i] = rand_range(&seed, 8, 128);
		small_ptrs[i] = malloc(small_sizes[i], TYPE, M_WAITOK);
		total_allocs++;
		if ((i & 15) == 0) {
			printf("small batch %d: allocated %d entries\n", i >> 4, 16);
		}
	}

	/* Free in different pattern than allocation */
	for (i = 0; i < 256; i += 2) {
		free(small_ptrs[i], TYPE, small_sizes[i]);
		total_frees++;
	}
	for (i = 1; i < 256; i += 2) {
		free(small_ptrs[i], TYPE, small_sizes[i]);
		total_frees++;
	}
	printf("small stress: freed all 256 entries\n");

	/* Phase 4: Cleanup remaining allocations */
	printf("\n=== Phase 4: Cleanup ===\n");
	for (i = 0; i < MAX_LIVE_ALLOCS; i++) {
		if (allocs[i].active) {
			printf("cleanup[%d]: size=%zu ptr=%p\n",
			       i, allocs[i].size, allocs[i].ptr);
			free(allocs[i].ptr, TYPE, allocs[i].size);
			allocs[i].active = 0;
			total_frees++;
		}
	}

	printf("\n=== Test Summary ===\n");
	printf("Total allocations: %d\n", total_allocs);
	printf("Total frees: %d\n", total_frees);
	printf("Leaked: %d\n", total_allocs - total_frees);
}

static struct pool kasan_test_pool;
static void *pool_ptrs[256];

/*
 * Positive test: exercise pool(9) get/put across several item sizes, touching
 * every byte of each item, so KASAN catches under-marked items or stale
 * poison on the shared backing pages.
 */
static void
pool_test(void)
{
	static const size_t sizes[] = { 8, 24, 64, 200, 1000 };
	uint32_t seed = 0x12345678;
	int total_gets = 0, total_puts = 0;
	size_t s;
	int i;

	printf("\npool_test: starting\n");

	for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
		size_t isz = sizes[s];

		pool_init(&kasan_test_pool, isz, 0, IPL_NONE, 0, "kasantst", NULL);
		printf("=== pool item size %zu ===\n", isz);

		/* Phase A: fill, touching first and last byte, then drain. */
		for (i = 0; i < 256; i++) {
			char *p = pool_get(&kasan_test_pool, PR_WAITOK | PR_ZERO);
			pool_ptrs[i] = p;
			/*
			 * Items must live in mapped KVA so KASAN can shadow them;
			 * a direct-mapped (unmonitored) item would slip past every
			 * check below and defeat the test.
			 */
			if ((vaddr_t)p < VM_MIN_KERNEL_ADDRESS ||
			    (vaddr_t)p >= VM_MAX_KERNEL_ADDRESS)
				panic("pool_test: item %p (size %zu) is not in the "
				    "KASAN-monitored range", p, isz);
			p[0] = 0x41;
			p[isz - 1] = 0x5a;
			total_gets++;
		}
		for (i = 0; i < 256; i++) {
			pool_put(&kasan_test_pool, pool_ptrs[i]);
			pool_ptrs[i] = NULL;
			total_puts++;
		}

		/* Phase B: interleaved get/put for fragmentation, full-item write. */
		for (i = 0; i < 1000; i++) {
			int slot = rand_range(&seed, 0, 255);

			if (pool_ptrs[slot] == NULL) {
				char *p = pool_get(&kasan_test_pool, PR_WAITOK);
				memset(p, 0x33, isz);
				pool_ptrs[slot] = p;
				total_gets++;
			} else {
				pool_put(&kasan_test_pool, pool_ptrs[slot]);
				pool_ptrs[slot] = NULL;
				total_puts++;
			}
		}
		for (i = 0; i < 256; i++) {
			if (pool_ptrs[i] != NULL) {
				pool_put(&kasan_test_pool, pool_ptrs[i]);
				pool_ptrs[i] = NULL;
				total_puts++;
			}
		}

		pool_destroy(&kasan_test_pool);
	}

	printf("pool_test: gets=%d puts=%d done\n", total_gets, total_puts);
}

/*
 * Positive test / regression test for the per-CPU pool cache.  With pool_debug
 * on, pool_cache_put() both KASAN-redzones and pool-poisons an item's body; on
 * the next pool_cache_get() the cache's poison_check() reads that body, so
 * KASAN must revalidate the item before the check runs.  Fill the cache
 * (freeing a batch redzones each body) then re-get the batch to drive
 * poison_check across cached items: reaching the final print means the
 * ordering is right; a KASAN report in poison_check is the bug.  Needs a live
 * per-CPU cache, which exists only after cpu_configure()/dostartuphooks() --
 * hence the suite runs from main(), not uvm_init().
 */
static void
kasan_poolcache_test(void)
{
	static struct pool pc_test_pool;
	void *items[64];
	int i;

	pool_init(&pc_test_pool, 128, 0, IPL_NONE, 0, "kctst", NULL);
	pool_cache_init(&pc_test_pool);
	if (pc_test_pool.pr_cache == NULL) {
		printf("kasan_poolcache_test: no per-CPU cache; skipped\n");
		return;
	}

	for (i = 0; i < 64; i++)
		items[i] = pool_get(&pc_test_pool, PR_WAITOK);
	for (i = 0; i < 64; i++)
		pool_put(&pc_test_pool, items[i]);	/* poison + redzone bodies */
	for (i = 0; i < 64; i++) {
		items[i] = pool_get(&pc_test_pool, PR_WAITOK); /* poison_check here */
		*(volatile char *)items[i] = 0x5a;
	}
	for (i = 0; i < 64; i++)
		pool_put(&pc_test_pool, items[i]);

	printf("kasan_poolcache_test: cache get/put cycle OK\n");
}

#define KT_MTYPE	M_DEVBUF

/*
 * Freelist tail link: a freed malloc object carries the bucket freelist's
 * XSIMPLEQ link in its own body at offset 8 (struct kmem_freelist.kf_flist,
 * kern_malloc.c), and free()/malloc() write and read that link through
 * *sqx_last / REMOVE_HEAD while the object sits on the freelist, which is
 * poisoned end to end.  Three frees into one bucket make each INSERT_TAIL
 * write the previous tail's link inside a poisoned object; only the
 * __kasan_exempt accessors keep that clean.  Regression test for the syzbot
 * ktrgenio crash (extid f028f6e8).
 */
static void
kt_freelist_link(void)
{
	char *q = malloc(64, KT_MTYPE, M_WAITOK);
	char *p = malloc(64, KT_MTYPE, M_WAITOK);
	char *r = malloc(64, KT_MTYPE, M_WAITOK);

	free(q, KT_MTYPE, 64);		/* keep the bucket freelist non-empty */
	free(p, KT_MTYPE, 64);		/* INSERT_TAIL writes q's link */
	free(r, KT_MTYPE, 64);		/* and this one writes p's */
}

/*
 * The same granule reached by something that is not the allocator.  The link
 * must be left intact -- a malloc bucket is shared with the whole kernel --
 * so the word is read and stored straight back; clang folds the store check
 * into the load check, hence op=read.
 */
static void
kt_malloc_uaf_link(void)
{
	char *q = malloc(64, KT_MTYPE, M_WAITOK);
	char *p = malloc(64, KT_MTYPE, M_WAITOK);
	volatile unsigned long *link;

	free(q, KT_MTYPE, 64);		/* keep the bucket freelist non-empty */
	free(p, KT_MTYPE, 64);		/* p is now the freelist tail */

	link = (volatile unsigned long *)(p + 8);	/* kf_flist */
	*link = *link;			/* freed link access -> 0xFC */
}

/* Heap out-of-bounds read: 1 byte past a 64-byte object lands in its 0xFB
 * trailing redzone (malloc adds one via kasan_add_redzone). */
static void
kt_heap_oob_read(void)
{
	volatile char *p = malloc(64, KT_MTYPE, M_WAITOK);
	volatile int idx = 64;
	volatile char sink;

	sink = p[idx];				/* __asan_load1 -> 0xFB read */
	(void)sink;
	free((void *)p, KT_MTYPE, 64);
}

/* Heap out-of-bounds write into the same trailing redzone (within our own
 * 128-byte bucket slot, so the write is harmless to neighbours). */
static void
kt_heap_oob_write(void)
{
	volatile char *p = malloc(64, KT_MTYPE, M_WAITOK);
	volatile int idx = 64;

	p[idx] = 0x41;				/* __asan_store1 -> 0xFB write */
	free((void *)p, KT_MTYPE, 64);
}

/* Heap use-after-free: free() poisons the freed object 0xFC (all but its
 * freelist link granule at offset 8, see kt_freelist_link), so a read of its
 * first byte reports.  Read (not write) to avoid disturbing the freelist. */
static void
kt_heap_uaf(void)
{
	volatile char *p = malloc(64, KT_MTYPE, M_WAITOK);
	volatile int idx = 0;
	volatile char sink;

	free((void *)p, KT_MTYPE, 64);
	sink = p[idx];				/* freed body -> 0xFC read */
	(void)sink;
}

/* Partial granule: a 13-byte object leaves the last granule (offsets 8..15)
 * marked with 5 valid bytes, so a read at offset 13 trips with shadow 0x05. */
static void
kt_partial_granule(void)
{
	volatile char *p = malloc(13, KT_MTYPE, M_WAITOK);
	volatile int idx = 13;
	volatile char sink;

	sink = p[idx];				/* shadow 0x05 -> partial granule */
	(void)sink;
	free((void *)p, KT_MTYPE, 13);
}

/* Access-width coverage: 2/4/8/16-byte reads into the 0xFB redzone exercise
 * kasan_shadow_{2,4,8,N}byte_isvalid respectively. */
static void
kt_width2(void)
{
	volatile char *p = malloc(64, KT_MTYPE, M_WAITOK);
	volatile int off = 64;
	volatile uint16_t sink;

	sink = *(volatile uint16_t *)(p + off);	/* __asan_load2 -> 0xFB */
	(void)sink;
	free((void *)p, KT_MTYPE, 64);
}

static void
kt_width4(void)
{
	volatile char *p = malloc(64, KT_MTYPE, M_WAITOK);
	volatile int off = 64;
	volatile uint32_t sink;

	sink = *(volatile uint32_t *)(p + off);	/* __asan_load4 -> 0xFB */
	(void)sink;
	free((void *)p, KT_MTYPE, 64);
}

static void
kt_width8(void)
{
	volatile char *p = malloc(64, KT_MTYPE, M_WAITOK);
	volatile int off = 64;
	volatile uint64_t sink;

	sink = *(volatile uint64_t *)(p + off);	/* __asan_load8 -> 0xFB */
	(void)sink;
	free((void *)p, KT_MTYPE, 64);
}

static void
kt_width16(void)
{
	volatile char *p = malloc(64, KT_MTYPE, M_WAITOK);
	volatile int off = 64;
	volatile __int128 sink;

	sink = *(volatile __int128 *)(p + off);	/* __asan_load16/N -> 0xFB */
	(void)sink;
	free((void *)p, KT_MTYPE, 64);
}

/* Pool use-after-free: pool_put() redzones a freed item's body 0xFD (keeping
 * only the freelist link valid), so a read past the link reports.  Pools pack
 * items with no inter-item redzone, so a live-item overrun is not detectable;
 * the free path is. */
static struct pool kt_pool;
static void
kt_pool_uaf(void)
{
	char *p;
	volatile int idx = 64;
	volatile char sink;

	pool_init(&kt_pool, 128, 0, IPL_NONE, 0, "kttst", NULL);
	p = pool_get(&kt_pool, PR_WAITOK);
	if ((vaddr_t)p < VM_MIN_KERNEL_ADDRESS ||
	    (vaddr_t)p >= VM_MAX_KERNEL_ADDRESS)
		panic("kt_pool_uaf: item %p not in KASAN-monitored range", p);
	pool_put(&kt_pool, p);			/* redzones the item body 0xFD */
	sink = p[idx];				/* freed body -> 0xFD read */
	(void)sink;
	pool_destroy(&kt_pool);
}

/* Pool describe misattribution (syzbot a1a3c17d): pools sharing page geometry
 * all pass pool_kasan_lookup's in-page header probe on each other's pages, and
 * the newest-first walk let an empty pool claim the page and mislabel the
 * report.  The decoy is initialized after the real pool (so the walk visits it
 * first) and never allocates; the report must still name the owner. */
static struct pool kt_owner_pool, kt_decoy_pool;
static void
kt_pool_decoy(void)
{
	char *p;
	volatile int idx = 64;
	volatile char sink;

	pool_init(&kt_owner_pool, 128, 0, IPL_NONE, 0, "ktowner", NULL);
	p = pool_get(&kt_owner_pool, PR_WAITOK);
	if ((vaddr_t)p < VM_MIN_KERNEL_ADDRESS ||
	    (vaddr_t)p >= VM_MAX_KERNEL_ADDRESS)
		panic("kt_pool_decoy: item %p not in KASAN-monitored range", p);
	pool_init(&kt_decoy_pool, 128, 0, IPL_NONE, 0, "ktdecoy", NULL);
	pool_put(&kt_owner_pool, p);
	sink = p[idx];				/* must describe 'ktowner' */
	(void)sink;
	pool_destroy(&kt_decoy_pool);
	pool_destroy(&kt_owner_pool);
}

/*
 * Stack redzone: overrun a 64-byte stack buffer by one byte into the
 * compiler's inline stack redzone (shadow 0xf1/0xf2/0xf3).  The volatile index
 * keeps the store opaque to -Warray-bounds and alive under -Og.  Runs on the
 * proc0 kernel stack, covered once kasan_premap_image_shadow() maps shadow out
 * to kern_end.
 */
static void
kasan_stack_test(void)
{
	volatile char buf[64];
	volatile int idx = sizeof(buf);		/* 1 past the end */

	buf[idx] = 0x41;			/* stack redzone -> 0xf1/f2/f3 */
}

/* Global redzone: write one byte past a 64-byte static global into the
 * asan-globals 0xFA redzone padding. */
static volatile char kt_global_buf[64];
static void
kt_global_oob(void)
{
	volatile int idx = sizeof(kt_global_buf);

	kt_global_buf[idx] = 0x41;		/* global redzone -> 0xFA */
}

/*
 * Offset 8 of a free pool item is pi_list, which aliases whatever the object
 * kept there -- so_lock.rwl_owner for struct socket, inp_queue for struct
 * inpcb.  A store there after the free is the bug this models.
 *
 * The corrupted link is left behind: a second item is held allocated so the
 * page never goes idle and pool_gc_pages() cannot walk it, and the pool is
 * not destroyed.  The cache case cannot do that -- pool_cache_gc() may flush
 * a magazine at any time -- so it stores the same value back, which clang
 * folds into one check, hence op=read.
 */
static struct pool kt_link_pool;
static void
kt_pool_uaf_link(void)
{
	char *p, *pin;

	pool_init(&kt_link_pool, 128, 0, IPL_NONE, 0, "ktlink", NULL);
	pin = pool_get(&kt_link_pool, PR_WAITOK);	/* pins the page */
	p = pool_get(&kt_link_pool, PR_WAITOK);
	if ((vaddr_t)p < VM_MIN_KERNEL_ADDRESS ||
	    (vaddr_t)p >= VM_MAX_KERNEL_ADDRESS)
		panic("kt_pool_uaf_link: item %p not in KASAN-monitored range",
		    p);
	pool_put(&kt_link_pool, p);		/* poisons the item end to end */

	*(volatile unsigned long *)(p + 8) = 0;	/* pi_list -> 0xFD */

	(void)pin;				/* never freed; see above */
}

/* The same offset reached through the per-CPU magazine (ci_nitems), or the
 * plain free list on a kernel without a cache. */
static struct pool kt_clink_pool;
static void
kt_poolcache_uaf_link(void)
{
	volatile unsigned long *link;
	char *p;

	pool_init(&kt_clink_pool, 128, 0, IPL_NONE, 0, "kclink", NULL);
	pool_cache_init(&kt_clink_pool);
	p = pool_get(&kt_clink_pool, PR_WAITOK);
	if ((vaddr_t)p < VM_MIN_KERNEL_ADDRESS ||
	    (vaddr_t)p >= VM_MAX_KERNEL_ADDRESS)
		panic("kt_poolcache_uaf_link: item %p not in KASAN-monitored "
		    "range", p);
	pool_put(&kt_clink_pool, p);		/* poisons the item end to end */

	link = (volatile unsigned long *)(p + 8);	/* ci_nitems / pi_list */
	*link = *link;				/* freed header access -> 0xFD */
}

#define KT_CLEAN	0	/* expect no report (positive test) */
#define KT_REPORT	1	/* expect a report (negative test) */

struct kasan_test {
	const char	*kt_name;
	int		 kt_expect;	/* KT_CLEAN or KT_REPORT */
	int		 kt_op;		/* 0 read, 1 write (KT_REPORT only) */
	uint8_t		 kt_code;	/* expected shadow code (KT_REPORT only) */
	const char	*kt_descr;	/* substring of kasan_shadow_descr() */
	const char	*kt_where;	/* substring of the object-description
					   line ("KASAN: 0x... is ..."), or ""
					   if the case expects none */
	const char	*kt_alloc_by;	/* fn expected in the "allocated at:"
					   trace, or "" for no expectation */
	const char	*kt_freed_by;	/* fn expected in the "freed at:"
					   trace, or "" for no expectation */
	void		(*kt_fn)(void);
};

/*
 * kt_where notes: malloc(64) plus the KASAN redzone lands in the 128-byte
 * bucket, malloc(13) in the 32-byte one; kt_pool's items are 128 bytes.
 */
static const struct kasan_test kasan_tests[] = {
	/* Positive: valid traffic, expect a clean run. */
	{ "malloc_test",    KT_CLEAN,  0, 0x00, "", "", "", "", malloc_test  },
	{ "pool_test",      KT_CLEAN,  0, 0x00, "", "", "", "", pool_test    },
	{ "poolcache_test", KT_CLEAN,  0, 0x00, "", "", "", "",
	    kasan_poolcache_test },
	{ "freelist_link",  KT_CLEAN,  0, 0x00, "", "", "", "",
	    kt_freelist_link },
	/* Negative: one deliberate bad access each, expect the listed report. */
	{ "heap_oob_read",  KT_REPORT, 0, 0xFB, "malloc redzone",
	    "64 bytes inside the 128-byte malloc slot",
	    "kt_heap_oob_read", "",                      kt_heap_oob_read   },
	{ "heap_oob_write", KT_REPORT, 1, 0xFB, "malloc redzone",
	    "64 bytes inside the 128-byte malloc slot",
	    "kt_heap_oob_write", "",                     kt_heap_oob_write  },
	{ "heap_uaf",       KT_REPORT, 0, 0xFC, "malloc use-after-free",
	    "0 bytes inside the 128-byte malloc slot",
	    "kt_heap_uaf", "kt_heap_uaf",                kt_heap_uaf  },
	{ "malloc_uaf_link", KT_REPORT, 0, 0xFC, "malloc use-after-free",
	    "8 bytes inside the 128-byte malloc slot",
	    "kt_malloc_uaf_link", "kt_malloc_uaf_link",  kt_malloc_uaf_link },
	{ "partial_gran",   KT_REPORT, 0, 0x05, "partial granule",
	    "13 bytes inside the 32-byte malloc slot",
	    "kt_partial_granule", "",                    kt_partial_granule },
	{ "width2",         KT_REPORT, 0, 0xFB, "malloc redzone",
	    "128-byte malloc slot", "kt_width2", "",     kt_width2          },
	{ "width4",         KT_REPORT, 0, 0xFB, "malloc redzone",
	    "128-byte malloc slot", "kt_width4", "",     kt_width4          },
	{ "width8",         KT_REPORT, 0, 0xFB, "malloc redzone",
	    "128-byte malloc slot", "kt_width8", "",     kt_width8          },
	{ "width16",        KT_REPORT, 0, 0xFB, "malloc redzone",
	    "128-byte malloc slot", "kt_width16", "",    kt_width16         },
	{ "pool_uaf",       KT_REPORT, 0, 0xFD, "pool use-after-free",
	    "in pool 'kttst'", "kt_pool_uaf", "kt_pool_uaf", kt_pool_uaf    },
	{ "pool_decoy",     KT_REPORT, 0, 0xFD, "pool use-after-free",
	    "in pool 'ktowner'", "kt_pool_decoy", "kt_pool_decoy",
	    kt_pool_decoy  },
	{ "pool_uaf_link",  KT_REPORT, 1, 0xFD, "pool use-after-free",
	    "8 bytes inside the 128-byte item", "kt_pool_uaf_link",
	    "kt_pool_uaf_link",                          kt_pool_uaf_link   },
	{ "poolcache_link", KT_REPORT, 0, 0xFD, "pool use-after-free",
	    "8 bytes inside the 128-byte item", "kt_poolcache_uaf_link",
	    "kt_poolcache_uaf_link",                 kt_poolcache_uaf_link  },
	{ "stack_redzone",  KT_REPORT, 1, 0xF1, "stack redzone", "", "", "",
	    kasan_stack_test   },
	{ "global_oob",     KT_REPORT, 1, 0xFA, "global redzone",
	    "right of the 64-byte global 'kt_global_buf'", "", "",
	    kt_global_oob      },
};

/*
 * Self-iterating suite: positive tests first (valid traffic, expect clean),
 * then the negative battery (one deliberate bad access each, expect a report).
 * Each case announces its expectation -- so the harness reads it from the same
 * kasan_tests[] table that runs it -- and ends at kasan_test_caseend(), where
 * the harness reads kasan_cur / kasan_test_fired / kasan_last_* and classifies:
 *   KT_REPORT: fired -> verify op+code (PASS/FAIL); not fired -> FAIL (miss).
 *   KT_CLEAN:  fired -> FAIL (false positive); not fired -> PASS.
 * Finishes at kasan_test_complete(); the harness kills qemu there.  Without gdb
 * the console shows every report and MISS/false-positive line, then vmkill_now()
 * exits the guest.
 */
void
kasan_test_run(void)
{
	const struct kasan_test *t;
	unsigned int i;

	printf("KASAN-TEST: ntests=%u\n", (unsigned int)nitems(kasan_tests));
	for (i = 0; i < nitems(kasan_tests); i++) {
		kasan_cur = i;
		t = &kasan_tests[i];
		if (t->kt_expect == KT_REPORT)
			printf("KASAN-TEST: case %u %s expect op=%s code=0x%02x "
			    "descr=\"%s\" where=\"%s\" alloc=\"%s\" "
			    "free=\"%s\"\n", i, t->kt_name,
			    t->kt_op ? "write" : "read", t->kt_code,
			    t->kt_descr, t->kt_where, t->kt_alloc_by,
			    t->kt_freed_by);
		else
			printf("KASAN-TEST: case %u %s expect clean\n", i,
			    t->kt_name);

		kasan_test_fired = 0;
		t->kt_fn();

		if (t->kt_expect == KT_REPORT && !kasan_test_fired)
			printf("KASAN-TEST: MISS %s\n", t->kt_name);
		else if (t->kt_expect == KT_CLEAN && kasan_test_fired)
			printf("KASAN-TEST: FALSE-POSITIVE %s\n", t->kt_name);
		kasan_test_caseend();
	}
	printf("KASAN-TEST: complete (%u cases)\n",
	    (unsigned int)nitems(kasan_tests));
	kasan_test_complete();
	vmkill_now();
}

#endif /* KASAN_TEST */
