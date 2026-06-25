/*	$OpenBSD: uvm_init.c,v 1.43 2025/04/16 09:16:48 mpi Exp $	*/
/*	$NetBSD: uvm_init.c,v 1.14 2000/06/27 17:29:23 mrg Exp $	*/

/*
 * Copyright (c) 1997 Charles D. Cranor and Washington University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * from: Id: uvm_init.c,v 1.1.2.3 1998/02/06 05:15:27 chs Exp
 */

/*
 * uvm_init.c: init the vm system.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/percpu.h>
#include <sys/resourcevar.h>
#include <sys/mman.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/pool.h>

#include <uvm/uvm.h>
#include <uvm/uvm_addr.h>

/*
 * struct uvm: we store all global vars in this structure to make them
 * easier to spot...
 */

struct uvm uvm;		/* decl */
struct uvmexp uvmexp;	/* decl */

COUNTERS_BOOT_MEMORY(uvmexp_countersboot, exp_ncounters);
struct cpumem *uvmexp_counters = COUNTERS_BOOT_INITIALIZER(uvmexp_countersboot);

#if defined(VM_MIN_KERNEL_ADDRESS)
vaddr_t vm_min_kernel_address = VM_MIN_KERNEL_ADDRESS;
#else
vaddr_t vm_min_kernel_address;
#endif

/*
This enhanced test provides:

1. **Deterministic PRNG**: Simple LCG with adjustable seed for reproducible
behavior

2. **Multiple test phases**:
   - Power-of-two allocations (tests alignment handling)
   - Random allocations with deliberate fragmentation
   - Small allocation stress test (tests small block management)
   - Proper cleanup phase

3. **Interesting allocation sizes**:
   - Exact powers of two
   - Just below powers of two (tests boundary conditions)
   - Just above powers of two (tests next size class selection)
   - Random sizes

4. **Fragmentation patterns**: Maintains up to 32 live allocations, randomly
allocating and freeing to create fragmentation

5. **Different free patterns**: In the small allocation test, frees even indices
first, then odd indices, to test coalescing behavior

6. **Tracking and reporting**: Counts allocations/frees and reports potential
leaks

You can adjust the seed value to get different but reproducible test patterns,
making it useful for regression testing and debugging specific allocation
patterns that might trigger bugs.

*/


/* Test parameters */
static const int NUM_ITERATIONS = 50;
static const int MAX_LIVE_ALLOCS = 32;
static const size_t MIN_SIZE = 16;
static const size_t MAX_SIZE = (1 << 20);  /* 1MB */

/* Use inline functions instead of macros to avoid sequencing issues */
static inline uint32_t rand_next(uint32_t *s) {
	*s = *s * 1103515245 + 12345;
	return *s;
}

static inline uint32_t rand_range(uint32_t *s, uint32_t min, uint32_t max) {
	return (rand_next(s) % (max - min + 1)) + min;
}

/* Track live allocations, too large for stack */
struct alloc_entry {
	void *ptr;
	size_t size;
	int active;
} allocs[MAX_LIVE_ALLOCS];
static void *small_ptrs[256];
static size_t small_sizes[256];

void
malloc_test()
{
	const int TYPE = M_PF;

	/* Simple linear congruential generator for deterministic behavior */
	uint32_t seed = 0xcafebabe;  /* Adjust this seed as needed */


	int i, j;
	int total_allocs = 0;
	int total_frees = 0;

	/* Initialize tracking array using designated initializers */
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

	/* extern void db_enter(); */
	/* db_enter(); */
	extern void vmkill_now(void);
	vmkill_now();
}

static struct pool kasan_test_pool;
static void *pool_ptrs[256];

/*
 * Exercise pool(9) get/put across several item sizes, touching every byte
 * of each item, so KASAN catches under-marked items or stale poison on the
 * shared backing pages.
 */
void
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

#ifdef KASAN
/*
 * Negative test: deliberately overrun a stack buffer by one byte to prove the
 * compiler's inline stack-redzone poisoning lands in mapped, checked shadow.
 * The store must trip a KASAN "stack redzone (out-of-bounds)" report (shadow
 * code 0xf1/0xf2/0xf3) and panic; a silent return ("MISS") or an unmapped-shadow
 * fault is a failure.  Runs on the proc0 kernel stack, which lives in the
 * bootstrap steal region [end, kern_end) -- past &end, so it is only covered
 * once kasan_premap_image_shadow() maps shadow out to kern_end.  One-shot (it
 * panics into ddb), so the call in uvm_init() is left disabled; enable it to run.
 */
void
kasan_stack_test(void)
{
	volatile char buf[64];
	volatile int idx = sizeof(buf);	/* 1 past the end; opaque to -Warray-bounds */

	printf("kasan_stack_test: overrunning a %zu-byte stack buffer by 1 "
	    "(expect a KASAN stack-redzone report)\n", sizeof(buf));
	buf[idx] = 0x41;
	printf("kasan_stack_test: MISS -- overflow went undetected\n");
}

/*
 * Regression test for the per-CPU pool cache under KASAN.  With pool_debug on,
 * pool_cache_put() both KASAN-redzones and pool-poisons an item's body; on the
 * next pool_cache_get() the cache's poison_check() reads that body, so KASAN
 * must revalidate the item before the check runs.  Fill the cache (freeing a
 * batch redzones each body) then re-get the batch to drive poison_check across
 * cached items: reaching the final print means the ordering is right; a KASAN
 * report in poison_check is the bug.  Needs a live per-CPU cache, so it is
 * called from main() after cpu_configure()/dostartuphooks(), not uvm_init().
 */
void
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
#endif /* KASAN */

/*
 * local prototypes
 */

/*
 * uvm_init: init the VM system.   called from kern/init_main.c.
 */

void
uvm_init(void)
{
	vaddr_t kvm_start, kvm_end;

	/*
	 * Ensure that the hardware set the page size.
	 */
	if (uvmexp.pagesize == 0) {
		panic("uvm_init: page size not set");
	}
	averunnable.fscale = FSCALE;

	/*
	 * Init the page sub-system.  This includes allocating the vm_page
	 * structures, and setting up all the page queues (and locks).
	 * Available memory will be put in the "free" queue, kvm_start and
	 * kvm_end will be set to the area of kernel virtual memory which
	 * is available for general use.
	 */
	uvm_page_init(&kvm_start, &kvm_end);

	/*
	 * Init the map sub-system.
	 *
	 * Allocates the static pool of vm_map_entry structures that are
	 * used for "special" kernel maps (e.g. kernel_map, kmem_map, etc...).
	 */
	uvm_map_init();

	/*
	 * Setup the kernel's virtual memory data structures.  This includes
	 * setting up the kernel_map/kernel_object.
	 */
	uvm_km_init(vm_min_kernel_address, kvm_start, kvm_end);

	/*
	 * step 4.5: init (tune) the fault recovery code.
	 */
	uvmfault_init();

	/*
	 * Init the pmap module.  The pmap module is free to allocate
	 * memory for its private use (e.g. pvlists).
	 */
	pmap_init();

	/*
	 * step 6: init uvm_km_page allocator memory.
	 */
	uvm_km_page_init();

	/*
	 * Make kernel memory allocators ready for use.
	 * After this call the malloc memory allocator can be used.
	 */
	kmeminit();

	/*
	 * step 7.5: init the dma allocator, which is backed by pools.
	 */
	dma_alloc_init();

	/*
	 * Init all pagers and the pager_map.
	 */
	uvm_pager_init();

	/*
	 * step 9: init anonymous memory system
	 */
	amap_init();

	/*
	 * step 10: start uvm_km_page allocator thread.
	 */
	uvm_km_page_lateinit();

	//	kasan_stack_test();	/* negative test: panics; enable to run */
	//	pool_test();
	//	malloc_test();

	/*
	 * the VM system is now up!  now that malloc is up we can
	 * enable paging of kernel objects.
	 */
	uao_create(VM_KERNEL_SPACE_SIZE, UAO_FLAG_KERNSWAP);

	/*
	 * reserve some unmapped space for malloc/pool use after free usage
	 */
#ifdef DEADBEEF0
	kvm_start = trunc_page(DEADBEEF0) - PAGE_SIZE;
	if (uvm_map(kernel_map, &kvm_start, 3 * PAGE_SIZE,
	    NULL, UVM_UNKNOWN_OFFSET, 0, UVM_MAPFLAG(PROT_NONE,
	    PROT_NONE, MAP_INHERIT_NONE, MADV_RANDOM, UVM_FLAG_FIXED)))
		panic("uvm_init: cannot reserve dead beef @0x%x", DEADBEEF0);
#endif
#ifdef DEADBEEF1
	kvm_start = trunc_page(DEADBEEF1) - PAGE_SIZE;
	if (uvm_map(kernel_map, &kvm_start, 3 * PAGE_SIZE,
	    NULL, UVM_UNKNOWN_OFFSET, 0, UVM_MAPFLAG(PROT_NONE,
	    PROT_NONE, MAP_INHERIT_NONE, MADV_RANDOM, UVM_FLAG_FIXED)))
		panic("uvm_init: cannot reserve dead beef @0x%x", DEADBEEF1);
#endif
	/*
	 * Init anonymous memory systems.
	 */
	uvm_anon_init();

#ifndef SMALL_KERNEL
	/*
	 * Switch kernel and kmem_map over to a best-fit allocator,
	 * instead of walking the tree.
	 */
	uvm_map_set_uaddr(kernel_map, &kernel_map->uaddr_any[3],
	    uaddr_bestfit_create(vm_map_min(kernel_map),
	    vm_map_max(kernel_map)));
	uvm_map_set_uaddr(kmem_map, &kmem_map->uaddr_any[3],
	    uaddr_bestfit_create(vm_map_min(kmem_map),
	    vm_map_max(kmem_map)));
#endif /* !SMALL_KERNEL */
}

void
uvm_init_percpu(void)
{
	uvmexp_counters = counters_alloc_ncpus(uvmexp_counters, exp_ncounters);

	uvm_anon_init_percpu();
}
