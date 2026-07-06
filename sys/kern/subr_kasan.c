/*	$OpenBSD$	*/

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/user.h>

#include <uvm/uvm_extern.h>
#include <uvm/uvm.h>

#include <machine/cpu.h>
#include <machine/pmap.h>
#include <machine/kasan.h>

#include <ddb/db_output.h>

#include <sys/kasan.h>

#define __RET_ADDR	(vaddr_t)__builtin_return_address(0)

#ifdef KASAN_TEST
/* Result of the most recent report, consumed by the test harness; the storage
 * lives in kern/subr_kasan_test.c. */
extern volatile int kasan_test_fired;
extern volatile int kasan_last_op;
extern volatile uint8_t kasan_last_code;
extern volatile size_t kasan_last_size;
extern volatile unsigned long kasan_last_addr;
#endif

vaddr_t pmap_steal_memory(vsize_t, vaddr_t *, vaddr_t *);
/* TLB shootdown for the leaf COW in kasan_enter_shad(); see pmap.c. */
void pmap_tlb_shootpage(struct pmap *, vaddr_t, int);
#ifdef MULTIPROCESSOR
void pmap_tlb_shootwait(void);
#else
#define	pmap_tlb_shootwait()		do { } while (0)
#endif

static int kasan_enabled;
/* Set to 1 (e.g. from ddb) to log every shadow map/alloc operation. */
int kasan_debug = 0;
static uint8_t kasan_early_pages[USPACE + 3 * PAGE_SIZE] __aligned(PAGE_SIZE);
static size_t kasan_allocated_early_pages;
extern struct user *proc0paddr;

/*
 * One shared, zeroed page mapped read-only across the whole shadow region by
 * kasan_premap_zero_shadow().  Untracked in-range memory thus reads as 0x00
 * (valid) instead of faulting on an unmapped shadow page; kasan_enter_shad()
 * copies-on-write a private writable page over it the first time a region is
 * actually poisoned.
 */
static paddr_t kasan_zero_shadow_pa;

/*
 * The kernel image plus the bootstrap memory stolen just above it -- the proc0
 * u-area and the per-CPU interrupt/IST stacks among it -- live at
 * [KERNBASE, kern_end), outside the monitored heap window.  (proc0's stack sits
 * past &end, in the first_avail steal region, so &end is too low a bound;
 * kern_end = KERNBASE + first_avail covers all of it.)  The compiler still
 * emits inline stack-redzone poison and global redzones for that region, so it
 * needs real, writable, checked shadow.  kasan_premap_image_shadow() maps it;
 * kasan_unsupported() then treats [kasan_image_start, kasan_image_end) as
 * monitored so the out-of-line checks actually run there too.
 */
static vaddr_t kasan_image_start;
static vaddr_t kasan_image_end;
int kasan_img_l4slot;		/* PML4 slot of the image shadow; see pmap_pdp_ctor */
extern vaddr_t kern_end;	/* end of bootstrap-allocated kernel memory */

static inline uint8_t *
kasan_addr_to_shad(vaddr_t va)
{
	return (uint8_t *)(KASAN_SHADOW_START +
	    ((va - VM_MIN_KERNEL_ADDRESS) >> KASAN_SHADOW_SCALE_SHIFT));
}

/* Shadow primitives; built on kasan_addr_to_shad() above. */
#include "kasan_shadow.h"

static int
kasan_unsupported(vaddr_t addr)
{
	/* The monitored heap window. */
	if (addr >= VM_MIN_KERNEL_ADDRESS && addr < VM_MAX_KERNEL_ADDRESS)
		return 0;
	/* The kernel image + statically-embedded stacks. */
	if (addr >= kasan_image_start && addr < kasan_image_end)
		return 0;
	return 1;
}

/*
 * Allocate a zeroed physical page to back one shadow (leaf) page.  Shadow
 * starts out 0x00 (all valid), so untracked memory in the monitored range
 * reads as accessible until something poisons it.  Handles both the early
 * phase (before UVM is up, via steal) and normal operation.  Leaf pages are
 * written only through their shadow VA, so their physical placement is
 * unconstrained.
 */
static paddr_t
kasan_alloc_shadow_page(void)
{
	struct vm_page *pg;
	vaddr_t va;

	if (uvm.page_init_done == 0) {
		va = pmap_steal_memory(PAGE_SIZE, NULL, NULL);
		__builtin_memset((void *)va, 0, PAGE_SIZE);
		return PMAP_DIRECT_UNMAP(va);
	}

	pg = uvm_pagealloc(NULL, 0, NULL, UVM_PGA_USERESERVE | UVM_PGA_ZERO);
	if (pg == NULL)
		panic("%s: out of memory", __func__);
	return VM_PAGE_TO_PHYS(pg);
}

static void
kasan_enter_shad(vaddr_t sva)
{
	struct pmap *pmap = pmap_kernel();
	pd_entry_t opte, npte;
	paddr_t npa;

	/*
	 * Walk and populate top-down through the recursive page-table self-map
	 * (L4_BASE..L1_BASE), never through PMAP_DIRECT_MAP: the direct map is
	 * read-only over the kernel image's physical range, so a page-table page
	 * that lands there cannot have its entries written via the direct map,
	 * whereas the recursive alias is always writable.  Each level must be
	 * present before the next is accessed, so link as we descend.
	 *
	 * The L4..L2 skeleton is fully populated single-threaded at boot
	 * (kasan_premap_zero_shadow() for the heap window,
	 * kasan_premap_image_shadow() for the image window), so these three
	 * branches never run once other CPUs are up; only the L1 leaf below
	 * changes at runtime and needs the CAS.
	 */
	if ((L4_BASE[pl4_i(sva)] & PG_V) == 0) {
		L4_BASE[pl4_i(sva)] =
		    kasan_alloc_shadow_page() | PG_KW | pg_nx | PG_V;
		pmap->pm_stats.resident_count++;
	}
	if ((L3_BASE[pl3_i(sva)] & PG_V) == 0) {
		L3_BASE[pl3_i(sva)] =
		    kasan_alloc_shadow_page() | PG_KW | pg_nx | PG_V;
		pmap->pm_stats.resident_count++;
	}
	if ((L2_BASE[pl2_i(sva)] & PG_V) == 0) {
		L2_BASE[pl2_i(sva)] =
		    kasan_alloc_shadow_page() | PG_KW | pg_g_kern | pg_nx | PG_V;
		pmap->pm_stats.resident_count++;
	}

	/*
	 * Back the shadow with a private, writable page so distinct regions
	 * never share a shadow cell.  A leaf still pointing at the shared
	 * read-only zero page (or never mapped at all) is copied-on-write to a
	 * fresh zeroed page here; an already-private leaf is left untouched,
	 * preserving the poison state recorded so far.
	 *
	 * The swap must be a CAS: this runs unlocked and concurrently
	 * (km_alloc() and pmap_growkernel() both drive it), and a
	 * check-then-write lets two CPUs each install a private page --
	 * whoever loses has its subsequent shadow marks land on a detached
	 * page, silently erasing poison and valid state alike.  The loser
	 * frees its page and continues with the winner's.
	 *
	 * Both then shoot the old translation down: the replaced PTE was the
	 * read-only zero page, which every CPU's shadow reads may have cached,
	 * and a stale lesser-permission entry can raise a spurious #PF on the
	 * next shadow write (Intel SDM 4.10.4) -- fatal here, since the shadow
	 * VA is outside kernel_map.  The shootwait also orders the swap before
	 * the caller publishes the region, so no CPU can poison or check this
	 * leaf through a stale entry afterwards.
	 */
	opte = L1_BASE[pl1_i(sva)];
	if (opte == 0 ||
	    (opte & PMAP_PA_MASK & PG_FRAME) == kasan_zero_shadow_pa) {
		npa = kasan_alloc_shadow_page();
		npte = npa | PG_KW | pg_nx | PG_V;
		if (atomic_cas_ulong(
		    (volatile unsigned long *)&L1_BASE[pl1_i(sva)],
		    opte, npte) == opte) {
			pmap->pm_stats.resident_count++;
		} else {
			/* Lost the race; only possible once UVM is up. */
			KASSERT(uvm.page_init_done);
			uvm_pagefree(PHYS_TO_VM_PAGE(npa));
		}
		pmap_tlb_shootpage(pmap, sva, 1);
		pmap_tlb_shootwait();
	}
}

void
kasan_enter_shad_multi(vaddr_t va, size_t sz)
{
	size_t ssz, spgs, i;
	vaddr_t sva;

	/* Only the monitored range has shadow; ignore e.g. direct-map VAs. */
	if (kasan_unsupported(va))
		return;

	sva = (vaddr_t)kasan_addr_to_shad(va);
	sva &= PMAP_PA_MASK;
	ssz = (sz + KASAN_SHADOW_SCALE_SIZE - 1) / KASAN_SHADOW_SCALE_SIZE;
	spgs = (ssz + PAGE_SIZE - 1) / PAGE_SIZE;

	if (kasan_debug)
		printf("%s: shadow 0x%lx to 0x%lx\n", __func__, sva, sva + ssz);
	for (i = 0; i < spgs; i++)
		kasan_enter_shad(sva + i * PAGE_SIZE);
}

/*
 * Hand out one page of kasan_early_pages by physical address; the array
 * lives in the image, mapped at KERNBASE, so PA = VA - KERNBASE.
 */
static paddr_t
kasan_get_early_page(void)
{
	paddr_t npa;
	size_t n = kasan_allocated_early_pages++;
	npa = (vaddr_t)&kasan_early_pages[0] + n * PAGE_SIZE;
	return npa - KERNBASE;
}

/*
 * Add page table entries using pages backed by .data in the kernel image.
 */
static void
kasan_enter_early_shad(vaddr_t sva)
{
	uint64_t l4idx, l3idx, l2idx, l1idx;
	pd_entry_t *pd, npte;
	paddr_t npa;

	l4idx = (sva & L4_MASK) >> L4_SHIFT;
	l3idx = (sva & L3_MASK) >> L3_SHIFT;
	l2idx = (sva & L2_MASK) >> L2_SHIFT;
	l1idx = (sva & L1_MASK) >> L1_SHIFT;

	pd = (pd_entry_t *)(proc0paddr->u_pcb.pcb_cr3 + KERNBASE);
	npa = pd[l4idx] & PMAP_PA_MASK & PG_FRAME;
	if (!npa) {
		npa = kasan_get_early_page();
		pd[l4idx] = (npa | PG_KW | pg_nx | PG_V);
	}

	pd = (pd_entry_t *)(npa + KERNBASE);
	npa = pd[l3idx] & PMAP_PA_MASK & PG_FRAME;
	if (!npa) {
		npa = kasan_get_early_page();
		pd[l3idx] = (npa | PG_KW | pg_nx | PG_V);
	}

	pd = (pd_entry_t *)(npa + KERNBASE);
	npa = pd[l2idx] & PMAP_PA_MASK & PG_FRAME;
	if (!npa) {
		npa = kasan_get_early_page();
		pd[l2idx] = (npa | PG_KW | pg_g_kern | pg_nx | PG_V);
	}

	pd = (pd_entry_t *)(npa + KERNBASE);
	npa = kasan_get_early_page();
	npte = npa | PG_KW | pg_nx | PG_V;
	pd[l1idx] = npte;
}

/*
 * Called from locore0 before init_x86_64: map shadow for proc0's stack so
 * the very first instrumented prologue can write its stack redzones.
 */
void
kasan_bootstrap(void)
{
	size_t i;
	vaddr_t sva;

	sva = (vaddr_t)kasan_addr_to_shad((vaddr_t)proc0paddr + USPACE - 16);
	sva &= PMAP_PA_MASK;

	for (i = 0; i < UPAGES; i++)
		kasan_enter_early_shad(sva + i * PAGE_SIZE);
}

/*
 * Map every shadow page in the monitored range to one shared, read-only,
 * zeroed page.  This guarantees a shadow read never faults: untracked
 * in-range memory reads as 0x00 (valid).  All leaf PTEs alias a single
 * physical page, so the cost is the page-table skeleton (~256 PT pages for
 * the 512MB shadow) plus that one zero page.  kasan_enter_shad() later
 * copies a private writable page over a leaf the first time it is poisoned.
 */
static void
kasan_premap_zero_shadow(void)
{
	vaddr_t sva, send;

	kasan_zero_shadow_pa = kasan_alloc_shadow_page();

	sva = (vaddr_t)kasan_addr_to_shad(VM_MIN_KERNEL_ADDRESS) & ~PAGE_MASK;
	send = (vaddr_t)kasan_addr_to_shad(VM_MAX_KERNEL_ADDRESS);

	/* Populate top-down through the recursive self-map (always writable). */
	for (; sva < send; sva += PAGE_SIZE) {
		if ((L4_BASE[pl4_i(sva)] & PG_V) == 0)
			L4_BASE[pl4_i(sva)] =
			    kasan_alloc_shadow_page() | PG_KW | pg_nx | PG_V;
		if ((L3_BASE[pl3_i(sva)] & PG_V) == 0)
			L3_BASE[pl3_i(sva)] =
			    kasan_alloc_shadow_page() | PG_KW | pg_nx | PG_V;
		if ((L2_BASE[pl2_i(sva)] & PG_V) == 0)
			L2_BASE[pl2_i(sva)] = kasan_alloc_shadow_page() |
			    PG_KW | pg_g_kern | pg_nx | PG_V;

		/*
		 * Read-only (no PG_KW) so an accidental shadow write to an
		 * un-poisoned region faults loudly rather than silently
		 * scribbling on the shared page; the real poison paths run
		 * kasan_enter_shad() first, which COWs in a writable page.
		 * Leave any already-mapped leaf (e.g. the bootstrap stack
		 * shadow) untouched.
		 */
		if (L1_BASE[pl1_i(sva)] == 0)
			L1_BASE[pl1_i(sva)] =
			    (kasan_zero_shadow_pa | pg_nx | PG_V);
	}
}

/*
 * Map writable shadow for the kernel image + bootstrap steal region
 * ([KERNBASE, kern_end)).  Unlike the heap shadow (one shared read-only zero page,
 * COWed on first poison), the compiler poisons stack-frame and global redzones
 * here with INLINE writes that never call kasan_enter_shad(), so every leaf
 * must be a private writable page up front.  kasan_enter_shad() does exactly
 * that -- it COWs a fresh zeroed writable page over an empty/zero leaf -- so we
 * just drive it across the whole range, then record the range (so
 * kasan_unsupported() starts checking it) and its PML4 slot (so pmap_pdp_ctor()
 * shares it with every pmap).
 */
static void
kasan_premap_image_shadow(void)
{
	vaddr_t sva, send;

	kasan_image_start = (vaddr_t)KERNBASE;
	kasan_image_end = kern_end;		/* page-aligned; past proc0's u-area */

	sva = (vaddr_t)kasan_addr_to_shad(kasan_image_start) & ~PAGE_MASK;
	send = (vaddr_t)kasan_addr_to_shad(kasan_image_end - 1);
	kasan_img_l4slot = pl4_pi(sva);

	for (; sva <= send; sva += PAGE_SIZE)
		kasan_enter_shad(sva);

	/* The image shadow must not spill into a second, un-propagated slot. */
	KASSERT(pl4_pi(send) == kasan_img_l4slot);
}

/*
 * Create the shadow mapping. We don't create the 'User' area, because we
 * exclude it from the monitoring. The 'Main' area is created dynamically
 * in pmap_growkernel.
 */
void
kasan_init(void)
{
	if (kasan_enabled)
		panic("KASAN already enabled");

	/* Back the whole shadow range before any check can read it. */
	kasan_premap_zero_shadow();

	/*
	 * Give the kernel image + embedded stacks real writable shadow and mark
	 * the range monitored, before kasan_ctors() (which poisons global
	 * redzones into it) or any inline stack poison runs.
	 */
	kasan_premap_image_shadow();

	kasan_enabled = 1;

	/* Call the ASAN constructors. */
	kasan_ctors();
}

static const char *
kasan_shadow_descr(uint8_t code)
{
	switch (code) {
	case 0:
		return "valid";
	case KASAN_MEMORY_REDZONE:
		return "heap redzone (out-of-bounds)";
	case KASAN_GLOBAL_REDZONE:
		return "global redzone (out-of-bounds)";
	case KASAN_STACK_LEFT:
	case KASAN_STACK_MID:
	case KASAN_STACK_RIGHT:
	case KASAN_STACK_PARTIAL:
		return "stack redzone (out-of-bounds)";
	case KASAN_USE_AFTER_SCOPE:
		return "use-after-scope";
	case KASAN_SHADOW_SCALE_SIZE:
		return "valid";
	default:
		if (code < KASAN_SHADOW_SCALE_SIZE)
			return "partial granule (out-of-bounds)";
		return "unknown";
	}
}

static void
kasan_report(vaddr_t addr, size_t size, int op, vaddr_t rip)
{
	vaddr_t bad = addr;
	size_t i;
	uint8_t code;

	/* The base may be valid while a later byte trips; point at the
	 * first offending byte so the offset into the object is obvious. */
	for (i = 0; i < size; i++) {
		if (!kasan_shadow_1byte_isvalid(addr + i)) {
			bad = addr + i;
			break;
		}
	}
	code = *kasan_addr_to_shad(bad);

	printf("KASAN: invalid %s of %zu byte%s at 0x%lx from pc 0x%lx\n",
	    (op ? "write" : "read"), size, (size > 1 ? "s" : ""), addr, rip);
	printf("KASAN: first bad byte at 0x%lx (+%lu); shadow 0x%02x: %s\n",
	    bad, (unsigned long)(bad - addr), code, kasan_shadow_descr(code));

#ifdef KASAN_TEST
	/* Record the result for the test harness to read at the
	 * kasan_test_caseend() breakpoint (subr_kasan_test.c). */
	kasan_last_addr = addr;
	kasan_last_size = size;
	kasan_last_op = op;
	kasan_last_code = code;
	kasan_test_fired = 1;
#endif
}

static void
kasan_shadow_fill(vaddr_t addr, size_t size, uint8_t val)
{
	if (size == 0)
		return;
	if (kasan_unsupported(addr))
		return;

	KASSERT(addr % KASAN_SHADOW_SCALE_SIZE == 0);
	KASSERT(size % KASAN_SHADOW_SCALE_SIZE == 0);

	kasan_shadow_memset(addr, size, val);
}

void
kasan_add_redzone(size_t *size)
{
	*size = roundup(*size, KASAN_SHADOW_SCALE_SIZE);
	*size += KASAN_SHADOW_SCALE_SIZE;
}

static void
kasan_markmem(vaddr_t addr, size_t size, int valid, uint8_t code)
{
	if (addr % KASAN_SHADOW_SCALE_SIZE != 0)
		panic("%s: %s region at 0x%lx size %zu is not %lu-byte shadow "
		    "aligned", __func__, valid ? "valid" : "redzone", addr,
		    size, KASAN_SHADOW_SCALE_SIZE);

	if (valid) {
		kasan_shadow_markvalid(addr, size);
	} else {
		KASSERT(size % KASAN_SHADOW_SCALE_SIZE == 0);
		kasan_shadow_fill(addr, size, code);
	}
}

void
kasan_alloc(vaddr_t addr, size_t size, size_t redzone, uint8_t code)
{
	size_t rzbeg;

	/* Memory outside the monitored range (e.g. direct map) has no shadow. */
	if (kasan_unsupported(addr))
		return;

	if (kasan_debug)
		printf("%s: 0x%lx+%zu-%zu\n", __func__, addr, size, redzone);
	/* Redzone starts past the object's partial granule (kept aligned). */
	rzbeg = kasan_redzone_start(size);
	kasan_markmem(addr + rzbeg, redzone - rzbeg, 0, code);
	kasan_markmem(addr, size, 1, 0);
}

void
kasan_free(vaddr_t addr, size_t sz_with_redz, uint8_t code)
{
	if (sz_with_redz == 0)
		return;
	if (kasan_unsupported(addr))
		return;

	kasan_markmem(addr, sz_with_redz, 0, code);
}

/*
 * Set while emitting a report.  The report path (kasan_report, db_stack_dump,
 * and ddb's panic handlers) touches plenty of poisoned/freed memory itself;
 * without this guard each such access re-reports and re-panics, spinning out
 * endless nested reports instead of the one we care about.
 */
static int kasan_reporting;
static inline void
kasan_shadow_check(vaddr_t addr, size_t size, int op, vaddr_t retaddr)
{
	int valid;

	if (!kasan_enabled || kasan_reporting)
		return;
	if (size == 0)
		return;
	if (kasan_unsupported(addr))
		return;

	if (__builtin_constant_p(size)) {
		switch (size) {
		case 1:
			valid = kasan_shadow_1byte_isvalid(addr);
			break;
		case 2:
			valid = kasan_shadow_2byte_isvalid(addr);
			break;
		case 4:
			valid = kasan_shadow_4byte_isvalid(addr);
			break;
		case 8:
			valid = kasan_shadow_8byte_isvalid(addr);
			break;
		default:
			valid = kasan_shadow_Nbyte_isvalid(addr, size);
			break;
		}
	} else {
		valid = kasan_shadow_Nbyte_isvalid(addr, size);
	}

	if (!valid) {
		kasan_reporting = 1;
		kasan_report(addr, size, op, retaddr);
#ifdef KASAN_TEST
		/* Test build: don't panic.  kasan_report() recorded the result
		 * for the negative-test harness; fall through to clear
		 * kasan_reporting and resume so the next case runs.  Safe only
		 * because every battery access is a tiny overrun into mapped
		 * memory (see subr_kasan_test.c).  Clearing kasan_reporting is
		 * mandatory: a stuck flag would suppress every later case into a
		 * false MISS. */
#elif defined(DDB)
		db_stack_dump();
		panic("Caught invalid memory access at %lx size %zu op %d",
		    addr, size, op);
#endif
		kasan_reporting = 0;
	}
}

void *
kasan_memcpy(void *dst, const void *src, size_t len)
{
	kasan_shadow_check((vaddr_t)src, len, 0, __RET_ADDR);
	kasan_shadow_check((vaddr_t)dst, len, 1, __RET_ADDR);
	return __builtin_memcpy(dst, src, len);
}

int
kasan_memcmp(const void *b1, const void *b2, size_t len)
{
	kasan_shadow_check((vaddr_t)b1, len, 0, __RET_ADDR);
	kasan_shadow_check((vaddr_t)b2, len, 0, __RET_ADDR);
	return __builtin_memcmp(b1, b2, len);
}

void *
kasan_memset(void *b, int c, size_t len)
{
	kasan_shadow_check((vaddr_t)b, len, 1, __RET_ADDR);
	return __builtin_memset(b, c, len);
}

static void
kasan_register_global(struct __asan_global *global)
{
	size_t aligned_size = roundup(global->size, KASAN_SHADOW_SCALE_SIZE);

	/* Poison the redzone following the var. */
	kasan_shadow_fill((vaddr_t)((uintptr_t)global->beg + aligned_size),
	    global->size_with_redzone - aligned_size, KASAN_GLOBAL_REDZONE);
}

void
__asan_register_globals(struct __asan_global *globals, size_t size)
{
	size_t i;
	for (i = 0; i < size; i++) {
		kasan_register_global(&globals[i]);
	}
}

void
__asan_unregister_globals(struct __asan_global *globals, size_t size)
{
	/* Only reached on module unload; the kernel never unloads. */
}

#define ASAN_LOAD_STORE(size)					\
	void __asan_load##size(unsigned long);			\
	void __asan_load##size(unsigned long addr)		\
	{							\
		kasan_shadow_check(addr, size, 0, __RET_ADDR);\
	}							\
	void __asan_load##size##_noabort(unsigned long);	\
	void __asan_load##size##_noabort(unsigned long addr)	\
	{							\
		kasan_shadow_check(addr, size, 0, __RET_ADDR);\
	}							\
	void __asan_store##size(unsigned long);			\
	void __asan_store##size(unsigned long addr)		\
	{							\
		kasan_shadow_check(addr, size, 1, __RET_ADDR);\
	}							\
	void __asan_store##size##_noabort(unsigned long);	\
	void __asan_store##size##_noabort(unsigned long addr)	\
	{							\
		kasan_shadow_check(addr, size, 1, __RET_ADDR);\
	}

ASAN_LOAD_STORE(1);
ASAN_LOAD_STORE(2);
ASAN_LOAD_STORE(4);
ASAN_LOAD_STORE(8);
ASAN_LOAD_STORE(16);

void
__asan_loadN(unsigned long addr, size_t size)
{
	kasan_shadow_check(addr, size, 0, __RET_ADDR);
}

void
__asan_loadN_noabort(unsigned long addr, size_t size)
{
	kasan_shadow_check(addr, size, 0, __RET_ADDR);
}

void
__asan_storeN(unsigned long addr, size_t size)
{
	kasan_shadow_check(addr, size, 1, __RET_ADDR);
}

void
__asan_storeN_noabort(unsigned long addr, size_t size)
{
	kasan_shadow_check(addr, size, 1, __RET_ADDR);
}

void
__asan_handle_no_return(void)
{
	/* nothing */
}

void
__asan_poison_stack_memory(const void *addr, size_t size)
{
	vaddr_t va = (vaddr_t)addr;

	KASSERT(va % KASAN_SHADOW_SCALE_SIZE == 0);
	kasan_shadow_fill(va, size, KASAN_USE_AFTER_SCOPE);
}

void
__asan_unpoison_stack_memory(const void *addr, size_t size)
{
	vaddr_t va = (vaddr_t)addr;

	KASSERT(va % KASAN_SHADOW_SCALE_SIZE == 0);
	kasan_shadow_fill(va, size, 0);
}

/* The kernel uses neither alloca nor VLAs, so these must never fire. */
void
__asan_alloca_poison(unsigned long addr, size_t size)
{
	panic("%s: impossible!", __func__);
}

void
__asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
{
	panic("%s: impossible!", __func__);
}

#define ASAN_SET_SHADOW(byte) \
	void __asan_set_shadow_##byte(void *, size_t);			\
	void __asan_set_shadow_##byte(void *addr, size_t size)		\
	{								\
		__builtin_memset((void *)addr, 0x##byte, size);		\
	}

ASAN_SET_SHADOW(00);
ASAN_SET_SHADOW(f1);
ASAN_SET_SHADOW(f2);
ASAN_SET_SHADOW(f3);
ASAN_SET_SHADOW(f5);
ASAN_SET_SHADOW(f8);
