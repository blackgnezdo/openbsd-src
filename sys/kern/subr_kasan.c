/*	$OpenBSD$	*/

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/user.h>

#include <uvm/uvm_extern.h>

#include <machine/kasan.h>
#include <machine/cpu.h>
#include <machine/pmap.h>
#include <machine/segments.h>
#include <machine/vmmvar.h>

#include <ddb/db_output.h>

#include <sys/kasan.h>

#define __RET_ADDR	(vaddr_t)__builtin_return_address(0)

#define ADDR_CROSSES_SCALE_BOUNDARY(addr, size) 		\
	(addr >> KASAN_SHADOW_SCALE_SHIFT) !=			\
	    ((addr + size - 1) >> KASAN_SHADOW_SCALE_SHIFT)

void kasan_init(void);
int pmap_get_physpage(vaddr_t, int, paddr_t *); // XXX

static int kasan_enabled;
static paddr_t kasan_zero;
int kasan_in_init;
static char kasan_early_pages[USPACE + 3 * PAGE_SIZE] __aligned(PAGE_SIZE);
static size_t kasan_allocated_early_pages;

inline char *
kasan_addr_to_shad(vaddr_t va)
{
	return (char *)(KASAN_SHADOW_START +
	    ((va - VM_MIN_KERNEL_ADDRESS) >> KASAN_SHADOW_SCALE_SHIFT));
}

static int
kasan_unsupported(vaddr_t addr)
{
	return (addr >= VM_MAX_KERNEL_ADDRESS ||
	    addr < VM_MIN_KERNEL_ADDRESS);
}

int
kasan_enter_shad(vaddr_t sva, paddr_t pa)
{
	uint64_t l4idx, l3idx, l2idx, l1idx;
	pd_entry_t *pd, npte;
	paddr_t npa;
	struct pmap *pmap = pmap_kernel();

	l4idx = (sva & L4_MASK) >> L4_SHIFT; /* PML4E idx */
	l3idx = (sva & L3_MASK) >> L3_SHIFT; /* PDPTE idx */
	l2idx = (sva & L2_MASK) >> L2_SHIFT; /* PDE idx */
	l1idx = (sva & L1_MASK) >> L1_SHIFT; /* PTE idx */

	/* Start at PML4 / top level */
	pd = (pd_entry_t *)pmap->pm_pdir;

	if (pd == NULL)
		return ENOMEM;

	/* npa = physaddr of PDPT */
	npa = pd[l4idx] & PMAP_PA_MASK & PG_FRAME;

	/* Valid PML4e for the 512GB region containing sva? */
	if (!npa) {
		/* No valid PML4e - allocate PDPT page and set PML4e */
		pmap_get_physpage(sva, 3, &npa);

		/*
		 * Higher levels get full perms; specific permissions are
		 * entered at the lowest level.
		 */
		pd[l4idx] = (npa | PG_KW | pg_nx | PG_V);
	}

	pd = (pd_entry_t *)PMAP_DIRECT_MAP(npa);
	if (pd == NULL)
		panic("%s: can't locate PDPT @ pa=0x%llx", __func__,
		    (uint64_t)npa);

	/* npa = physaddr of PD page */
	npa = pd[l3idx] & PMAP_PA_MASK & PG_FRAME;

	/* Valid PDPTe for the 1GB region containing sva? */
	if (!npa) {
		/* No valid PDPTe - allocate PD page and set PDPTe */
		pmap_get_physpage(sva, 2, &npa);

		/*
		 * Higher levels get full perms; specific permissions are
		 * entered at the lowest level.
		 */
		pd[l3idx] = (npa | PG_KW | pg_nx | PG_V);
	}

	pd = (pd_entry_t *)PMAP_DIRECT_MAP(npa);
	if (pd == NULL)
		panic("%s: can't locate PD page @ pa=0x%llx", __func__,
		    (uint64_t)npa);

	/* npa = physaddr of PT page */
	npa = pd[l2idx] & PMAP_PA_MASK & PG_FRAME;

	/* Valid PDE for the 2MB region containing sva? */
	if (!npa) {
		/* No valid PDE - allocate PT page and set PDE */
		pmap_get_physpage(sva, 1, &npa);

		/*
		 * Higher level get full perms; specific permissions are
		 * entered at the lowest level.
		 */
		pd[l2idx] = (npa | PG_KW | pg_g_kern | pg_nx | PG_V);
	}

	pd = (pd_entry_t *)PMAP_DIRECT_MAP(npa);
	if (pd == NULL)
		panic("%s: can't locate PT page @ pa=0x%llx", __func__,
		    (uint64_t)npa);

	npte = pa | PG_KW | pg_nx | PG_V;

	if (pd[l1idx] == 0) {
		pmap->pm_stats.resident_count++;
	} else {
		/* XXX flush ept */
	}

	pd[l1idx] = npte;

	return 0;
}

void
kasan_enter_shad_multi(vaddr_t va, size_t sz)
{
	size_t ssz, spgs, i;
	vaddr_t sva;

	sva = (vaddr_t)kasan_addr_to_shad(va);
	ssz = (sz + KASAN_SHADOW_SCALE_SIZE - 1) / KASAN_SHADOW_SCALE_SIZE;
	sva = (sva / PAGE_SIZE) * PAGE_SIZE;
	spgs = (ssz + PAGE_SIZE - 1) / PAGE_SIZE;

printf("early start: 0x%llx\n", VA_SIGN_NEG((L4_SLOT_EARLY * NBPD_L4)));
printf("shadow start: 0x%lx\n", KASAN_SHADOW_START);
printf("shadow end: 0x%lx\n", KASAN_SHADOW_END);
printf("mapped 0x%lx to 0x%lx\n", sva, sva + ssz);
	for (i = 0; i < spgs; i++)
{
		if (kasan_enter_shad(sva + i * PAGE_SIZE, kasan_zero))
			panic("failed to create kasa page at 0x%lx", sva +
			    i * PAGE_SIZE);
//printf("mapped 0x%lx\n", sva + i * PAGE_SIZE);
}

}

paddr_t
kasan_get_early_page(void)
{
	paddr_t npa;
	size_t n = kasan_allocated_early_pages++;
	npa = (vaddr_t)&kasan_early_pages[0] + n * PAGE_SIZE;
	return npa - KERNBASE;
}

void
kasan_enter_early_shad(vaddr_t sva)
{
	uint64_t l4idx, l3idx, l2idx, l1idx;
	pd_entry_t *pd, npte;
	paddr_t npa;

	l4idx = (sva & L4_MASK) >> L4_SHIFT;
	l3idx = (sva & L3_MASK) >> L3_SHIFT;
	l2idx = (sva & L2_MASK) >> L2_SHIFT;
	l1idx = (sva & L1_MASK) >> L1_SHIFT;

	pd = (pd_entry_t *)(proc0.p_addr->u_pcb.pcb_cr3 + KERNBASE);

	npa = pd[l4idx] & PMAP_PA_MASK & PG_FRAME;
	if (!npa) {
		npa = kasan_get_early_page();
		pd[l4idx] = (npa | PG_KW | pg_nx | PG_V);
	}

	pd = (pd_entry_t *)PMAP_DIRECT_MAP(npa);
	if (pd == NULL)
		panic("%s: can't locate PDPT @ pa=0x%llx", __func__,
		    (uint64_t)npa);

	npa = pd[l3idx] & PMAP_PA_MASK & PG_FRAME;
	if (!npa) {
		npa = kasan_get_early_page();
		pd[l3idx] = (npa | PG_KW | pg_nx | PG_V);
	}

	pd = (pd_entry_t *)PMAP_DIRECT_MAP(npa);
	if (pd == NULL)
		panic("%s: can't locate PD page @ pa=0x%llx", __func__,
		    (uint64_t)npa);

	npa = pd[l2idx] & PMAP_PA_MASK & PG_FRAME;
	if (!npa) {
		npa = kasan_get_early_page();
		pd[l2idx] = (npa | PG_KW | pg_g_kern | pg_nx | PG_V);
	}

	pd = (pd_entry_t *)PMAP_DIRECT_MAP(npa);
	if (pd == NULL)
		panic("%s: can't locate PT page @ pa=0x%llx", __func__,
		    (uint64_t)npa);

	npa = kasan_get_early_page();
	npte = npa | PG_KW | pg_nx | PG_V;
	pd[l1idx] = npte;
}

/*
 * Map the stack to avoid crashing in early initialization code.
 */
void
kasan_bootstrap(void) {
	size_t i;
	vaddr_t sva;

	sva = (vaddr_t)kasan_addr_to_shad((vaddr_t)proc0.p_addr + USPACE - 16);
	sva = (sva / PAGE_SIZE) * PAGE_SIZE;

	for (i = 0; i < UPAGES; i++)
		kasan_enter_early_shad(sva + i * PAGE_SIZE);
}

vaddr_t		pmap_steal_memory(vsize_t, vaddr_t *, vaddr_t *);
/*
 * Create the shadow mapping. We don't create the 'User' area, because we
 * exclude it from the monitoring. The 'Main' area is created dynamically
 * in pmap_growkernel.
 */
void
kasan_init(void)
{
	vaddr_t zva;

	if (kasan_enabled)
		panic("KASAN already enabled");
	kasan_enabled = 1;

printf("allocing kasan_zero\n");
	zva = pmap_steal_memory(PAGE_SIZE, NULL, NULL);
	kasan_zero = PMAP_DIRECT_UNMAP(zva);
	pmap_get_physpage(zva, 1, &kasan_zero);
	__builtin_memset((char *)zva, 0xFF, PAGE_SIZE);

	/* Call the ASAN constructors. */
	kasan_ctors();
}

static void
kasan_report(vaddr_t addr, size_t size, int op, vaddr_t rip)
{
	printf("KASAN: unregistered access at 0x%lx: "
	    "%s of %lu byte%s from 0x%lx\n", rip,
	    (op ? "write" : "read"), size, (size > 1 ? "s" : ""), addr);
}

static void
kasan_shadow_fill(vaddr_t addr, size_t size, uint8_t val)
{
	char *shad;

	if (!kasan_enabled || kasan_in_init)
		return;
	if (size == 0)
		return;
	if (kasan_unsupported(addr))
		return;

	KASSERT(addr % KASAN_SHADOW_SCALE_SIZE == 0);
	KASSERT(size % KASAN_SHADOW_SCALE_SIZE == 0);

	shad = kasan_addr_to_shad(addr);
	size = size >> KASAN_SHADOW_SCALE_SHIFT;

	__builtin_memset(shad, val, size);
}

static inline void
kasan_shadow_1byte_markvalid(vaddr_t addr)
{
	char *byte = kasan_addr_to_shad(addr);
	char last = (addr & KASAN_SHADOW_MASK) + 1;

	*byte = last;
}

void
kasan_add_redzone(size_t *size)
{
	*size = roundup(*size, KASAN_SHADOW_SCALE_SIZE);
	*size += KASAN_SHADOW_SCALE_SIZE;
}

struct vm_page *pmap_find_ptp(struct pmap *, vaddr_t, paddr_t, int);

static void
kasan_markmem(vaddr_t addr, size_t size, int valid)
{
	struct vm_page *vm;
	size_t i;

	KASSERT(addr % KASAN_SHADOW_SCALE_SIZE == 0);

	// XXX: PHYS_TO_VM_PAGE might also work
	if ((vm = pmap_find_ptp(pmap_kernel(), addr, kasan_zero, 1)) == NULL) {
		//		printf("found pmap pa ptp kasan_zero thing\n");
	} else {
		//		panic("no pmap pa ptp kasan_zero thing\n");
	}

	if (valid) {
		for (i = 0; i < size; i++)
			kasan_shadow_1byte_markvalid(addr + i);
	} else {
		KASSERT(size % KASAN_SHADOW_SCALE_SIZE == 0);
		kasan_shadow_fill(addr, size, KASAN_MEMORY_REDZONE);
	}
}

void
kasan_alloc(vaddr_t addr, size_t size, size_t sz_with_redz)
{
	if (!kasan_enabled || kasan_in_init)
		return;
	if (size == 0)
		return;
	if (kasan_unsupported(addr))
		panic("malloc 0x%lx outside of VM_KERNEL_ADDRESS range", addr);
	printf("kasan_alloc 0x%lx %lu %lu\n", addr, sz_with_redz, size);
	kasan_markmem(addr, sz_with_redz, 0);
	kasan_markmem(addr, size, 1);
}

void
kasan_free(vaddr_t addr, size_t sz_with_redz)
{
	if (!kasan_enabled || kasan_in_init)
		return;
	if (sz_with_redz == 0)
		return;
	if (kasan_unsupported(addr))
		return;

	kasan_markmem(addr, sz_with_redz, 1);
}

static inline int
kasan_shadow_1byte_isvalid(vaddr_t addr)
{
	char *byte = kasan_addr_to_shad(addr);
	char last = (addr & KASAN_SHADOW_MASK) + 1;

	return (*byte == 0 || last <= *byte);
}

static inline int
kasan_shadow_2byte_isvalid(vaddr_t addr)
{
	char *byte, last;

	if (ADDR_CROSSES_SCALE_BOUNDARY(addr, 2)) {
		return (kasan_shadow_1byte_isvalid(addr) &&
		    kasan_shadow_1byte_isvalid(addr + 1));
	}

	byte = kasan_addr_to_shad(addr);
	last = ((addr + 1) & KASAN_SHADOW_MASK) + 1;

	return (*byte == 0 || last <= *byte);
}

static inline int
kasan_shadow_4byte_isvalid(vaddr_t addr)
{
	char *byte, last;

	if (ADDR_CROSSES_SCALE_BOUNDARY(addr, 4)) {
		return (kasan_shadow_2byte_isvalid(addr) &&
		    kasan_shadow_2byte_isvalid(addr + 2));
	}

	byte = kasan_addr_to_shad(addr);
	last = ((addr + 3) & KASAN_SHADOW_MASK) + 1;

	return (*byte == 0 || last <= *byte);
}

static inline int
kasan_shadow_8byte_isvalid(vaddr_t addr)
{
	int8_t *byte, last;

	if (ADDR_CROSSES_SCALE_BOUNDARY(addr, 8)) {
		return (kasan_shadow_4byte_isvalid(addr) &&
		    kasan_shadow_4byte_isvalid(addr + 4));
	}

	byte = kasan_addr_to_shad(addr);
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

static size_t valid_access = 0;
static inline void
kasan_shadow_check(vaddr_t addr, size_t size, int op, vaddr_t retaddr)
{
	int valid;

	if (!kasan_enabled || kasan_in_init)
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
		printf("%zu valid accesses\n", valid_access);
		kasan_report(addr, size, op, retaddr);
#ifdef DDB
		db_stack_dump();
		panic("Caught invalid memory access at %lx size %lu op %d",
		    addr, size, op);
#endif
	} else
		valid_access++;
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
printf("%s\n", __func__);
	size_t i;
	for (i = 0; i < size; i++) {
		kasan_register_global(&globals[i]);
	}
}

void
__asan_unregister_globals(struct __asan_global *globals, size_t size)
{
printf("%s\n", __func__);
}

#define ASAN_LOAD_STORE(size)					\
	void __asan_load##size(unsigned long);			\
	void __asan_load##size(unsigned long addr)		\
	{							\
		kasan_shadow_check(addr, size, 0, __RET_ADDR);\
	} 							\
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
printf("%s\n", __func__);
	kasan_shadow_check(addr, size, 0, __RET_ADDR);
}

void
__asan_loadN_noabort(unsigned long addr, size_t size)
{
printf("%s\n", __func__);
	kasan_shadow_check(addr, size, 0, __RET_ADDR);
}

void
__asan_storeN(unsigned long addr, size_t size)
{
printf("%s\n", __func__);
	kasan_shadow_check(addr, size, 1, __RET_ADDR);
}

void
__asan_storeN_noabort(unsigned long addr, size_t size)
{
printf("%s\n", __func__);
	kasan_shadow_check(addr, size, 1, __RET_ADDR);
}

void
__asan_handle_no_return(void)
{
printf("%s\n", __func__);
	/* nothing */
}

void
__asan_poison_stack_memory(const void *addr, size_t size)
{
printf("%s\n", __func__);
	vaddr_t va = (vaddr_t)addr;
	KASSERT(va % KASAN_SHADOW_SCALE_SIZE == 0);
	kasan_shadow_fill(va, size, KASAN_USE_AFTER_SCOPE);
}

void
__asan_unpoison_stack_memory(const void *addr, size_t size)
{
printf("%s\n", __func__);
	vaddr_t va = (vaddr_t)addr;
	KASSERT(va % KASAN_SHADOW_SCALE_SIZE == 0);
	kasan_shadow_fill(va, size, 0);
}

void
__asan_alloca_poison(unsigned long addr, size_t size)
{
printf("%s\n", __func__);
	panic("%s: impossible!", __func__);
}

void
__asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
{
printf("%s\n", __func__);
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
