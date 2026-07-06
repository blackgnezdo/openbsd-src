/*	$OpenBSD$	*/

#ifndef _MACHINE_KASAN_H_
#define _MACHINE_KASAN_H_

/*
 * Base of the heap shadow, one byte per 8 bytes of
 * [VM_MIN_KERNEL_ADDRESS, VM_MAX_KERNEL_ADDRESS), in its own PML4 slot.
 * Requires <machine/pmap.h>.  Keep -asan-mapping-offset in Makefile.amd64
 * in sync: it is KASAN_SHADOW_START - (VM_MIN_KERNEL_ADDRESS >> 3).
 */
#define KASAN_SHADOW_START	(VA_SIGN_NEG((L4_SLOT_KASAN * NBPD_L4)))

void	kasan_bootstrap(void);		/* called from locore0 */
void	kasan_init(void);
void	kasan_ctors(void);
void	kasan_enter_shad_multi(vaddr_t, size_t);

/* PML4 slot of the kernel image/stack shadow; shared with every pmap. */
extern int kasan_img_l4slot;

#endif /* !_MACHINE_KASAN_H_ */
