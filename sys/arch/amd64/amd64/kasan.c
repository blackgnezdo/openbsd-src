/*	$OpenBSD$	*/

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <uvm/uvm_extern.h>

#include <machine/cpu.h>
#include <machine/pmap.h>
#include <machine/segments.h>
#include <machine/vmmvar.h>

#include <sys/kasan.h>

void	kasan_enter_shad_multi(vaddr_t, size_t);

void
kasan_ctors(void)
{
	extern uint64_t __CTOR_LIST__, __CTOR_END__;
	size_t nentries, i;
	uint64_t *ptr;

	nentries = ((size_t)&__CTOR_END__ - (size_t)&__CTOR_LIST__) /
	    sizeof(uintptr_t);

	ptr = &__CTOR_LIST__;
	for (i = 0; i < nentries; i++) {
		void (*func)(void);

		func = (void *)(*ptr);
		(*func)();

		ptr++;
	}
}
