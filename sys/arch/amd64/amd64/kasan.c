/*	$OpenBSD$	*/

#include <sys/param.h>
#include <sys/systm.h>

#include <machine/kasan.h>

/*
 * Run the module constructors the compiler emitted for asan-instrumented
 * globals (__asan_register_globals calls).  The kernel has no csu, so
 * nothing else walks .ctors/.init_array; kasan_init() calls this once the
 * global redzones have somewhere to live.
 */
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
