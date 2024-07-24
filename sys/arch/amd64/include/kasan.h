/*    $OpenBSD$       */

#ifndef _MACHINE_KASAN_H_
#define _MACHINE_KASAN_H_

void	kasan_init(void);
void	kasan_ctors(void);
void	kasan_enter_shad_multi(vaddr_t, size_t);

#endif /* !_MACHINE_KASAN_H_ */
