/*	$OpenBSD$	*/

#ifndef _SYS_KASAN_H_
#define _SYS_KASAN_H_

#define KASAN_SHADOW_SCALE_SHIFT	3
#define KASAN_SHADOW_SCALE_SIZE		(1UL << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK		(KASAN_SHADOW_SCALE_SIZE - 1)

#define KASAN_SHADOW_START	(VA_SIGN_NEG((L4_SLOT_KASAN * NBPD_L4)))

/* Our redzone values. */
#define KASAN_GLOBAL_REDZONE	0xFA
#define KASAN_MEMORY_REDZONE	0xFB

/* Stack redzone shadow values. Part of the compiler ABI. */
#define KASAN_STACK_LEFT	0xF1
#define KASAN_STACK_MID		0xF2
#define KASAN_STACK_RIGHT	0xF3
#define KASAN_STACK_PARTIAL	0xF4
#define KASAN_USE_AFTER_SCOPE	0xF8

extern int kasan_in_init;

void	 kasan_add_redzone(size_t *);
void	 kasan_alloc(vaddr_t, size_t, size_t);
void	 kasan_free(vaddr_t, size_t);

struct __asan_global;

void __asan_register_globals(struct __asan_global *, size_t);
void __asan_unregister_globals(struct __asan_global *, size_t);

void __asan_loadN(unsigned long, size_t);
void __asan_loadN_noabort(unsigned long, size_t);
void __asan_storeN(unsigned long, size_t);
void __asan_storeN_noabort(unsigned long, size_t);
void __asan_handle_no_return(void);
void __asan_poison_stack_memory(const void *, size_t);
void __asan_unpoison_stack_memory(const void *, size_t);
void __asan_alloca_poison(unsigned long, size_t);
void __asan_allocas_unpoison(const void *, const void *);

#if defined(__clang__) && (__clang_major__ - 0 >= 6)
#define ASAN_ABI_VERSION	8
#elif __GNUC_PREREQ__(7, 1) && !defined(__clang__)
#define ASAN_ABI_VERSION	8
#elif __GNUC_PREREQ__(6, 1) && !defined(__clang__)
#define ASAN_ABI_VERSION	6
#else
#error "Unsupported compiler version"
#endif

/*
 * Part of the compiler ABI.
 */
struct __asan_global_source_location {
	const char *filename;
	int line_no;
	int column_no;
};
struct __asan_global {
	const void *beg;		/* address of the global variable */
	size_t size;			/* size of the global variable */
	size_t size_with_redzone;	/* size with the redzone */
	const void *name;		/* name of the variable */
	const void *module_name;	/* name of the module where the var is declared */
	unsigned long has_dynamic_init;	/* the var has dyn initializer (c++) */
	struct __asan_global_source_location *location;
#if ASAN_ABI_VERSION >= 7
	uintptr_t odr_indicator;	/* the address of the ODR indicator symbol */
#endif
};

#endif /* !_SYS_KASAN_H_ */
