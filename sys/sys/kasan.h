/*	$OpenBSD$	*/

#ifndef _SYS_KASAN_H_
#define _SYS_KASAN_H_

#define KASAN_SHADOW_SCALE_SHIFT	3
#define KASAN_SHADOW_SCALE_SIZE		(1UL << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK		(KASAN_SHADOW_SCALE_SIZE - 1)

/*
 * Our poison values.  A shadow byte both blocks the access and names the
 * memory's state in the report, so freed memory is distinguishable from a
 * live object's trailing redzone (UAF vs out-of-bounds).
 */
#define KASAN_GLOBAL_REDZONE	0xFA	/* global variable trailing redzone */
#define KASAN_MALLOC_REDZONE	0xFB	/* malloc(9) live-object redzone */
#define KASAN_MALLOC_FREE	0xFC	/* malloc(9) freed object */
#define KASAN_POOL_FREE		0xFD	/* pool(9) freed/never-allocated item */
#define KASAN_KMEM_REDZONE	0xFE	/* km_alloc backing not yet carved */

/* Stack redzone shadow values. Part of the compiler ABI. */
#define KASAN_STACK_LEFT	0xF1
#define KASAN_STACK_MID		0xF2
#define KASAN_STACK_RIGHT	0xF3
#define KASAN_STACK_PARTIAL	0xF4
#define KASAN_USE_AFTER_SCOPE	0xF8

void	 kasan_add_redzone(size_t *);
void	 kasan_alloc(vaddr_t, size_t, size_t, uint8_t);
void	 kasan_free(vaddr_t, size_t, uint8_t);

/*
 * Alloc/free provenance: the allocators call these with the object base on
 * every hand-out and free, so a report can print where the object was
 * allocated and freed.
 */
void	 kasan_track_alloc(vaddr_t);
void	 kasan_track_free(vaddr_t);

/*
 * Report-time object lookups, implemented by the allocators.  Unlocked and
 * fault-safe: called between "KASAN: invalid ..." and the panic to attribute
 * the bad address to a pool item or malloc slot; a miss just omits the line.
 */
struct pool;
struct pool	*pool_kasan_lookup(vaddr_t, vaddr_t *);
int		 malloc_kasan_lookup(vaddr_t, vaddr_t *, size_t *);

/*
 * No-sleep brackets for raw process-tree / list walks.  Several kernel walks
 * follow raw struct process * links holding no reference (ktrace descend,
 * KTROP_CLEARFILE, ...) and are safe only because they run under KERNEL_LOCK
 * -- which is dropped the instant they sleep (e.g. vrele -> biowait), opening
 * a use-after-free window for a concurrent reaper on another CPU (syzbot
 * ebaa4253).  Bracketing such a walk sets P_CANTSLEEP so a sleep inside it
 * panics deterministically on ONE cpu at the offending sleep, instead of
 * waiting for the MP race to be lost at a much later poisoned read.  Toggle
 * off at runtime with kasan_walk_nosleep (ddb: w kasan_walk_nosleep 0).
 */
struct proc;
#ifdef KASAN
extern int kasan_walk_nosleep;
void	 kasan_walk_enter(struct proc *);
void	 kasan_walk_leave(struct proc *);
#else
#define	kasan_walk_enter(p)	do { } while (0)
#define	kasan_walk_leave(p)	do { } while (0)
#endif

/*
 * Reaper exit-window guard.  The single reaper kthread publishes PS_ZOMBIE and
 * then keeps using pr across a sleeping knote_processexit(); since a parent's
 * dowait6() reaps zombies WITHOUT the kernel lock it can free pr in that window
 * (syzbot a1a3c17d).  The reaper records the pr it is mid-exit on (one reaper =>
 * one slot, held OUTSIDE pr so clearing it never touches freed memory), and
 * process_zap() -- the sole free chokepoint, reached from dowait6 or the
 * reaper's own NOZOMBIE branch -- panics if asked to free that pr, naming the
 * race instead of leaving a late poisoned read.
 */
struct process;
#ifdef KASAN
extern struct process * volatile kasan_reaper_pr;
void	 kasan_reap_enter(struct process *);
void	 kasan_reap_leave(void);
void	 kasan_reap_check(struct process *);
#else
#define	kasan_reap_enter(pr)	do { } while (0)
#define	kasan_reap_leave()	do { } while (0)
#define	kasan_reap_check(pr)	do { } while (0)
#endif

#ifdef KASAN_TEST
void	 kasan_test_run(void);
#endif

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
