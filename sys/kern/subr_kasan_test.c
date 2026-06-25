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
 * The suite is driven and verified by ~/bin/kasan-negtest, which boots this
 * kernel once under the qemu gdb stub and breaks on kasan_test_caseend() to read
 * kasan_cur/kasan_test_fired/kasan_last_* and compare against each case's
 * expectation in kasan_tests[].  The same kernel also works without gdb: it
 * prints every report and MISS/false-positive line, then exits via vmkill_now().
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/pool.h>

#include <uvm/uvm_extern.h>
#include <machine/vmparam.h>

#ifdef KASAN_TEST

extern void vmkill_now(void);		/* amd64 db_interface.c; test-only */

/*
 * Result of the most recent report, written by kasan_report() (subr_kasan.c)
 * and read by the egdb harness at the kasan_test_caseend() breakpoint.
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

#define KT_MTYPE	M_DEVBUF

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

/* Heap use-after-free: free() poisons the whole freed object 0xFB, so a read
 * of any byte of it reports.  Read (not write) to avoid disturbing the freelist
 * link that lives in the freed object. */
static void
kt_heap_uaf(void)
{
	volatile char *p = malloc(64, KT_MTYPE, M_WAITOK);
	volatile int idx = 0;
	volatile char sink;

	free((void *)p, KT_MTYPE, 64);
	sink = p[idx];				/* freed body -> 0xFB read */
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

/* Pool use-after-free: pool_put() redzones a freed item's body 0xFB (keeping
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
	pool_put(&kt_pool, p);			/* redzones the item body 0xFB */
	sink = p[idx];				/* freed body -> 0xFB read */
	(void)sink;
	pool_destroy(&kt_pool);
}

/*
 * Stack redzone: overrun a 64-byte stack buffer by one byte into the
 * compiler's inline stack redzone (shadow 0xf1/0xf2/0xf3).  The volatile index
 * keeps the store opaque to -Warray-bounds and alive under -Og.  Runs on the
 * proc0 kernel stack, covered once kasan_premap_image_shadow() maps shadow out
 * to kern_end.
 */
void
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

/* Positive tests: exercise valid allocator traffic and must run to completion
 * with NO KASAN report (a report here is a false positive).  Defined in
 * uvm/uvm_init.c (malloc_test/pool_test) and below in this module
 * (kasan_poolcache_test, via init_main.c historically). */
void malloc_test(void);
void pool_test(void);
void kasan_poolcache_test(void);

#define KT_CLEAN	0	/* expect no report (positive test) */
#define KT_REPORT	1	/* expect a report (negative test) */

struct kasan_test {
	const char	*kt_name;
	int		 kt_expect;	/* KT_CLEAN or KT_REPORT */
	int		 kt_op;		/* 0 read, 1 write (KT_REPORT only) */
	uint8_t		 kt_code;	/* expected shadow code (KT_REPORT only) */
	const char	*kt_descr;	/* substring of kasan_shadow_descr() */
	void		(*kt_fn)(void);
};

static const struct kasan_test kasan_tests[] = {
	/* Positive: valid traffic, expect a clean run. */
	{ "malloc_test",    KT_CLEAN,  0, 0x00, "",               malloc_test        },
	{ "pool_test",      KT_CLEAN,  0, 0x00, "",               pool_test          },
	{ "poolcache_test", KT_CLEAN,  0, 0x00, "",               kasan_poolcache_test },
	/* Negative: one deliberate bad access each, expect the listed report. */
	{ "heap_oob_read",  KT_REPORT, 0, 0xFB, "heap redzone",    kt_heap_oob_read   },
	{ "heap_oob_write", KT_REPORT, 1, 0xFB, "heap redzone",    kt_heap_oob_write  },
	{ "heap_uaf",       KT_REPORT, 0, 0xFB, "heap redzone",    kt_heap_uaf        },
	{ "partial_gran",   KT_REPORT, 0, 0x05, "partial granule", kt_partial_granule },
	{ "width2",         KT_REPORT, 0, 0xFB, "heap redzone",    kt_width2          },
	{ "width4",         KT_REPORT, 0, 0xFB, "heap redzone",    kt_width4          },
	{ "width8",         KT_REPORT, 0, 0xFB, "heap redzone",    kt_width8          },
	{ "width16",        KT_REPORT, 0, 0xFB, "heap redzone",    kt_width16         },
	{ "pool_uaf",       KT_REPORT, 0, 0xFB, "heap redzone",    kt_pool_uaf        },
	{ "stack_redzone",  KT_REPORT, 1, 0xF1, "stack redzone",   kasan_stack_test   },
	{ "global_oob",     KT_REPORT, 1, 0xFA, "global redzone",  kt_global_oob      },
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
			    "descr=\"%s\"\n", i, t->kt_name,
			    t->kt_op ? "write" : "read", t->kt_code,
			    t->kt_descr);
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
