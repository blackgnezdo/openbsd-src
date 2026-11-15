/*
 * Native runtime for cbmc targets: libFuzzer entry point, nondet values,
 * CBMC primitives (see shim.h), per-input reset, leak check.
 * Built with the system headers and the sanitizer of the build mode, but
 * without coverage instrumentation.  See README.native.
 *
 * Input layout: scalar values (nondet_*(), return values of functions
 * without a body) are taken from the front of the input, bulk data
 * (__CPROVER_havoc_slice: copyin data, MEMCPY_HAVOC) from the back, so a
 * long copyin does not push later scalars out of the fuzzer's reach.
 * Both streams yield zero bytes once they meet.
 */
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sanitizer/allocator_interface.h>
#include <sanitizer/common_interface_defs.h>
#if defined(NATIVE_ASAN)
#include <sanitizer/asan_interface.h>
#endif
#if defined(NATIVE_MSAN)
#include <sanitizer/msan_interface.h>
#endif

int harness_main(void);
void __native_for_each_global(void (*)(void *, size_t),
    void (*)(void *, size_t));

static const uint8_t *in_data;
static size_t in_front, in_back;
static int in_run;
static jmp_buf run_jb;
static int trace;
static unsigned long n_assume;

/* ---- nondet values ---- */

void
__native_fill(void *p, size_t n)
{
	uint8_t *d = p;
	size_t k = in_back - in_front;

	if (k > n)
		k = n;
	memcpy(d, in_data + in_front, k);
	in_front += k;
	memset(d + k, 0, n - k);
}

void
__native_havoc(void *p, unsigned long n)
{
	uint8_t *d = p;
	size_t k = in_back - in_front;

	if (k > n)
		k = n;
	/* checked like any other store into the region */
	memset(d, 0, n);
	/* the last k bytes, in order: CMP-guided mutations stay aligned */
	memcpy(d, in_data + in_back - k, k);
	in_back -= k;
}

void
__native_stub(const char *name)
{
	if (trace)
		fprintf(stderr, "native: stub %s\n", name);
}

/* ---- CBMC primitives ---- */

static const void *bad_p;
static unsigned long bad_n;

void
__native_assert_fail(const char *msg, const char *file, int line,
    const char *func)
{
	fprintf(stderr, "==NATIVE== ASSERTION FAILED: %s\n"
	    "==NATIVE==   at %s:%d in %s()\n", msg, file, line, func);
	if (bad_p != NULL || bad_n != 0) {
		fprintf(stderr, "==NATIVE==   region %p, %lu bytes\n",
		    bad_p, bad_n);
#if defined(NATIVE_ASAN)
		if (bad_p != NULL)
			__asan_describe_address((void *)bad_p);
#endif
	}
	__sanitizer_print_stack_trace();
	abort();
}

/* fptargets: the pointer called at SITE must be one of the n targets */
void
__native_fp_check(const char *site, void *fp, int n, ...)
{
	va_list ap;
	int i, ok = 0;

	va_start(ap, n);
	for (i = 0; i < n; i++)
		if (va_arg(ap, void *) == fp)
			ok = 1;
	va_end(ap);
	if (!ok) {
		fprintf(stderr, "==NATIVE== function pointer at %s (%p) is "
		    "not one of its fptargets\n", site, fp);
		__native_assert_fail("fptargets binding", site, 0, "");
	}
}

void
__native_assume_fail(void)
{
	n_assume++;
	if (trace)
		fprintf(stderr, "native: assumption false, path ends\n");
	if (in_run)
		longjmp(run_jb, 1);
	abort();
}

void
__native_noreturn(const char *name)
{
	if (trace)
		fprintf(stderr, "native: noreturn function %s without body, "
		    "path ends\n", name);
	__native_assume_fail();
}

int
__native_region_ok(const void *p, unsigned long n, int write,
    const char *func)
{
	volatile const unsigned char *c = p;

	bad_p = p;
	bad_n = n;
	if (n == 0)
		goto ok;
	if (p == NULL || (uintptr_t)p + n < (uintptr_t)p)
		return 0;
	/* no object in this process is that large */
	if (n > (1UL << 36))
		return 0;
#if defined(NATIVE_ASAN)
	if (__asan_region_is_poisoned((void *)p, n) != NULL)
		return 0;
#endif
	/* an address that is not mapped at all faults here */
	(void)c[0];
	(void)c[n - 1];
#if defined(NATIVE_MSAN)
	/*
	 * Uninitialised kernel memory must not reach user space.  Only the
	 * copyout model asks; for memcpy sources it is legitimate.
	 */
	if (!write && strcmp(func, "copyout") == 0)
		__msan_check_mem_is_initialized(p, n);
#endif
ok:
	bad_p = NULL;
	bad_n = 0;
	return 1;
}

/* __CPROVER_OBJECT_SIZE: the size of the heap object p points to */
unsigned long
__native_object_size(const void *p)
{
	if (p != NULL && __sanitizer_get_ownership(p))
		return __sanitizer_get_allocated_size(p);
	return 0;
}

/*
 * Heap content.  CBMC's malloc returns arbitrary bytes.  Here only objects
 * that harness.c allocates itself (device data, ioctl buffers, model
 * results) get their content from the input: rewrite.py puts a call to
 * __native_harness_heap after each such allocation.  Memory the kernel
 * code allocates keeps the sanitizer's content: ASan's fill pattern
 * (0xbe), or "uninitialised" under MSan, which is the point of that build.
 * Filling every allocation from the input was tried first: on short inputs
 * the kernel's buffers used up the bytes meant for later nondet values.
 * calloc goes through __native_calloc (shim.h) so that zeroed objects are
 * recognised and stay zero, as under CBMC.
 */
static void *last_zeroed;
static int zeroing;
#define MAXFILL	(1UL << 20)

void *
__native_calloc(size_t n, size_t sz)
{
	void *p;

	zeroing = 1;
	p = calloc(n, sz);
	zeroing = 0;
	return p;
}

void *
__native_allocate(unsigned long n, int zero)
{
	return zero ? __native_calloc(1, n ? n : 1) : malloc(n ? n : 1);
}

void
__native_harness_heap(void *p)
{
	uint8_t *d = p;
	size_t n, k;

	if (p == NULL || p == last_zeroed || !__sanitizer_get_ownership(p))
		return;
	n = __sanitizer_get_allocated_size(p);
	if (n > MAXFILL)
		n = MAXFILL;
	k = in_back - in_front;
	if (k > n)
		k = n;
	/* the last k bytes, in order: CMP-guided mutations stay aligned */
	memcpy(d, in_data + in_back - k, k);
	in_back -= k;
	memset(d + k, 0, n - k);
}

/* ---- heap objects allocated by one execution ---- */

#define TSIZE	(1 << 16)
static void *tab[TSIZE];
static size_t tsz[TSIZE];
static size_t tcount;
static int toverflow;
#define TOMB	((void *)1)

static size_t
slot(const void *p)
{
	return ((uintptr_t)p >> 4) * 2654435761u % TSIZE;
}

/*
 * Only the thread that runs the harness is tracked: libFuzzer's timer
 * thread allocates while an execution runs, and freeing its memory after
 * the execution was a double free (seen on udf/dirstream).
 */
static __thread int harness_thread;

static void
malloc_hook(const volatile void *p, size_t n)
{
	size_t i, k;

	if (!in_run || p == NULL || !harness_thread)
		return;
	last_zeroed = zeroing ? (void *)p : NULL;
	for (i = slot((void *)p), k = 0; k < TSIZE; k++, i = (i + 1) % TSIZE)
		if (tab[i] == NULL || tab[i] == TOMB) {
			tab[i] = (void *)p;
			tsz[i] = n;
			tcount++;
			return;
		}
	toverflow = 1;
}

static void
free_hook(const volatile void *p)
{
	size_t i, k;

	if (p == NULL || tcount == 0 || !harness_thread)
		return;
	for (i = slot((void *)p), k = 0; k < TSIZE; k++, i = (i + 1) % TSIZE) {
		if (tab[i] == NULL)
			return;
		if (tab[i] == p) {
			tab[i] = TOMB;
			tcount--;
			return;
		}
	}
}

static void
release_all(void)
{
	size_t i;

	in_run = 0;
	for (i = 0; i < TSIZE; i++) {
		void *p = tab[i];
		tab[i] = NULL;
		if (p != NULL && p != TOMB)
			free(p);
	}
	tcount = 0;
	toverflow = 0;
}

static void
leak_report(void)
{
	size_t i, shown = 0;

	fprintf(stderr, "==NATIVE== MEMORY LEAK: %zu heap object(s) "
	    "allocated by this execution are not freed when the harness "
	    "returns (cf. cbmc --memory-leak-check)\n", tcount);
	for (i = 0; i < TSIZE && shown < 3; i++)
		if (tab[i] != NULL && tab[i] != TOMB) {
			fprintf(stderr, "==NATIVE==   %p, %zu bytes\n",
			    tab[i], tsz[i]);
#if defined(NATIVE_ASAN)
			__asan_describe_address(tab[i]);
#endif
			shown++;
		}
	abort();
}

/* ---- per-input reset of kernel and harness globals ---- */

struct gsave { void *p; size_t n; void *copy; };
static struct gsave *gs;
static size_t gn, gcap;

static void
save_cb(void *p, size_t n)
{
	if (gn == gcap) {
		gcap = gcap ? 2 * gcap : 64;
		gs = realloc(gs, gcap * sizeof(*gs));
	}
	gs[gn].p = p;
	gs[gn].n = n;
	gs[gn].copy = malloc(n ? n : 1);
	memcpy(gs[gn].copy, p, n);
	gn++;
}

/*
 * Data symbols that no unit defines (extern without definition): CBMC
 * gives them arbitrary content.  rewrite.py defines them, and before each
 * execution they are filled with pseudo-random bytes derived from a hash
 * of the input (NATIVE_EXTERN_ZERO=1: zeros instead).  Taking the bytes
 * from the input itself was tried first: large objects (pools, statistics)
 * used up the whole input before the harness drew its first value.
 * Zeros were tried second: ffs/mountfs then never got past
 * "fragtbl[fs_frag] == NULL" in ffs_validate, which CBMC passes.
 */
static int extern_zero;

static void
prng_fill(uint8_t *d, size_t n, uint64_t *st)
{
	size_t i;
	uint64_t z;

	for (i = 0; i < n; i++) {
		if (i % 8 == 0) {
			z = (*st += 0x9e3779b97f4a7c15ULL);
			z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
			z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
			z ^= z >> 31;
		}
		d[i] = z >> (8 * (i % 8));
	}
}

static struct gsave *fs;
static size_t fn_, fcap;

static void
fill_cb(void *p, size_t n)
{
	if (fn_ == fcap) {
		fcap = fcap ? 2 * fcap : 16;
		fs = realloc(fs, fcap * sizeof(*fs));
	}
	fs[fn_].p = p;
	fs[fn_].n = n;
	fn_++;
}

static void
restore_globals(void)
{
	size_t i;

	for (i = 0; i < gn; i++)
		memcpy(gs[i].p, gs[i].copy, gs[i].n);
	if (fn_ > 0) {
		uint64_t h = 1469598103934665603ULL;

		for (i = 0; i < in_back; i++)
			h = (h ^ in_data[i]) * 1099511628211ULL;
		for (i = 0; i < fn_; i++) {
			if (extern_zero)
				memset(fs[i].p, 0, fs[i].n);
			else
				prng_fill(fs[i].p, fs[i].n, &h);
		}
	}
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	trace = getenv("NATIVE_TRACE") != NULL;
	extern_zero = getenv("NATIVE_EXTERN_ZERO") != NULL;
	harness_thread = 1;
	__sanitizer_install_malloc_and_free_hooks(malloc_hook, free_hook);
	__native_for_each_global(save_cb, fill_cb);
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	in_data = data;
	in_front = 0;
	in_back = size;
	restore_globals();
	in_run = 1;
	if (setjmp(run_jb) == 0) {
		harness_main();
		in_run = 0;
#if defined(NATIVE_LEAK_CHECK)
		if (tcount > 0 && !toverflow)
			leak_report();
#endif
	}
	release_all();
	return 0;
}
