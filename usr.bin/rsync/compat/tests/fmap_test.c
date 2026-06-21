/*
 * Unit tests for the fmap persistence layer (fmap.h).
 *
 * Compiled once per backend (mmap / file) and linked only against that
 * backend, so each implementation is validated in isolation -- no rsync
 * protocol, no network.  Run by compat/tests/run_fmap_tests.sh.
 *
 * The backend under test is named by -DFMAP_BACKEND="..."; FMAP_IS_FILE
 * is defined for the pread() backend so we can exercise backend-specific
 * error paths (mmap would SIGBUS on a truncate-under-us, so that case is
 * file-only; a bad fd faults at fmap_open() only for mmap).
 */
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fmap.h"

#ifndef FMAP_BACKEND
#define FMAP_BACKEND "unknown"
#endif

static int failures;
static int checks;

#define CHECK(cond, msg) do {					\
	checks++;						\
	if (!(cond)) {						\
		failures++;					\
		fprintf(stderr, "  FAIL [%s] %s:%d: %s\n",	\
		    FMAP_BACKEND, __func__, __LINE__, msg);	\
	}							\
} while (0)

/* Build a temp file with deterministic, position-dependent content. */
static int
make_file(unsigned char **out, size_t sz)
{
	char		tmpl[] = "/tmp/fmap_test.XXXXXX";
	unsigned char	*data;
	int		 fd;
	size_t		 i;

	if ((fd = mkstemp(tmpl)) == -1) {
		perror("mkstemp");
		exit(2);
	}
	unlink(tmpl);		/* keep fd, drop the name */
	if ((data = malloc(sz)) == NULL) {
		perror("malloc");
		exit(2);
	}
	for (i = 0; i < sz; i++)
		data[i] = (unsigned char)((i * 31 + (i >> 8) * 7 + 11) & 0xff);
	if (pwrite(fd, data, sz, 0) != (ssize_t)sz) {
		perror("pwrite");
		exit(2);
	}
	*out = data;
	return fd;
}

/* Window read-back at assorted offsets/lengths equals the source. */
static void
test_windows(void)
{
	const size_t	 sz = 1000000;	/* > readahead, forces refills */
	unsigned char	*data;
	int		 fd = make_file(&data, sz);
	struct fmap	*m = fmap_open(fd, sz);
	size_t		 offs, len;

	CHECK(m != NULL, "fmap_open");
	if (m == NULL) { close(fd); free(data); return; }
	CHECK(fmap_size(m) == sz, "fmap_size");

	size_t cases[][2] = {
		{0, 1}, {0, 100}, {1, 100}, {500, 1024},
		{sz - 1, 1}, {sz - 1000, 1000}, {sz - 1, 0},
		{123456, 200000}, {0, sz},
	};
	for (size_t k = 0; k < sizeof(cases)/sizeof(cases[0]); k++) {
		const void *p;
		offs = cases[k][0];
		len = cases[k][1];
		p = fmap_data(m, (off_t)offs, len);
		CHECK(p != NULL, "fmap_data window");
		if (p != NULL && len > 0)
			CHECK(memcmp(p, data + offs, len) == 0,
			    "window content");
	}

	fmap_close(m);
	close(fd);
	free(data);
}

/*
 * The rolling-hash shape: a window of fixed block length that advances
 * one byte at a time, plus the single look-ahead byte win[osz] that
 * blocks.c reads.  This is the access pattern most likely to expose a
 * cache bug in the file backend.
 */
static void
test_rolling(void)
{
	const size_t	 sz = 300000;
	const size_t	 blk = 700;
	unsigned char	*data;
	int		 fd = make_file(&data, sz);
	struct fmap	*m = fmap_open(fd, sz);
	size_t		 offs;

	CHECK(m != NULL, "fmap_open");
	if (m == NULL) { close(fd); free(data); return; }

	for (offs = 0; offs + blk < sz; offs++) {
		const unsigned char *w = fmap_data(m, (off_t)offs, blk + 1);
		if (w == NULL) { CHECK(0, "rolling window"); break; }
		/* spot-check first, middle, last, and look-ahead bytes */
		if (w[0] != data[offs] ||
		    w[blk / 2] != data[offs + blk / 2] ||
		    w[blk - 1] != data[offs + blk - 1] ||
		    w[blk] != data[offs + blk]) {
			CHECK(0, "rolling content");
			break;
		}
		offs += 137;	/* sample, but keep overlap exercised */
	}

	fmap_close(m);
	close(fd);
	free(data);
}

/* A whole-file streamed read in MAX_CHUNK-sized pieces. */
static void
test_stream(void)
{
	const size_t	 sz = 500000;
	const size_t	 chunk = 32 * 1024;
	unsigned char	*data;
	int		 fd = make_file(&data, sz);
	struct fmap	*m = fmap_open(fd, sz);
	off_t		 off;

	CHECK(m != NULL, "fmap_open");
	if (m == NULL) { close(fd); free(data); return; }

	for (off = 0; (size_t)off < sz; ) {
		size_t n = sz - (size_t)off < chunk ? sz - (size_t)off : chunk;
		const void *p = fmap_data(m, off, n);
		CHECK(p != NULL, "stream chunk");
		if (p == NULL) break;
		CHECK(memcmp(p, data + off, n) == 0, "stream content");
		off += (off_t)n;
	}

	fmap_close(m);
	close(fd);
	free(data);
}

/* fmap_open with sz==0 must fail with EINVAL on either backend. */
static void
test_open_zero(void)
{
	unsigned char	*data;
	int		 fd = make_file(&data, 16);
	struct fmap	*m;

	errno = 0;
	m = fmap_open(fd, 0);
	CHECK(m == NULL, "fmap_open(sz=0) returns NULL");
	CHECK(errno == EINVAL, "fmap_open(sz=0) sets EINVAL");
	close(fd);
	free(data);
}

/* Backend-specific error injection. */
static void
test_errors(void)
{
#ifdef FMAP_IS_FILE
	/*
	 * File backend: truncate the file under us, then ask for a window
	 * past the new end.  pread() hits premature EOF -> EIO -> NULL.
	 */
	const size_t	 sz = 200000;
	unsigned char	*data;
	int		 fd = make_file(&data, sz);
	struct fmap	*m = fmap_open(fd, sz);
	const void	*p;

	CHECK(m != NULL, "fmap_open");
	if (m != NULL) {
		if (ftruncate(fd, 0) == -1)
			perror("ftruncate");
		errno = 0;
		p = fmap_data(m, (off_t)sz - 100, 100);
		CHECK(p == NULL, "fmap_data after truncate returns NULL");
		fmap_close(m);
	}
	close(fd);
	free(data);
#else
	/*
	 * mmap backend: mapping a bad descriptor fails at fmap_open().
	 */
	struct fmap	*m;
	errno = 0;
	m = fmap_open(-1, 4096);
	CHECK(m == NULL, "fmap_open(bad fd) returns NULL");
#endif
}

int
main(void)
{
	printf("fmap backend: %s\n", FMAP_BACKEND);
	test_windows();
	test_rolling();
	test_stream();
	test_open_zero();
	test_errors();
	printf("  %d checks, %d failures\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
