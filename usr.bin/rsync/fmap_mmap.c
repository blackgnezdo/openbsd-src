/*	$OpenBSD$ */
/*
 * Copyright (c) 2026 openrsync contributors
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * fmap backend: mmap(2).
 *
 * The whole file is mapped PROT_READ, MAP_SHARED and windows are served
 * as zero-copy pointers into the mapping.  This reproduces openrsync's
 * historical behaviour exactly; it is the reference implementation that
 * the file-I/O backend is validated against.
 */

#include <sys/types.h>
#include <sys/mman.h>

#include <errno.h>
#include <stdlib.h>

#include "fmap.h"

struct fmap {
	void	*base;	/* mmap base address */
	size_t	 sz;	/* mapping / file size */
};

struct fmap *
fmap_open(int fd, size_t sz)
{
	struct fmap	*m;

	if (sz == 0) {
		errno = EINVAL;
		return NULL;
	}
	if ((m = calloc(1, sizeof(*m))) == NULL)
		return NULL;

	m->base = mmap(NULL, sz, PROT_READ, MAP_SHARED, fd, 0);
	if (m->base == MAP_FAILED) {
		int saved = errno;
		free(m);
		errno = saved;
		return NULL;
	}
	m->sz = sz;
	return m;
}

size_t
fmap_size(const struct fmap *m)
{
	return m->sz;
}

const void *
fmap_data(struct fmap *m, off_t offs, size_t len)
{
	/*
	 * Bounds are a caller contract; guard them anyway so a logic
	 * error is a clean EINVAL rather than an out-of-bounds pointer.
	 */
	if (offs < 0 || (size_t)offs > m->sz || len > m->sz - (size_t)offs) {
		errno = EINVAL;
		return NULL;
	}
	return (const char *)m->base + offs;
}

void
fmap_close(struct fmap *m)
{
	if (m == NULL)
		return;
	munmap(m->base, m->sz);
	free(m);
}
