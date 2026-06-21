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
 * fmap backend: ordinary file I/O (pread(2)).
 *
 * Instead of mapping the whole file, a single window cache buffer is
 * kept and refilled with pread() on demand.  The buffer is grown only
 * to the largest window a caller actually requests, so memory use is
 * bounded by the rsync block/chunk size rather than the file size --
 * which is the entire point of this exercise.
 *
 * A readahead margin makes the rolling-hash access pattern (overlapping
 * windows that advance one byte at a time) cheap: a refill pulls in
 * extra trailing bytes so the following windows are served from cache.
 *
 * Strictly POSIX and byte-oriented: portable across OS and endianness.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fmap.h"

/*
 * Extra bytes to pull in beyond the requested window on a cache miss, to
 * amortise the rolling-hash one-byte-advance pattern.  Purely a
 * performance knob; correctness is independent of its value.
 */
#define FMAP_READAHEAD	(128 * 1024)

struct fmap {
	int		 fd;	/* borrowed descriptor */
	size_t		 sz;	/* total file size */
	unsigned char	*buf;	/* window cache */
	size_t		 bufcap;/* allocated size of buf */
	off_t		 cacheoff;/* file offset of buf[0] */
	size_t		 cachelen;/* valid bytes in buf */
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
	m->fd = fd;
	m->sz = sz;
	m->cacheoff = 0;
	m->cachelen = 0;
	return m;
}

size_t
fmap_size(const struct fmap *m)
{
	return m->sz;
}

/*
 * Ensure buf can hold at least n bytes, growing as needed.
 * Returns 0 on success, -1 on allocation failure (errno set).
 */
static int
fmap_ensure(struct fmap *m, size_t n)
{
	unsigned char	*nb;

	if (n <= m->bufcap)
		return 0;
	if ((nb = realloc(m->buf, n)) == NULL)
		return -1;
	m->buf = nb;
	m->bufcap = n;
	return 0;
}

/*
 * pread() exactly n bytes at file offset off into dst, looping over
 * short reads.  A premature EOF is reported as EIO (the file was
 * truncated underneath us).  Returns 0 on success, -1 on failure.
 */
static int
fmap_pread_full(struct fmap *m, unsigned char *dst, size_t n, off_t off)
{
	while (n > 0) {
		ssize_t r = pread(m->fd, dst, n, off);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (r == 0) {
			errno = EIO;
			return -1;
		}
		dst += r;
		off += (off_t)r;
		n -= (size_t)r;
	}
	return 0;
}

const void *
fmap_data(struct fmap *m, off_t offs, size_t len)
{
	size_t	 fill;
	off_t	 avail;

	if (offs < 0 || (size_t)offs > m->sz || len > m->sz - (size_t)offs) {
		errno = EINVAL;
		return NULL;
	}
	if (len == 0)
		return m->buf != NULL ? m->buf : (const void *)m;

	/* Cache hit: window fully contained in the current buffer. */
	if (m->cachelen > 0 &&
	    offs >= m->cacheoff &&
	    (size_t)(offs - m->cacheoff) + len <= m->cachelen)
		return m->buf + (offs - m->cacheoff);

	/* Miss: refill from offs, pulling in a readahead margin. */
	fill = len;
	avail = (off_t)m->sz - offs;
	if ((off_t)fill < avail) {
		size_t want = len > FMAP_READAHEAD ? len : FMAP_READAHEAD;
		fill = (off_t)want <= avail ? want : (size_t)avail;
	}

	if (fmap_ensure(m, fill) == -1)
		return NULL;
	if (fmap_pread_full(m, m->buf, fill, offs) == -1) {
		m->cachelen = 0;	/* invalidate */
		return NULL;
	}
	m->cacheoff = offs;
	m->cachelen = fill;
	return m->buf;
}

void
fmap_close(struct fmap *m)
{
	if (m == NULL)
		return;
	free(m->buf);
	free(m);
}
