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
#ifndef FMAP_H
#define FMAP_H

#include <sys/types.h>
#include <stddef.h>

/*
 * A read-only, random-access view over the contents of an already-open
 * local file.  This abstracts away how those bytes are obtained: either
 * by mmap(2) (fmap_mmap.c) or by ordinary pread(2) I/O (fmap_file.c),
 * selected at build time via FMAP_IMPL.  The view replaces openrsync's
 * historical habit of mmap()ing whole files, which exhausts virtual
 * address space on large transfers.
 *
 * The layer is intentionally self-contained: it performs no logging and
 * includes no other rsync headers, so it can be unit-tested in
 * isolation.  Callers are responsible for reporting errors.
 *
 * It is strictly POSIX and byte-oriented, hence portable across operating
 * systems (OpenBSD, Linux, ...) and CPU endianness.
 */
struct fmap;

/*
 * Create a view over the first sz bytes of the open descriptor fd.
 *
 * The descriptor is *borrowed*: fmap never closes it.  The caller must
 * keep fd open for the lifetime of the handle and close it only after
 * fmap_close().  sz must be > 0 and equal to the file's current size.
 *
 * Returns the handle, or NULL with errno set on failure.
 */
struct fmap	*fmap_open(int fd, size_t sz);

/*
 * Total size of the view, as passed to fmap_open().
 */
size_t		 fmap_size(const struct fmap *);

/*
 * Return a pointer to a contiguous readable window covering
 * [offs, offs+len).  offs+len must be <= fmap_size().  The returned
 * pointer is valid until the next fmap_data() call on the same handle or
 * until fmap_close(); the caller must consume or copy the bytes before
 * issuing another call.
 *
 * Returns NULL with errno set on I/O failure (for example if the file
 * was truncated underneath us).  A zero-length request returns a
 * non-NULL, non-dereferenceable pointer.
 */
const void	*fmap_data(struct fmap *, off_t offs, size_t len);

/*
 * Tear down a view created by fmap_open().  Does nothing on NULL.  Does
 * NOT close the underlying descriptor.
 */
void		 fmap_close(struct fmap *);

#endif /* FMAP_H */
