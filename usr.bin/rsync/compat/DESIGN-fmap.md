# Persistence abstraction: `struct fmap`

## Problem

The original openrsync reads local file contents for block matching by
`mmap()`ing the whole file `PROT_READ, MAP_SHARED`.  For very large files
this exhausts virtual address space (and on 32-bit / memory-constrained
hosts, fails outright).  The mapping is used purely as a *random-access,
read-only view* of an existing local file, so it can be replaced by an
abstraction backed either by `mmap()` or by ordinary `pread()` I/O.

## The interface (`fmap.h`)

```c
struct fmap;

struct fmap *fmap_open(int fd, size_t sz);          /* borrow fd, size sz>0 */
size_t       fmap_size(const struct fmap *);
const void  *fmap_data(struct fmap *, off_t offs, size_t len);
void         fmap_close(struct fmap *);             /* does NOT close fd */
```

Contract:

- `fmap_open` borrows `fd`; it neither takes ownership nor closes it.
  The caller must keep `fd` open for the lifetime of the handle and
  close it only *after* `fmap_close` (matching the existing
  munmap-then-close ordering).  `sz` must be > 0 and must equal the
  current file size.  Returns NULL (with `errno` set) on failure.
- `fmap_data` returns a pointer to a contiguous readable window covering
  `[offs, offs+len)`.  `offs+len` must be <= `fmap_size`.  The pointer is
  valid until the next `fmap_data` call on the same handle or until
  `fmap_close`; callers must consume/copy before the next call.  Returns
  NULL (errno set) on I/O failure -- e.g. the file was truncated under
  us.
- The layer does **no logging** and pulls in no rsync headers; callers
  do the `ERR()`/`ERRX()` reporting.  This keeps it unit-testable in
  isolation and cohesive (persistence != logging).

## Backends (build-time selectable)

`FMAP_IMPL` selects the implementation file:

- `fmap_mmap.c` (`FMAP_IMPL=mmap`, the default): `mmap`s the whole file;
  `fmap_data` returns `base+offs` with zero copy.  Behaviourally
  identical to the original code.
- `fmap_file.c` (`FMAP_IMPL=file`): holds a single grown-on-demand cache
  buffer and services `fmap_data` with `pread()`.  Sequential and
  overlapping small windows (the rolling-hash and token-copy patterns)
  hit the cache; a window larger than the cache grows it.  No
  whole-file allocation as long as callers keep windows bounded.

Both are strictly POSIX (`mmap`, `pread`, `fstat`) and byte-oriented, so
they are endianness- and OS-agnostic (OpenBSD + Linux).

## Caller changes

- `struct blkstat` / `struct download`: `void *map` -> `struct fmap *map`
  (sentinel `MAP_FAILED` -> `NULL`); the `mapsz` size field is retained.
- All `map + off` accesses become bounded `fmap_data()` windows.
- `blk_match()` now returns `int`: the large MD4 feeds over a match gap
  are streamed in `MAX_CHUNK` pieces through `fmap_data`, so an I/O
  error is propagated instead of crashing, and the file backend never
  buffers a whole gap.

## Testing (`compat/tests/fmap_test.c`)

Links against the selected backend only.  Verifies, for both backends:
window read-back equals source; the rolling-hash access shape
(1-byte-advancing overlapping windows incl. the `win[osz]` look-ahead
byte); a full-file streamed read; and the error path (`fmap_open` on a
bad fd returns NULL).  The truncate-under-us `fmap_data` error is
exercised on the file backend only (mmap would `SIGBUS`).
