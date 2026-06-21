# Linux build + interop harness for openrsync

This directory lets you build OpenBSD's `openrsync` on Linux (outside the
BSD `bsd.*.mk` make infrastructure) and test it for wire-protocol interop
against the stock `rsync` (e.g. `/bin/rsync`).

No Linux-specific changes are made to the upstream `.c`/`.h` sources:
everything Linux-specific lives here and is force-included at compile
time. The only changes to the sources themselves are genuine,
platform-independent openrsync bug fixes, kept as standalone diffs in
`patches/` for upstreaming.

**AddressSanitizer is the default build/dev mode.** `./openrsync` is
built with ASan + UBSan and is what the interop harness drives on *both*
ends of every transfer, so the whole protocol exercise runs instrumented.

## Prerequisites

```sh
sudo apt-get install -y libssl-dev libbsd-dev
```

(`libssl-dev` for `<openssl/md4.h>`, `libbsd-dev` for `strlcpy`,
`reallocarray`, `strtonum`, `getprogname`, `err(3)`, etc.)

## Build

```sh
./compat/build.sh            # default: ASan + UBSan, -g -O1
./compat/build.sh release    # optimised, no sanitizer, -O2
```

Both produce `./openrsync`. Env overrides: `CC`, `OUT` (output name),
`EXTRA_CFLAGS`, `EXTRA_LDFLAGS`. The `msan` mode exists but needs an
MSan-instrumented libc/libbsd/libcrypto and is rarely usable as-is.

What the shim provides (`compat/compat.h`, force-included via `cc -include`):

- `S_ISTXT`            -> `S_ISVTX`
- `recallocarray`      -> local zeroing-realloc implementation
- `scan_scaled`        -> local size-suffix parser (OpenBSD libutil only)
- `pledge` / `unveil`  -> no-ops
- `<sys/sysmacros.h>`  for `major`/`minor`
- `compat/util.h`      -> empty stub for `#include <util.h>`

## Interop tests

```sh
./compat/tests/interop.sh
```

It builds a small source tree and transfers it in all four
client/server x push/pull combinations (plus openrsync<->openrsync), for
each option set in `OPTS_LIST`, using a fake remote shell
(`tests/localrsh.sh`) so the real rsync protocol is exercised over a pipe
with no ssh or network.

Env overrides: `OPENRSYNC`, `RSYNC`, `TIMEOUT`, `OPTS_LIST`, `XFAIL`.

The harness is sanitizer-aware: when `./openrsync` is ASan/UBSan-built
(the `sanitized: yes` banner line), any sanitizer report fails the
relevant test even if the transfer otherwise succeeds — reports are
picked up both from the per-process log files and from the server's
stderr (relayed back through the client). A finding is reported as
`SAN <name>` with the backtrace, and is never tolerated, not even for an
`XFAIL`. Sanitizer behaviour can be tuned via the usual `ASAN_OPTIONS` /
`UBSAN_OPTIONS` (the harness only appends `log_path`, `exitcode`, and
non-aborting defaults).

### Current status (openrsync proto 27 vs rsync 3.2.7)

All combinations pass, in both quiet (`-a`) and verbose (`-av`) mode:

| direction                                   | result |
|---------------------------------------------|--------|
| push  openrsync-client -> rsync-server      | PASS   |
| push  rsync-client     -> openrsync-server  | PASS   |
| pull  openrsync-client <- rsync-server      | PASS   |
| pull  rsync-client     <- openrsync-server  | PASS   |
| push/pull openrsync <-> openrsync           | PASS   |

Two upstream openrsync bugs were needed to make the last interop
direction (rsync client pulling from an openrsync server) work; see
`patches/` for standalone, upstreamable diffs.
