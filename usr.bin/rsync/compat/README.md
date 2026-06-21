# Linux build + interop harness for openrsync

This directory lets you build OpenBSD's `openrsync` on Linux (outside the
BSD `bsd.*.mk` make infrastructure) and test it for wire-protocol interop
against the stock `rsync` (e.g. `/bin/rsync`).

The upstream OpenBSD sources are **not modified**. Everything Linux-specific
lives here and is force-included at compile time.

## Prerequisites

```sh
sudo apt-get install -y libssl-dev libbsd-dev
```

(`libssl-dev` for `<openssl/md4.h>`, `libbsd-dev` for `strlcpy`,
`reallocarray`, `strtonum`, `getprogname`, `err(3)`, etc.)

## Build

```sh
./compat/build.sh        # produces ./openrsync
```

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
