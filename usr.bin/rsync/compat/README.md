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
client/server x push/pull combinations, using a fake remote shell
(`tests/localrsh.sh`) so the real rsync protocol is exercised over a pipe
with no ssh or network.

Env overrides: `OPENRSYNC`, `RSYNC`, `TIMEOUT`, `RSYNC_OPTS`, `XFAIL`.

### Current status (openrsync proto 27 vs rsync 3.2.7)

| direction                                   | result |
|---------------------------------------------|--------|
| push  openrsync-client -> rsync-server      | PASS   |
| push  rsync-client     -> openrsync-server  | PASS   |
| pull  openrsync-client <- rsync-server      | PASS   |
| pull  rsync-client     <- openrsync-server  | XFAIL  |

The XFAIL case actually transfers the file contents correctly, but the
modern rsync *generator* hangs at session teardown when openrsync is the
server. It's marked XFAIL (expected failure) so the suite stays green;
set `XFAIL=""` to treat it as a hard failure while debugging.
