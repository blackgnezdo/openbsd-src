#!/bin/sh
#
# Build openrsync on Linux without the OpenBSD bsd.*.mk infrastructure.
# Uses a force-included compat shim (compat/compat.h) + libbsd.
#
# Usage:  build.sh [MODE]
#   MODE = asan   (default) AddressSanitizer + UBSan, -g -O1  -> ./openrsync
#          msan            MemorySanitizer (needs instrumented libs; rarely usable)
#          release         optimised, no sanitizer, -O2     -> ./openrsync
#
# Env overrides:  CC, OUT (output binary name), EXTRA_CFLAGS, EXTRA_LDFLAGS.
#
# ASan is our primary development mode: the resulting ./openrsync is what
# the interop harness drives (on BOTH ends of every transfer), so the
# whole protocol exercise runs instrumented.
#
set -e
cd "$(dirname "$0")/.."

SRCS="blocks.c client.c copy.c downloader.c fargs.c flist.c hash.c ids.c \
io.c log.c main.c misc.c mkpath.c mktemp.c receiver.c rmatch.c rules.c \
sender.c server.c session.c socket.c symlinks.c uploader.c"

: "${CC:=cc}"
: "${OUT:=openrsync}"
MODE="${1:-${MODE:-asan}}"

# Persistence backend selection (mirrors the Makefile's FMAP_IMPL):
#   mmap (default) -> fmap_mmap.c     file -> fmap_file.c
: "${FMAP_IMPL:=mmap}"
case "$FMAP_IMPL" in
mmap|file) SRCS="$SRCS fmap_$FMAP_IMPL.c" ;;
*) echo "build.sh: unknown FMAP_IMPL '$FMAP_IMPL' (mmap|file)" >&2; exit 2 ;;
esac

case "$MODE" in
asan)
	# -fno-common catches duplicate definitions; -fno-omit-frame-pointer
	# + -g give readable ASan backtraces.
	SAN="-fsanitize=address,undefined -fno-omit-frame-pointer \
-fno-sanitize-recover=undefined -g -O1"
	;;
msan)
	SAN="-fsanitize=memory -fno-omit-frame-pointer -g -O1"
	;;
release|none)
	SAN="-O2"
	;;
*)
	echo "build.sh: unknown mode '$MODE' (asan|msan|release)" >&2
	exit 2
	;;
esac

echo "building $OUT [mode=$MODE fmap=$FMAP_IMPL]" >&2
exec $CC -w $SAN ${EXTRA_CFLAGS:-} \
	-include compat/compat.h \
	-Icompat \
	-o "$OUT" $SRCS \
	${EXTRA_LDFLAGS:-} \
	-lcrypto -lm -lbsd
