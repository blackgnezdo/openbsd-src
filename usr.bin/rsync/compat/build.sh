#!/bin/sh
# Build openrsync on Linux without the OpenBSD bsd.*.mk infrastructure.
# Uses a force-included compat shim (compat/compat.h) + libbsd.
set -e
cd "$(dirname "$0")/.."

SRCS="blocks.c client.c copy.c downloader.c fargs.c flist.c hash.c ids.c \
io.c log.c main.c misc.c mkpath.c mktemp.c receiver.c rmatch.c rules.c \
sender.c server.c session.c socket.c symlinks.c uploader.c"

exec cc -O2 -w \
	-include compat/compat.h \
	-Icompat \
	-o openrsync $SRCS \
	-lcrypto -lm -lbsd
