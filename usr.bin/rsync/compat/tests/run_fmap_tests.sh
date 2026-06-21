#!/bin/sh
#
# Build and run the fmap unit tests against BOTH backends.
# Each backend is compiled in isolation (no rsync objects, no network).
#
set -e
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
: "${CC:=cc}"
SAN="${SAN:--fsanitize=address,undefined -fno-omit-frame-pointer -g -O1}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

rc=0
for impl in mmap file; do
	defs="-DFMAP_BACKEND=\"$impl\""
	[ "$impl" = file ] && defs="$defs -DFMAP_IS_FILE"
	# shellcheck disable=SC2086
	$CC $SAN -w -I"$root" $defs \
		"$here/fmap_test.c" "$root/fmap_$impl.c" \
		-o "$tmp/fmap_test_$impl"
	echo "== fmap backend: $impl =="
	if "$tmp/fmap_test_$impl"; then
		:
	else
		rc=1
	fi
done

exit $rc
