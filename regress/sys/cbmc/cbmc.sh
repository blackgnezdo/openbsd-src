#!/bin/sh
#
# Bounded model checking of kernel code paths with CBMC.
#
# usage: cbmc.sh <target-dir>
#
# A target directory contains:
#   harness.c   main() that drives the code under test (built with kernel
#               headers; malloc/free are renamed to kmalloc/kfree)
#   sources     kernel files to compile, relative to sys/
#   included    optional; kernel files that harness.c #includes itself (to
#               reach static functions).  Not compiled separately, but
#               usable in must_reach and subject to CBMC_OVERRIDE_DIR
#   keep        functions from those files whose real bodies are analysed
#   nobody      functions whose bodies are removed: they return an
#               unconstrained value and have no side effects
#   opts        extra cbmc options (loop bounds), one per line
#   config      optional; "HEADER MACRO VALUE" lines, stand-ins for headers
#               config(8) generates (e.g. "ioapic.h NIOAPIC 1")
#   replace     optional; FUNCTION:MODEL lines, calls to FUNCTION are
#               redirected to MODEL, which the harness defines
#   fptargets   optional; CALLSITE/FUNCTION bindings for function pointer
#               calls
#   must_reach  FILE:TEXT anchors; at least one source line containing TEXT
#               must be reachable, otherwise a pass is treated as vacuous
#
# Every function not in "keep" and not defined by the harness loses its
# body.  Each cbmc run is limited to CBMC_TIMEOUT seconds (default 300).
# Exit status: 0 verified, 1 property violated, 2 vacuous, timed out or broken.

set -eu
T=$(cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
SYS=$(cd "$HERE/../../../sys" && pwd)
W=${CBMC_WORKDIR:-$(mktemp -d)}
mkdir -p "$W/inc"

# What config(8) would provide in a kernel compile directory.
ln -sfn "$SYS/arch/amd64/include" "$W/inc/machine"
ln -sfn "$SYS/arch/amd64/include" "$W/inc/amd64"
echo '#define NBPFILTER 1' > "$W/inc/bpfilter.h"
# <target>/config: "HEADER MACRO VALUE" lines for further config(8) headers.
[ -f "$T/config" ] && while read -r h m v; do
	echo "#define $m $v" > "$W/inc/$h"
done < "$T/config"

CPPFLAGS="-nostdinc -D_KERNEL -D__OpenBSD__ -DDIAGNOSTIC -Dmalloc=kmalloc \
    -Dfree=kfree -I$W/inc -I$SYS -I$SYS/arch -I$SYS/dev/usb"

objs=""
# CBMC_OVERRIDE_DIR may hold replacement copies of kernel files (matched by
# basename), e.g. a pre-fix usbdi.c to confirm that a harness detects a bug.
resolve() {
	if [ -n "${CBMC_OVERRIDE_DIR:-}" ] &&
	    [ -f "$CBMC_OVERRIDE_DIR/$(basename "$1")" ]; then
		echo "$CBMC_OVERRIDE_DIR/$(basename "$1")"
	else
		echo "$SYS/$1"
	fi
}
# Files the harness includes are staged so that overrides apply to them.
mkdir -p "$W/included"
[ -f "$T/included" ] && while read -r s; do
	cp "$(resolve "$s")" "$W/included/$(basename "$s")"
done < "$T/included"
CPPFLAGS="$CPPFLAGS -I$W/included"

for f in $(while read -r s; do resolve "$s"; done < "$T/sources") \
    "$T/harness.c"; do
	b=$(basename "$f" .c)
	gcc -E $CPPFLAGS "$f" -o "$W/$b.i"
	goto-cc -c "$W/$b.i" -o "$W/$b.gb" 2> "$W/$b.err" ||
	    { cat "$W/$b.err" >&2; exit 2; }
	objs="$objs $W/$b.gb"
done
goto-cc -c "$HERE/common/stubs_alloc.c" -o "$W/stubs_alloc.gb"
gcc -E $CPPFLAGS "$HERE/common/stubs_pool.c" -o "$W/stubs_pool.i"
goto-cc -c "$W/stubs_pool.i" -o "$W/stubs_pool.gb"
goto-cc $objs "$W/stubs_alloc.gb" "$W/stubs_pool.gb" -o "$W/all.gb"

# Remove every body that is neither whitelisted nor part of the model.
harness_fns=$(goto-instrument --show-goto-functions "$W/harness.gb" \
    2>/dev/null | sed -n 's|^\([A-Za-z_][A-Za-z0-9_]*\) /\* .* \*/$|\1|p')
keep=" $(cat "$T/keep" | tr '\n' ' ') $(echo $harness_fns) \
    kmalloc kfree mallocarray malloc calloc free pool_get pool_put __builtin_bcopy __builtin_memcpy __builtin_memmove memcpy memmove panic "
args=""
for f in $(goto-instrument --show-goto-functions "$W/all.gb" 2>/dev/null |
    sed -n 's|^\([A-Za-z_][A-Za-z0-9_]*\) /\* .* \*/$|\1|p' | sort -u); do
	case "$f" in __CPROVER*) continue;; esac
	case "$keep" in *" $f "*) ;; *) args="$args --remove-function-body $f";; esac
done
for f in $(cat "$T/nobody"); do
	case "$keep" in *" $f "*)
		echo "$f is in both keep and nobody" >&2; exit 2;; esac
done
goto-instrument $args "$W/all.gb" "$W/sliced.gb" > /dev/null 2>&1

# Bind the bus and pipe method calls to the harness's host controller model.
# Without this CBMC tries every address-taken function of a compatible type,
# which includes driver entry points and makes some targets intractable.
# Redirect calls to a kernel function to a model defined by the harness.
if [ -s "$T/replace" ]; then
	args=""
	for r in $(cat "$T/replace"); do args="$args --replace-calls $r"; done
	goto-instrument $args "$W/sliced.gb" "$W/replaced.gb" \
	    > "$W/replace.out" 2>&1 || { cat "$W/replace.out" >&2; exit 2; }
	mv "$W/replaced.gb" "$W/sliced.gb"
fi

args=""
[ -f "$T/fptargets" ] && for r in $(cat "$T/fptargets"); do args="$args --restrict-function-pointer $r"; done
goto-instrument $args "$W/sliced.gb" "$W/model.gb" > "$W/fp.out" 2>&1 ||
    { cat "$W/fp.out" >&2; exit 2; }

OPTS="$(cat "$T/opts" | tr '\n' ' ') --object-bits 12"
TMO=${CBMC_TIMEOUT:-300}

# 1. Reachability: a pass means nothing if the error path was cut off.
crc=0
if [ -n "${CBMC_NO_COVER:-}" ]; then
	# For diagnosing slow targets only; the result is then unqualified.
	echo "reachability not checked (CBMC_NO_COVER)"
	: > "$W/cover.out"
else
timeout "$TMO" cbmc "$W/model.gb" $OPTS --cover location \
    > "$W/cover.out" 2>&1 || crc=$?
fi
[ $crc -ne 124 ] || { echo "RESULT: TIMEOUT (coverage run)"; exit 2; }
[ $crc -eq 0 ] || [ $crc -eq 10 ] ||
    { echo "RESULT: ERROR (coverage run, cbmc exit $crc)"; exit 2; }
# Expand "(lines FILE:FUNC:1,3-5): SATISFIED" into one "FILE LINE" per line.
sed -n 's|.*(lines \(.*\)): SATISFIED$|\1|p' "$W/cover.out" | tr ';' '\n' |
    awk -F: '{ n = split($NF, r, ",");
	for (i = 1; i <= n; i++) { m = split(r[i], ab, "-");
	    for (l = ab[1]; l <= ab[m]; l++) print $1, l } }' |
    sort -u > "$W/reached"
vacuous=0
while IFS= read -r anchor; do
	[ -n "$anchor" ] || continue
	file=${anchor%%:*}; text=${anchor#*:}
	if grep -qs "/$file\$" "$T/included"; then
		src="$W/included/$file"
	else
		src=$(resolve "$(grep "/$file\$" "$T/sources")")
	fi
	lines=$(grep -nF -- "$text" "$src" | cut -d: -f1)
	hit=0
	for l in $lines; do
		grep -qx "$src $l" "$W/reached" && hit=1
	done
	if [ $hit -eq 0 ]; then
		echo "UNREACHED: $anchor"; vacuous=1
	fi
done < "$T/must_reach"
[ -z "${CBMC_NO_COVER:-}" ] || vacuous=0

# 2. Memory safety.
rc=0
timeout "$TMO" cbmc "$W/model.gb" $OPTS --pointer-check \
    --unwinding-assertions \
    --slice-formula > "$W/check.out" 2>&1 || rc=$?
grep -E 'FAILURE$' "$W/check.out" | sed 's/^\[[^]]*\] //' | sort | uniq -c || true
grep -E '^\*\* [0-9]+ of|^VERIFICATION' "$W/check.out" || true
echo "output in $W"

[ $vacuous -eq 0 ] || { echo "RESULT: VACUOUS"; exit 2; }
case $rc in
0)	[ -z "${CBMC_NO_COVER:-}" ] ||
	    { echo "RESULT: UNQUALIFIED (no failures, reachability unknown)"
	      exit 2; }
	echo "RESULT: VERIFIED"; exit 0;;
10)	echo "RESULT: VIOLATED"; exit 1;;
124)	echo "RESULT: TIMEOUT"; exit 2;;
*)	echo "RESULT: ERROR (cbmc exit $rc)"; exit 2;;
esac
