#!/bin/sh
#
# Bounded model checking of USB driver error paths with CBMC.
#
# usage: cbmc.sh <target-dir>
#
# A target directory contains:
#   harness.c   main() that drives the code under test (built with kernel
#               headers; malloc/free are renamed to kmalloc/kfree)
#   sources     kernel files to compile, relative to sys/
#   keep        functions from those files whose real bodies are analysed
#   nobody      functions whose bodies are removed: they return an
#               unconstrained value and have no side effects
#   opts        extra cbmc options (loop bounds), one per line
#   must_reach  FILE:TEXT anchors; at least one source line containing TEXT
#               must be reachable, otherwise a pass is treated as vacuous
#
# Every function not in "keep" and not defined by the harness loses its
# body.  Exit status: 0 verified, 1 property violated, 2 vacuous or broken.

set -eu
T=$(cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
SYS=$(cd "$HERE/../../../../../sys" && pwd)
W=${CBMC_WORKDIR:-$(mktemp -d)}
mkdir -p "$W/inc"

# What config(8) would provide in a kernel compile directory.
ln -sfn "$SYS/arch/amd64/include" "$W/inc/machine"
ln -sfn "$SYS/arch/amd64/include" "$W/inc/amd64"
echo '#define NBPFILTER 1' > "$W/inc/bpfilter.h"

CPPFLAGS="-nostdinc -D_KERNEL -D__OpenBSD__ -DDIAGNOSTIC -Dmalloc=kmalloc \
    -Dfree=kfree -I$W/inc -I$SYS -I$SYS/arch -I$SYS/dev/usb"

objs=""
for f in $(sed "s|^|$SYS/|" "$T/sources") "$T/harness.c"; do
	b=$(basename "$f" .c)
	gcc -E $CPPFLAGS "$f" -o "$W/$b.i"
	goto-cc -c "$W/$b.i" -o "$W/$b.gb" 2> "$W/$b.err" ||
	    { cat "$W/$b.err" >&2; exit 2; }
	objs="$objs $W/$b.gb"
done
goto-cc -c "$HERE/common/stubs_alloc.c" -o "$W/stubs_alloc.gb"
goto-cc $objs "$W/stubs_alloc.gb" -o "$W/all.gb"

# Remove every body that is neither whitelisted nor part of the model.
harness_fns=$(goto-instrument --show-goto-functions "$W/harness.gb" \
    2>/dev/null | sed -n 's|^\([A-Za-z_][A-Za-z0-9_]*\) /\* .* \*/$|\1|p')
keep=" $(cat "$T/keep" | tr '\n' ' ') $(echo $harness_fns) \
    kmalloc kfree malloc calloc free "
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
goto-instrument $args "$W/all.gb" "$W/model.gb" > /dev/null 2>&1

OPTS="$(cat "$T/opts" | tr '\n' ' ') --object-bits 12"

# 1. Reachability: a pass means nothing if the error path was cut off.
cbmc "$W/model.gb" $OPTS --cover location > "$W/cover.out" 2>&1 || true
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
	src=$(grep "/$file\$" "$T/sources" | sed "s|^|$SYS/|")
	lines=$(grep -nF -- "$text" "$src" | cut -d: -f1)
	hit=0
	for l in $lines; do
		grep -qx "$src $l" "$W/reached" && hit=1
	done
	if [ $hit -eq 0 ]; then
		echo "UNREACHED: $anchor"; vacuous=1
	fi
done < "$T/must_reach"

# 2. Memory safety.
rc=0
cbmc "$W/model.gb" $OPTS --pointer-check --unwinding-assertions \
    --slice-formula > "$W/check.out" 2>&1 || rc=$?
grep -E 'FAILURE$' "$W/check.out" | sed 's/^\[[^]]*\] //' | sort | uniq -c || true
grep -E '^\*\* [0-9]+ of|^VERIFICATION' "$W/check.out" || true
echo "output in $W"

[ $vacuous -eq 0 ] || { echo "RESULT: VACUOUS"; exit 2; }
case $rc in
0)	echo "RESULT: VERIFIED"; exit 0;;
10)	echo "RESULT: VIOLATED"; exit 1;;
*)	echo "RESULT: ERROR (cbmc exit $rc)"; exit 2;;
esac
