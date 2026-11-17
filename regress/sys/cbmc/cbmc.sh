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
#   keep        functions from the files in "sources" whose real bodies
#               are analysed.  Every function defined in harness.c or in a
#               file it includes ("included") keeps its body without being
#               listed; so do inline functions defined in headers.
#   nobody      functions whose bodies are removed, wherever they are
#               defined (also in an included file or a header): they return
#               an unconstrained value and have no side effects.  A name
#               that is also in "keep" is an error.
#   opts        extra cbmc options (loop bounds), one per line
#   config      optional; "HEADER MACRO VALUE" lines, stand-ins for headers
#               config(8) generates (e.g. "ioapic.h NIOAPIC 1")
#   models      optional; further common models to link, e.g. "mbuf"
#   stubflags   optional; -D options for common/stubs_alloc.c
#   replace     optional; FUNCTION:MODEL lines, calls to FUNCTION are
#               redirected to MODEL, which the harness defines
#   fptargets   optional; CALLSITE/FUNCTION bindings for function pointer
#               calls
#   must_reach  FILE:TEXT anchors; at least one source line containing TEXT
#               must be reachable, otherwise a pass is treated as vacuous
#
# Every function not in "keep" and not defined by the harness or an included
# file loses its body.  Each cbmc run is limited to CBMC_TIMEOUT seconds (default 300) and
# to CBMC_MEMLIMIT_MB megabytes of address space (default 6000).
# If CBMC_BUDGET_FILE is set, every run is logged there and at most
# CBMC_BUDGET (default 20) runs are allowed; see README.
# Exit status: 0 verified, 1 property violated, 2 vacuous, timed out, out of
# memory or broken, 3 run budget used up.  The last line is always a RESULT
# line, except when goto-cc or goto-instrument fail.
# The work directory is removed on exit when the result is VERIFIED, unless
# CBMC_WORKDIR or CBMC_KEEP=1 is set.

set -eu
START=$(date +%s)
[ $# -eq 1 ] || { echo "usage: cbmc.sh <target-dir>"
    echo "RESULT: ERROR (usage)"; exit 2; }
NAME=$1

# Run budget: one line per run in $CBMC_BUDGET_FILE, checked before any work.
if [ -n "${CBMC_BUDGET_FILE:-}" ]; then
	BUDGET=${CBMC_BUDGET:-20}
	used=0
	[ ! -f "$CBMC_BUDGET_FILE" ] || used=$(wc -l < "$CBMC_BUDGET_FILE")
	used=$((used + 0))
	if [ "$used" -ge "$BUDGET" ]; then
		echo "RESULT: BUDGET EXHAUSTED ($used runs used)"
		exit 3
	fi
	echo "run $((used + 1)) of $BUDGET"
fi

# On exit, interrupt or kill: stop the running cbmc and log the run.
RESULT=""
CPID=""
W=""
TMPW=""
onexit() {
	rc=$?
	trap - EXIT
	if [ -n "$CPID" ]; then
		kill "$CPID" 2>/dev/null || true
		wait "$CPID" 2>/dev/null || true
	fi
	if [ -n "$TMPW" ] && [ "$RESULT" = VERIFIED ] &&
	    [ -z "${CBMC_KEEP:-}" ]; then
		rm -rf "$TMPW"
	fi
	if [ -n "${CBMC_BUDGET_FILE:-}" ]; then
		printf '%s\t%s\t%s\t%s\n' "$START" "$NAME" \
		    "${RESULT:-ERROR (no result, exit $rc)}" \
		    "$(( $(date +%s) - START ))" >> "$CBMC_BUDGET_FILE" || true
	fi
	exit $rc
}
trap onexit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# finish RESULT-TEXT EXIT-STATUS
finish() {
	RESULT=$1
	echo "RESULT: $1"
	exit $2
}

[ -d "$1" ] || finish "ERROR (no such target directory: $1)" 2
T=$(cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
SYS=$(cd "$HERE/../../../sys" && pwd)

# Check the target's configuration before doing any work.
for f in harness.c sources keep nobody opts must_reach; do
	[ -f "$T/$f" ] || finish "ERROR (missing target file: $f)" 2
done
for f in $(cat "$T/nobody"); do
	if grep -qxF -- "$f" "$T/keep"; then
		finish "ERROR ($f is in both keep and nobody: it is named in the keep file)" 2
	fi
done
while IFS= read -r anchor; do
	[ -n "$anchor" ] || continue
	file=${anchor%%:*}
	grep -qs "/$file\$" "$T/sources" "$T/included" ||
	    finish "ERROR (must_reach anchor names $file, which is in neither sources nor included)" 2
done < "$T/must_reach"

if [ -n "${CBMC_WORKDIR:-}" ]; then
	W=$CBMC_WORKDIR
else
	W=$(mktemp -d)
	TMPW=$W
fi
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
    -Dfree=kfree -I$W/inc -I$SYS -I$SYS/arch -I$SYS/dev/usb \
    -I$HERE/common"

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
# <target>/stubflags: -D options for the common models (e.g. -DMEMCPY_HAVOC).
goto-cc -c $(cat "$T/stubflags" 2>/dev/null) "$HERE/common/stubs_alloc.c" \
    -o "$W/stubs_alloc.gb"
goto-cc -c "$HERE/common/stubs_user.c" -o "$W/stubs_user.gb"
gcc -E $CPPFLAGS "$HERE/common/stubs_pool.c" -o "$W/stubs_pool.i"
goto-cc -c "$W/stubs_pool.i" -o "$W/stubs_pool.gb"
# <target>/models: further common models, one name per line (e.g. "mbuf").
extra=""
[ -f "$T/models" ] && for m in $(cat "$T/models"); do
	gcc -E $CPPFLAGS "$HERE/common/stubs_$m.c" -o "$W/stubs_$m.i"
	goto-cc -c "$W/stubs_$m.i" -o "$W/stubs_$m.gb"
	extra="$extra $W/stubs_$m.gb"
done
goto-cc $objs "$W/stubs_alloc.gb" "$W/stubs_pool.gb" "$W/stubs_user.gb" \
    $extra -o "$W/all.gb"

# Remove every body that is neither whitelisted nor part of the model.
harness_fns=$(goto-instrument --show-goto-functions "$W/harness.gb" \
    2>/dev/null | sed -n 's|^\([A-Za-z_][A-Za-z0-9_]*\) /\* .* \*/$|\1|p')
# Inline functions defined in headers (min, max, ...) keep their bodies.
header_fns=$(goto-instrument --show-goto-functions "$W/all.gb" 2>/dev/null |
    awk '/^[A-Za-z_][A-Za-z0-9_]* \/\* /{ fn = $1; seen = 0 }
	/ file [^ ]+ line /{ if (!seen) { for (i = 1; i <= NF; i++)
	    if ($i == "file" && $(i+1) ~ /\.h$/) print fn; seen = 1 } }')
keep=" $(cat "$T/keep" | tr '\n' ' ') $(echo $harness_fns) $(echo $header_fns) \
    kmalloc kfree mallocarray malloc calloc free pool_get pool_put __builtin_bcopy __builtin_memcpy __builtin_memmove memcpy memmove panic \
    copyin copyout copyinstr m_get m_clget m_free m_freem \
    __builtin_bzero explicit_bzero __builtin_bcmp __builtin_memcmp \
    timingsafe_bcmp memchr strnlen strlcpy strlcat ffs fls flsl "
# "nobody" wins over everything else: harness, header and included functions
# in it lose their bodies too.
nobody=" $(cat "$T/nobody" | tr '\n' ' ') "
args=""
for f in $(goto-instrument --show-goto-functions "$W/all.gb" 2>/dev/null |
    sed -n 's|^\([A-Za-z_][A-Za-z0-9_]*\) /\* .* \*/$|\1|p' | sort -u); do
	case "$f" in __CPROVER*) continue;; esac
	case "$nobody" in *" $f "*) args="$args --remove-function-body $f"
		continue;; esac
	case "$keep" in *" $f "*) ;; *) args="$args --remove-function-body $f";; esac
done
goto-instrument $args "$W/all.gb" "$W/sliced.gb" > /dev/null 2>&1

# Bind the bus and pipe method calls to the harness's host controller model.
# Without this CBMC tries every address-taken function of a compatible type,
# which includes driver entry points and makes some targets intractable.
# Bind calls through function pointers to the functions the harness names.
# Without this CBMC tries every address-taken function of a compatible type,
# which includes driver entry points and makes some targets intractable.
# This has to precede --replace-calls, which resolves function pointers.
args=""
[ -f "$T/fptargets" ] && for r in $(cat "$T/fptargets"); do
	args="$args --restrict-function-pointer $r"
done
goto-instrument $args "$W/sliced.gb" "$W/bound.gb" > "$W/fp.out" 2>&1 ||
    { cat "$W/fp.out" >&2; exit 2; }

# Redirect calls to a kernel function to a model defined by the harness.
args=""
[ -s "$T/replace" ] && for r in $(cat "$T/replace"); do
	args="$args --replace-calls $r"
done
goto-instrument $args "$W/bound.gb" "$W/model.gb" > "$W/replace.out" 2>&1 ||
    { cat "$W/replace.out" >&2; exit 2; }

# <target>/loops: loop contracts (invariant, decreases, assigns) in the
# JSON format of goto-instrument --loop-contracts-file.  A loop with a
# contract is checked as one arbitrary iteration instead of being unwound.
if [ -s "$T/loops" ]; then
	mv "$W/model.gb" "$W/unwound.gb"
	goto-instrument --loop-contracts-file "$T/loops" \
	    --apply-loop-contracts "$W/unwound.gb" "$W/model.gb" \
	    > "$W/loops.out" 2>&1 ||
	    { grep -v 'no body for function' "$W/loops.out" >&2; exit 2; }
fi

OPTS="$(cat "$T/opts" | tr '\n' ' ') --object-bits 12"
TMO=${CBMC_TIMEOUT:-300}
MEMMB=${CBMC_MEMLIMIT_MB:-6000}

# run_cbmc OUTFILE ARGS...: run cbmc under the time and memory limits with
# its output in OUTFILE.  It runs in the background and is waited for, so
# that a signal sent to this script reaches the trap at once.  Sets crc.
run_cbmc() {
	out=$1; shift
	(
		ulimit -v $((MEMMB * 1024)) ||
		    echo "warning: cannot set the memory limit"
		exec timeout "$TMO" cbmc "$@"
	) > "$out" 2>&1 &
	CPID=$!
	crc=0
	wait $CPID || crc=$?
	CPID=""
}

# phase NAME OUTFILE CBMC-EXIT START: print the PHASE line and, if the phase
# was slow or big, HINT lines.  Sets PSTATUS to ok, timeout, oom or error.
phase() {
	pn=$1; po=$2; pc=$3; pt=$(( $(date +%s) - $4 ))
	case $pc in
	0|10)	PSTATUS=ok;;
	124)	PSTATUS=timeout;;
	*)	if [ "$pc" -eq 137 ] || grep -qiE \
		    'bad_alloc|out of memory|memory exhausted' "$po"; then
			PSTATUS=oom
		else
			PSTATUS=error
		fi;;
	esac
	# Largest solver problem of all iterations.
	vc=$(awk '/^[0-9]+ variables, [0-9]+ clauses$/ { if ($1 + 0 > v ||
	    ($1 + 0 == v && $3 + 0 > c)) { v = $1 + 0; c = $3 + 0 } }
	    END { print v + 0, c + 0 }' "$po")
	pv=${vc% *}; pcl=${vc#* }
	sx=$(sed -n 's/^Runtime Symex: \([0-9.e+-]*\)s$/\1/p' "$po" | head -1)
	if [ -n "$sx" ]; then
		sxs=$(awk -v s="$sx" 'BEGIN { printf "%.1fs", s }')
	else
		sxs=-
	fi
	extra=""
	if [ "$pn" = check ]; then
		nf=$(sed -n 's/^\*\* \([0-9]*\) of [0-9]* failed.*/\1/p' "$po" |
		    tail -1)
		extra=" failed=${nf:--}"
	fi
	printf 'PHASE %-6s time=%ss symex=%s vars=%s clauses=%s status=%s%s\n' \
	    "$pn" "$pt" "$sxs" "$pv" "$pcl" "$PSTATUS" "$extra"
	[ "$PSTATUS" != ok ] || [ "$pv" -gt 1000000 ] || return 0
	# Symex dominates if it did not finish or took half the time or more.
	dom=$(awk -v s="$sx" -v t="$pt" \
	    'BEGIN { print (s == "" || s * 2 >= t) ? 1 : 0 }')
	if [ "$dom" -eq 1 ]; then
		top=$(awk '/^Unwinding loop /{ c[$3]++ }
		    END { for (k in c) print c[k], k }' "$po" | sort -rn |
		    head -5 | awk '{ printf "%s%s (%sx)", sep, $2, $1;
		    sep = ", " }')
		echo "HINT $pn: symbolic execution dominates (symex $sxs of ${pt}s): loop bounds are probably too large."
		echo "HINT $pn: most unwound loops: ${top:-none listed}; bound them with --unwindset ID:N in opts, or shrink the model's sizes."
	elif [ "$pv" -gt 500000 ] || [ "$PSTATUS" = oom ]; then
		echo "HINT $pn: the solver stage is the cost ($pv variables so far, symex only $sxs): usually untyped allocations (if the harness uses CBMC_NEW already, the target is simply large: split it)."
		echo "HINT $pn: allocate objects reached through tables or lists with CBMC_NEW (README, 'Adding a target', step 3); worked example sysv/shm/harness.c."
	else
		echo "HINT $pn: neither loops nor allocation sizes explain it: split the target at an internal interface (README 'assume/guarantee split'; example ipmi/transport_bt with ioctl/ipmi)."
	fi
}

# 1. Reachability: a pass means nothing if the error path was cut off.
crc=0
PSTATUS=ok
if [ -n "${CBMC_NO_COVER:-}" ]; then
	# For diagnosing slow targets only; the result is then unqualified.
	echo "reachability not checked (CBMC_NO_COVER)"
	: > "$W/cover.out"
else
t0=$(date +%s)
run_cbmc "$W/cover.out" "$W/model.gb" $OPTS --cover location --slice-formula
phase cover "$W/cover.out" $crc $t0
fi
[ "$PSTATUS" != timeout ] || finish "TIMEOUT (coverage run)" 2
[ "$PSTATUS" != oom ] || finish "OUT OF MEMORY (cover)" 2
[ $crc -eq 0 ] || [ $crc -eq 10 ] ||
    finish "ERROR (coverage run, cbmc exit $crc)" 2
# Expand "(lines FILE:FUNC:1,3-5): SATISFIED" into one "FILE LINE" per line.
sed -n 's|.*(lines \(.*\)): SATISFIED$|\1|p' "$W/cover.out" | tr ';' '\n' |
    sed 's/^ *//' |
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
t0=$(date +%s)
run_cbmc "$W/check.out" "$W/model.gb" $OPTS --pointer-check \
    --unwinding-assertions --slice-formula
rc=$crc
grep -E 'FAILURE$' "$W/check.out" | sed 's/^\[[^]]*\] //' | sort | uniq -c || true
grep -E '^\*\* [0-9]+ of|^VERIFICATION' "$W/check.out" || true
phase check "$W/check.out" $rc $t0
# Functions the check run called without a body: they returned arbitrary
# values and had no side effects.  One line, at most about 1000 bytes.
nobody_seen=$(sed -n 's/^\*\*\*\* WARNING: no body for function \(.*\)$/\1/p' \
    "$W/check.out" | sort -u | tr '\n' ' ' | sed 's/ $//')
echo "NOBODY ${nobody_seen:--}" | awk '{ if (length($0) > 1000) {
	n = 0; s = $1; for (i = 2; i <= NF; i++) { if (length(s) + length($i) > 960)
	    break; s = s " " $i } printf "%s ... (%d more)\n", s, NF - i + 1 }
	else print }'
if [ -z "$TMPW" ]; then
	echo "output in $W"
elif [ -n "${CBMC_KEEP:-}" ]; then
	echo "output in $W (kept: CBMC_KEEP)"
elif [ $vacuous -eq 0 ] && [ "$PSTATUS" = ok ] && [ $rc -eq 0 ] &&
    [ -z "${CBMC_NO_COVER:-}" ]; then
	echo "output in $W (removed on exit: VERIFIED)"
else
	echo "output in $W (kept: not VERIFIED)"
fi

[ $vacuous -eq 0 ] || finish VACUOUS 2
[ "$PSTATUS" != oom ] || finish "OUT OF MEMORY (check)" 2
case $rc in
0)	[ -z "${CBMC_NO_COVER:-}" ] ||
	    finish "UNQUALIFIED (no failures, reachability unknown)" 2
	finish VERIFIED 0;;
10)	finish VIOLATED 1;;
124)	finish TIMEOUT 2;;
*)	finish "ERROR (cbmc exit $rc)" 2;;
esac
