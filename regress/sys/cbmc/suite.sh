#!/bin/sh
#
# Run every target and compare the result with the target's own files.
#
# usage: sh suite.sh [-j N] [-n | -m] [target-dir ...]
#
# Without arguments every directory below this one that has a harness.c,
# except selftest/, is a target (the selftests have their own runner,
# selftest/run.sh).
#
# -j N runs N cbmc.sh (or native.sh) processes at a time (default 1).  Each
# target run and each mutant run is a job of its own; jobs of targets with
# a timeout file start first (they are the long ones).  The report is
# printed when all jobs are done, in the same order as with -j 1; while
# they run, one "done <name> <result>" line per job goes to stderr.  Each
# cbmc run may use CBMC_MEMLIMIT_MB (6000 by default): N times that should
# fit in memory.
#
# Files in a target directory:
#   expect         line 1: the expected RESULT word of cbmc.sh (VERIFIED,
#                  VIOLATED, VACUOUS, TIMEOUT, ...), as in selftest/expect.
#                  Further lines are ignored.  A target without it is not
#                  run and counts as a failure ("no expect").
#   timeout        optional: seconds, exported as CBMC_TIMEOUT for that
#                  target (cbmc.sh default 300).  Ignored with -n.
#   expect.native  optional: expected RESULT word of native.sh (CLEAN,
#                  FINDING, VACUOUS, ...).  With -n it is required.
#
# -n runs native.sh (default duration) instead of cbmc.sh, and only that:
# the two engines are not run together, run the suite twice to get both.
#
# -m also runs each target on every <target>/mutant*/ directory (kernel
# files with a defect put back, CBMC_OVERRIDE_DIR) and expects VIOLATED.
#
# One line per target:
#   PASS|FAIL target result expected [check=<s>s vars=<n>]
# check and vars come from the PHASE check line of cbmc.sh ("-" if the
# run stopped before it; always "-" with -n).  The last 15 lines of the
# output of a failed run follow, indented.  SUITE_LOGDIR=<dir> keeps the
# complete output of every target and mutant run in
# <dir>/<target with / as _>.log.
# The summary line is "suite: N passed, M failed, S s"; the exit status
# is non-zero if anything failed.

HERE=$(cd "$(dirname "$0")" && pwd)

# one job: run it, leave the report block in $SUITE_TMP/res.<idx>
if [ "${1:-}" = --job ]; then
	idx=$2 kind=$3 engine=$4 T=$5 t=$6 md=${7#-} want=$8 to=${9#-}
	out=$SUITE_TMP/out.$idx res=$SUITE_TMP/res.$idx
	if [ $kind = target ]; then
		name=$t
		if [ $engine = cbmc.sh ]; then
			( [ -n "$to" ] && export CBMC_TIMEOUT=$to
			  exec sh "$HERE/cbmc.sh" "$T" ) > "$out" 2>&1 < /dev/null
		else
			sh "$HERE/native.sh" "$T" > "$out" 2>&1 < /dev/null
		fi
	else
		name=$t/$(basename "$md")
		( [ -n "$to" ] && export CBMC_TIMEOUT=$to
		  CBMC_OVERRIDE_DIR=$md CBMC_NO_COVER=1 \
		    exec sh "$HERE/cbmc.sh" "$T" ) > "$out" 2>&1 < /dev/null
	fi
	[ -n "${SUITE_LOGDIR:-}" ] &&
	    cp "$out" "$SUITE_LOGDIR/$(echo "$name" | tr / _).log"
	got=$(sed -n '/^RESULT: /{s///;s/ (.*//;p;}' "$out" | tail -1)
	got=${got:-ERROR}	# configuration errors print no RESULT line
	info=""
	if [ $kind = target ] && [ $engine = cbmc.sh ]; then
		info=$(sed -n '/^PHASE check /{
			s/.* time=\([0-9]*s\).* vars=\([0-9]*\).*/ check=\1 vars=\2/p
			}' "$out" | tail -1)
		[ -n "$info" ] || info=" check=- vars=-"
	fi
	if [ "$got" = "$want" ]; then
		echo "PASS $name $got $want$info"
	else
		echo "FAIL $name $got $want$info"
		[ $kind = target ] && tail -15 "$out" | sed 's/^/    | /'
	fi > "$res.tmp"
	# the failed properties: a mutant must fail for its own reason
	[ $kind = mutant ] &&
	    grep -a 'FAILURE$' "$out" | head -5 | sed 's/^/    | /' >> "$res.tmp"
	mv "$res.tmp" "$res"
	rm -f "$out"
	echo "done $name $got" >&2
	exit 0
fi

jobs=1
if [ "${1:-}" = -j ]; then
	jobs=$2; shift 2
	case $jobs in ''|*[!0-9]*|0) echo "suite: -j needs a number" >&2; exit 2;; esac
fi
engine=cbmc.sh; expfile=expect; mutants=""
if [ "${1:-}" = -n ]; then
	engine=native.sh; expfile=expect.native; shift
elif [ "${1:-}" = -m ]; then
	mutants=1; shift
fi

if [ $# -gt 0 ]; then
	targets="$*"
else
	targets=$(cd "$HERE" && find . -name harness.c -not -path './selftest/*' |
	    sed 's|^\./||; s|/harness\.c$||' | sort)
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
[ -n "${SUITE_LOGDIR:-}" ] && mkdir -p "$SUITE_LOGDIR"
export SUITE_TMP=$tmp

# the job list, in report order: idx kind engine T t md want timeout
# (fields may not contain blanks; "-" for an empty field)
start=$(date +%s); n=0
: > "$tmp/jobs"
for t in $targets; do
	n=$((n + 1))
	T=$(cd "$HERE" && cd "$t" 2>/dev/null && pwd) || {
		echo "FAIL $t: no such target" > "$tmp/res.$n"; continue
	}
	t=${T#$HERE/}
	if [ ! -f "$T/$expfile" ]; then
		echo "FAIL $t: no $expfile" > "$tmp/res.$n"; continue
	fi
	want=$(sed -n '1{s/ *(.*//;p;}' "$T/$expfile")
	to=""
	[ $engine = cbmc.sh ] && [ -f "$T/timeout" ] &&
	    to=$(sed -n 1p "$T/timeout")
	echo "$n target $engine $T $t - $want ${to:--}" >> "$tmp/jobs"
	# -m: every <target>/mutant*/ directory is a set of kernel files with
	# a defect put back; the target must be VIOLATED on each.
	[ -n "$mutants" ] && [ $engine = cbmc.sh ] &&
	for md in "$T"/mutant*/; do
		[ -d "$md" ] || continue
		n=$((n + 1))
		echo "$n mutant $engine $T $t ${md%/} VIOLATED ${to:--}" \
		    >> "$tmp/jobs"
	done
done

# long ones (a timeout file) first; the report keeps the list's order
awk '{ print ($8 == "-" ? 0 : $8), $0 }' "$tmp/jobs" | sort -s -k1,1nr |
    cut -d' ' -f2- | xargs -L 1 -P "$jobs" sh "$HERE/$(basename "$0")" --job

pass=0; fail=0; i=0
while [ $i -lt $n ]; do
	i=$((i + 1))
	if [ ! -f "$tmp/res.$i" ]; then
		echo "FAIL job $i: no result"; fail=$((fail + 1)); continue
	fi
	cat "$tmp/res.$i"
	case $(sed -n '1s/ .*//p' "$tmp/res.$i") in
	PASS)	pass=$((pass + 1));;
	*)	fail=$((fail + 1));;
	esac
done
echo "suite: $pass passed, $fail failed, $(($(date +%s) - start)) s"
[ $fail -eq 0 ]
