#!/bin/sh
#
# Run every target and compare the result with the target's own files.
#
# usage: sh suite.sh [-n | -m] [target-dir ...]
#
# Without arguments every directory below this one that has a harness.c,
# except selftest/, is a target (the selftests have their own runner,
# selftest/run.sh).  Targets are run one after the other.
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
# complete output of every target in <dir>/<target with / as _>.log.
# The summary line is "suite: N passed, M failed, S s"; the exit status
# is non-zero if anything failed.

HERE=$(cd "$(dirname "$0")" && pwd)
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

pass=0; fail=0; start=$(date +%s)
for t in $targets; do
	T=$(cd "$HERE" && cd "$t" 2>/dev/null && pwd) || {
		echo "FAIL $t: no such target"; fail=$((fail + 1)); continue
	}
	t=${T#$HERE/}
	if [ ! -f "$T/$expfile" ]; then
		echo "FAIL $t: no $expfile"; fail=$((fail + 1)); continue
	fi
	want=$(sed -n '1{s/ *(.*//;p;}' "$T/$expfile")
	out="$tmp/out"
	if [ $engine = cbmc.sh ]; then
		to=""
		[ -f "$T/timeout" ] && to=$(sed -n 1p "$T/timeout")
		( [ -n "$to" ] && export CBMC_TIMEOUT=$to
		  exec sh "$HERE/cbmc.sh" "$T" ) > "$out" 2>&1 < /dev/null
	else
		sh "$HERE/native.sh" "$T" > "$out" 2>&1 < /dev/null
	fi
	[ -n "${SUITE_LOGDIR:-}" ] &&
	    cp "$out" "$SUITE_LOGDIR/$(echo "$t" | tr / _).log"
	got=$(sed -n '/^RESULT: /{s///;s/ (.*//;p;}' "$out" | tail -1)
	got=${got:-ERROR}	# configuration errors print no RESULT line
	info=""
	if [ $engine = cbmc.sh ]; then
		info=$(sed -n '/^PHASE check /{
			s/.* time=\([0-9]*s\).* vars=\([0-9]*\).*/ check=\1 vars=\2/p
			}' "$out" | tail -1)
		[ -n "$info" ] || info=" check=- vars=-"
	fi
	if [ "$got" = "$want" ]; then
		echo "PASS $t $got $want$info"; pass=$((pass + 1))
	else
		echo "FAIL $t $got $want$info"; fail=$((fail + 1))
		tail -15 "$out" | sed 's/^/    | /'
	fi
	# -m: every <target>/mutant*/ directory is a set of kernel files with
	# a defect put back; the target must be VIOLATED on each.
	[ -n "$mutants" ] && [ $engine = cbmc.sh ] &&
	for md in "$T"/mutant*/; do
		[ -d "$md" ] || continue
		( [ -n "$to" ] && export CBMC_TIMEOUT=$to
		  CBMC_OVERRIDE_DIR=${md%/} CBMC_NO_COVER=1 \
		    exec sh "$HERE/cbmc.sh" "$T" ) > "$out" 2>&1 < /dev/null
		got=$(sed -n '/^RESULT: /{s///;s/ (.*//;p;}' "$out" | tail -1)
		mn=$t/$(basename "$md")
		if [ "${got:-ERROR}" = VIOLATED ]; then
			echo "PASS $mn VIOLATED VIOLATED"; pass=$((pass + 1))
		else
			echo "FAIL $mn ${got:-ERROR} VIOLATED"
			fail=$((fail + 1))
		fi
	done
done
echo "suite: $pass passed, $fail failed, $(($(date +%s) - start)) s"
[ $fail -eq 0 ]
