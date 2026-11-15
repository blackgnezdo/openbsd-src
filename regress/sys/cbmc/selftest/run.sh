#!/bin/sh
#
# Self-test of the cbmc harness and its common models.
#
# usage: sh run.sh [test ...]
#
# Every directory here with an "expect" file is a target run through
# ../cbmc.sh.  expect: line 1 is the RESULT word; each further line is a
# substring that must occur in the failure lines cbmc.sh prints; a line
# starting with "!" is a substring that must not occur.  For ERROR (cbmc.sh
# stopped without a RESULT line, or printed RESULT: ERROR) they are matched
# against the whole output.  An optional
# file "env" is sourced (sh syntax, $T is the test directory) before the
# run, e.g. to set CBMC_OVERRIDE_DIR.  SELFTEST_KEEP=1 keeps the work
# directories.  Exit status is non-zero if any test failed.

HERE=$(cd "$(dirname "$0")" && pwd)
export CBMC_TIMEOUT=60
tmp=$(mktemp -d)
[ -n "${SELFTEST_KEEP:-}" ] || trap 'rm -rf "$tmp"' EXIT

if [ $# -gt 0 ]; then
	tests="$*"
else
	tests=$(cd "$HERE" && for e in */expect; do dirname "$e"; done)
fi

pass=0; fail=0; start=$(date +%s)
for t in $tests; do
	T="$HERE/$t"
	if [ ! -f "$T/expect" ]; then
		echo "FAIL $t: no such test"; fail=$((fail + 1)); continue
	fi
	out="$tmp/$t.out"
	( [ -f "$T/env" ] && . "$T/env"
	  CBMC_WORKDIR="$tmp/$t.w" sh "$HERE/../cbmc.sh" "$T" ) \
	    > "$out" 2>&1 < /dev/null
	got=$(sed -n 's/^RESULT: \([A-Z]*\).*/\1/p' "$out" | tail -1)
	got=${got:-ERROR}	# configuration errors print no RESULT line
	want=$(sed -n 1p "$T/expect")
	if [ "$want" = ERROR ]; then
		cp "$out" "$tmp/$t.fail"	# match against the whole output
	else
		grep 'FAILURE$' "$out" > "$tmp/$t.fail"
	fi
	why=""
	if [ "$got" != "$want" ]; then
		why="result ${got:-none}, expected $want"
	else
		while IFS= read -r line; do
			case "$line" in
			"") ;;
			!*)	s=${line#!}
				if grep -qF -- "$s" "$tmp/$t.fail"; then
					why="unexpected failure: $s"; break
				fi;;
			*)	if ! grep -qF -- "$line" "$tmp/$t.fail"; then
					why="missing failure: $line"; break
				fi;;
			esac
		done <<EOT
$(sed 1d "$T/expect")
EOT
	fi
	if [ -z "$why" ]; then
		echo "PASS $t"; pass=$((pass + 1))
	else
		echo "FAIL $t: $why"; fail=$((fail + 1))
		sed 's/^/    | /' "$out" | tail -15
	fi
done
echo "selftest: $pass passed, $fail failed, $(($(date +%s) - start)) s"
[ $fail -eq 0 ]
