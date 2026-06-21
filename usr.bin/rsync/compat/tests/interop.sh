#!/bin/sh
#
# interop.sh - exercise openrsync against the stock rsync (/bin/rsync).
#
# Builds a tree of source files, then runs transfers in every
# client/server x push/pull combination, diffing the result against the
# source. Uses a fake remote shell (localrsh.sh) so the real rsync wire
# protocol is exercised over a pipe with no ssh/network needed.
#
# Env overrides:
#   OPENRSYNC   path to openrsync binary  (default: ../../openrsync)
#   RSYNC       path to stock rsync       (default: /bin/rsync)
#   TIMEOUT     per-transfer timeout secs (default: 15)
#   OPTS_LIST   '|'-separated rsync option sets to sweep (default: -a|-av)
#   XFAIL       space-separated test names expected to fail (default: none)
#
# Sanitizers: if ./openrsync was built with ASan/UBSan (the default dev
# mode, see compat/build.sh), any sanitizer report fails the relevant
# test even when the transfer otherwise succeeds. openrsync runs on BOTH
# ends of every transfer, so the whole protocol exercise is instrumented.
#
set -u

here=$(cd "$(dirname "$0")" && pwd)
OPENRSYNC=${OPENRSYNC:-$here/../../openrsync}
RSYNC=${RSYNC:-/bin/rsync}
TIMEOUT=${TIMEOUT:-15}
RSH=$here/localrsh.sh

fail=0
pass=0
xfail=0
sanfail=0

# Space-separated list of test names expected to fail (known limitations).
# Empty by default: all combinations are expected to pass.
XFAIL=${XFAIL:-""}

is_xfail() {
	case " $XFAIL " in
	*" $1 "*) return 0 ;;
	esac
	return 1
}

log()  { printf '%s\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
red()  { printf '\033[31m%s\033[0m\n' "$*"; }

if [ ! -x "$OPENRSYNC" ]; then
	red "openrsync not found/executable at $OPENRSYNC (run compat/build.sh)"
	exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"; pkill -9 -P $$ 2>/dev/null' EXIT INT TERM

# Route sanitizer reports to per-process log files we can scan after each
# run, and keep the tools from killing the whole process group mid-
# protocol (which would just look like a hang). The caller's settings win.
sanlog=$work/san
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}:abort_on_error=0:halt_on_error=0:exitcode=99:log_path=$sanlog.asan"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1}:halt_on_error=0:exitcode=99:log_path=$sanlog.ubsan"
export LSAN_OPTIONS="${LSAN_OPTIONS:-exitcode=99}"

# Is ./openrsync sanitizer-instrumented? (controls report wording only)
if nm "$OPENRSYNC" 2>/dev/null | grep -q __asan_init; then
	sanitized=yes
else
	sanitized=no
fi

# Collect+clear sanitizer log files written since the last call; echo any
# content (empty if clean).
san_collect() {
	cat "$sanlog".* 2>/dev/null
	rm -f "$sanlog".* 2>/dev/null
}

src=$work/src
mkdir -p "$src/sub/deep"
printf 'hello world\n'              > "$src/a.txt"
printf 'second file\n'             > "$src/b.txt"
printf 'nested\n'                  > "$src/sub/c.txt"
printf 'deeply nested content\n'  > "$src/sub/deep/d.txt"
head -c 100000 /dev/urandom        > "$src/blob.bin"
# A multi-megabyte file so the file-backend readahead cache is refilled
# many times, and so delta transfers exercise real block matching.
head -c 3000000 /dev/urandom       > "$src/big.bin"
ln -s a.txt                          "$src/link"      2>/dev/null || true
chmod 0750                           "$src/sub"

# A "basis" tree: a copy of src with big.bin perturbed in the middle, so
# that when used to pre-seed a transfer destination it forces the sender
# through the rolling-hash matcher (insert/replace/keep) instead of a
# plain whole-file send. This is the path that hammers fmap_data().
basis=$work/basis
cp -a "$src" "$basis"
# Replace a 4 KB span ~1 MB in, and prepend 1234 bytes (shifts offsets).
dd if=/dev/urandom of="$basis/big.bin" bs=1 seek=1000000 count=4096 \
	conv=notrunc status=none
head -c 1234 /dev/urandom > "$work/_pre"
cat "$basis/big.bin" >> "$work/_pre"
mv "$work/_pre" "$basis/big.bin"

# run DIR NAME CLIENT SERVER SRC DST [SEED]
#   DIR is "push" or "pull"; CLIENT drives, SERVER via --rsync-path.
#   push: local SRC      -> localhost:DST
#   pull: localhost:SRC  -> local DST
#   SEED (optional): pre-populate DST from this dir before transferring,
#     forcing a delta (rolling-hash block-matching) transfer rather than
#     a fresh whole-file send. The final DST must still equal SRC.
run() {
	dir=$1; name=$2; client=$3; server=$4; s=$5; d=$6; seed=${7:-}
	rm -rf "$d"
	if [ -n "$seed" ]; then
		cp -a "$seed" "$d"
		# Backdate the seeded files so rsync's size+mtime quick-check
		# never short-circuits the transfer -- we want the rolling-hash
		# delta path to actually run against the (stale) basis.
		find "$d" -type f -exec touch -d '2000-01-01' {} +
	fi
	san_collect >/dev/null   # discard any stragglers from a prior run
	if [ "$dir" = pull ]; then
		from="localhost:$s"; to="$d"
	else
		from="$s"; to="localhost:$d"
	fi
	out=$(timeout "$TIMEOUT" "$client" $RSYNC_OPTS \
		--rsync-path="$server" -e "$RSH" \
		"$from" "$to" 2>&1)
	rc=$?

	# A sanitizer report may surface three ways: via the log files, via
	# the exitcode=99 we configured, or inline in stderr (the server's
	# stderr is relayed through the client).
	san=$(san_collect)
	if [ -z "$san" ]; then
		case $rc in 99) san="(sanitizer exit 99; see stderr)\n$out" ;; esac
	fi
	if [ -z "$san" ]; then
		case $out in
		*Sanitizer*|*"runtime error:"*|*"AddressSanitizer"*)
			san=$out ;;
		esac
	fi

	ok=1; detail=
	if [ -n "$san" ]; then
		ok=0; detail="sanitizer report"
	elif [ $rc -eq 124 ]; then
		ok=0; detail="timeout after ${TIMEOUT}s"
	elif [ $rc -ne 0 ]; then
		ok=0; detail="exit $rc: $(printf '%s' "$out" | head -1)"
	elif ! diff -r "${s%/}" "$d" >/dev/null 2>&1; then
		ok=0; detail="output differs from source"
	fi

	if [ $ok -eq 1 ]; then
		green "PASS   $name"; pass=$((pass+1))
	elif [ -n "$san" ]; then
		# Sanitizer findings are never silently tolerated, even for XFAILs.
		red   "SAN    $name  ($detail)"; sanfail=$((sanfail+1)); fail=$((fail+1))
		printf '%b\n' "$san" | sed 's/^/    /' | head -40
	elif is_xfail "$name"; then
		log   "XFAIL  $name  ($detail)"; xfail=$((xfail+1))
	else
		red   "FAIL   $name  ($detail)"; fail=$((fail+1))
		[ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/    /' | head
	fi
}

log "openrsync: $($OPENRSYNC --version 2>&1 | head -1)"
log "rsync:     $($RSYNC --version 2>&1 | head -1)"
log "sanitized: $sanitized"
log "timeout:   ${TIMEOUT}s"

# Option sets to sweep. Verbose mode matters because the end-of-session
# statistics exchange used to be gated on verbosity; keep both.
: "${OPTS_LIST:=-a|-av}"

OIFS=$IFS
IFS='|'
for RSYNC_OPTS in $OPTS_LIST; do
	IFS=$OIFS
	log ""
	log "==== opts: $RSYNC_OPTS ===="
	# Trailing slash on the source copies contents, not the dir itself.
	run push "push  openrsync-cli -> rsync-srv     [$RSYNC_OPTS]" "$OPENRSYNC" "$RSYNC"     "$src/" "$work/d1"
	run push "push  rsync-cli     -> openrsync-srv [$RSYNC_OPTS]" "$RSYNC"     "$OPENRSYNC" "$src/" "$work/d2"
	run pull "pull  openrsync-cli <- rsync-srv     [$RSYNC_OPTS]" "$OPENRSYNC" "$RSYNC"     "$src/" "$work/d3"
	run pull "pull  rsync-cli     <- openrsync-srv [$RSYNC_OPTS]" "$RSYNC"     "$OPENRSYNC" "$src/" "$work/d4"
	# openrsync talking to itself, to catch self-interop regressions.
	run push "push  openrsync-cli -> openrsync-srv [$RSYNC_OPTS]" "$OPENRSYNC" "$OPENRSYNC" "$src/" "$work/d5"
	run pull "pull  openrsync-cli <- openrsync-srv [$RSYNC_OPTS]" "$OPENRSYNC" "$OPENRSYNC" "$src/" "$work/d6"
	# Delta transfers: pre-seed the destination with the perturbed basis
	# so the sender runs the rolling-hash block matcher (the fmap_data
	# hot path). openrsync is exercised as sender in each.
	run push "delta openrsync-cli -> rsync-srv     [$RSYNC_OPTS]" "$OPENRSYNC" "$RSYNC"     "$src/" "$work/e1" "$basis"
	run pull "delta rsync-cli     <- openrsync-srv [$RSYNC_OPTS]" "$RSYNC"     "$OPENRSYNC" "$src/" "$work/e2" "$basis"
	run push "delta openrsync-cli -> openrsync-srv [$RSYNC_OPTS]" "$OPENRSYNC" "$OPENRSYNC" "$src/" "$work/e3" "$basis"
	IFS='|'
done
IFS=$OIFS

log ""
log "-------- $pass passed, $fail failed ($sanfail sanitizer), $xfail xfail --------"
[ $fail -eq 0 ]
