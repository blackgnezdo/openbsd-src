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
#   RSYNC_OPTS  extra opts passed to both (default: -a)
#
set -u

here=$(cd "$(dirname "$0")" && pwd)
OPENRSYNC=${OPENRSYNC:-$here/../../openrsync}
RSYNC=${RSYNC:-/bin/rsync}
TIMEOUT=${TIMEOUT:-15}
RSYNC_OPTS=${RSYNC_OPTS:--a}
RSH=$here/localrsh.sh

fail=0
pass=0
xfail=0

# Space-separated list of test names expected to fail (known limitations).
# Override with XFAIL="" to treat them as hard failures.
XFAIL=${XFAIL:-"pull  rsync-client     <- openrsync-server"}

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

src=$work/src
mkdir -p "$src/sub/deep"
printf 'hello world\n'              > "$src/a.txt"
printf 'second file\n'             > "$src/b.txt"
printf 'nested\n'                  > "$src/sub/c.txt"
printf 'deeply nested content\n'  > "$src/sub/deep/d.txt"
head -c 100000 /dev/urandom        > "$src/blob.bin"
ln -s a.txt                          "$src/link"      2>/dev/null || true
chmod 0750                           "$src/sub"

# run DIR NAME CLIENT SERVER SRC DST
#   DIR is "push" or "pull"; CLIENT drives, SERVER via --rsync-path.
#   push: local SRC      -> localhost:DST
#   pull: localhost:SRC  -> local DST
run() {
	dir=$1; name=$2; client=$3; server=$4; s=$5; d=$6
	rm -rf "$d"
	if [ "$dir" = pull ]; then
		from="localhost:$s"; to="$d"
	else
		from="$s"; to="localhost:$d"
	fi
	out=$(timeout "$TIMEOUT" "$client" $RSYNC_OPTS \
		--rsync-path="$server" -e "$RSH" \
		"$from" "$to" 2>&1)
	rc=$?
	ok=1; detail=
	if [ $rc -eq 124 ]; then
		ok=0; detail="timeout after ${TIMEOUT}s"
	elif [ $rc -ne 0 ]; then
		ok=0; detail="exit $rc: $(printf '%s' "$out" | head -1)"
	elif ! diff -r "${s%/}" "$d" >/dev/null 2>&1; then
		ok=0; detail="output differs from source"
	fi

	if [ $ok -eq 1 ]; then
		green "PASS   $name"; pass=$((pass+1))
	elif is_xfail "$name"; then
		log   "XFAIL  $name  ($detail)"; xfail=$((xfail+1))
	else
		red   "FAIL   $name  ($detail)"; fail=$((fail+1))
		[ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/    /' | head
	fi
}

log "openrsync: $($OPENRSYNC --version 2>&1 | head -1)"
log "rsync:     $($RSYNC --version 2>&1 | head -1)"
log "opts:      $RSYNC_OPTS  (timeout ${TIMEOUT}s)"
log ""

# Note the trailing slash on $src/ to copy contents, not the dir itself.
run push "push  openrsync-client -> rsync-server"     "$OPENRSYNC" "$RSYNC"     "$src/" "$work/d1"
run push "push  rsync-client     -> openrsync-server" "$RSYNC"     "$OPENRSYNC" "$src/" "$work/d2"
run pull "pull  openrsync-client <- rsync-server"     "$OPENRSYNC" "$RSYNC"     "$src/" "$work/d3"
run pull "pull  rsync-client     <- openrsync-server" "$RSYNC"     "$OPENRSYNC" "$src/" "$work/d4"

log ""
log "-------- $pass passed, $fail failed, $xfail xfail --------"
[ $fail -eq 0 ]
