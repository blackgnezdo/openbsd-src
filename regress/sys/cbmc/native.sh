#!/bin/sh
#
# Run a cbmc target natively: the same harness, kernel files and common
# models, compiled with clang, sanitizers and libFuzzer.  Every nondet_*()
# value and every result of a function without a body comes from the
# fuzzer's input.  See native/README.native.
#
# usage: native.sh <target-dir> [seconds]
#
# Environment:
#   NATIVE_SAN=asan|msan  sanitizer build (default asan: ASan+UBSan;
#                         msan: MemorySanitizer, copyout checks that the
#                         kernel buffer is initialised)
#   NATIVE_SEED           libFuzzer seed (default 1)
#   NATIVE_WORKDIR        build directory (default: mktemp -d)
#   NATIVE_TRACE=1        log stub calls and path ends while running
#   NATIVE_FUZZ_OPTS      further libFuzzer options (e.g. -max_len=16384)
#
# Like cbmc.sh, a clean run whose coverage misses a must_reach anchor is
# RESULT: VACUOUS.
#   CBMC_OVERRIDE_DIR     replacement copies of kernel files, by basename
#
# Prints RESULT: CLEAN (N execs, M s), RESULT: FINDING (the report is
# above it, reproduced in a fresh process) or RESULT: ERROR.
# Exit status: 0 clean, 1 finding, 2 error.

set -eu
T=$(cd "$1" && pwd)
SECS=${2:-20}
HERE=$(cd "$(dirname "$0")" && pwd)
N="$HERE/native"
SYS=$(cd "$HERE/../../../sys" && pwd)
W=${NATIVE_WORKDIR:-$(mktemp -d)}
SAN=${NATIVE_SAN:-asan}
mkdir -p "$W/inc"

fail() { echo "$*" >&2; echo "output in $W"; echo "RESULT: ERROR"; exit 2; }

# What config(8) would provide in a kernel compile directory (as cbmc.sh).
ln -sfn "$SYS/arch/amd64/include" "$W/inc/machine"
ln -sfn "$SYS/arch/amd64/include" "$W/inc/amd64"
echo '#define NBPFILTER 1' > "$W/inc/bpfilter.h"
[ -f "$T/config" ] && while read -r h m v; do
	echo "#define $m $v" > "$W/inc/$h"
done < "$T/config"

# Configuration checks of cbmc.sh.
for f in harness.c sources keep nobody opts must_reach; do
	[ -f "$T/$f" ] || fail "missing target file: $f"
done
for f in $(cat "$T/nobody"); do
	grep -qxF -- "$f" "$T/keep" &&
	    fail "$f is in both keep and nobody: it is named in the keep file"
done

# Same preprocessing as cbmc.sh (gcc -E), plus the CBMC primitive shim.
CPPFLAGS="-nostdinc -D_KERNEL -D__OpenBSD__ -DDIAGNOSTIC -Dmalloc=kmalloc \
    -Dfree=kfree -I$W/inc -I$SYS -I$SYS/arch -I$SYS/dev/usb \
    -I$HERE/common"
SHIM="-include $N/shim.h"

resolve() {
	if [ -n "${CBMC_OVERRIDE_DIR:-}" ] &&
	    [ -f "$CBMC_OVERRIDE_DIR/$(basename "$1")" ]; then
		echo "$CBMC_OVERRIDE_DIR/$(basename "$1")"
	else
		echo "$SYS/$1"
	fi
}
mkdir -p "$W/included"
[ -f "$T/included" ] && while read -r s; do
	cp "$(resolve "$s")" "$W/included/$(basename "$s")"
done < "$T/included"
CPPFLAGS="$CPPFLAGS -I$W/included"

case $SAN in
asan)	SANFLAGS="-fsanitize=address,undefined \
	    -fno-sanitize=alignment,function,pointer-overflow \
	    -fno-sanitize-recover=all"
	RTFLAGS="-DNATIVE_ASAN";;
msan)	SANFLAGS="-fsanitize=memory -fsanitize-memory-track-origins=2"
	RTFLAGS="-DNATIVE_MSAN";;
*)	fail "NATIVE_SAN must be asan or msan";;
esac
grep -qx -- '--memory-leak-check' "$T/opts" 2>/dev/null &&
    RTFLAGS="$RTFLAGS -DNATIVE_LEAK_CHECK"

# Kernel code is C for gcc: errors that gcc only warns about stay warnings.
# Source-based coverage serves the must_reach check.
CFLAGS="-O1 -g -w -ffreestanding -fno-omit-frame-pointer -fno-optimize-sibling-calls -fprofile-instr-generate -fcoverage-mapping -fno-strict-aliasing -fno-common \
    -Wno-error=implicit-function-declaration -Wno-error=int-conversion \
    -Wno-error=incompatible-function-pointer-types \
    -Wno-error=incompatible-pointer-types"
EMIT="clang -S -emit-llvm $CFLAGS -Xclang -disable-llvm-passes $SANFLAGS \
    -fsanitize=fuzzer-no-link"

# 1. preprocess like cbmc.sh, emit IR without running any pass yet
emit() {	# emit <source> <name> <cpp flags...>
	src=$1; b=$2; shift 2
	${CPP:-gcc} -E "$@" $SHIM "$src" -o "$W/$b.i" 2> "$W/$b.err" &&
	    $EMIT "$W/$b.i" -o "$W/$b.ll" 2>> "$W/$b.err" ||
	    { cat "$W/$b.err" >&2; fail "cannot compile $src"; }
}
kern=""
for f in $(while read -r s; do resolve "$s"; done < "$T/sources"); do
	b=$(basename "$f" .c)
	emit "$f" "$b" $CPPFLAGS
	kern="$kern $W/$b.ll"
done
emit "$T/harness.c" harness $CPPFLAGS -Dmain=harness_main
# common models, built as cbmc.sh builds them
# The two models built against the C library headers are preprocessed with
# clang: glibc's headers take a different path under gcc.
CPP=clang emit "$HERE/common/stubs_alloc.c" stubs_alloc \
    $(cat "$T/stubflags" 2>/dev/null)
CPP=clang emit "$HERE/common/stubs_user.c" stubs_user
emit "$HERE/common/stubs_pool.c" stubs_pool $CPPFLAGS
models="$W/stubs_alloc.ll $W/stubs_user.ll $W/stubs_pool.ll"
[ -f "$T/models" ] && for m in $(cat "$T/models"); do
	emit "$HERE/common/stubs_$m.c" "stubs_$m" $CPPFLAGS
	models="$models $W/stubs_$m.ll"
done

# 2. strip bodies, forward replaced functions, generate stubs
python3 "$N/rewrite.py" --keep "$T/keep" --replace "$T/replace" \
    --nobody "$T/nobody" --fptargets "$T/fptargets" \
    --out "$W" --harness "$W/harness.ll" --kernel $kern --model $models ||
    fail "rewrite failed"

# 3. instrument and compile; one relocatable object for the kernel side
objs=""
for f in "$W"/*.rw.ll $models "$W/stubs.ll"; do
	o=${f%.ll}.o
	clang -c $CFLAGS $SANFLAGS -fsanitize=fuzzer-no-link "$f" -o "$o" \
	    2> "$o.err" || { cat "$o.err" >&2; fail "cannot compile $f"; }
	objs="$objs $o"
done
ld -r $objs -o "$W/kernel-r.o" || fail "ld -r failed"
# Only the entry points stay global, so kernel names (printf, log, ...) do
# not bind to libc or to the fuzzer runtime.
objcopy --keep-global-symbol=harness_main \
    --keep-global-symbol=__native_for_each_global \
    "$W/kernel-r.o" "$W/kernel.o" || fail "objcopy failed"
# Everything the kernel side still needs must come from libc (string
# functions), the sanitizer/fuzzer runtime or native/runtime.c.
nm -u "$W/kernel.o" | awk '{ print $2 }' | grep -Ev \
    '^(__(asan|ubsan|msan|sanitizer|sancov|lsan|native)_|__start___sancov|__stop___sancov|__start_asan_globals|__stop_asan_globals|_GLOBAL_OFFSET_TABLE_)' \
    > "$W/undefined.txt" || true
for s in $(cat "$W/undefined.txt"); do
	case " memcpy memmove memset memcmp bcmp memchr bzero strlen strnlen strcmp strncmp strchr strrchr strcpy strncpy strlcpy strlcat strstr malloc calloc realloc free abort " in
	*" $s "*) ;;
	*) fail "no body and no stub for $s";;
	esac
done

clang -c -O1 -g -fno-omit-frame-pointer $SANFLAGS $RTFLAGS "$N/runtime.c" -o "$W/runtime.o" ||
    fail "cannot compile runtime"
clang $SANFLAGS -fsanitize=fuzzer -fprofile-instr-generate "$W/kernel.o" "$W/runtime.o" \
    -o "$W/fuzz" 2> "$W/link.err" || { cat "$W/link.err" >&2; fail "link failed"; }

# 4. fuzz
mkdir -p "$W/corpus" "$W/crash"
# native/seeds/<target>/: hand-made inputs for paths the fuzzer does not
# find on its own (see README.native); read only, new inputs go to corpus.
SEEDS="$N/seeds/${T#$HERE/}"
[ -d "$SEEDS" ] || SEEDS=""
rm -f "$W"/crash/*
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:symbolize=1:${ASAN_OPTIONS:-}"
export UBSAN_OPTIONS="print_stacktrace=1:${UBSAN_OPTIONS:-}"
export MSAN_OPTIONS="${MSAN_OPTIONS:-}"
# the coverage runtime writes default.profraw into the cwd otherwise
export LLVM_PROFILE_FILE="$W/other.profraw"
rc=0
t0=$(date +%s)
LLVM_PROFILE_FILE="$W/fuzz.profraw" "$W/fuzz" -seed="${NATIVE_SEED:-1}" \
    -max_total_time="$SECS" -rss_limit_mb=2048 -timeout=10 -detect_leaks=0 \
    -print_final_stats=1 ${NATIVE_FUZZ_OPTS:-} -artifact_prefix="$W/crash/" \
    "$W/corpus" $SEEDS \
    > "$W/fuzz.out" 2>&1 || rc=$?
t1=$(date +%s)
execs=$(sed -n 's/^stat::number_of_executed_units: *//p' "$W/fuzz.out" | tail -1)
art=$(ls "$W"/crash/ 2>/dev/null | head -1)
echo "output in $W"
if [ -z "$art" ]; then
	if [ $rc -ne 0 ]; then
		tail -20 "$W/fuzz.out"
		echo "RESULT: ERROR (fuzzer exit $rc)"; exit 2
	fi
	# A clean run means nothing if the path under test was not executed:
	# check the must_reach anchors against the run's line coverage.
	llvm-profdata merge -sparse "$W/fuzz.profraw" -o "$W/fuzz.profdata" ||
	    fail "no coverage profile"
	pairs=""
	for i in "$W/harness.i" $(for k in $kern; do echo "${k%.ll}.i"; done); do
		llvm-cov show "$W/fuzz" -instr-profile="$W/fuzz.profdata" \
		    "$i" > "$i.cov" 2>/dev/null || fail "llvm-cov failed"
		pairs="$pairs $i $i.cov"
	done
	python3 "$N/reached.py" $pairs > "$W/reached"
	vacuous=0
	while IFS= read -r anchor; do
		[ -n "$anchor" ] || continue
		file=${anchor%%:*}; text=${anchor#*:}
		if grep -qs "/$file\$" "$T/included"; then
			src="$W/included/$file"
		else
			src=$(resolve "$(grep "/$file\$" "$T/sources")")
		fi
		hit=0
		for l in $(grep -nF -- "$text" "$src" | cut -d: -f1); do
			grep -qx "$src $l" "$W/reached" && hit=1
		done
		[ $hit -eq 1 ] || { echo "UNREACHED: $anchor"; vacuous=1; }
	done < "$T/must_reach"
	if [ $vacuous -ne 0 ]; then
		echo "RESULT: VACUOUS (${execs:-?} execs, $((t1 - t0)) s)"; exit 2
	fi
	echo "RESULT: CLEAN (${execs:-?} execs, $((t1 - t0)) s)"
	exit 0
fi
# Reproduce in a fresh process: the finding must not depend on state left
# behind by earlier inputs.
echo "found after $((t1 - t0)) s: $(grep -E '^#[0-9]+' "$W/fuzz.out" | tail -1)"
timeout 60 "$W/fuzz" -timeout=10 "$W/crash/$art" > "$W/repro.out" 2>&1 || true
awk '/==NATIVE==|(ERROR|WARNING): (AddressSanitizer|MemorySanitizer|LeakSanitizer)|runtime error|ERROR: libFuzzer: timeout/ { on = 1 }
    /ERROR: libFuzzer: deadly signal/ && on { exit }
    on { sub(/ \(BuildId: [0-9a-f]+\)/, ""); print; n++ }
    /^SUMMARY:/ && on { exit } n >= 80 { exit }' "$W/repro.out"
if grep -q 'NATIVE==\|Sanitizer\|runtime error\|libFuzzer: \(deadly\|timeout\)' \
    "$W/repro.out"; then
	echo "input: $W/crash/$art (reproduced in a fresh process)"
	echo "RESULT: FINDING"; exit 1
fi
echo "input: $W/crash/$art did not reproduce in a fresh process"
sed -n '/ERROR\|==NATIVE==/,$p' "$W/fuzz.out" | head -40
echo "RESULT: FINDING (not reproducible in a fresh process: state carried between inputs?)"
exit 1
