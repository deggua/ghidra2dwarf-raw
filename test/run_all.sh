#!/bin/bash
# Full test suite:
#   1. unit tests of the Ghidra-independent DWARF/ELF writer
#   2. for -O0/-O1/-O2 builds of the PPC test firmware: import the raw image
#      into Ghidra headless, apply simulated annotations (incl. the edge
#      cases), export, validate with llvm-dwarfdump --verify, and debug it in
#      QEMU with GDB (main checks + edge-case checks).
#   3. the same with sanitize_names=true (-O1 only).
#
#   test/run_all.sh [work dir]        (default: ./work)
#   OPTS="O1" test/run_all.sh         (subset of -O levels)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$HERE")"
WORK="$(realpath -m "${1:-$REPO/work}")"
OPTS="${OPTS:-O0 O1 O2}"
fail=0

echo "=== writer unit tests"
python3 "$HERE/test_writer.py" 2>&1 | tail -1 | grep -q "^OK" || { python3 "$HERE/test_writer.py"; fail=1; }

gdb_run() {  # <label> <checks script> <out dir> <fw.bin> [--sanitized]
    local label=$1 checks=$2 out=$3 fw=$4; shift 4
    local log
    log=$(python3 "$HERE/run_gdb_test.py" "$@" --checks "$HERE/$checks" "$out/fw.bin.elf" "$out/fw.bin.c" "$fw")
    local rc=$?
    echo "$log" | grep -E "^(FAIL|SKIP)|Traceback" | sed "s/^/  [$label] /"
    echo "  [$label] $(echo "$log" | grep SUMMARY)"
    [ $rc = 0 ] || fail=1
}

export_and_check() {  # <name> <-O level> [exporter options...]
    local name=$1 O=$2; shift 2
    local fw="$HERE/firmware/build-$O/fw.bin"
    FW_BUILD="$HERE/firmware/build-$O" "$HERE/export_fw.sh" "$WORK/$name" "skip_decompile=bad?func" "$@" \
        | grep -E "^ghidra2dwarf-raw: [a-z_]+=|^WARNING|EDGE FAILED" | sed "s/^/  /" || { fail=1; return; }
    local out="$WORK/$name/out"
    llvm-dwarfdump --verify "$out/fw.bin.elf" | tail -1 | grep -q "No errors" \
        || { echo "  llvm-dwarfdump --verify FAILED"; fail=1; }
    local san=()
    [[ " $* " == *" sanitize_names=true "* ]] && san=(--sanitized)
    gdb_run main gdb_checks.py "$out" "$fw" "${san[@]}"
    gdb_run edge gdb_edge_checks.py "$out" "$fw" "${san[@]}"
}

for O in $OPTS; do
    echo "=== firmware -$O"
    make -s -C "$HERE/firmware" OPT=-$O OUT=build-$O >/dev/null || { fail=1; continue; }
    export_and_check "$O" "$O"
done

O=$(echo $OPTS | awk '{print ($0 ~ /O1/) ? "O1" : $1}')
echo "=== firmware -$O, sanitize_names=true"
export_and_check "$O-sanitized" "$O" sanitize_names=true

[ $fail = 0 ] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
exit $fail
