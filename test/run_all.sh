#!/bin/bash
# Full test suite:
#   1. unit tests of the Ghidra-independent DWARF/ELF writer
#   2. for -O0/-O1/-O2 builds of the PPC test firmware: import the raw image
#      into Ghidra headless, apply simulated annotations, export, validate
#      with llvm-dwarfdump --verify, and debug it in QEMU with GDB.
#
#   test/run_all.sh [work dir]        (default: ./work)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$HERE")"
WORK="$(realpath -m "${1:-$REPO/work}")"
OPTS="${OPTS:-O0 O1 O2}"
fail=0

echo "=== writer unit tests"
python3 "$HERE/test_writer.py" || fail=1

for O in $OPTS; do
    echo "=== firmware -$O"
    make -s -C "$HERE/firmware" OPT=-$O OUT=build-$O >/dev/null || { fail=1; continue; }
    FW_BUILD="$HERE/firmware/build-$O" "$HERE/export_fw.sh" "$WORK/$O" \
        | grep -E "^(ghidra2dwarf-raw: [a-z_]+=|WARNING)" || { fail=1; continue; }
    out="$WORK/$O/out"
    llvm-dwarfdump --verify "$out/fw.bin.elf" | tail -1 | grep -q "No errors" \
        || { echo "llvm-dwarfdump --verify FAILED"; fail=1; }
    python3 "$HERE/run_gdb_test.py" "$out/fw.bin.elf" "$out/fw.bin.c" \
        "$HERE/firmware/build-$O/fw.bin" | grep -E "^(FAIL|SKIP|SUMMARY)|Traceback" || true
    python3 "$HERE/run_gdb_test.py" "$out/fw.bin.elf" "$out/fw.bin.c" \
        "$HERE/firmware/build-$O/fw.bin" >/dev/null || fail=1
done

[ $fail = 0 ] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
exit $fail
