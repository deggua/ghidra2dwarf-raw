#!/bin/bash
# Import the raw test firmware into a fresh Ghidra project, apply the
# simulated RE annotations, and run the exporter.
#
#   test/export_fw.sh <work dir> [exporter key=value options...]
#
# Env: GHIDRA_INSTALL_DIR (default: ../ghidra_12.2_PUBLIC next to the repo)
#      FW_BUILD          (default: test/firmware/build)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$HERE")"
GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-$(dirname "$REPO")/ghidra_12.2_PUBLIC}"
FW_BUILD="${FW_BUILD:-$HERE/firmware/build}"

WORK="$(realpath -m "${1:?usage: $0 <work dir> [options]}")"
shift
mkdir -p "$WORK/project" "$WORK/out"
rm -rf "$WORK/project/"* "$WORK/out/"*

# pyghidraRun asks once whether to install PyGhidra into Ghidra's venv.
echo y | "$GHIDRA_INSTALL_DIR/support/pyghidraRun" -H "$WORK/project" fwtest \
    -import "$FW_BUILD/fw.bin" -overwrite \
    -loader BinaryLoader -loader-baseAddr 0xfff00000 \
    -processor PowerPC:BE:32:default \
    -postScript "$HERE/ghidra_setup.py" "$FW_BUILD" "$HERE/firmware/fw.h" "$HERE/firmware/edge.h" \
    -postScript "$HERE/ghidra_setup_edge.py" "$FW_BUILD" \
    -postScript "$REPO/ghidra_scripts/ExportDwarfELF.py" "$WORK/out" "$@" \
    > "$WORK/ghidra.log" 2>&1 || { tail -50 "$WORK/ghidra.log"; exit 1; }

if grep -qE "ERROR|Traceback" "$WORK/ghidra.log"; then
    grep -B2 -A20 -E "ERROR|Traceback" "$WORK/ghidra.log" | head -80
    exit 1
fi
grep -E "^(ghidra2dwarf-raw|WARNING|parsed|setup done|EDGE|  )" "$WORK/ghidra.log" || true
ls -la "$WORK/out"
