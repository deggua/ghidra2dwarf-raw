#!/usr/bin/env python3
"""Import a test firmware build into a fresh Ghidra project (raw binary at its
base address), apply the simulated RE annotations, and run the exporter.

    test/export_fw.py <firmware build dir> <work dir> [exporter key=value ...]

Writes <work dir>/out/fw.bin.{elf,c} and <work dir>/ghidra.log.
Env: GHIDRA_INSTALL_DIR (default: ../ghidra_12.2_PUBLIC next to the repo).
"""

import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def export(build, work, opts=()):
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", os.path.join(os.path.dirname(REPO), "ghidra_12.2_PUBLIC"))
    with open(os.path.join(build, "layout.json")) as f:
        layout = json.load(f)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(os.path.join(work, "project"))
    os.makedirs(os.path.join(work, "out"))
    fw = os.path.join(HERE, "firmware")
    cmd = [os.path.join(ghidra, "support", "pyghidraRun"), "-H", os.path.join(work, "project"), "fwtest",
           "-import", os.path.join(build, "fw.bin"), "-overwrite",
           "-loader", "BinaryLoader", "-loader-baseAddr", "0x%x" % layout["base"], "-noanalysis",
           "-processor", layout["lang"], "-cspec", layout["cspec"],
           "-postScript", os.path.join(HERE, "ghidra_setup.py"), build,
           os.path.join(fw, "fw.h"), os.path.join(fw, "edge.h")] + \
          ([os.path.join(fw, "irq.h")] if layout.get("irq") else []) + \
          ["-postScript", os.path.join(HERE, "ghidra_setup_edge.py"), build] + \
          (["-postScript", os.path.join(HERE, "ghidra_setup_irq.py"), build] if layout.get("irq") else []) + [
           "-postScript", os.path.join(REPO, "ghidra_scripts", "ExportDwarfELF.py"),
           os.path.join(work, "out")] + list(opts) + [
           # what the DWARF round trip (test/roundtrip.py) compares against
           "-postScript", os.path.join(HERE, "ghidra_dump.py"), os.path.join(work, "original.json")]
    log_path = os.path.join(work, "ghidra.log")
    with open(log_path, "w") as log:
        # pyghidraRun asks once whether to install PyGhidra into Ghidra's venv.
        r = subprocess.run(cmd, input="y\n", stdout=log, stderr=subprocess.STDOUT, text=True)
    with open(log_path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    errors = re.findall(r"^(?:ERROR .*|Traceback.*)$", text, re.M)
    notes = [l for l in text.splitlines()
             if l.startswith(("ghidra2dwarf-raw: ", "WARNING", "EDGE FAILED", "EDGE skipped",
                              "Interrupt/exception handlers", "IRQ setup"))]
    ok = r.returncode == 0 and not errors and os.path.exists(os.path.join(work, "out", "fw.bin.elf"))
    return ok, notes, text


if __name__ == "__main__":
    ok, notes, text = export(sys.argv[1], sys.argv[2], sys.argv[3:])
    print("\n".join(notes))
    if not ok:
        print(text[-4000:])
        sys.exit(1)
