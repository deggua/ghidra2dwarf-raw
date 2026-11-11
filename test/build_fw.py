#!/usr/bin/env python3
"""Build the test firmware for one target.

    test/build_fw.py <target> <-O level, e.g. O1> <out dir>

Outputs in <out dir>:
    fw.elf        reference ELF with GCC's debug info (used to run the
                  target under QEMU user mode; never shown to Ghidra/GDB tests)
    fw.bin        raw image (objcopy -O binary) imported into Ghidra
    symbols.txt   "name 0xaddr 0xsize type" for the simulated RE annotations
    layout.json   base address, RAM blocks to create in Ghidra, Thumb flag
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FW = os.path.join(HERE, "firmware")
sys.path.insert(0, HERE)
from targets import TARGETS, COMMON_CFLAGS, COMMON_LDFLAGS  # noqa: E402


def sh(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise SystemExit("command failed: %s\n%s%s" % (" ".join(cmd), r.stdout, r.stderr))
    return r.stdout


def build(name, opt, out):
    t = TARGETS[name]
    os.makedirs(out, exist_ok=True)
    cc = t["cross"] + "gcc"
    tool = lambda n: t["cross"] + n  # noqa: E731
    cflags = ["-" + opt] + COMMON_CFLAGS + t["cflags"]
    isa_dir = os.path.join(FW, t["isa"])
    objs = []
    for src, flags in ((os.path.join(isa_dir, "crt0.S"), t["asflags"]),
                       (os.path.join(isa_dir, "edge_asm.S"), t["asflags"]),
                       (os.path.join(FW, "main.c"), cflags),
                       (os.path.join(FW, "edge.c"), cflags)):
        obj = os.path.join(out, os.path.basename(src).rsplit(".", 1)[0] + ".o")
        sh([cc] + flags + ["-g", "-c", src, "-o", obj])
        objs.append(obj)

    if t["mode"] == "rom":
        script = os.path.join(isa_dir, "link.ld")
    else:
        script = os.path.join(out, "link.ld")
        with open(os.path.join(FW, "user.ld.in")) as f:
            text = f.read().replace("@BASE@", "0x%x" % t["base"])
        with open(script, "w") as f:
            f.write(text)
    elf = os.path.join(out, "fw.elf")
    sh([cc] + cflags + COMMON_LDFLAGS + t["ldflags"] + ["-Wl,-T," + script] + objs + ["-o", elf])
    sh([tool("objcopy"), "-O", "binary", elf, os.path.join(out, "fw.bin")])

    syms = {}
    lines = []
    for line in sh([tool("nm"), "-S", "--defined-only", elf]).splitlines():
        parts = line.split()
        if len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16)
        if len(parts) == 4 and parts[2] in "TtDdBbRr":
            lines.append("%s 0x%s 0x%s %s" % (parts[3], parts[0], parts[1], parts[2]))
            syms[parts[3]] = int(parts[0], 16)
    with open(os.path.join(out, "symbols.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")

    if t["mode"] == "rom":
        ram = [[0x00100000, 0x10000]]
    else:
        ram = [[syms["__bss_start"], max(syms["__bss_end"] - syms["__bss_start"], 8)]]
    layout = {"target": name, "base": t["base"], "ram": ram, "thumb": t["thumb"],
              "lang": t["lang"], "cspec": t["cspec"]}
    with open(os.path.join(out, "layout.json"), "w") as f:
        json.dump(layout, f, indent=1)
    return out


if __name__ == "__main__":
    build(sys.argv[1], sys.argv[2], sys.argv[3])
