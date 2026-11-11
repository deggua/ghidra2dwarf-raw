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


def elf_section(path, wanted):
    """(address, bytes) of a section of an ELF64 big/little-endian file."""
    import struct
    data = open(path, "rb").read()
    if data[4] != 2:
        return None
    end = ">" if data[5] == 2 else "<"
    shoff = struct.unpack_from(end + "Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", data, 0x3A)
    def sh(i):
        return struct.unpack_from(end + "IIQQQQIIQQ", data, shoff + i * shentsize)
    stroff = sh(shstrndx)[4]
    for i in range(shnum):
        nm, typ, flags, addr, off, size = sh(i)[:6]
        name = data[stroff + nm:data.index(b"\0", stroff + nm)].decode()
        if name == wanted:
            return addr, data[off:off + size]
    return None


def build(name, opt, out):
    t = TARGETS[name]
    os.makedirs(out, exist_ok=True)
    cc = t["cross"] + "gcc"
    tool = lambda n: t["cross"] + n  # noqa: E731
    cflags = ["-" + opt] + COMMON_CFLAGS + t["cflags"] + (["-DHAVE_IRQ"] if t["irq"] else [])
    isa_dir = os.path.join(FW, t["isa"])
    objs = []
    srcs = [(os.path.join(isa_dir, "crt0.S"), t["asflags"]),
            (os.path.join(isa_dir, "edge_asm.S"), t["asflags"]),
            (os.path.join(FW, "main.c"), cflags),
            (os.path.join(FW, "edge.c"), cflags)]
    if t["irq"]:
        srcs += [(os.path.join(isa_dir, "irq.S"), t["asflags"]), (os.path.join(FW, "irq.c"), cflags)]
    for src, flags in srcs:
        obj = os.path.join(out, os.path.basename(src) + ".o")
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
    entries = []
    opd = elf_section(elf, ".opd")
    for line in sh([tool("nm"), "-S", "--defined-only", elf]).splitlines():
        parts = line.split()
        if len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16)
        if len(parts) == 4 and parts[2] in "TtDdBbRr":
            sym, addr, size, kind = parts[3], int(parts[0], 16), int(parts[1], 16), parts[2]
            if opd and opd[0] <= addr < opd[0] + len(opd[1]):
                # ELFv1: the symbol is a function descriptor; the analyst
                # knows the code address it points to.
                off = addr - opd[0]
                addr = int.from_bytes(opd[1][off:off + 8], "big")
                kind, size = "T", 0
            entries.append([sym, addr, size, kind])
            syms[sym] = addr
    # sizes unknown for descriptor-resolved code: distance to the next symbol
    starts = sorted(set(e[1] for e in entries))
    for e in entries:
        if e[2] == 0:
            nxt = [s for s in starts if s > e[1]]
            e[2] = (nxt[0] - e[1]) if nxt else 4
    lines = ["%s 0x%x 0x%x %s" % (n, a, s, k) for n, a, s, k in entries]
    with open(os.path.join(out, "symbols.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")

    if t["mode"] == "rom":
        ram = [[0x00100000, 0x10000]]
    else:
        ram = [[syms["__bss_start"], max(syms["__bss_end"] - syms["__bss_start"], 8)]]
    layout = {"target": name, "base": t["base"], "ram": ram, "thumb": t["thumb"],
              "lang": t["lang"], "cspec": t["cspec"], "irq": t["irq"], "elfv2": t["elfv2"],
              "sret_memory": t["sret_memory"], "calling_convention": t["calling_convention"],
              "positional_args": t["positional_args"]}
    if opd:
        # PPC64 ELFv1: the TOC base an analyst sets r2 to (from a descriptor)
        layout["toc"] = int.from_bytes(opd[1][8:16], "big")
    with open(os.path.join(out, "layout.json"), "w") as f:
        json.dump(layout, f, indent=1)
    return out


if __name__ == "__main__":
    build(sys.argv[1], sys.argv[2], sys.argv[3])
