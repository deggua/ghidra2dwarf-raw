"""GDB side of the differential unwinding test (test/difftrace.py): from a
start address, single-step the firmware and record the unwound (pc, sp) of
every frame at every instruction, one JSON line per step.

Env: ELF (symbol file to use), QEMU_PORT, OUT (jsonl), START (address),
STEPS, DEPTH.
"""

import json
import os

import gdb

ELF = os.environ["ELF"]
OUT = os.environ["OUT"]
STEPS = int(os.environ.get("STEPS", "3000"))
DEPTH = int(os.environ.get("DEPTH", "8"))


def run(c):
    return gdb.execute(c, to_string=True)


run("set pagination off")
run("set confirm off")
run("set exec-file-mismatch off")
run("set sysroot /nonexistent")   # QEMU user mode: don't fetch the reference ELF
run("set print entry-values no")
run("file " + ELF)
run("set tcp auto-retry on")
run("set tcp connect-timeout 20")
run("target remote :%s" % os.environ["QEMU_PORT"])
run("tbreak *%s" % os.environ["START"])
if os.environ.get("ELFV2") == "1":
    # local calls enter at the local entry point (after the TOC setup)
    run("tbreak *(%s + 8)" % os.environ["START"])
run("continue")

with open(OUT, "w") as out:
    for i in range(STEPS):
        rec = {"i": i, "frames": []}
        try:
            f = gdb.newest_frame()
            sal = f.find_sal()
            if sal is not None and sal.symtab is not None:
                rec["src"] = [sal.symtab.fullname(), sal.line]
            while f is not None and len(rec["frames"]) < DEPTH:
                if f.type() == gdb.TAILCALL_FRAME:   # GDB's call-site pseudo frames (GCC info)
                    f = f.older()
                    continue
                try:
                    sp = int(f.read_register("sp")) & 0xffffffffffffffff
                except Exception as e:  # noqa: BLE001
                    sp = "ERR " + str(e)[:40]
                rec["frames"].append([int(f.pc()), sp])
                try:
                    f = f.older()
                except Exception as e:  # noqa: BLE001
                    rec["bt_err"] = str(e)[:80]
                    break
        except Exception as e:  # noqa: BLE001
            rec["err"] = str(e)[:80]
        out.write(json.dumps(rec) + "\n")
        try:
            run("stepi")
        except Exception as e:  # noqa: BLE001
            out.write(json.dumps({"i": i, "fatal": str(e)[:100]}) + "\n")
            break
try:
    gdb.execute("kill")
except gdb.error:
    pass
