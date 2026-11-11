#!/usr/bin/env python3
"""End-to-end test: run the test firmware under QEMU and debug it with GDB
using only the exported ELF + C file.

    test/run_gdb_test.py [--checks script.py] [--sanitized] <build dir> <exported .elf> <exported .c>

<build dir> is a test/build_fw.py output (its layout.json names the target).
The ROM target boots fw.bin in qemu-system-ppc; the others run fw.elf (the
reference build, used only to execute the code) under QEMU user mode.
Exit status 0 if every check passes.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from targets import TARGETS  # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def qemu_command(build, port):
    with open(os.path.join(build, "layout.json")) as f:
        t = TARGETS[json.load(f)["target"]]
    if t["mode"] == "rom":
        return ["qemu-system-ppc", "-M", "mac99", "-bios", os.path.join(build, "fw.bin"),
                "-display", "none", "-S", "-gdb", "tcp:127.0.0.1:%d" % port,
                "-monitor", "none", "-serial", "none"]
    return [t["qemu"]] + t["qemu_args"] + ["-g", str(port), os.path.join(build, "fw.elf")]


FP_PROBE = """
set pagination off
set confirm off
break mix
continue
printf "PROBE_ARGS %d\\n", a == 1.5 && b == 2.25
finish
printf "PROBE_RET %d\\n", $ == 6.375
kill
"""


def fp_probe(build):
    """Do float/double arguments and return values read correctly in this
    GDB + QEMU combination *with GCC's own debug info* (the reference ELF)?
    Some don't (x86-64 user mode misnumbers xmm registers, MIPS o32 doubles
    in FPR pairs and AArch64 big-endian vector registers read as 0); there
    the checks verify our locations instead of the values. Cached per build."""
    # Probe with an -O1 reference build: at -O0 GCC keeps arguments in stack
    # slots, which would hide unreadable FP registers.
    with open(os.path.join(build, "layout.json")) as f:
        target = json.load(f)["target"]
    probe_build = os.path.join(os.path.dirname(os.path.abspath(build)), "fpprobe-" + target)
    cache = os.path.join(probe_build, "fp_probe.json")
    if os.path.exists(cache):
        with open(cache) as f:
            return json.load(f)
    import build_fw
    build_fw.build(target, "O1", probe_build)
    build = probe_build
    port = free_port()
    cmd = qemu_command(build, port)
    qemu = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    script = os.path.join(build, "fp_probe.gdb")
    with open(script, "w") as f:
        f.write(FP_PROBE)
    try:
        if cmd[0].startswith("qemu-system"):
            time.sleep(0.5)
        r = subprocess.run(["gdb-multiarch", "-q", "-nx", "-batch",
                            "-ex", "set exec-file-mismatch off",
                            "-ex", "file " + os.path.join(build, "fw.elf"),
                            "-ex", "set tcp auto-retry on", "-ex", "set tcp connect-timeout 20",
                            "-ex", "target remote :%d" % port, "-x", script],
                           capture_output=True, text=True, timeout=120)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        out = ""
    finally:
        qemu.kill()
        qemu.wait()
    res = {"args": "PROBE_ARGS 1" in out, "ret": "PROBE_RET 1" in out}
    with open(cache, "w") as f:
        json.dump(res, f)
    return res


def run(build, elf, csrc, checks=None, sanitized=False, timeout=180):
    """Returns (ok, output lines of interest, full output)."""
    checks = checks or os.path.join(HERE, "gdb_checks.py")
    probe = fp_probe(build)
    port = free_port()
    cmd = qemu_command(build, port)
    qemu = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if cmd[0].startswith("qemu-system"):
            # System-mode stubs accept reconnects; wait until it listens.
            # (User-mode stubs serve only the first connection, so there we
            # rely on GDB's own connect retries instead.)
            for _ in range(50):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
        env = dict(os.environ, ELF=os.path.abspath(elf), CSRC=os.path.abspath(csrc),
                   QEMU_PORT=str(port), SANITIZED="1" if sanitized else "0",
                   FP_ARGS_OK="1" if probe["args"] else "0", FP_RET_OK="1" if probe["ret"] else "0",
                   PYTHONIOENCODING="utf-8")
        try:
            r = subprocess.run(["gdb-multiarch", "-q", "-nx", "-batch", "-x", os.path.abspath(checks)],
                               env=env, capture_output=True, text=True, timeout=timeout)
            out = r.stdout + r.stderr
        except subprocess.TimeoutExpired as e:
            def _s(x):
                return x.decode() if isinstance(x, bytes) else (x or "")
            out = _s(e.stdout) + _s(e.stderr) + "\nFAIL gdb timed out"
    finally:
        qemu.kill()
        qemu.wait()
    lines = [l for l in out.splitlines()
             if l.startswith(("PASS", "FAIL", "SKIP", "SUMMARY", "Traceback", "  "))]
    ok = "SUMMARY" in out and " 0 failed" in out
    return ok, lines, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checks")
    ap.add_argument("--sanitized", action="store_true")
    ap.add_argument("build")
    ap.add_argument("elf")
    ap.add_argument("csrc")
    a = ap.parse_args()
    ok, lines, out = run(a.build, a.elf, a.csrc, a.checks, a.sanitized)
    print("\n".join(lines))
    if not ok and "SUMMARY" not in out:
        print(out[-3000:])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
