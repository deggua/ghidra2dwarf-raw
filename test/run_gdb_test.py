#!/usr/bin/env python3
"""End-to-end test: boot the raw test firmware in QEMU and debug it with GDB
using only the exported ELF + C file.

    test/run_gdb_test.py <exported .elf> <exported .c> [firmware .bin]

Exit status 0 if every check in gdb_checks.py passes.
"""

import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    elf = os.path.abspath(sys.argv[1])
    csrc = os.path.abspath(sys.argv[2])
    fw = os.path.abspath(sys.argv[3] if len(sys.argv) > 3 else
                         os.path.join(HERE, "firmware", "build", "fw.bin"))
    port = free_port()
    qemu = subprocess.Popen(
        ["qemu-system-ppc", "-M", "mac99", "-bios", fw, "-display", "none",
         "-S", "-gdb", "tcp:127.0.0.1:%d" % port, "-monitor", "none", "-serial", "none"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        env = dict(os.environ, ELF=elf, CSRC=csrc, QEMU_PORT=str(port))
        try:
            r = subprocess.run(["gdb-multiarch", "-q", "-nx", "-batch",
                                "-x", os.path.join(HERE, "gdb_checks.py")],
                               env=env, capture_output=True, text=True, timeout=300)
            out = r.stdout + r.stderr
        except subprocess.TimeoutExpired as e:
            def _s(x):
                return x.decode() if isinstance(x, bytes) else (x or "")
            out = _s(e.stdout) + _s(e.stderr) + "\nFAIL gdb timed out"
    finally:
        qemu.kill()
        qemu.wait()
    lines = [l for l in out.splitlines() if l.startswith(("PASS", "FAIL", "SKIP", "SUMMARY", "Traceback", "  "))]
    print("\n".join(lines))
    ok = "SUMMARY" in out and " 0 failed" in out
    if not ok and "SUMMARY" not in out:
        print(out[-3000:])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
