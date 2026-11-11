#!/usr/bin/env python3
"""Differential unwinding test: single-step the firmware twice from the same
start, once with GCC's own debug info (the reference) and once with the
exported ELF, and compare the unwound (pc, sp) of every frame at every
instruction. Frames are compared while they are in functions GCC has CFI
for (C code; hand-written assembly has none, so GDB guesses there), plus the
first frame outside them (its pc/sp still come from the callee's CFI).

    test/difftrace.py <build dir> <exported elf> [steps] [start symbol]

Exit status 1 on any mismatch. Thanks to the adversarial review that wrote
the first version of this tracer.
"""

import bisect
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run_gdb_test  # noqa: E402


def _trace(build, elf, out, start, steps, elfv2=False):
    recs = _trace_once(build, elf, out, start, steps, elfv2)
    if not recs:
        # (QEMU user mode serves one connection; a lost race leaves nothing)
        recs = _trace_once(build, elf, out, start, steps, elfv2)
    return recs


def _trace_once(build, elf, out, start, steps, elfv2):
    import time
    t0 = time.time() - 1
    port = run_gdb_test.free_port()
    cmd = run_gdb_test.qemu_command(build, port)
    qemu = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        env = dict(os.environ, ELF=os.path.abspath(elf), QEMU_PORT=str(port), OUT=out,
                   START="0x%x" % start, STEPS=str(steps), ELFV2="1" if elfv2 else "0")
        try:
            subprocess.run(["gdb-multiarch", "-q", "-nx", "-batch", "-x", os.path.join(HERE, "gdb_trace.py")],
                           env=env, capture_output=True, text=True, timeout=600,
                           preexec_fn=run_gdb_test._no_core)
        except subprocess.TimeoutExpired:
            pass    # the partial trace is compared; a short one fails the test
    finally:
        qemu.kill()
        qemu.wait()
    recs = []
    if os.path.exists(out) and os.path.getmtime(out) >= t0:
        with open(out) as f:
            recs = [json.loads(l) for l in f]
    return recs


def _cfi_ranges(elf):
    """[(lo, hi)] covered by FDEs in GCC's ELF."""
    r = subprocess.run(["llvm-dwarfdump", "--debug-frame", elf], capture_output=True, text=True)
    out = []
    for m in re.finditer(r"FDE cie=\w+ pc=([0-9a-f]+)\.\.\.([0-9a-f]+)", r.stdout):
        out.append((int(m.group(1), 16), int(m.group(2), 16)))
    return sorted(out)


def _symbols(build, thumb):
    syms = []
    with open(os.path.join(build, "symbols.txt")) as f:
        for line in f:
            n, a, s, k = line.split()
            if k in "Tt":
                syms.append((int(a, 16) & ~1 if thumb else int(a, 16), n))
    return sorted(syms)


# Functions not compared (neither their own instructions nor unwinding
# through them): after a stack realignment ("and esp,-64") the export leaves
# the code to GDB's prologue analyzer (README: Limitations), which gets
# i386 realigned frames wrong.
NOT_COMPARED = ("shape_align",)


def compare(ref, exp, cfi, syms):
    starts = [lo for lo, _ in cfi]

    def has_cfi(pc):
        i = bisect.bisect_right(starts, pc) - 1
        return i >= 0 and cfi[i][0] <= pc < cfi[i][1]

    def where(pc):
        i = bisect.bisect_right(syms, (pc, "\xff")) - 1
        return "%s+0x%x" % (syms[i][1], pc - syms[i][0]) if i >= 0 else hex(pc)

    def norm(recs):
        base = None
        for r in recs:
            if r.get("frames") and isinstance(r["frames"][0][1], int):
                base = r["frames"][0][1]
                break
        for r in recs:
            for fr in r.get("frames", []):
                if base is not None and isinstance(fr[1], int):
                    fr[1] = fr[1] - base
    norm(ref)
    norm(exp)
    bad = {}
    compared = desync = 0
    for t, e in zip(ref, exp):
        tf, ef = t.get("frames"), e.get("frames")
        if not tf or not ef:
            continue
        if tf[0][0] != ef[0][0]:
            desync += 1
            continue
        if not has_cfi(tf[0][0]) or where(tf[0][0]).split("+")[0] in NOT_COMPARED:
            continue
        compared += 1
        for j, fr in enumerate(tf):
            if j > 0 and where(fr[0]).split("+")[0] in NOT_COMPARED:
                break
            if j >= len(ef) or ef[j] != fr:
                key = where(tf[0][0])
                if key not in bad:
                    bad[key] = (t["i"], " <- ".join("%s/sp%+d" % (where(p), s) if isinstance(s, int) else where(p)
                                                    for p, s in tf[:j + 1]),
                                " <- ".join("%s/sp%+d" % (where(p), s) if isinstance(s, int) else where(p)
                                            for p, s in ef[:j + 1]), e.get("bt_err"))
                break
            if not has_cfi(fr[0]) or where(fr[0]).split("+")[0] in NOT_COMPARED:
                break
    return compared, desync, bad


def difftrace(build, elf, steps=3000, start_sym="edge_main", work=None):
    """Returns (ok, report lines)."""
    with open(os.path.join(build, "layout.json")) as f:
        layout = json.load(f)
    syms = _symbols(build, layout.get("thumb"))
    start = dict((n, a) for a, n in syms).get(start_sym)
    if start is None:
        return False, ["no symbol %s" % start_sym]
    work = work or os.path.dirname(os.path.abspath(elf))
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(2) as ex:
        fr = ex.submit(_trace, build, os.path.join(build, "fw.elf"), os.path.join(work, "trace-gcc.jsonl"),
                       start, steps, layout.get("elfv2"))
        fe = ex.submit(_trace, build, elf, os.path.join(work, "trace-export.jsonl"), start, steps,
                       layout.get("elfv2"))
        ref, exp = fr.result(), fe.result()
    if len(ref) < steps // 2 or len(exp) < steps // 2:
        return False, ["trace too short: reference %d, export %d steps" % (len(ref), len(exp))]
    compared, desync, bad = compare(ref, exp, _cfi_ranges(os.path.join(build, "fw.elf")), syms)
    lines = ["%d steps compared, %d desynced, %d mismatching PCs" % (compared, desync, len(bad))]
    for k, (i, t, e, err) in list(bad.items())[:15]:
        lines.append("step %d at %s\n      gcc   : %s\n      export: %s %s" % (i, k, t, e, err or ""))
    return not bad and desync == 0 and compared > 0, lines


if __name__ == "__main__":
    a = sys.argv[1:]
    ok, lines = difftrace(a[0], a[1], int(a[2]) if len(a) > 2 else 3000, a[3] if len(a) > 3 else "edge_main")
    print("\n".join(lines))
    sys.exit(0 if ok else 1)
