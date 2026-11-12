#!/usr/bin/env python3
"""Full test suite.

  1. unit tests of the Ghidra-independent DWARF/ELF writer;
  2. for every target x -O level: build the test firmware, import the raw
     image into Ghidra headless, apply the simulated annotations (including
     the edge cases), export, validate with llvm-dwarfdump --verify,
     re-import the ELF into Ghidra (DWARF analyzer only) and compare with the
     annotated original, and debug it in QEMU with GDB (main, edge-case,
     GDB-feature and, where the firmware has them, interrupt checks);
  3. at -O1, the same with sanitize_names=true.

    test/run_all.py [-t target,...] [-O O0,O1,O2] [-j jobs] [--work dir] [-v]
"""

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from targets import TARGETS  # noqa: E402
import build_fw  # noqa: E402
import export_fw  # noqa: E402
import difftrace  # noqa: E402
import roundtrip  # noqa: E402
import run_gdb_test  # noqa: E402


def job(target, opt, sanitized, work, verbose):
    name = "%s-%s%s" % (target, opt, "-sanitized" if sanitized else "")
    report = {"name": name, "ok": True, "lines": [], "counts": {}}

    def fail(msg):
        report["ok"] = False
        report["lines"].append("FAIL " + msg)

    t0 = time.time()
    build = os.path.join(work, "build", "%s-%s" % (target, opt))
    try:
        if not os.path.exists(os.path.join(build, "layout.json")) or not sanitized:
            build_fw.build(target, opt, build)
    except SystemExit as e:
        fail("build: %s" % e)
        return report
    out_dir = os.path.join(work, name)
    # The sanitized-names runs also split the pseudo-C into many small files,
    # so all GDB checks run against a multi-file export.
    split = ["c_max_lines=%d" % SPLIT_LINES, "c_max_bytes=%d" % SPLIT_BYTES]
    opts = ["skip_decompile=bad?func,shape_skipme"] + (["sanitize_names=true"] + split if sanitized else [])
    ok, notes, text = export_fw.export(build, out_dir, opts)
    report["lines"] += [n for n in notes if not n.startswith("ghidra2dwarf-raw: wrote")]
    if not ok:
        fail("export (see %s/ghidra.log)" % out_dir)
        return report
    elf = os.path.join(out_dir, "out", "fw.bin.elf")
    csrc = os.path.join(out_dir, "out", "fw.bin.src")
    r = subprocess.run(["llvm-dwarfdump", "--verify", elf], capture_output=True, text=True)
    if "No errors." not in r.stdout:
        fail("llvm-dwarfdump --verify:\n" + r.stdout[-2000:])
    if opt == "O1" and not sanitized:
        # parallel decompilation must not change anything: export serially
        # and compare
        same, why = serial_matches(build, out_dir, opts)
        report["counts"]["serial"] = "ok" if same else "differs"
        if not same:
            fail("serial export (decompile_threads=1) differs: " + why)
    if sanitized:
        why = check_split(os.path.join(out_dir, "out", "fw.bin.src"))
        report["counts"]["split"] = why or "ok"
        if why:
            fail("split C files: " + why)
    rt_ok, rt_diffs = roundtrip.roundtrip(out_dir, sanitized)
    report["counts"]["rt"] = "ok" if rt_ok else "%d diffs" % len(rt_diffs)
    if not rt_ok:
        fail("DWARF round trip through Ghidra:\n    " + "\n    ".join(rt_diffs[:30]))
    import json
    with open(os.path.join(build, "layout.json")) as f:
        has_irq = json.load(f).get("irq")
    suites = [("main", "gdb_checks.py"), ("edge", "gdb_edge_checks.py"),
              ("feat", "gdb_feature_checks.py")]
    if has_irq:
        suites.append(("irq", "gdb_irq_checks.py"))
    for label, checks in suites:
        ok, lines, out = run_gdb_test.run(build, elf, csrc, os.path.join(HERE, checks), sanitized)
        summary = [l for l in lines if l.startswith("SUMMARY")]
        report["counts"][label] = summary[0][len("SUMMARY "):] if summary else "no summary"
        shown = [l for l in lines if verbose or l.startswith(("FAIL", "SKIP", "Traceback", "  "))]
        report["lines"] += ["[%s] %s" % (label, l) for l in shown if not l.startswith("SUMMARY")]
        if not ok:
            report["ok"] = False
            if not summary:
                report["lines"].append("[%s] %s" % (label, out[-2000:]))
    if not sanitized:
        # unwinding at every instruction vs GCC's own CFI
        msgs = []
        for start, steps in (("shapes_main", 10000), ("edge_main", 3000)):
            ok, lines = difftrace.difftrace(build, elf, steps, start,
                                            work=os.path.join(out_dir, "out"))
            msgs.append(lines[0])
            if not ok:
                fail("unwinding differs from GCC's CFI (from %s):\n    %s" % (start, "\n    ".join(lines)))
        report["counts"]["diff"] = "ok" if report["ok"] else "; ".join(msgs)
    report["time"] = time.time() - t0
    return report


SPLIT_LINES = 300
SPLIT_BYTES = 20000


def check_split(src):
    """Several .c files, each within the limits unless it holds a single
    (oversized) function, plus the types header."""
    names = sorted(n for n in os.listdir(src) if n.endswith(".c"))
    if len(names) < 2:
        return "expected several .c files, got %s" % names
    if not any(n.endswith(".types.h") for n in os.listdir(src)):
        return "no types header"
    for n in names:
        with open(os.path.join(src, n), "rb") as f:
            data = f.read()
        lines = data.count(b"\n")
        funcs = data.count(b"/* ---- ")
        if (lines > SPLIT_LINES or len(data) > SPLIT_BYTES) and funcs > 1:
            return "%s has %d lines / %d bytes with %d functions" % (n, lines, len(data), funcs)
        if funcs == 0:
            return "%s has no functions" % n
    return None


def serial_matches(build, out_dir, opts):
    sdir = out_dir + "-serial"
    ok, _, _ = export_fw.export(build, sdir, list(opts) + ["decompile_threads=1"])
    if not ok:
        return False, "serial export failed (see %s/ghidra.log)" % sdir
    a, b = os.path.join(out_dir, "out"), os.path.join(sdir, "out")
    for name in sorted(os.listdir(os.path.join(a, "fw.bin.src"))):
        with open(os.path.join(a, "fw.bin.src", name), "rb") as f1, \
                open(os.path.join(b, "fw.bin.src", name), "rb") as f2:
            if f1.read() != f2.read():
                return False, name
    for sec in ("--debug-info", "--debug-loc", "--debug-frame", "--debug-line", "--symbols"):
        outs = []
        for d in (a, b):
            r = subprocess.run(["llvm-dwarfdump" if sec != "--symbols" else "llvm-nm", sec if sec != "--symbols"
                                else "-n", os.path.join(d, "fw.bin.elf")], capture_output=True, text=True)
            outs.append(r.stdout.replace(os.path.dirname(d), "<dir>").split("\n", 1)[-1])
        if outs[0] != outs[1]:
            return False, sec
    return True, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", "--targets", default=",".join(TARGETS))
    ap.add_argument("-O", "--opts", default="O0,O1,O2")
    ap.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 4) // 3))
    ap.add_argument("--work", default=os.path.join(REPO, "work"))
    ap.add_argument("--no-sanitized", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    work = os.path.abspath(a.work)
    targets = a.targets.split(",")
    opts = a.opts.split(",")
    for t in targets:
        if t not in TARGETS:
            sys.exit("unknown target %s (known: %s)" % (t, ", ".join(TARGETS)))

    print("=== writer unit tests")
    r = subprocess.run([sys.executable, os.path.join(HERE, "test_writer.py")], capture_output=True, text=True)
    all_ok = r.returncode == 0
    print("  " + (r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "?"))

    jobs = [(t, o, False) for t in targets for o in opts]
    if not a.no_sanitized and "O1" in opts:
        jobs += [(t, "O1", True) for t in targets]
    # Build each (target, opt) once before the sanitized variant reuses it.
    jobs.sort(key=lambda j: j[2])
    results = {}
    with concurrent.futures.ThreadPoolExecutor(a.jobs) as ex:
        plain = {ex.submit(job, t, o, s, work, a.verbose): (t, o, s) for t, o, s in jobs if not s}
        for f in concurrent.futures.as_completed(plain):
            rep = f.result()
            results[rep["name"]] = rep
            print_report(rep)
        san = {ex.submit(job, t, o, s, work, a.verbose): (t, o, s) for t, o, s in jobs if s}
        for f in concurrent.futures.as_completed(san):
            rep = f.result()
            results[rep["name"]] = rep
            print_report(rep)

    # the GUI options dialog (headless, with askValues stubbed), once
    proj = next((os.path.join(work, n, "project") for n in sorted(results)
                 if os.path.isdir(os.path.join(work, n, "project"))), None)
    if proj is not None:
        ghidra = os.environ.get("GHIDRA_INSTALL_DIR", os.path.join(os.path.dirname(REPO), "ghidra_12.2_PUBLIC"))
        scratch = os.path.join(work, "gui-check")
        os.makedirs(scratch, exist_ok=True)
        r = subprocess.run([os.path.join(ghidra, "support", "pyghidraRun"), "-H", proj, "fwtest", "-process",
                            "fw.bin", "-noanalysis", "-readOnly", "-postScript",
                            os.path.join(HERE, "check_gui_options.py"), scratch],
                           input="y\n", capture_output=True, text=True)
        summary = [l for l in r.stdout.splitlines() if l.startswith("GUI SUMMARY")]
        gui_ok = bool(summary) and " 0 failed" in summary[0]
        all_ok &= gui_ok
        print("=== GUI options dialog: %s" % (summary[0][len("GUI SUMMARY "):] if summary else "no result"))
        for l in r.stdout.splitlines():
            if l.startswith("GUI FAIL") or "Traceback" in l:
                print("  " + l)

    print("\n=== summary")
    for name in sorted(results):
        rep = results[name]
        all_ok &= rep["ok"]
        print("  %-28s %-4s main: %-22s edge: %-22s%s" % (
            name, "ok" if rep["ok"] else "FAIL", rep["counts"].get("main", "-"),
            rep["counts"].get("edge", "-"),
            " feat: " + rep["counts"].get("feat", "-") + " rt: " + rep["counts"].get("rt", "-")
            + " diff: " + ("ok" if rep["counts"].get("diff") == "ok" else rep["counts"].get("diff", "-"))
            + ((" split: " + rep["counts"]["split"]) if "split" in rep["counts"] else "")
            + ((" irq: " + rep["counts"]["irq"]) if "irq" in rep["counts"] else "")))
    print("ALL TESTS PASSED" if all_ok else "SOME TESTS FAILED")
    return 0 if all_ok else 1


def print_report(rep):
    print("=== %s: %s (%.0fs)" % (rep["name"], "ok" if rep["ok"] else "FAIL", rep.get("time", 0)))
    for l in rep["lines"]:
        print("  " + l)
    sys.stdout.flush()


if __name__ == "__main__":
    sys.exit(main())
