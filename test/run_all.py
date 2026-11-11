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
    opts = ["skip_decompile=bad?func"] + (["sanitize_names=true"] if sanitized else [])
    ok, notes, text = export_fw.export(build, out_dir, opts)
    report["lines"] += [n for n in notes if not n.startswith("ghidra2dwarf-raw: wrote")]
    if not ok:
        fail("export (see %s/ghidra.log)" % out_dir)
        return report
    elf = os.path.join(out_dir, "out", "fw.bin.elf")
    csrc = os.path.join(out_dir, "out", "fw.bin.c")
    r = subprocess.run(["llvm-dwarfdump", "--verify", elf], capture_output=True, text=True)
    if "No errors." not in r.stdout:
        fail("llvm-dwarfdump --verify:\n" + r.stdout[-2000:])
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
    report["time"] = time.time() - t0
    return report


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

    print("\n=== summary")
    for name in sorted(results):
        rep = results[name]
        all_ok &= rep["ok"]
        print("  %-28s %-4s main: %-22s edge: %-22s%s" % (
            name, "ok" if rep["ok"] else "FAIL", rep["counts"].get("main", "-"),
            rep["counts"].get("edge", "-"),
            " feat: " + rep["counts"].get("feat", "-") + " rt: " + rep["counts"].get("rt", "-")
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
