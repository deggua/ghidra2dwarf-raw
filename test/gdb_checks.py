"""GDB-side checks (run inside gdb-multiarch via -x).

Expects these convenience settings from the runner (via -ex):
    set $port = <qemu gdbstub port>
and the env vars ELF (exported symbol file) and CSRC (generated C file).

Every expectation is derived from the semantics of test/firmware/main.c.
Prints "PASS <name>" / "FAIL <name>: <why>" lines and a final summary.
"""

import os
import re
import traceback

import gdb

ELF = os.environ["ELF"]
CSRC = os.environ["CSRC"]
PORT = int(os.environ["QEMU_PORT"])

results = []


def run(cmd):
    return gdb.execute(cmd, to_string=True)


def val(expr):
    return gdb.parse_and_eval(expr)


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS %s" % name) if cond else ("FAIL %s: %s" % (name, detail)))


def check_eq(name, expr, expected):
    try:
        v = val(expr)
        if v.is_optimized_out:
            check(name, False, "%s is <optimized out>, expected %r" % (expr, expected))
            return
        if isinstance(expected, float):
            got = float(v)
            ok = abs(got - expected) < 1e-6
        elif isinstance(expected, str):
            got = v.string() if v.type.strip_typedefs().code in (gdb.TYPE_CODE_ARRAY, gdb.TYPE_CODE_PTR) else str(v)
            ok = got == expected
        else:
            got = int(v)
            ok = got == expected
        check(name, ok, "%s = %r, expected %r" % (expr, got, expected))
    except gdb.error as e:
        check(name, False, "%s: %s" % (expr, e))


def finish_value():
    """Runs 'finish' and returns the returned value (None if none)."""
    run("p 0x5eed5eed")
    sentinel = gdb.history(0)
    run("finish")
    v = gdb.history(0)
    if int(v) == int(sentinel) and str(v.type) == str(sentinel.type):
        return None
    return int(v)


def check_finish(name, expected):
    try:
        got = finish_value()
    except gdb.error as e:
        check(name, False, str(e))
        return
    check(name, got == expected, "returned %r, expected %r" % (got, expected))


def frame_names():
    names = []
    f = gdb.newest_frame()
    while f is not None:
        names.append(f.name())
        f = f.older()
    return names


def cont_to(bp_spec, cond=None):
    for b in gdb.breakpoints() or []:
        b.delete()
    b = gdb.Breakpoint(bp_spec, temporary=True)
    if cond:
        b.condition = cond
    run("continue")
    return gdb.selected_frame()


def line_of(pattern, after=None):
    """First line number in the C file matching regex (after a line no)."""
    with open(CSRC) as f:
        for i, line in enumerate(f, 1):
            if (after is None or i > after) and re.search(pattern, line):
                return i
    raise KeyError(pattern)


def main():
    run("set pagination off")
    run("set confirm off")
    run("symbol-file " + ELF)
    run("target remote :%d" % PORT)

    # --- static info ---------------------------------------------------------
    out = run("list sensor_update")
    check("list shows decompiled source", "sensor_update(sensor_t *s,int sample)" in out, out)
    out = run("ptype sensor_t")
    check("ptype struct with bitfields",
          "uint8_t enabled : 1;" in out and "uint8_t channel : 3;" in out
          and "struct sensor *next;" in out and "filter_fn filter;" in out, out)
    out = run("ptype enum mode")
    check("ptype enum", "MODE_FAULT" in out and "MODE_CALIBRATE" in out, out)
    out = run("info line *0xfff00350")
    check("info line maps into C file", os.path.basename(CSRC) in out, out)
    check("reset frame has a symbol", gdb.selected_frame().name() == "_reset", gdb.selected_frame().name())

    # --- recursion: fact(5) -> ... -> fact(1) ----------------------------------
    cont_to("fact", "n == 1")
    names = frame_names()
    check("recursive backtrace", names[:6] == ["fact"] * 5 + ["fw_main"], names)
    check("backtrace reaches entry point", names[-1] == "_reset", names)
    out = run("bt")
    check("backtrace ends cleanly", "Backtrace stopped" not in out, out)
    check_eq("fact n", "n", 1)
    run("frame 1")
    check_eq("fact caller frame n (callee-saved reg)", "n", 2)
    run("frame 4")
    check_eq("fact outermost frame n", "n", 5)
    run("frame 0")
    check_finish("finish returns fact(1)", 1)

    # --- 64-bit args in register pairs ---------------------------------------
    cont_to("mul64")
    check_eq("int64 arg a (r3:r4 pieces)", "a", 0x100000000)
    check_eq("int64 arg b", "b", 3)
    check_finish("finish returns int64", 0x300000001)

    # --- stack-passed args ------------------------------------------------------
    cont_to("many_args")
    for i, n in enumerate("abcdefghij", 1):
        check_eq("many_args %s" % n, n, i)
    check_finish("finish returns many_args", 385)

    # --- clamp via filter_double via indirect call ---------------------------
    cont_to("clamp")
    check_eq("clamp v", "v", 514)
    check_eq("clamp lo", "lo", -1000)
    check_eq("clamp hi", "hi", 1000)
    names = frame_names()
    check("backtrace through indirect call",
          names[:7] == ["clamp", "filter_double", "sensor_update", "process_all",
                        "fw_main", "_cstart", "_reset"], names)
    run("frame 2")
    check_eq("caller frame: sensor_update s", "s", int(val("&g_sensors[0]")))
    check_eq("caller frame: s->id", "s->id", 0x101)
    run("frame 3")
    check_eq("caller frame: process_all list", "list", int(val("&g_sensors[0]")))
    run("frame 4")
    check_eq("caller frame: fw_main round", "round", 0)
    run("frame 0")
    check_finish("finish returns clamp", 514)

    # --- update_stats: struct pointer arg, float result -----------------------
    cont_to("update_stats")
    check_eq("update_stats st", "st", int(val("&g_stats")))
    check_eq("update_stats v", "v", 514)
    check_eq("st->min before", "st->min", 0x7fffffff)
    run("finish")
    check_eq("g_stats.total", "g_stats.total", 514)
    check_eq("g_stats.min", "g_stats.min", 514)
    check_eq("g_stats.last.f", "g_stats.last.f", 129.0)

    # --- conditional breakpoint on a struct pointer, stepping -----------------
    cont_to("sensor_update", "s == &g_sensors[1]")
    check_eq("sensor[1] sample", "sample", 0x202)
    check_eq("s->name", "s->name", "press")
    check_eq("s->channel bitfield", "s->channel", 5)
    check_eq("s->enabled bitfield", "s->enabled", 1)
    check("s->mode enum", str(val("s->mode")) == "MODE_IDLE", str(val("s->mode")))
    check_eq("s->pos.x", "s->pos.x", -3)
    call_line = line_of(r"sample = \(\*s->filter\)\(sample\);")
    sal = gdb.selected_frame().find_sal()
    run("next")
    sal = gdb.selected_frame().find_sal()
    check("next steps to the call line", sal.line == call_line, "at line %d, expected %d" % (sal.line, call_line))
    run("step")
    check("step into indirect call target", gdb.selected_frame().name() == "filter_offset",
          gdb.selected_frame().name())
    check_eq("filter_offset v", "v", 0x202)
    run("finish")
    run("next")
    check_eq("sample after filter", "sample", 0x202 + 100)
    check_eq("s still valid after call (r31)", "s->id", 0x202)

    # --- end state -------------------------------------------------------------
    for b in gdb.breakpoints() or []:
        b.delete()
    fw_main_line = line_of(r"^void fw_main\(void\)")
    loop_line = line_of(r"WARNING: Do nothing block with infinite loop", fw_main_line) - 1
    cont_to("%s:%d" % (os.path.basename(CSRC), loop_line))
    check("stopped in final loop", gdb.selected_frame().name() == "fw_main", gdb.selected_frame().name())
    run("stepi 40")
    check_eq("g_result[0] fact(5)", "g_result[0]", 120)
    check_eq("g_result[1] checksum", "g_result[1]", -45536819)
    check_eq("g_result[2] mul64", "g_result[2]", 1)
    check_eq("g_result[3] many_args", "g_result[3]", 385)
    check_eq("g_result[4] process_all", "g_result[4]", 2)
    check_eq("g_result[5] sum_history", "g_result[5]", 514 + 534 + 554)
    check_eq("g_result[6] counter", "g_result[6]", 8)
    check_eq("g_result[7] marker", "g_result[7]", 0x600d)
    check_eq("g_sensors[0].history[2]", "g_sensors[0].history[2]", 554)
    check_eq("g_sensor_list->next->next->name", "g_sensor_list->next->next->name", "volt")
    check_eq("g_banner", "g_banner", "fw-test")
    check_eq("g_counter", "g_counter", 8)


try:
    main()
except Exception:
    traceback.print_exc()
    results.append(("exception", False))
    print("FAIL exception")

failed = [n for n, ok in results if not ok]
print("SUMMARY %d passed, %d failed" % (len(results) - len(failed), len(failed)))
gdb.execute("kill")
