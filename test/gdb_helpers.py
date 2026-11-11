"""Helpers shared by the GDB-side check scripts (imported inside GDB)."""

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
    if str(v.type) == str(sentinel.type) and int(v) == int(sentinel):
        return None
    return v


def check_finish(name, expected):
    try:
        got = finish_value()
    except gdb.error as e:
        check(name, False, str(e))
        return
    if got is not None:
        got = float(got) if isinstance(expected, float) else int(got)
    ok = got is not None and (abs(got - expected) < 1e-9 if isinstance(expected, float) else got == expected)
    check(name, ok, "returned %r, expected %r" % (got, expected))


def select_frame(name):
    """Select the newest frame of function `name`."""
    f = gdb.newest_frame()
    while f is not None:
        if f.name() == name:
            f.select()
            return True
        f = f.older()
    check("frame %s exists" % name, False, "no frame for %s in %s" % (name, frame_names()))
    return False


def frame_names():
    names = []
    f = gdb.newest_frame()
    while f is not None:
        names.append(f.name())
        f = f.older()
    return names


BACKSTOP = []


def cont_to(bp_spec, cond=None):
    """Continue to a breakpoint. A backstop breakpoint on the firmware's
    final idle loop turns "never hit" into a failure instead of a hang."""
    for b in gdb.breakpoints() or []:
        b.delete()
    b = gdb.Breakpoint(bp_spec, temporary=True)
    if cond:
        b.condition = cond
    for spec in BACKSTOP:
        gdb.Breakpoint(spec, internal=True)
    run("continue")
    f = gdb.selected_frame()
    if BACKSTOP and bp_spec not in BACKSTOP and f.find_sal().line == BACKSTOP_LINE[0]:
        raise RuntimeError("never reached %s (ran to the idle loop)" % bp_spec)
    return f


BACKSTOP_LINE = []


def func_text(name):
    """Decompiled text of a function in the C file."""
    with open(CSRC) as f:
        text = f.read()
    m = re.search(r"/\* ---- %s @ [0-9a-f]+ ---- \*/(.*?)(?=/\* ---- |\Z)" % re.escape(name), text, re.S)
    return m.group(1) if m else ""


def line_of(pattern, after=None):
    """First line number in the C file matching regex (after a line no)."""
    with open(CSRC) as f:
        for i, line in enumerate(f, 1):
            if (after is None or i > after) and re.search(pattern, line):
                return i
    raise KeyError(pattern)


def setup_session():
    run("set pagination off")
    run("set confirm off")
    run("set charset UTF-8")
    run("symbol-file " + ELF)
    run("target remote :%d" % PORT)
    fw_main_line = line_of(r"^void fw_main\(void\)")
    loop_line = line_of(r"WARNING: Do nothing block with infinite loop", fw_main_line) - 1
    BACKSTOP.append("%s:%d" % (os.path.basename(CSRC), loop_line))
    BACKSTOP_LINE.append(loop_line)


def run_checks(main):
    try:
        main()
    except Exception:
        traceback.print_exc()
        results.append(("exception", False))
        print("FAIL exception")
    failed = [n for n, ok in results if not ok]
    print("SUMMARY %d passed, %d failed" % (len(results) - len(failed), len(failed)))
    gdb.execute("kill")
