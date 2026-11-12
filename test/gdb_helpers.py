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
        try:
            f = f.older()
        except gdb.error as e:
            names.append("<error: %s>" % e)
            break
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
    sal = f.find_sal()
    if (BACKSTOP and bp_spec not in BACKSTOP and sal.line == BACKSTOP_LINE[0] and sal.symtab is not None
            and os.path.basename(sal.symtab.filename) == os.path.basename(BACKSTOP_LINE[0].path)):
        raise RuntimeError("never reached %s (ran to the idle loop)" % bp_spec)
    return f


BACKSTOP_LINE = []


# CSRC is the exported source directory (<basename>.src): the pseudo-C is
# split over <basename>.<N>.c files, the types are in <basename>.types.h.
def _src_files():
    if os.path.isfile(CSRC):
        return [CSRC]
    names = [n for n in os.listdir(CSRC) if n.endswith(".c")]
    names.sort(key=lambda n: int(n.rsplit(".", 2)[-2]))
    return [os.path.join(CSRC, n) for n in names]


SRC_FILES = _src_files()
SRC_NAMES = [os.path.basename(f) for f in SRC_FILES]
_TEXT = {}


def _read(path):
    if path not in _TEXT:
        with open(path, encoding="utf-8") as f:
            _TEXT[path] = f.read()
    return _TEXT[path]


def all_source_text():
    """All generated source text (C files and the types header)."""
    paths = list(SRC_FILES)
    if os.path.isdir(CSRC):
        paths += [os.path.join(CSRC, n) for n in sorted(os.listdir(CSRC)) if n.endswith(".h")]
    return "\n".join(_read(p) for p in paths)


class Line(int):
    """A line number in one of the generated C files (compares as int)."""

    def __new__(cls, n, path):
        o = int.__new__(cls, n)
        o.path = path
        return o

    def __add__(self, k):
        return Line(int(self) + k, self.path)

    def __sub__(self, k):
        return Line(int(self) - k, self.path)


def spec(line):
    """GDB location "file:line" for a Line."""
    return "%s:%d" % (os.path.basename(line.path), line)


def func_text(name):
    """Decompiled text of a function in the C files."""
    for path in SRC_FILES:
        m = re.search(r"/\* ---- %s @ [0-9a-f]+ ---- \*/(.*?)(?=/\* ---- |\Z)" % re.escape(name),
                      _read(path), re.S)
        if m:
            return m.group(1)
    return ""


def _lines(path):
    return _read(path).split("\n")


def source_line(sal):
    """Text of a symtab-and-line's line in the generated C files."""
    if sal is None or sal.symtab is None:
        return ""
    for path in SRC_FILES:
        if os.path.basename(path) == os.path.basename(sal.symtab.filename):
            lines = _lines(path)
            return lines[sal.line - 1] if 0 < sal.line <= len(lines) else ""
    return ""


def line_of(pattern, after=None):
    """First line in the C files matching regex (after a Line)."""
    start = SRC_FILES.index(after.path) if isinstance(after, Line) else 0
    for fi in range(start, len(SRC_FILES)):
        for i, line in enumerate(_lines(SRC_FILES[fi]), 1):
            if fi == start and after is not None and i <= after:
                continue
            if re.search(pattern, line):
                return Line(i, SRC_FILES[fi])
    raise KeyError(pattern)


def setup_session():
    run("set pagination off")
    run("set confirm off")
    run("set charset UTF-8")
    # Load the exported ELF as both the executable and the symbol file: with
    # QEMU user mode GDB would otherwise fetch the running (reference) ELF from
    # the stub and use its real debug info instead of ours.
    run("set exec-file-mismatch off")
    run("set sysroot /nonexistent")
    run("file " + ELF)
    run("set tcp auto-retry on")
    run("set tcp connect-timeout 20")
    run("target remote :%d" % PORT)
    files = run("info files")
    if os.path.basename(ELF) not in files or "fw.elf" in files.replace(os.path.basename(ELF), ""):
        raise RuntimeError("GDB is not using the exported ELF:\n" + files)
    if "producer" in run("info source") and "GNU C" in run("info source"):
        raise RuntimeError("GCC debug info leaked into the session")
    fw_main_line = line_of(r"^void (?:__\w+ )?fw_main\(void\)")
    try:
        loop_line = line_of(r"WARNING: Do nothing block with infinite loop", fw_main_line) - 1
    except KeyError:
        # the idle loop's stores are visible: "do { ... } while( true );"
        end = line_of(r"^\s*\} while\( true \);", fw_main_line)
        loop_line = Line(max(i for i in range(fw_main_line, end)
                             if re.match(r"^\s*do \{", _lines(fw_main_line.path)[i - 1])), fw_main_line.path)
    BACKSTOP.append(spec(loop_line))
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
