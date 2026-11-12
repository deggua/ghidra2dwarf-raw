"""GDB-side checks for the edge cases (test/firmware/edge.c +
test/ghidra_setup_edge.py). Run inside gdb-multiarch via -x.

Env: ELF, CSRC, QEMU_PORT, and SANITIZED=1 if the export used
sanitize_names=true (names are then plain C identifiers).
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gdb_helpers import *  # noqa: E402,F401,F403

SANITIZED = os.environ.get("SANITIZED") == "1"


def N(verbatim, sanitized):
    """Expected exported name in the current naming mode."""
    return sanitized if SANITIZED else verbatim


def Q(name):
    """How to write a name in a GDB expression."""
    return name if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name) else "'%s'" % name


GET_VALUE = N("Get?Value", "Get_Value")
P_ARG = N("p?arg", "p_arg")
FOO_INIT = N("Foo::init", "Foo__init")
BAR_INIT = N("Bar::init", "Bar__init")
G_THING = N("g?thing", "g_thing")
THING_T = N("Thing?Info", "Thing_Info")
FIELD1 = N("field?1", "field_1")
FOO_COUNTER = N("Foo::counter", "Foo__counter")
BAR_COUNTER = N("Bar::counter", "Bar__counter")
KW = N("switch", "switch_")
UNI = N("größe", "gr__e")
UNTYPED = N("untyped?label", "untyped_label")
BAD = N("bad?func", "bad_func")
LOC = N("loc?", "loc_")


def _unused_vector_regs_misread(var, expected):
    """True if GDB reads `var` wrong although its location is an x86 xmm
    register that does hold the expected value (GDB numbers QEMU user-mode's
    x86-64 registers differently from its DWARF register mapping)."""
    try:
        if abs(float(val(var)) - expected) < 1e-9:
            return False
        where = run("info address %s" % var)
        m = re.search(r"\$(xmm\d+)", where)
        return bool(m) and abs(float(val("$%s.v4_float[0]" % m.group(1))) - expected) < 1e-9
    except gdb.error:
        return False


def check_correct_or_unavailable(name, expr, expected):
    """A value may legitimately be <optimized out>, but never wrong."""
    try:
        v = val(expr)
        if v.is_optimized_out:
            print("SKIP %s (<optimized out>)" % name)
            return
        check(name, int(v) == expected, "%s = %s, expected %s" % (expr, v, expected))
    except gdb.error as e:
        check(name, False, "%s: %s" % (expr, e))


def check_full_backtrace(label, must_contain):
    names = frame_names()
    check("%s: backtrace %s" % (label, " <- ".join(must_contain)),
          all(n in names for n in must_contain) and names[-1] == "_reset", names)
    out = run("bt")
    check("%s: backtrace ends cleanly" % label, "Backtrace stopped" not in out, out)


def check_shapes():
    """Code shapes from the adversarial review (firmware/shapes.c)."""
    # conditional return before the frame setup (PPC blelr, ARM bxls lr)
    cont_to("shape_swap")
    check_full_backtrace("qsort", ["shape_swap", "shape_qsort", "shapes_main", "edge_main"])
    select_frame("shape_qsort")
    check_correct_or_unavailable("qsort n (caller frame)", "n", 10)
    check_correct_or_unavailable("qsort a (caller frame)", "a", int(val("&g_shape_arr[0]")))
    cont_to("shape_qsort", "n > 1 && n < 10")
    names = frame_names()
    check("recursive qsort: two qsort frames", names.count("shape_qsort") >= 2, names)
    check_full_backtrace("recursive qsort", ["shape_qsort", "shapes_main"])

    # conditional epilogue (ARM "pople {..,pc}")
    cont_to("shape_fib", "n == 1")
    check_full_backtrace("fib", ["shape_fib", "shapes_main"])
    check("fib: recursion frames", frame_names().count("shape_fib") >= 3, frame_names())
    # a caller frame shows the line of the call (MIPS: the PC is in the delay
    # slot after the jal)
    if re.search(r"\bshape_fib\(", func_text("shape_fib").split("{", 1)[-1]):
        f1 = gdb.newest_frame().older()
        text = source_line(f1.find_sal() if f1 is not None else None)
        check("caller frame shows the call's line", "shape_fib(" in text, text)
    else:
        # (PPC64 ELFv2 -O0: the decompiler turns the recursive calls to the
        # local entry point into a loop)
        print("SKIP caller frame line (no call in the decompiled shape_fib)")

    # conditional move into a callee-saved register
    cont_to("shape_leaf", "v == 77")
    check_full_backtrace("csel", ["shape_leaf", "shape_csel", "shapes_main"])
    select_frame("shape_csel")
    check_correct_or_unavailable("csel b (conditionally moved)", "b", 77)
    check_correct_or_unavailable("csel a", "a", 0)

    # 40 KB frame
    cont_to("shape_leaf", "v == 5")
    check_full_backtrace("40 KB frame", ["shape_leaf", "shape_big", "shapes_main"])
    select_frame("shape_big")
    check_correct_or_unavailable("big frame n", "n", 5)

    # arguments copied into a stack object that the callee modifies
    cont_to("shape_leaf", "v == 1035")
    check_full_backtrace("alias", ["shape_leaf", "shape_alias", "shapes_main"])
    select_frame("shape_alias")
    check_correct_or_unavailable("alias id after mutate(&m)", "id", 42)
    check_correct_or_unavailable("alias val after mutate(&m)", "val", 7)
    ret_addr = int(gdb.newest_frame().older().pc()) if gdb.newest_frame().older() else None
    bogus = []
    b = gdb.selected_frame().block()
    while b is not None and b.function is None:
        for sym in b:
            try:
                v = sym.value(gdb.selected_frame())
                if not v.is_optimized_out and v.type.strip_typedefs().code == gdb.TYPE_CODE_INT \
                        and (int(v) & 0xffffffff) == ((ret_addr or -1) & 0xffffffff):
                    bogus.append(sym.name)
            except gdb.error:
                pass
        b = b.superblock
    check("alias: no local shows the return address (decompiler temporaries)", not bogus, bogus)

    # a store as the first instruction
    cont_to("shape_poke")
    check_eq("poke: breakpoint before the first store", "g_poke", 0x1111)

    # over-aligned stack
    cont_to("shape_leaf", "v == 9")
    names = frame_names()
    ok = "shape_align" in names and "shapes_main" in names
    if not ok and os.environ.get("TARGET_ARCH", "") == "x86_32":
        # README limitation: realigned i386 frames are left to GDB's
        # prologue analyzer, which needs the (call-clobbered) DRAP register
        print("SKIP aligned stack caller frames on i386 (known limitation): %s" % names)
    else:
        check("aligned stack: caller frames", ok, names)

    # thunk (-O1/-O2: "b shape_leaf"): its own one-line body, not the callee's
    text = func_text("shape_wrap")
    check("thunk/wrapper body is not the callee's", "g_shape_sink" not in text, text)
    cont_to("shape_wrap")
    check_correct_or_unavailable("thunk/wrapper parameter", "v", 20)


def check_fp(name, expr, func):
    """A function pointer is right (its symbol, also through a PPC64 ELFv1
    descriptor) or unavailable."""
    try:
        v = val(expr)
        if v.is_optimized_out:
            print("SKIP %s (<optimized out>)" % name)
            return
        out = run("info symbol 0x%x" % (int(v) & 0xffffffffffffffff))
        check(name, out.split()[0] == func if out.strip() else False, out)
    except gdb.error as e:
        check(name, False, str(e))


def check_shapes_2():
    """Shapes from the second review (firmware/shapes.c)."""
    # early return through a non-contiguous decompiler block: the variable
    # holding shape_copy_to's result must not show the old (lookup) value
    m = re.search(r"\b(\w+) = shape_copy_to\(", func_text("shape_build"))
    cont_to("shape_fill")
    dst = int(val("dst"))
    check_full_backtrace("early-return shape", ["shape_fill", "shape_build", "shapes_main"])
    if m:
        select_frame("shape_build")
        check_correct_or_unavailable("copy_to result in the caller (%s)" % m.group(1), m.group(1), dst - 1)
    else:
        print("SKIP copy_to result (no variable assigned from shape_copy_to)")

    # the shared epilogue belongs to the final "return", not the early one
    start = line_of(r"^\w[\w *]* (?:__\w+ )?shape_build\(")
    rets = [l for l in func_text("shape_build").split("\n") if re.match(r"^\s*return\b", l)]
    if len(rets) > 1:
        last = line_of("^" + re.escape(rets[-1]) + "$", start)
        try:
            sals = gdb.decode_line(spec(last))[1] or []
        except gdb.error:
            sals = []
        where = [gdb.current_progspace().block_for_pc(int(x.pc)).function for x in sals]
        check("final return line has code in its function",
              any(w is not None and w.name == "shape_build" for w in where), [str(w) for w in where])
    else:
        print("SKIP final return line (one return in the decompiled shape_build)")

    # indirect calls: caller-frame values right or unavailable (MIPS: delay
    # slots must not be analyzed as unreached code)
    cont_to("shape_helper3", "x == 7")
    select_frame("shape_two")
    check_fp("indirect-call caller: fp", "fp", "shape_cb")
    out = run("ptype fp")
    check("function-pointer parameter type", "int (*)(int)" in out, out)
    check_correct_or_unavailable("indirect-call caller: n", "n", 1234)
    check_correct_or_unavailable("indirect-call caller: flag", "flag", 7)
    for _ in range(3):
        cont_to("shape_cb2")
    check_full_backtrace("loop of indirect calls", ["shape_cb2", "shape_loop3", "shapes_main"])
    select_frame("shape_loop3")
    check_fp("loop caller: fp", "fp", "shape_cb2")
    check_correct_or_unavailable("loop caller: n", "n", 5)

    # computed goto through a table in RAM, cases analyzed from the jump
    cont_to("shape_helper3", "x == 13")
    names = frame_names()
    check("indirect tail call from a computed-goto function: backtrace",
          "shapes_main" in names and names[-1] == "_reset", names)
    cont_to("shape_dhelper")
    check_full_backtrace("computed-goto case", ["shape_dhelper", "shape_disp", "shapes_main"])
    cont_to("shape_dhelper")
    check_full_backtrace("computed-goto case 68", ["shape_dhelper", "shape_disp", "shapes_main"])

    # a function exported without decompilation (skip_decompile) still has
    # its prototype's parameters
    cont_to("shape_skipme")
    check_correct_or_unavailable("skipped function parameter s[0]", "s[0]", ord("c"))
    check_correct_or_unavailable("skipped function parameter *p", "*p", 7)
    out = run("info args")
    check("skipped function lists its parameters", "s = " in out and "p = " in out, out)


def _assigned(func, callee):
    """{argument text: variable} for the "var = callee(args);" lines of func."""
    found = {}
    for m in re.finditer(r"\b(\w+) = (?:\([\w ]+\))?%s\(([^;]*)\);" % callee, func_text(func)):
        found[m.group(2).strip()] = m.group(1)
    return found


def check_kept_results(func, callee, leaf_v, expected, is_float):
    """Call results (a register pair, an FPR) stored in variables and kept
    across the next call: right or unavailable, while in that call."""
    cont_to("shape_leaf", "v == %d" % leaf_v)
    check_full_backtrace(func, ["shape_leaf", func, "shapes_main"])
    select_frame(func)
    found = _assigned(func, callee)
    if not found:
        print("SKIP %s results (no variable assigned from %s)" % (func, callee))
    for arg, var in sorted(found.items()):
        name = "%s: %s = %s(%s) after the next call" % (func, var, callee, arg)
        exp = expected.get(arg)
        try:
            v = val(var)
            if v.is_optimized_out:
                print("SKIP %s (<optimized out>)" % name)
                continue
            if is_float:
                got = float(v)
                ok = any(abs(got - e) < 1e-6 for e in ([exp] if exp is not None else expected.values()))
            else:
                mask = (1 << (8 * v.type.sizeof)) - 1
                got = int(v) & mask
                ok = got in [e & mask for e in ([exp] if exp is not None else expected.values())]
            check(name, ok, "%s = %r, expected %r" % (var, got, exp if exp is not None else expected))
        except gdb.error as e:
            check(name, False, "%s: %s" % (var, e))


def step_lines(func, cond):
    """Stops at func (if cond), steps it with nexti until it returns; the
    (line, text) shown at each instruction."""
    cont_to(func, cond)
    seen = []
    for _ in range(3000):
        f = gdb.selected_frame()
        if f.name() != func:
            break
        sal = f.find_sal()
        seen.append((sal.line, source_line(sal).strip()))
        run("nexti")
    return seen


def func_lines(func):
    """[(file line, text)] of a function in the C files."""
    first = line_of(r"/\* ---- %s @ [0-9a-f]+ ---- \*/" % re.escape(func))
    return [(first + i, t) for i, t in enumerate(func_text(func).split("\n"))]


def check_shapes_3():
    """Shapes from the third review (firmware/shapes.c)."""
    # call results kept across a call: a 64-bit result in a register pair,
    # a float result in an FPR
    check_kept_results("shape_keepll", "shape_get64", 6, {"a": (4 << 32) | 5, "a + 1": (5 << 32) | 6}, False)
    check_finish("finish shape_keepll (64-bit return)", (1 << 32) | 3)
    if os.environ.get("FP_ARGS_OK", "1") == "1":
        check_kept_results("shape_keepf", "shape_getf", 4, {"a": 3.0, "a + 1": 4.5}, True)
    else:
        print("SKIP float results (unreadable in this GDB+QEMU setup even with GCC's DWARF)")
        cont_to("shape_leaf", "v == 4")
        select_frame("shape_keepf")
    if os.environ.get("FP_RET_OK", "1") == "1":
        check_finish("finish shape_keepf (float return)", 7.5)

    # an early return in a loop: the shared return code is never shown as
    # the early "return -1;" on the normal path
    seen = step_lines("shape_phi3", None)
    texts = [t for _, t in seen]
    check("phi3: stepped through the function", len(seen) > 5, texts)
    bad = [t for t in texts if re.match(r"^return -1;", t)]
    check("phi3: early return never shown on the normal path", not bad, texts)

    # switch: a breakpoint or stop on a case's statements is in that case;
    # case labels have no code of their own
    owner = {}
    depth, sw_depth, cur = 0, None, None
    for ln, t in func_lines("shape_switch"):
        m = re.match(r"^\s*(?:case (\w+)|(default)):", t)
        if sw_depth is not None and m:
            cur = m.group(1) or "default"
            owner[ln] = ("label", cur)
        elif cur is not None:
            owner[ln] = ("case", cur)
        if re.match(r"^\s*switch\s*\(", t):
            sw_depth = depth
        depth += t.count("{") - t.count("}")
        if sw_depth is not None and depth <= sw_depth and cur is not None:
            owner.pop(ln, None)
            sw_depth, cur = None, None
    if not any(kind == "label" for kind, _ in owner.values()):
        print("SKIP switch cases (no switch in the decompiled shape_switch)")
        return
    for k in (1, 2, 3, 6):
        seen = step_lines("shape_switch", "op == %d" % k)
        mine = [t for ln, t in seen if owner.get(ln) == ("case", str(k))]
        other = [(ln, t) for ln, t in seen if ln in owner and owner[ln][0] == "case" and owner[ln][1] != str(k)]
        labels = [(ln, t) for ln, t in seen if owner.get(ln, ("",))[0] == "label"]
        check("switch op=%d: its case's statements are shown" % k, mine, seen)
        check("switch op=%d: no other case's statement shown" % k, not other, other)
        check("switch op=%d: case labels have no code" % k, not labels, labels)


def main():
    setup_session()

    # --- names in the generated C match the DWARF names ---------------------
    csrc = all_source_text()
    check("C file uses exported function name",
          re.search(r"int (?:__\w+ )?%s\(int %s\)" % (re.escape(GET_VALUE), re.escape(P_ARG)), csrc) is not None)
    check("C file uses exported namespaced name", "%s(10)" % FOO_INIT in csrc)
    check("C file uses exported type name", "struct %s" % THING_T in csrc)
    check("no unquotable quote left in C names", "it's" not in csrc)
    if SANITIZED:
        m = re.search(r"\b\w+\?\w*\b", csrc)
        check("sanitized C files have no '?' identifiers", m is None, m.group(0) if m else "")
    # prototypes the exporter writes itself keep pointer declarators
    m = re.search(r"shape_skipme\(([^)]*)\)", csrc)
    check("written prototype keeps pointer types", m is not None and re.search(r"char \*\s*s\b", m.group(1))
          and re.search(r"int \*\s*p\b", m.group(1)) and "__" not in m.group(1), m.group(0) if m else csrc[:0])

    # --- name with '?': function + parameter -----------------------------------
    cont_to(GET_VALUE)  # breakpoint location syntax: no quoting needed
    check("break on name with '?'", gdb.selected_frame().name() == GET_VALUE, gdb.selected_frame().name())
    check_eq("parameter with '?'", Q(P_ARG), 5)
    out = run("info args")
    check("info args shows '?' name", "%s = 5" % P_ARG in out, out)
    check_finish("finish %s" % GET_VALUE, 16)

    # --- namespaced duplicate names --------------------------------------------
    cont_to(FOO_INIT)
    check("namespaced function frame name", gdb.selected_frame().name() == FOO_INIT, gdb.selected_frame().name())
    check_eq("Foo::init x", "x", 10)
    check_finish("finish Foo::init", 11)
    cont_to("'%s'" % BAR_INIT)
    check("second namespaced function", gdb.selected_frame().name() == BAR_INIT, gdb.selected_frame().name())
    check_finish("finish Bar::init", 12)

    # --- varargs -------------------------------------------------------------------
    out = run("ptype sum_va")
    check("varargs prototype", "..." in out, out)
    cont_to("sum_va")
    check_eq("varargs fixed arg", "n", 3)
    check_finish("finish sum_va", 60)

    # --- struct return (hidden pointer) ----------------------------------------
    cont_to("make_point")
    check_eq("make_point x", "x", 3)
    check_eq("make_point y", "y", -4)

    # --- float / double args and return ----------------------------------------
    cont_to("mix")
    check_eq("int arg", "c", 3)
    if os.environ.get("FP_ARGS_OK", "1") == "1":
        check_eq("float arg in FPR", "a", 1.5)
        check_eq("double arg in FPR", "b", 2.25)
    else:
        # GCC's own debug info reads these wrong too in this GDB+QEMU setup
        # (see run_gdb_test.fp_probe): check that we point at FP registers.
        print("SKIP float/double arg values (unreadable in this GDB+QEMU setup even with GCC's DWARF)")
        for v in ("a", "b"):
            where = run("info address %s" % v)
            check("%s located in an FP/vector register" % v,
                  re.search(r"\$(f|d|s|v|q|xmm)\d+", where) is not None, where)
    if os.environ.get("FP_RET_OK", "1") == "1":
        check_finish("finish returns double", 6.375)
    else:
        print("SKIP finish double (unreadable in this GDB+QEMU setup even with GCC's DWARF)")

    # --- renamed locals, stack array -----------------------------------------
    start = line_of(r"^int (?:__\w+ )?edge_locals\(")
    body = func_text("edge_locals").split("\n")
    rets = [l for l in body if re.match(r"^\s*return\b", l)]
    ret_text = rets[-1]
    ret_line = line_of("^" + re.escape(ret_text) + "$", start)
    cont_to(spec(ret_line))
    out = run("info locals")
    check("locals with '?' names listed", LOC in out, out)
    check("stack array local content", "abcdefg" in out, out)
    # declaration lines of parameters and locals (GDB's Python API)
    blk = gdb.selected_frame().block()
    while blk is not None and blk.function is None:
        blk = blk.superblock
    nolines = [sym.name for sym in blk if (sym.is_argument or sym.is_variable) and not sym.line] if blk else ["?"]
    check("variables have declaration lines", not nolines, nolines)
    values = []
    for sym in gdb.selected_frame().block():
        if sym.is_variable and sym.name.startswith(LOC):
            v = sym.value(gdb.selected_frame())
            if not v.is_optimized_out and v.type.strip_typedefs().code == gdb.TYPE_CODE_INT:
                values.append(int(v))
    if re.match(r"^\s*return %s\d+;" % re.escape(LOC), ret_text):
        check("local sum = 700", 700 in values, values)
    else:
        print("SKIP local sum (returned as an expression: %s)" % ret_text.strip())
    check_finish("finish edge_locals", 700)

    # --- non-contiguous function ------------------------------------------------
    cont_to("split_func")
    between = int(val("(unsigned long)&asm_between"))
    for _ in range(4):
        if int(gdb.selected_frame().pc()) > between:
            break
        run("stepi")
    pc = int(gdb.selected_frame().pc())
    check("stepped into the detached tail", pc > between, hex(pc))
    check("tail belongs to split_func", gdb.selected_frame().name() == "split_func", gdb.selected_frame().name())
    check("backtrace from the tail", frame_names()[:2] == ["split_func", "edge_main"], frame_names())
    check_finish("finish split_func", 8)

    # --- Ghidra 'code *' local --------------------------------------------------------
    m = re.search(r"(pcVar\d+)", func_text("call_ptr"))
    if m is None:
        # PPC64 ELFv1 calls through the descriptor: (*(code *)*puVar3)()
        print("SKIP code * local (indirect call through a function descriptor)")
        cont_to("call_ptr")
    else:
        call_line = line_of(r"\(\*pcVar\d+\)\(\);", line_of(r"^int (?:__\w+ )?call_ptr\("))
        cont_to(spec(call_line))
        pc_var = m.group(1)
        out = run("ptype %s" % pc_var)
        check("code * is a function pointer", "(" in out and "*" in out, out)
        # GDB prints a code pointer with its function (handles Thumb bits)
        out = run("p %s" % pc_var)
        check("code * value", "<split_func>" in out or "<split_func+1>" in out, out)
    check_finish("finish call_ptr", 16)

    # --- custom storage -------------------------------------------------------------
    cont_to("take_flags")
    out = run("ptype flags")
    check("custom storage: bitfield param type", "lo : 3" in out and "hi : 24" in out, out)
    for fld, i in (("lo", 0), ("mid", 1), ("hi", 2)):
        check_eq("custom storage: bitfield %s matches GCC" % fld, "flags.%s == g_flag_expect[%d]" % (fld, i), 1)
    cont_to("sum_pair")
    check_eq("custom storage: struct over two registers .x", "pt.x", 12)
    check_eq("custom storage: struct over two registers .y", "pt.y", 34)
    if "ij" in func_text("stack_pair").split("{")[0]:
        cont_to("stack_pair")
        check_eq("custom storage: struct in stack slots .x", "ij.x", 56)
        check_eq("custom storage: struct in stack slots .y", "ij.y", 78)
        check_eq("custom storage: other params intact", "h", 8)
    else:
        print("SKIP custom stack struct (arguments not in adjacent 4-byte stack slots)")
    out = run("ptype make_flags")
    check("custom storage: struct return type", "flagword" in out, out)

    check_shapes()
    check_shapes_2()
    check_shapes_3()

    # --- globals at the end ----------------------------------------------------------
    cont_to("edge_done")
    for i, e in enumerate([0xF, 12034, 56 * 1000 + 78 + 36, 0x432105]):
        check_eq("g_custom_result[%d]" % i, "g_custom_result[%d]" % i, e)
    for i, e in enumerate([16, 11, 12, 60, 296, 700, 8, 1, 16]):
        check_eq("g_edge_result[%d]" % i, "g_edge_result[%d]" % i, e)
    for i, e in enumerate([13, 77, 11, 1084, 11, 21]):
        check_eq("g_shape_result[%d]" % i, "g_shape_result[%d]" % i, e)
    check_eq("poke result", "g_poke", 0xabcd)
    check_eq("sorted", "g_shape_arr[0] == 0 && g_shape_arr[5] == 5 && g_shape_arr[9] == 9", 1)
    check_eq("double global", "g_dbl", 6.375)

    # aliases: extra labels on the same function / data item
    check_eq("data alias has the primary's address", "&g_counter_alias == &g_counter", 1)
    check_eq("data alias has the primary's value", "g_counter_alias == g_counter", 1)
    check("data alias has the primary's type", run("ptype g_stats_alias") == run("ptype g_stats"),
          run("ptype g_stats_alias"))
    check_eq("second data alias", "&g_stats_other == &g_stats", 1)
    check_eq("data alias field access", "g_stats_alias.min == g_stats.min", 1)
    out = run("info symbol &g_counter")
    check("primary name shown for an aliased address", out.startswith("g_counter "), out)
    try:
        pcs = [int(x.pc) for x in (gdb.decode_line("clamp_alias")[1] or [])]
    except gdb.error as e:
        pcs = []
        print("decode_line clamp_alias: %s" % e)
    fn = [gdb.current_progspace().block_for_pc(pc).function for pc in pcs]
    check("function alias resolves into the function", any(f is not None and f.name == "clamp" for f in fn),
          [str(f) for f in fn])
    out = run("info symbol (unsigned long)&clamp")
    check("primary function name shown for an aliased entry", out.startswith("clamp"), out)
    out = run("x/i (unsigned long)&clamp")
    check("disassembly names the function, not its alias", "<clamp" in out and "alias" not in out, out)
    out = run("p &g_counter")
    check("data address printed with the primary name", "<g_counter>" in out, out)
    check_eq("union float view", "g_union.f", 1.5)
    check_eq("union int view", "g_union.u", 0x3FC00000)
    check_eq("2-D array", "g_matrix[2][3]", -12)
    check_eq("2-D array middle", "g_matrix[1][2]", 7)
    check_eq("2-D array size", "sizeof(g_matrix)", 24)
    check_eq("flexible array len", "g_msg->len", 3)
    check_eq("flexible array element", "g_msg->data[1]", ord("b"))
    check_eq("packed struct size", "sizeof(g_packed)", 7)
    check_eq("packed misaligned field", "g_packed.value", 0x22334455)
    check_eq("packed last field", "g_packed.crc", 0x6677)
    out = run("p g_reg")
    check("anonymous union member", "305419896" in out and "ctrl = 9" in out, out)
    check("enum value > INT_MAX", str(val("g_big")) in ("BIG_HIGH", "BIG_ALIAS"), str(val("g_big")))
    check_eq("enum raw value", "(unsigned int)g_big", 0xF0000000)
    check("8-byte enum", "BIG64_TOP" in str(val("g_u64")), str(val("g_u64")))
    check_eq("8-byte enum raw", "(unsigned long long)g_u64", 0x8000000000000001)
    check_eq("bool", "(int)g_flag", 1)
    # char signedness follows Ghidra's compiler spec (signed for PPC), not GCC's
    check_eq("char value", "(unsigned char)g_neg", 240)
    check_eq("string data size", "sizeof(g_str)", 7)
    check_eq("string data byte", "g_str[5]", ord("?"))
    check_eq("string data prints as a C string", "g_str", "hello?")
    out = run("print g_wide")
    check("unicode string prints as a string", 'u"hi"' in out, out)
    check_eq("unicode string size", "sizeof(g_wide)", 6)
    check_eq("undefined4 global", "g_undef4", 0xCAFEBABE)
    try:
        val(Q(UNTYPED)).fetch_lazy()
        check("label without type is untyped", False, "evaluated without a cast")
    except gdb.error as e:
        check("label without type is untyped", "unknown type" in str(e), str(e))
    check_eq("label without type, cast", "*(int *)&%s" % Q(UNTYPED), 0x1234)
    check_eq("int64", "g_i64", -5)
    out = run("p g_filters[1]")
    check("function pointer array", re.search(r"<filter_offset(\+1)?>", out) is not None, out)
    check_eq("bitfield a", "g_bits.a", 21)
    check_eq("bitfield b (crosses byte)", "g_bits.b", 99)
    check_eq("bitfield c", "g_bits.c", 9)
    check_eq("signed bitfield", "g_sbits.s", -2)
    check_eq("bitfield after signed", "g_sbits.u", 13)
    check_eq("'?' global + '?' field", "%s.%s" % (Q(G_THING), Q(FIELD1)), 41)
    check_eq("'?' global other field", "%s.ok" % Q(G_THING), 42)
    out = run("ptype struct %s" % Q(THING_T))
    check("ptype '?' typedef/struct", FIELD1 in out, out)
    check_eq("quote replaced in name", "it_s", 7)
    # struct/union/enum names without the tag keyword, as the pseudo-C uses them
    check_eq("bare struct name", "sizeof(packed_rec)", 7)
    out = run("ptype struct msg")
    check("flexible array member", "data[];" in out, out)
    out = run("info types packed_rec")
    check("types listed with their header line", re.search(r"types\.h:\s*\n\d+:", out) is not None, out)
    check_eq("bare struct name (union member)", "sizeof(reg)", 8)
    check_eq("bare enum name", "(int)(big)0", 0)
    check_eq("namespaced global Foo", Q(FOO_COUNTER), 100)
    check_eq("namespaced global Bar", Q(BAR_COUNTER), 200)
    check_eq("C keyword as name", Q(KW), 77)
    check_eq("non-ASCII name", Q(UNI), 88)
    check_eq("placeholder struct pointer", "(long)g_opaque == (long)&%s" % Q(G_THING), 1)
    out = run("ptype g_opaque")
    check("placeholder struct is incomplete", "incomplete" in out, out)
    check_eq("shifted pointer as raw integer", "g_shifted", 0x100010)
    check("shifted pointer not dereferenceable", val("g_shifted").type.strip_typedefs().code == gdb.TYPE_CODE_INT,
          str(val("g_shifted").type.strip_typedefs()))
    check_eq("duplicate type name A", "g_dupA.a2", 2)
    check_eq("duplicate type name B", "g_dupB.b1", 3)
    out = run("info line %s" % Q(BAD))
    check("undecompilable function has line info", any(n in out for n in SRC_NAMES), out)
    check("skipped function in C file", "decompilation failed" in func_text(BAD), func_text(BAD)[:200])


run_checks(main)
