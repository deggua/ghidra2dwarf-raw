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


def main():
    setup_session()

    # --- names in the generated C match the DWARF names ---------------------
    with open(CSRC, encoding="utf-8") as f:
        csrc = f.read()
    check("C file uses exported function name",
          re.search(r"int (?:__\w+ )?%s\(int %s\)" % (re.escape(GET_VALUE), re.escape(P_ARG)), csrc) is not None)
    check("C file uses exported namespaced name", "%s(10)" % FOO_INIT in csrc)
    check("C file uses exported type name", "struct %s" % THING_T in csrc)
    check("no unquotable quote left in C names", "it's" not in csrc)
    if SANITIZED:
        check("sanitized C file has no '?' identifiers", re.search(r"\b\w+\?\w*\b", csrc.split("/* ---- Data types ---- */")[0]) is None)

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
    cont_to("%s:%d" % (os.path.basename(CSRC), ret_line))
    out = run("info locals")
    check("locals with '?' names listed", LOC in out, out)
    check("stack array local content", "abcdefg" in out, out)
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
        cont_to("%s:%d" % (os.path.basename(CSRC), call_line))
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

    # --- globals at the end ----------------------------------------------------------
    cont_to("edge_done")
    for i, e in enumerate([0xF, 12034, 56 * 1000 + 78 + 36, 0x432105]):
        check_eq("g_custom_result[%d]" % i, "g_custom_result[%d]" % i, e)
    for i, e in enumerate([16, 11, 12, 60, 296, 700, 8, 1, 16]):
        check_eq("g_edge_result[%d]" % i, "g_edge_result[%d]" % i, e)
    check_eq("double global", "g_dbl", 6.375)
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
    check("undecompilable function has line info", os.path.basename(CSRC) in out, out)
    check("skipped function in C file", "decompilation failed" in func_text(BAD), func_text(BAD)[:200])


run_checks(main)
