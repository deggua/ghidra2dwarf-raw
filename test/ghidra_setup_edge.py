# Test helper (runs after ghidra_setup.py): applies the edge-case annotations
# that are legal in Ghidra but have no direct C/DWARF equivalent.
#
# Usage (headless): -postScript ghidra_setup_edge.py <firmware build dir>
# @runtime PyGhidra

import os

from java.util import ArrayList
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import (
    ArrayDataType, CategoryPath, DataTypeConflictHandler, DataUtilities,
    EnumDataType, IntegerDataType, PointerDataType, PointerTypedef,
    StructureDataType, TerminatedStringDataType, TerminatedUnicodeDataType,
    Undefined4DataType,
)
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

USER = SourceType.USER_DEFINED
build_dir = str(getScriptArgs()[0])
prog = currentProgram
dtm = prog.getDataTypeManager()
st = prog.getSymbolTable()
fm = prog.getFunctionManager()
listing = prog.getListing()

SYMS = {}
with open(os.path.join(build_dir, "symbols.txt")) as f:
    for line in f:
        name, addr, size, kind = line.split()
        SYMS[name] = (int(addr, 16), int(size, 16))


def A(name):
    return toAddr("0x%x" % SYMS[name][0])


def find_type(name):
    from ghidra.program.model.data import BuiltInDataTypeManager
    for m in (dtm, BuiltInDataTypeManager.getDataTypeManager()):
        found = ArrayList()
        m.findDataTypes(name, found)
        if not found.isEmpty():
            return found.get(0)
    raise KeyError(name)


def set_type(gname, dt):
    DataUtilities.createData(prog, A(gname), dt, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)


def rename_global(gname, new, ns=None):
    sym = st.getPrimarySymbol(A(gname))
    if ns is not None:
        sym.setNameAndNamespace(new, ns, USER)
    else:
        sym.setName(new, USER)


def resolve(dt):
    return dtm.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER)


def report(what, fn):
    try:
        fn()
        print("EDGE ok: %s" % what)
    except Exception as e:
        print("EDGE FAILED to apply %s: %s" % (what, e))


# --- plain types from edge.h ---------------------------------------------------
set_type("g_union", find_type("value"))
set_type("g_matrix", ArrayDataType(ArrayDataType(find_type("short"), 4, -1), 3, -1))
set_type("g_msgbuf", find_type("msg"))
set_type("g_msg", PointerDataType(find_type("msg")))
set_type("g_packed", find_type("packed_rec"))
set_type("g_reg", find_type("reg"))
set_type("g_big", find_type("big"))
set_type("g_flag", find_type("bool"))
set_type("g_neg", find_type("char"))
set_type("g_i64", find_type("int64_t"))
set_type("g_filters", ArrayDataType(find_type("filter_fn"), 2, -1))
set_type("g_bits", find_type("bits16"))
set_type("g_sbits", find_type("sbits"))
set_type("g_quote", IntegerDataType.dataType)
set_type("g_counterA", IntegerDataType.dataType)
set_type("g_counterB", IntegerDataType.dataType)
set_type("g_kw", IntegerDataType.dataType)
set_type("g_uni", IntegerDataType.dataType)
set_type("g_dbl", find_type("double"))
set_type("g_edge_result", ArrayDataType(IntegerDataType.dataType, 10, -1))
set_type("g_fptab", ArrayDataType(PointerDataType(), 2, -1))

# --- names with '?' (type, field, global, function, parameter) ---------------
thing = find_type("thing")
report("struct/field names with '?'", lambda: (thing.setName("Thing?Info"),
                                              thing.getComponent(0).setFieldName("field?1")))
set_type("g_thing", thing)
report("global name with '?'", lambda: rename_global("g_thing", "g?thing"))
gv = fm.getFunctionAt(A("Get_Value"))
report("function/param names with '?'", lambda: (gv.setName("Get?Value", USER),
                                                 gv.getParameter(0).setName("p?arg", USER)))

# --- names GDB cannot quote / keywords / non-ASCII --------------------------
report("global name with a quote", lambda: rename_global("g_quote", "it's"))
report("global named like a C keyword", lambda: rename_global("g_kw", "switch"))
report("non-ASCII global name", lambda: rename_global("g_uni", "größe"))

# --- namespaces: two functions and two globals with the same base name ------
def namespaces():
    foo = st.createNameSpace(None, "Foo", USER)
    bar = st.createNameSpace(None, "Bar", USER)
    fa = fm.getFunctionAt(A("ns_init_a"))
    fb = fm.getFunctionAt(A("ns_init_b"))
    fa.setParentNamespace(foo)
    fa.setName("init", USER)
    fb.setParentNamespace(bar)
    fb.setName("init", USER)
    rename_global("g_counterA", "counter", foo)
    rename_global("g_counterB", "counter", bar)
report("namespaced duplicate names", namespaces)

# --- 8-byte enum with a value > 2^63 -----------------------------------------
def enum64():
    e = EnumDataType(CategoryPath("/edge"), "big64", 8)
    e.add("BIG64_ONE", 1)
    e.add("BIG64_TOP", -0x7FFFFFFFFFFFFFFF)  # 0x8000000000000001 as a Java long
    set_type("g_u64", resolve(e))
report("8-byte enum", enum64)

# --- dynamic-size data: strings ------------------------------------------------
report("terminated string", lambda: set_type("g_str", TerminatedStringDataType.dataType))
report("unicode string", lambda: set_type("g_wide", TerminatedUnicodeDataType.dataType))

# --- undefined4 and a label with no data at all -------------------------------
report("undefined4 global", lambda: set_type("g_undef4", Undefined4DataType.dataType))
def untyped():
    listing.clearCodeUnits(A("g_untyped_word"), A("g_untyped_word").add(3), False)
    rename_global("g_untyped_word", "untyped?label")
report("label without data", untyped)

# --- placeholder (not yet defined) struct --------------------------------------
def placeholder():
    s = resolve(StructureDataType(CategoryPath("/edge"), "opaque_s", 0))
    print("  opaque_s isNotYetDefined=%s" % s.isNotYetDefined())
    set_type("g_opaque", PointerDataType(s))
report("placeholder struct", placeholder)

# --- shifted / offset pointer typedef ------------------------------------------
def shifted():
    pt = resolve(PointerTypedef(None, IntegerDataType.dataType, 4, dtm, -4))
    print("  shifted pointer typedef: %s (%s)" % (pt.getName(), pt.getClass().getSimpleName()))
    set_type("g_shifted", pt)
report("offset pointer typedef", shifted)

# --- duplicate type names in different categories ------------------------------
def dups():
    a = StructureDataType(CategoryPath("/A"), "dup", 0)
    a.add(IntegerDataType.dataType, "a1", None)
    a.add(IntegerDataType.dataType, "a2", None)
    b = StructureDataType(CategoryPath("/B"), "dup", 0)
    b.add(IntegerDataType.dataType, "b1", None)
    set_type("g_dupA", resolve(a))
    set_type("g_dupB", resolve(b))
report("duplicate type names", dups)


# --- function that cannot be decompiled ----------------------------------------
def bad_func():
    a = A("bad_bytes")
    listing.clearCodeUnits(a, a.add(7), False)
    fm.createFunction("bad?func", a, AddressSet(a, a.add(7)), USER)
report("undecompilable function", bad_func)

# --- non-contiguous function body ----------------------------------------------
# split_func branches over asm_between to its tail; Ghidra treats the branch as
# a tail call, so add the tail to the body by hand as an analyst would.
def split_body():
    f = fm.getFunctionAt(A("split_func"))
    tail = A("asm_between").add(8)
    other = fm.getFunctionAt(tail)
    if other is not None:
        fm.removeFunction(tail)
    body = AddressSet(f.getBody())
    body.add(tail, tail.add(7))
    f.setBody(body)
    print("  split_func body: %s" % f.getBody())
report("non-contiguous function", split_body)

# --- struct return: GCC (PPC SVR4) returns aggregates via a hidden pointer in
# r3, which Ghidra's PPC model gets wrong for this 8-byte struct; fix the
# annotation as an analyst would (pointer return + explicit pointer param).
def struct_return():
    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
    from ghidra.app.util.parser import FunctionSignatureParser
    sig = FunctionSignatureParser(dtm, None).parse(None, "point * make_point(point * ret, int x, int y)")
    ApplyFunctionSignatureCmd(A("make_point"), sig, USER).applyTo(prog, monitor)
report("struct return via hidden pointer", struct_return)

# --- rename decompiler locals (committed to the database) ----------------------
def rename_locals():
    ifc = DecompInterface()
    ifc.openProgram(prog)
    func = fm.getFunctionAt(A("edge_locals"))
    hf = ifc.decompileFunction(func, 60, monitor).getHighFunction()
    syms = [s for s in hf.getLocalSymbolMap().getSymbols() if not s.isParameter()]
    for i, s in enumerate(syms):
        HighFunctionDBUtil.updateDBVariable(s, "loc?%d" % i, None, USER)
    ifc.dispose()
report("local names with '?'", rename_locals)

print("edge setup done")
