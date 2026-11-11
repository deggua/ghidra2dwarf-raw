# Test helper: recreate "human RE annotations" on a raw, symbol-less import of
# the test firmware, as an analyst would have done by hand:
#   * a RAM memory block for .data/.bss,
#   * function names + prototypes (parsed from fw.h with Ghidra's C parser),
#   * typed, named globals.
#
# Usage (headless): -postScript ghidra_setup.py <firmware build dir> <header.h>...
# @runtime PyGhidra

import os

from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd, CreateFunctionCmd
from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataUtilities
from ghidra.program.model.symbol import SourceType

args = [str(a) for a in getScriptArgs()]
build_dir, headers = args[0], args[1:]
prog = currentProgram
mem = prog.getMemory()
st = prog.getSymbolTable()
fm = prog.getFunctionManager()

# 1. RAM block (the raw ROM image doesn't contain .data/.bss at their runtime
#    addresses).
ram = mem.createUninitializedBlock("RAM", toAddr(0x00100000), 0x10000, False)
ram.setRead(True)
ram.setWrite(True)

# 2. Types and prototypes.
dtm = prog.getDataTypeManager()
parser = CParser(dtm, True, None)
parser.parse("\n".join(open(h).read() for h in headers))
if not parser.didParseSucceed():
    raise RuntimeError("C parse failed: %s" % parser.getParseMessages())
protos = parser.getFunctions()
print("parsed %d prototypes" % protos.size())


def find_type(name):
    from java.util import ArrayList
    found = ArrayList()
    dtm.findDataTypes(name, found)
    if found.isEmpty():
        raise KeyError(name)
    return found.get(0)


# CParser does not record extern declarations; give globals their types here.
from ghidra.program.model.data import ArrayDataType, PointerDataType
GLOBAL_TYPES = {
    "g_tick": lambda: find_type("uint32_t"),
    "g_counter": lambda: find_type("int"),
    "g_sensors": lambda: ArrayDataType(find_type("sensor_t"), 3, -1),
    "g_sensor_list": lambda: PointerDataType(find_type("sensor_t")),
    "g_stats": lambda: find_type("stats"),
    "g_result": lambda: ArrayDataType(find_type("int"), 8, -1),
    "g_banner": lambda: ArrayDataType(find_type("char"), 8, -1),
}

# 3. Symbols (name addr size type) from the reference build.
syms = []
with open(os.path.join(build_dir, "symbols.txt")) as f:
    for line in f:
        name, addr, size, kind = line.split()
        syms.append((name, int(addr, 16), int(size, 16), kind))
syms.append(("_reset", 0xFFF00100, 0x28, "T"))

for name, addr, size, kind in syms:
    if name == "bad_bytes":
        continue  # handled by ghidra_setup_edge.py
    a = toAddr("0x%x" % addr)
    if kind in "Tt":
        DisassembleCommand(a, None, True).applyTo(prog, monitor)
        f = fm.getFunctionAt(a)
        if f is None:
            CreateFunctionCmd(name, a, None, SourceType.USER_DEFINED).applyTo(prog, monitor)
            f = fm.getFunctionAt(a)
        else:
            f.setName(name, SourceType.USER_DEFINED)
        proto = protos.get(name)
        if proto is not None:
            ok = ApplyFunctionSignatureCmd(a, proto, SourceType.USER_DEFINED).applyTo(prog, monitor)
            if not ok:
                print("WARNING: could not apply prototype to %s" % name)
        if name == "_reset":
            st.addExternalEntryPoint(a)
    else:
        if name in GLOBAL_TYPES:
            dt = GLOBAL_TYPES[name]()
            DataUtilities.createData(prog, a, dt, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
        # (edge-case globals get their types in ghidra_setup_edge.py)
        st.createLabel(a, name, SourceType.USER_DEFINED)

analyzeChanges(prog)
print("setup done: %d functions" % fm.getFunctionCount())
