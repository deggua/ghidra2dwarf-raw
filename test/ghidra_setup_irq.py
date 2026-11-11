# Test helper (targets with interrupt vectors, after ghidra_setup.py): the
# annotations an analyst makes for exception handlers.
#   * dec_vector / sc_vector: marked as entry points (they're at vectors)
#   * prog_vector: NOT an entry point, but tagged INTERRUPT
#   * types for the interrupt test's globals
#
# Usage (headless): -postScript ghidra_setup_irq.py <firmware build dir>
# @runtime PyGhidra

import os

from java.util import ArrayList
from ghidra.program.model.data import (ArrayDataType, DataUtilities, IntegerDataType,
                                       UnsignedIntegerDataType)

build_dir = str(getScriptArgs()[0])
prog = currentProgram
st = prog.getSymbolTable()
fm = prog.getFunctionManager()
listing = prog.getListing()

SYMS = {}
with open(os.path.join(build_dir, "symbols.txt")) as f:
    for line in f:
        name, addr, size, kind = line.split()
        SYMS[name] = int(addr, 16)


def A(name):
    return toAddr("0x%x" % SYMS[name])


for name in ("dec_vector", "sc_vector"):
    st.addExternalEntryPoint(A(name))
fm.getFunctionAt(A("prog_vector")).addTag("INTERRUPT")
print("IRQ setup: entry points dec_vector, sc_vector; prog_vector tagged INTERRUPT")

for name, dt in (("g_ticks", IntegerDataType.dataType), ("g_syscalls", IntegerDataType.dataType),
                 ("g_traps", IntegerDataType.dataType), ("g_trap_pc", UnsignedIntegerDataType.dataType),
                 ("g_irq_result", ArrayDataType(IntegerDataType.dataType, 8, -1))):
    a = A(name)
    listing.clearCodeUnits(a, a.add(dt.getLength() - 1), False)
    DataUtilities.createData(prog, a, dt, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
