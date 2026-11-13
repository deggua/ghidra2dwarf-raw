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


for name in ("dec_vector", "sc_vector", "dsi_vector", "align_vector"):
    st.addExternalEntryPoint(A(name))
fm.getFunctionAt(A("prog_vector")).addTag("INTERRUPT")
# a no-return function, as an analyst marks it
fm.getFunctionAt(A("irq_fatal")).setNoReturn(True)
print("IRQ setup: entry points dec_vector, sc_vector, dsi_vector, align_vector; prog_vector tagged INTERRUPT")

# A bank-switched overlay whose code returns with rfi, at the offset of an
# ordinary (unreferenced) function in the default space: the overlay isn't
# exported, and the ordinary function must not become an interrupt handler.
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor
refs = prog.getReferenceManager()
default_space = prog.getAddressFactory().getDefaultAddressSpace()
victim = None
for f in fm.getFunctions(True):
    e = f.getEntryPoint()
    if (e.getAddressSpace() == default_space and f.getName() in SYMS and not f.getTags()
            and not st.isExternalEntryPoint(e)
            and not any(r.getReferenceType().isFlow() for r in refs.getReferencesTo(e))):
        victim = f
        break
assert victim is not None, "no unreferenced function for the overlay test"
block = prog.getMemory().createInitializedBlock("bank1", victim.getEntryPoint(), 4, 0, TaskMonitor.DUMMY, True)
prog.getMemory().setBytes(block.getStart(), bytes([0x4c, 0x00, 0x00, 0x64]))   # rfi
disassemble(block.getStart())
assert createFunction(block.getStart(), None) is not None
print("IRQ setup: overlay bank1 with rfi at %s (over %s)" % (block.getStart(), victim.getName()))

for name, dt in (("g_ticks", IntegerDataType.dataType), ("g_syscalls", IntegerDataType.dataType),
                 ("g_traps", IntegerDataType.dataType), ("g_trap_pc", UnsignedIntegerDataType.dataType),
                 ("g_irq_result", ArrayDataType(IntegerDataType.dataType, 8, -1))):
    a = A(name)
    listing.clearCodeUnits(a, a.add(dt.getLength() - 1), False)
    DataUtilities.createData(prog, a, dt, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
