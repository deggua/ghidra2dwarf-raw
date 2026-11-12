# Test helper: recreate "human RE annotations" on a raw, symbol-less import of
# the test firmware, as an analyst would have done by hand:
#   * a RAM memory block for .data/.bss,
#   * function names + prototypes (parsed from fw.h with Ghidra's C parser),
#   * typed, named globals.
#
# Usage (headless): -postScript ghidra_setup.py <firmware build dir> <header.h>...
# @runtime PyGhidra

import json
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

with open(os.path.join(build_dir, "layout.json")) as f:
    LAYOUT = json.load(f)

# 1. RAM blocks for memory the raw image doesn't contain (.data/.bss at their
#    runtime addresses on the ROM target, .bss on the others).
for i, (start, size) in enumerate(LAYOUT["ram"]):
    ram = mem.createUninitializedBlock("RAM%d" % i if i else "RAM", toAddr("0x%x" % start), size, False)
    ram.setRead(True)
    ram.setWrite(True)

# Thumb: ARM's TMode context register selects the instruction set. As an
# analyst would before analyzing a Thumb-only image, make it the default.
from java.math import BigInteger
TMODE = prog.getProgramContext().getRegister("TMode") if LAYOUT["thumb"] else None
if TMODE is not None:
    for blk in mem.getBlocks():
        if blk.isInitialized():
            prog.getProgramContext().setValue(TMODE, blk.getStart(), blk.getEnd(), BigInteger.ONE)

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
    "g_poke": lambda: find_type("int"),
    "g_shape_sink": lambda: find_type("int"),
    "g_shape_arr": lambda: ArrayDataType(find_type("int"), 10, -1),
    "g_shape_result": lambda: ArrayDataType(find_type("int"), 8, -1),
}

# 3. Symbols (name addr size type) from the reference build.
syms = []
with open(os.path.join(build_dir, "symbols.txt")) as f:
    for line in f:
        name, addr, size, kind = line.split()
        syms.append((name, int(addr, 16), int(size, 16), kind))
if "_reset" not in [s[0] for s in syms]:
    syms.append(("_reset", 0xFFF00100, 0x28, "T"))

def addr_of(name, addr, kind):
    thumb = LAYOUT["thumb"] and bool(addr & 1) and kind in "Tt"
    return toAddr("0x%x" % (addr & ~1 if thumb else addr)), thumb


# PPC64 ELFv1: r2 holds the TOC base everywhere; Ghidra's ELF loader sets
# it for ELF files, for a raw image the analyst sets it before analysis.
if LAYOUT.get("toc"):
    r2 = prog.getProgramContext().getRegister("r2")
    for blk in mem.getBlocks():
        if blk.isExecute() and blk.isInitialized():
            prog.getProgramContext().setValue(r2, blk.getStart(), blk.getEnd(),
                                              BigInteger.valueOf(LAYOUT["toc"]))
    print("set r2 = 0x%x (TOC)" % LAYOUT["toc"])

# 3a. Code first (as an analyst marks known entry points), then analysis.
for name, addr, size, kind in syms:
    if name in ("bad_bytes", "split_tail") or kind not in "Tt":
        continue  # bad_bytes / split_tail are handled by ghidra_setup_edge.py
    a, thumb = addr_of(name, addr, kind)
    if thumb and TMODE is not None:
        prog.getProgramContext().setValue(TMODE, a, a, BigInteger.ONE)
    DisassembleCommand(a, None, True).applyTo(prog, monitor)
    if fm.getFunctionAt(a) is None:
        CreateFunctionCmd(name, a, None, SourceType.USER_DEFINED).applyTo(prog, monitor)
    if name == "_reset":
        st.addExternalEntryPoint(a)

# The image was imported without analysis (it would have guessed at the raw
# bytes); analyze now that the functions are in place.
analyzeAll(prog)

# Switch cases that analysis didn't disassemble, fixed as an analyst would:
# if the decompiler recovers the table (PPC64 -O0: TOC-relative tables), at
# its cases; if not ("Could not recover jumptable": a 64-bit index only
# bounded by a 32-bit compare on PPC64/n32, a table address loaded from a
# literal pool in writable memory on ARM), over the function's whole range
# (see README, "Unrecovered switch tables").
SIZES = dict((addr, size) for name, addr, size, kind in syms if kind in "Tt")


def disassemble_cases():
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.address import AddressSet
    ifc = DecompInterface()
    ifc.openProgram(prog)
    listing = prog.getListing()
    try:
        for f in list(fm.getFunctions(True)):
            res = ifc.decompileFunction(f, 60, monitor)
            hf = res.getHighFunction() if res is not None else None
            if hf is None:
                continue
            added = False
            for jt in hf.getJumpTables():
                for c in jt.getCases():
                    if listing.getInstructionAt(c) is None:
                        DisassembleCommand(c, None, True).applyTo(prog, monitor)
                        added = True
            a = f.getEntryPoint()
            size = SIZES.get(int(a.getOffset()))
            if not size:
                continue
            whole = AddressSet(a, a.add(size - 1))
            dc = res.getDecompiledFunction()
            if dc is not None and "Could not recover jumptable" in str(dc.getC()):
                # (at aligned addresses only: given a range, the disassembler
                # also tries starts inside instructions)
                # (the language's alignment can be smaller than the ISA's:
                # 2 on PPC64 variants that include VLE)
                proc = str(prog.getLanguage().getProcessor())
                align = 4 if proc in ("PowerPC", "MIPS", "AARCH64") or (proc == "ARM" and TMODE is None) \
                    else prog.getLanguage().getInstructionAlignment()
                for ins in list(listing.getInstructions(whole, True)):
                    if int(ins.getAddress().getOffset()) % align:
                        # (analysis decoded data before the cases misaligned)
                        listing.clearCodeUnits(ins.getMinAddress(), ins.getMaxAddress(), False)
                for r in list(listing.getUndefinedRanges(whole, False, monitor)):
                    x = r.getMinAddress()
                    x = x.add((-int(x.getOffset())) % align)
                    while x.compareTo(r.getMaxAddress()) <= 0:
                        if listing.getInstructionContaining(x) is None:
                            if TMODE is not None:
                                prog.getProgramContext().setValue(TMODE, x, x, BigInteger.ONE)
                            DisassembleCommand(x, whole, True).applyTo(prog, monitor)
                        x = x.add(align)
                for g in list(fm.getFunctions(AddressSet(a.add(1), a.add(size - 1)), True)):
                    fm.removeFunction(g.getEntryPoint())
                added = True
            if added:
                try:
                    f.setBody(f.getBody().union(whole))
                except Exception as e:  # noqa: BLE001
                    print("SETUP: %s: body not extended over its cases: %s" % (f.getName(), e))
    finally:
        ifc.dispose()


# PPC64 ELFv2: local calls target "func+8" (after the TOC setup), so analysis
# creates functions there and splits ours (also at code that several jump
# table cases branch to); undo that as an analyst would.
def fix_ppc64_splits():
    if prog.getLanguage().getProcessor().toString() != "PowerPC" or prog.getDefaultPointerSize() != 8:
        return
    from ghidra.program.model.address import AddressSet
    for name, addr, size, kind in syms:
        if kind not in "Tt" or name in ("bad_bytes", "split_tail") or size < 2:
            continue
        a = toAddr("0x%x" % addr)
        inner = [g for g in fm.getFunctions(AddressSet(a.add(1), a.add(size - 1)), True)
                 if g.getName().startswith("FUN_")]
        if inner:
            for g in inner:
                fm.removeFunction(g.getEntryPoint())
            f = fm.getFunctionAt(a)
            if f is not None:
                f.setBody(AddressSet(a, a.add(size - 1)))
        f = fm.getFunctionAt(a)
        if f is not None and f.isThunk():
            f.setThunkedFunction(None)


fix_ppc64_splits()
disassemble_cases()
analyzeChanges(prog)     # (calls in the new code may split functions again)
fix_ppc64_splits()

# PPC64 ELFv2 passes stack arguments at SP+96; Ghidra's PPC64 compiler specs
# model the ELFv1 layout (SP+112). Correct the affected parameters with
# custom storage, as an analyst would (see README).
ELFV2_STACK_FIX = bool(LAYOUT.get("elfv2"))


def fix_elfv2_stack_params(f):
    from java.util import ArrayList
    from ghidra.program.model.listing import (Function, ParameterImpl, ReturnParameterImpl,
                                              VariableStorage)
    params = list(f.getParameters())
    if not any(p.getVariableStorage().isStackStorage() for p in params):
        return
    jl = ArrayList()
    for p in params:
        st_ = p.getVariableStorage()
        if st_.isStackStorage():
            st_ = VariableStorage(prog, st_.getStackOffset() - 16, st_.size())
        jl.add(ParameterImpl(p.getName(), p.getDataType(), st_, prog))
    r = f.getReturn()
    f.setCustomVariableStorage(True)
    f.updateFunction(f.getCallingConventionName(),
                     ReturnParameterImpl(r.getDataType(), r.getVariableStorage(), prog), jl,
                     Function.FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)


def fix_gcc_regparm(f, nregs=3):
    """GCC -mregparm=N: integer/pointer args go in EAX, EDX, ECX (an int64
    in a pair, low word first) until N words are used up; float/double and
    aggregates always go on the stack. Ghidra's __regparm3 hands registers
    to floats and never to an int64, so re-assign storage by GCC's rules."""
    from java.util import ArrayList
    from ghidra.program.model.data import AbstractFloatDataType, Composite, TypeDef
    from ghidra.program.model.listing import (Function, ParameterImpl, ReturnParameterImpl,
                                              VariableStorage)
    lang = prog.getLanguage()
    regs = [lang.getRegister(r) for r in ("EAX", "EDX", "ECX")][:nregs]
    used = 0
    stack = 4
    jl = ArrayList()
    for p in f.getParameters():
        dt = p.getDataType()
        while isinstance(dt, TypeDef):
            dt = dt.getBaseDataType()
        size = max(1, p.getLength())
        words = (size + 3) // 4
        if not isinstance(dt, (AbstractFloatDataType, Composite)) and words <= len(regs) - used:
            vns = [regs[used + i] for i in range(words)]
            st_ = (VariableStorage(prog, vns[0].getAddress(), size) if words == 1
                   else VariableStorage(prog, list(reversed(vns))))
            used += words
        else:
            if not isinstance(dt, (AbstractFloatDataType, Composite)):
                used = len(regs)     # GCC: no more register args after one spills
            st_ = VariableStorage(prog, stack, size)
            stack += words * 4
        jl.add(ParameterImpl(p.getName(), p.getDataType(), st_, prog))
    r = f.getReturn()
    f.setCustomVariableStorage(True)
    f.updateFunction(f.getCallingConventionName(),
                     ReturnParameterImpl(r.getDataType(), r.getVariableStorage(), prog), jl,
                     Function.FunctionUpdateType.CUSTOM_STORAGE, True, SourceType.USER_DEFINED)


# 3b. Annotations: names, prototypes, typed globals.
listing = prog.getListing()
for name, addr, size, kind in syms:
    if name in ("bad_bytes", "split_tail"):
        continue
    a, thumb = addr_of(name, addr, kind)
    if kind in "Tt":
        f = fm.getFunctionAt(a)
        if f is None:
            CreateFunctionCmd(name, a, None, SourceType.USER_DEFINED).applyTo(prog, monitor)
            f = fm.getFunctionAt(a)
        if f is None:
            print("WARNING: no function at %s for %s" % (a, name))
            continue
        f.setName(name, SourceType.USER_DEFINED)
        proto = protos.get(name)
        if proto is not None:
            ok = ApplyFunctionSignatureCmd(a, proto, SourceType.USER_DEFINED).applyTo(prog, monitor)
            if not ok:
                print("WARNING: could not apply prototype to %s" % name)
            elif ELFV2_STACK_FIX:
                fix_elfv2_stack_params(f)
            if LAYOUT.get("calling_convention") and not f.hasVarArgs():
                # the analyst's program-wide calling convention (soft-float,
                # regparm, stdcall, ...)
                f.setCallingConvention(LAYOUT["calling_convention"])
                if LAYOUT["calling_convention"] == "__regparm3" and f.getParameterCount():
                    fix_gcc_regparm(f)
    else:
        if name in GLOBAL_TYPES:
            dt = GLOBAL_TYPES[name]()
            listing.clearCodeUnits(a, a.add(max(dt.getLength(), 1) - 1), False)
            DataUtilities.createData(prog, a, dt, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
        # (edge-case globals get their types in ghidra_setup_edge.py)
        st.createLabel(a, name, SourceType.USER_DEFINED).setPrimary()

print("setup done: %d functions" % fm.getFunctionCount())
