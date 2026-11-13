# Java port check (development only): runs the Python flow analysis on every
# function and dumps the states in the format of java_scripts/PortFlowDump.java.
# Args: <out file>
# @runtime PyGhidra
import os
import sys
import time

here = os.path.dirname(str(getSourceFile().getAbsolutePath()))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(here)), "ghidra_scripts"))
from dwarfexport.ghidra_export import RegisterIndex, build_register_map  # noqa: E402
from dwarfexport.flow import CfiGenerator, FunctionFlow, MachineInfo  # noqa: E402
from dwarfexport.dwarf import DwarfBuilder  # noqa: E402


def fmt(x):
    if x is None:
        return "N"
    if isinstance(x, tuple):
        return "(" + ",".join(fmt(e) for e in x) + ")"
    return str(x)


def dump(st):
    return ("R{" + "".join("%s=%s;" % (fmt(k), fmt(v)) for k, v in st.regs.items()) +
            "}M{" + "".join("%s=%s;" % (o, fmt(sv)) for o, sv in st.mem.items()) +
            "}S{" + "".join("%s=%s;" % (fmt(k), v) for k, v in st.saved.items()) +
            "}E" + ("N" if st.esc is None else str(st.esc)))


out = str(getScriptArgs()[0])
prog = currentProgram
regmap, _ = build_register_map(prog.getLanguage())
regs = RegisterIndex(prog.getLanguage(), regmap)
cc = prog.getCompilerSpec().getDefaultCallingConvention()
m = MachineInfo(prog, regs, int(cc.getStackshift()) if cc is not None else 0)
eps = []
it = prog.getSymbolTable().getExternalEntryPointIterator()
while it.hasNext():
    eps.append(int(it.next().getOffset()))
dw = DwarfBuilder(prog.getDefaultPointerSize(), prog.getLanguage().isBigEndian())
cfi = CfiGenerator(m, dw, lambda a: a, eps, True)
t0 = time.time()
n = 0
quiet = out == "-"      # (analysis only: timing)
with open("/dev/null" if quiet else out, "w") as w:
    for f in prog.getFunctionManager().getFunctions(True):
        if f.isExternal():
            continue
        try:
            flow = FunctionFlow(m, f)
        except Exception as e:  # noqa: BLE001
            w.write("F %d %s FAILED %s\n" % (f.getEntryPoint().getOffset(), f.getName(), e))
            continue
        n += 1
        ranges = [(int(r.getMinAddress().getOffset()), int(r.getMaxAddress().getOffset()) + 1)
                  for r in f.getBody().getAddressRanges()]
        cfi.add_function(flow, ranges)
        if quiet:
            continue
        w.write("F %d %s conv=%s leaf=%s\n" % (f.getEntryPoint().getOffset(), f.getName(),
                                               "true" if flow.converged else "false",
                                               "true" if flow.is_leaf else "false"))
        for o in flow.insns:
            si, so = flow.state_in.get(o), flow.state_out.get(o)
            w.write("I %d %s | %s\n" % (o, "-" if si is None else dump(si), "-" if so is None else dump(so)))
if not quiet:
    with open(out + ".frame", "wb") as fr:
        fr.write(dw._build_frame() or b"")
print("PORT python flow: %d functions in %.2f s" % (n, time.time() - t0))
