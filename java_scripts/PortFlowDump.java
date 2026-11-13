// Java port check (development only): runs the Java flow analysis on every
// function and dumps the states, for comparison with test/port/flow_dump.py.
// Args: <out file>
// @category DWARF.Dev
import java.io.PrintWriter;
import java.util.Map;

import dwarfexport.CfiGenerator;
import dwarfexport.DwarfBuilder;
import dwarfexport.FunctionFlow;
import dwarfexport.MachineInfo;
import dwarfexport.RegisterIndex;
import dwarfexport.State;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import java.util.ArrayList;
import java.util.List;

public class PortFlowDump extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String out = getScriptArgs()[0];
        Integer[] sp = new Integer[1];
        Map<String, Integer> regmap = RegisterIndex.buildRegisterMap(currentProgram.getLanguage(), sp, this::println);
        RegisterIndex regs = new RegisterIndex(currentProgram.getLanguage(), regmap);
        PrototypeModel cc = currentProgram.getCompilerSpec().getDefaultCallingConvention();
        long stackshift = cc != null ? cc.getStackshift() : 0;
        MachineInfo m = new MachineInfo(currentProgram, regs, stackshift, this::println);
        List<Long> eps = new ArrayList<>();
        AddressIterator ai = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (ai.hasNext()) {
            eps.add(ai.next().getOffset());
        }
        DwarfBuilder dw = new DwarfBuilder(currentProgram.getDefaultPointerSize(), currentProgram.getLanguage().isBigEndian());
        CfiGenerator cfi = new CfiGenerator(m, dw, a -> a, eps, true);
        long t0 = System.nanoTime();
        int n = 0;
        boolean quiet = out.equals("-");      // (analysis only: timing)
        try (PrintWriter w = new PrintWriter(quiet ? "/dev/null" : out, "UTF-8")) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.isExternal()) {
                    continue;
                }
                FunctionFlow flow;
                try {
                    flow = new FunctionFlow(m, f, null, null);
                }
                catch (Exception e) {
                    w.println("F " + f.getEntryPoint().getOffset() + " " + f.getName() + " FAILED " + e);
                    continue;
                }
                n++;
                List<long[]> ranges = new ArrayList<>();
                for (AddressRange r : f.getBody().getAddressRanges()) {
                    ranges.add(new long[] {r.getMinAddress().getOffset(), r.getMaxAddress().getOffset() + 1});
                }
                cfi.addFunction(flow, ranges, false);
                if (quiet) {
                    continue;
                }
                w.println("F " + f.getEntryPoint().getOffset() + " " + f.getName() + " conv=" + flow.converged +
                    " leaf=" + flow.isLeaf);
                for (long o : flow.insns) {
                    State si = flow.stateIn.get(o), so = flow.stateOut.get(o);
                    w.println("I " + o + " " + (si == null ? "-" : si.dump()) + " | " + (so == null ? "-" : so.dump()));
                }
            }
        }
        if (!quiet) {
            for (Object[] sec : dw.build()) {
                if (sec[0].equals(".debug_frame")) {
                    java.nio.file.Files.write(java.nio.file.Path.of(out + ".frame"), (byte[]) sec[1]);
                }
            }
        }
        println(String.format("PORT java flow: %d functions in %.2f s", n, (System.nanoTime() - t0) / 1e9));
    }
}
