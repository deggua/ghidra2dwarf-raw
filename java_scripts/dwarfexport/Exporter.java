package dwarfexport;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dwarfexport.DwarfBuilder.Die;
import dwarfexport.DwarfBuilder.Row;
import dwarfexport.Names.NameFilter;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.viewer.field.Annotation;
import ghidra.app.util.viewer.field.CommentUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/**
 * Ghidra -> DWARF/ELF exporter (a port of ghidra_export.py's Exporter).
 * Writes basename.src/basename.N.c (pseudo-C from the decompiler),
 * basename.src/basename.types.h and basename.elf (section headers mirroring
 * the memory map, symbols, DWARF 4 whose line table points into the C files).
 */
public final class Exporter {
    public static final String PRODUCER = "ghidra2dwarf-raw";

    final Program program;
    final TaskMonitor monitor;
    /** The tool's options by name ("Decompiler", ...) when run from the GUI, else null. */
    final java.util.function.Function<String, ghidra.framework.options.ToolOptions> toolOptions;
    final Options opts;
    final Consumer<String> logger;
    private DecompileOptions decOpts;
    final Path outDir;
    final String base, srcDirName, hName;
    final Path srcDir, elfPath;
    final Language lang;
    final Listing listing;
    final Memory memory;
    final AddressSpace space;
    final int addrSize;
    final long addrMask;
    final boolean bigEndian;
    final DwarfBuilder dw;
    final NameFilter nm, nmType;
    final Set<String> skip = new HashSet<>();
    final TypeBuilder types;
    final RegisterIndex regs;
    final Integer spRegno;
    final long stackshift;
    final MachineInfo machine;
    final List<Long> entryPoints = new ArrayList<>();
    final CfiGenerator cfi;
    /** C files: name, file number, lines, bytes, function count. */
    final List<CFile> cFiles = new ArrayList<>();
    final List<String> hLines = new ArrayList<>();
    int[] typesHeaderLines;
    final List<long[]> funcRanges = new ArrayList<>();
    final List<ElfSym> elfSymbols = new ArrayList<>();
    final TreeMap<String, Long> stats = new TreeMap<>();
    private final Map<Long, Long> insnEndCache = new java.util.concurrent.ConcurrentHashMap<>();
    /** Register bytes -> DWARF expression (see FunctionContext.regExpr). */
    final Map<Key, byte[]> regExprCache = new java.util.concurrent.ConcurrentHashMap<>();
    int srcDirNo;
    List<String[]> qualifiedRenames;
    Set<Long> interrupts;
    Map<Long, List<long[]>> irqJumps = new HashMap<>();
    List<long[]> opdDescriptors = new ArrayList<>();
    // per-function state
    List<Object[]> varDies;
    Map<String, Integer> codeDecls = new HashMap<>();
    String annCarry = "";
    List<Object[]> labels;
    private Boolean ppc64Ge;
    private int runsUsed;
    /** Time spent per phase (ns), for the log. */
    final Map<String, Long> timers = new LinkedHashMap<>();

    void addTime(String k, long t0) {
        timers.merge(k, System.nanoTime() - t0, Long::sum);
    }

    /** Time (ns, summed over the worker threads) and counts per worker activity, for the log. */
    final Map<String, long[]> workerTimers = new java.util.concurrent.ConcurrentHashMap<>();

    void addWorkerTime(String k, long t0) {
        long[] a = workerTimers.computeIfAbsent(k, x -> new long[2]);
        long d = System.nanoTime() - t0;
        synchronized (a) {
            a[0] += d;
            a[1]++;
        }
    }

    static final class CFile {
        final String name;
        final int fileNo;
        final List<String> lines;
        long bytes;
        int funcs;

        CFile(String name, int fileNo, List<String> lines, long bytes) {
            this.name = name;
            this.fileNo = fileNo;
            this.lines = lines;
            this.bytes = bytes;
        }
    }

    /**
     * A function's decompilation and machine-level analysis, prepared by a
     * worker thread (the main thread then assembles the DWARF in order).
     */
    static final class Prepared {
        DecompileResults res;
        List<long[]> ranges;
        final Map<Long, List<Long>> extra = new HashMap<>();
        final List<Address> missing = new ArrayList<>();
        FunctionFlow flow;
        String flowError;
        /** Variables in export order: {HighSymbol, Boolean is param, Location or null, error or null}. */
        List<Object[]> vars;
        CfiGenerator.Fdes fdes;
    }

    /** Decompiler-independent parts of a function's export, computable in any thread. */
    Prepared prepare(Function func, DecompileResults res) {
        Prepared p = new Prepared();
        p.res = res;
        p.ranges = functionRanges(func);
        HighFunction hf = res != null ? res.getHighFunction() : null;
        if (hf != null) {
            try {
                for (JumpTable jt : hf.getJumpTables()) {
                    List<Long> cases = new ArrayList<>();
                    for (Address c : jt.getCases()) {
                        cases.add(c.getOffset());
                        if (listing.getInstructionAt(c) == null) {
                            p.missing.add(c);
                        }
                    }
                    p.extra.put(jt.getSwitchAddress().getOffset(), cases);
                }
            }
            catch (Exception e) {
                // no jump tables
            }
        }
        try {
            State init = irqEntryState(func);
            if (init == null) {
                init = helperEntryState(func);
            }
            p.flow = new FunctionFlow(machine, func, p.extra, init);
        }
        catch (Exception e) {
            p.flowError = String.valueOf(e);
            p.flow = null;
        }
        ClangTokenGroup markup = res != null ? res.getCCodeMarkup() : null;
        if (markup != null && hf != null) {
            p.vars = variableLocations(func, hf, p.ranges, p.flow, thunkTarget(func) != null);
        }
        if (cfi != null && p.flow != null) {
            p.fdes = cfi.compute(p.flow, p.ranges, interrupts.contains(func.getEntryPoint().getOffset()));
        }
        if (p.flow != null) {
            p.flow.releaseAnalysisState();
        }
        return p;
    }

    static final class ElfSym {
        final String name;
        final long value, size;
        final int type, other, bind;

        ElfSym(String name, long value, long size, int type, int other, int bind) {
            this.name = name;
            this.value = value;
            this.size = size;
            this.type = type;
            this.other = other;
            this.bind = bind;
        }
    }

    public Exporter(Program program, TaskMonitor monitor, String outDir, Options options,
            java.util.function.Function<String, ghidra.framework.options.ToolOptions> toolOptions,
            Consumer<String> logger) {
        this.program = program;
        this.monitor = monitor;
        this.toolOptions = toolOptions;
        this.opts = options != null ? options : new Options();
        this.logger = logger != null ? logger : System.out::println;
        this.outDir = Path.of(outDir).toAbsolutePath().normalize();
        this.base = opts.basename != null ? opts.basename : Names.sanitizeBasename(program.getName());
        this.srcDirName = base + ".src";
        this.srcDir = this.outDir.resolve(srcDirName);
        this.hName = base + ".types.h";
        this.elfPath = this.outDir.resolve(base + ".elf");
        this.lang = program.getLanguage();
        this.listing = program.getListing();
        this.memory = program.getMemory();
        this.space = program.getAddressFactory().getDefaultAddressSpace();
        int as = space.getPointerSize();
        if (as != 4 && as != 8) {
            as = as < 4 ? 4 : 8;
        }
        this.addrSize = as;
        this.addrMask = as == 8 ? -1L : (1L << (8 * as)) - 1;
        this.bigEndian = lang.isBigEndian();
        this.dw = new DwarfBuilder(addrSize, bigEndian);
        this.nm = Names.makeNameFilter(opts.sanitize_names, false);
        this.nmType = Names.makeNameFilter(opts.sanitize_names, true);
        this.dw.nameFilter = nm;
        for (String s : opts.skip_decompile.split(",")) {
            if (!s.strip().isEmpty()) {
                skip.add(s.strip());
            }
        }
        this.types = new TypeBuilder(dw, program);
        this.types.typeNameFilter = nmType;
        Integer[] sp = new Integer[1];
        Map<String, Integer> regmap = RegisterIndex.buildRegisterMap(lang, sp, this::log);
        this.spRegno = sp[0];
        this.regs = new RegisterIndex(lang, regmap);
        PrototypeModel cc = program.getCompilerSpec().getDefaultCallingConvention();
        this.stackshift = cc != null ? cc.getStackshift() : 0;
        this.machine = new MachineInfo(program, regs, stackshift, this::log);
        AddressIterator eps = program.getSymbolTable().getExternalEntryPointIterator();
        while (eps.hasNext()) {
            Address a = eps.next();
            if (inSpace(a)) {
                entryPoints.add(a.getOffset());
            }
        }
        this.cfi = opts.cfi ? new CfiGenerator(machine, dw, this::A, entryPoints, opts.irq_signal_frame) : null;
        for (String k : new String[] {"functions", "decompile_failed", "globals", "variables", "variables_located",
            "line_rows"}) {
            stats.put(k, 0L);
        }
    }

    void stat(String k) {
        stats.merge(k, 1L, Long::sum);
    }

    // -- helpers ------------------------------------------------------------------

    /** Ghidra offset -> target address. */
    public long A(long off) {
        return (off + opts.address_offset) & addrMask;
    }

    public boolean inSpace(Address addr) {
        return addr != null && addr.getAddressSpace().equals(space);
    }

    /** Offset just past the instruction containing addr (and its delay slots). */
    public long insnEnd(Address addr) {
        long off = addr.getOffset();
        Long hit = insnEndCache.get(off);
        if (hit != null) {
            return hit;
        }
        Instruction ins = listing.getInstructionContaining(addr);
        long end = ins != null ? ins.getMaxAddress().getOffset() + 1 : off + 1;
        int depth = ins != null ? ins.getDelaySlotDepth() : 0;
        while (depth > 0 && ins != null) {
            ins = ins.getNext();
            if (ins == null) {
                break;
            }
            end = ins.getMaxAddress().getOffset() + 1;
            depth--;
        }
        insnEndCache.put(off, end);
        return end;
    }

    void log(String msg) {
        logger.accept(msg);
    }

    static long utf8Len(String s) {
        return s.getBytes(StandardCharsets.UTF_8).length;
    }

    static String strip(String s) {
        return s.strip();
    }

    // -- main entry -----------------------------------------------------------------

    public void run() throws Exception {
        long t0 = System.nanoTime();
        Files.createDirectories(outDir);
        Die cu = dw.cu;
        dw.name(cu, srcDirName + "/" + base + ".0.c", true);
        cu.add(C.DW_AT_producer, C.DW_FORM_strp, PRODUCER);
        cu.add(C.DW_AT_language, C.DW_FORM_data2, (long) C.DW_LANG_C99);
        cu.add(C.DW_AT_comp_dir, C.DW_FORM_strp, outDir.toString());
        cu.add(C.DW_AT_low_pc, C.DW_FORM_addr, 0L);
        srcDirNo = dw.addDir(srcDirName);
        newCFile();

        qualifiedRenames = collectQualifiedRenames();
        interrupts = findInterruptHandlers();
        if (!interrupts.isEmpty()) {
            FunctionManager fm = program.getFunctionManager();
            List<String> names = new ArrayList<>();
            for (long o : interrupts) {
                names.add(fm.getFunctionAt(space.getAddress(o)).getName());
            }
            Collections.sort(names);
            log("Interrupt/exception handlers: " + String.join(", ", names));
        }
        writeTypesHeader();
        long tfun = System.nanoTime();
        exportFunctions();
        addTime("functions (all)", tfun);
        long tg = System.nanoTime();
        exportGlobals();
        exportEquates();
        if (opts.all_types) {
            exportAllTypes();
        }
        types.flush();
        types.addTagTypedefs();
        addTypeDeclLines();

        List<long[]> ranges = new ArrayList<>(funcRanges);
        ranges.sort((a, b) -> {
            int c = Long.compareUnsigned(a[0], b[0]);
            return c != 0 ? c : Long.compareUnsigned(a[1], b[1]);
        });
        cu.add(C.DW_AT_ranges, C.DW_FORM_sec_offset, (long) dw.addRanges(ranges));
        cu.add(C.DW_AT_stmt_list, C.DW_FORM_sec_offset, 0L);
        dw.aranges.addAll(ranges);

        addTime("globals, types", tg);
        long tw = System.nanoTime();
        renameInTypesHeader();
        writeSources();
        writeElf();
        addTime("writing", tw);
        List<String> st = new ArrayList<>();
        for (Map.Entry<String, Long> e : stats.entrySet()) {
            st.add(e.getKey() + "=" + e.getValue());
        }
        log("ghidra2dwarf-raw: " + String.join(", ", st));
        List<String> tl = new ArrayList<>();
        for (Map.Entry<String, Long> e : timers.entrySet()) {
            tl.add(String.format("%s %.1fs", e.getKey(), e.getValue() / 1e9));
        }
        log("ghidra2dwarf-raw: time: " + String.join(", ", tl));
        if (!workerTimers.isEmpty()) {
            List<String> wl = new ArrayList<>();
            for (Map.Entry<String, long[]> e : new java.util.TreeMap<>(workerTimers).entrySet()) {
                wl.add(String.format("%s %.1fs (%d)", e.getKey(), e.getValue()[0] / 1e9, e.getValue()[1]));
            }
            log("ghidra2dwarf-raw: thread time: " + String.join(", ", wl));
        }
        log(String.format("ghidra2dwarf-raw: wrote %s and %s/ (%d C files) in %.1fs", elfPath, srcDir, cFiles.size(),
            (System.nanoTime() - t0) / 1e9));
    }

    // -- C files ---------------------------------------------------------------------

    static final Pattern TAG_RE = Pattern.compile("^\\s*(?:typedef\\s+)?(struct|union|enum)\\s+([^\\s{;]+)\\s*\\{");
    static final Pattern TD_RE = Pattern.compile("^\\s*typedef\\s.*?([^\\s*;()\\[\\]]+)\\s*(?:\\[[^\\]]*\\]\\s*)*;\\s*$");

    void addTypeDeclLines() {
        if (!opts.types_header || hLines.isEmpty()) {
            return;
        }
        int hNo = dw.addFile(hName, srcDirNo);
        Map<String, Integer> where = new HashMap<>();
        for (int i = 0; i < hLines.size(); i++) {
            String text = hLines.get(i);
            Matcher m = TAG_RE.matcher(text);
            if (m.lookingAt()) {
                where.putIfAbsent(m.group(1) + "\u0000" + m.group(2), i + 1);
                continue;
            }
            m = TD_RE.matcher(text);
            if (m.lookingAt()) {
                where.putIfAbsent("typedef\u0000" + m.group(1), i + 1);
            }
        }
        for (TypeBuilder.Entry e : types.entries()) {
            if (!(e.kind.equals("struct") || e.kind.equals("union") || e.kind.equals("enum") || e.kind.equals("typedef"))) {
                continue;
            }
            Integer line = where.get(e.kind + "\u0000" + e.dt.getName());
            if (line != null) {
                e.die.add(C.DW_AT_decl_file, C.DW_FORM_udata, (long) hNo);
                e.die.add(C.DW_AT_decl_line, C.DW_FORM_udata, (long) line);
            }
        }
    }

    List<String> filePreamble(int index) {
        List<String> l = new ArrayList<>(List.of("/*",
            " * Pseudo-C generated by " + PRODUCER + " from the Ghidra decompiler output",
            " * (part " + index + "; the files are split between functions).",
            " *   program:  " + program.getName(),
            " *   language: " + program.getLanguageID() + " (" + program.getCompilerSpec().getCompilerSpecID() + ")",
            " * Line numbers in this file are referenced by the DWARF line table",
            " * of " + elfPath.getFileName() + " -- do not edit it.", " */"));
        if (opts.types_header) {
            l.add("#include \"" + hName + "\"");
        }
        l.add("");
        return l;
    }

    CFile newCFile() {
        int index = cFiles.size();
        String name = base + "." + index + ".c";
        List<String> lines = filePreamble(index);
        long bytes = 0;
        for (String l : lines) {
            bytes += utf8Len(l) + 1;
        }
        CFile f = new CFile(name, dw.addFile(name, srcDirNo), lines, bytes);
        cFiles.add(f);
        return f;
    }

    /** Appends a function's text to the current C file or a new one: (file, lines before the text). */
    Object[] placeFunction(List<String> flines) {
        long size = 0;
        for (String l : flines) {
            size += utf8Len(l) + 1;
        }
        CFile cur = cFiles.get(cFiles.size() - 1);
        long mb = opts.c_max_bytes, ml = opts.c_max_lines;
        if (cur.funcs > 0 && ((mb > 0 && cur.bytes + size > mb) || (ml > 0 && cur.lines.size() + flines.size() > ml))) {
            cur = newCFile();
        }
        int off = cur.lines.size();
        cur.lines.addAll(flines);
        cur.bytes += size;
        cur.funcs++;
        return new Object[] {cur, off};
    }

    void writeSources() throws IOException {
        Files.createDirectories(srcDir);
        Set<String> keep = new HashSet<>();
        for (CFile f : cFiles) {
            keep.add(f.name);
        }
        if (opts.types_header) {
            keep.add(hName);
        }
        Pattern ours = Pattern.compile("^" + Pattern.quote(base) + "\\.(\\d+\\.c|types\\.h)$");
        try (var ds = Files.list(srcDir)) {
            for (Path p : (Iterable<Path>) ds::iterator) {
                String n = p.getFileName().toString();
                if (ours.matcher(n).matches() && !keep.contains(n)) {
                    Files.delete(p);
                }
            }
        }
        for (CFile f : cFiles) {
            Files.write(srcDir.resolve(f.name), (String.join("\n", f.lines) + "\n").getBytes(StandardCharsets.UTF_8));
        }
        if (opts.types_header) {
            Files.write(srcDir.resolve(hName), (String.join("\n", hLines) + "\n").getBytes(StandardCharsets.UTF_8));
        }
    }

    void writeTypesHeader() throws Exception {
        if (!opts.types_header) {
            return;
        }
        StringWriter sw = new StringWriter();
        List<DataType> all = new ArrayList<>();
        program.getDataTypeManager().getAllDataTypes().forEachRemaining(all::add);
        new DataTypeWriter(program.getDataTypeManager(), sw, false).write(all, monitor);
        String text = sw.toString();
        String guard = hName.replaceAll("[^A-Za-z0-9]", "_").toUpperCase();
        hLines.add("/* Data types of " + program.getName() + ", generated by " + PRODUCER +
            " (included by the .c files). */");
        hLines.add("#ifndef " + guard);
        hLines.add("#define " + guard);
        hLines.add("");
        int first = hLines.size();
        hLines.addAll(Arrays.asList(text.replace("\r\n", "\n").split("\n", -1)));
        typesHeaderLines = new int[] {first, hLines.size()};
        hLines.add("");
        hLines.add("#endif");
    }

    // -- interrupt handlers -----------------------------------------------------------

    static final Pattern IRQ_RETURN = Pattern.compile(
        "^(rfi|rfid|hrfid|rfci|rfmci|rfdi|rfgi|eret|eretaa|eretab|deret|iret|iretd|iretq)$", Pattern.CASE_INSENSITIVE);

    boolean isVectorAddress(long off) {
        if (!lang.getProcessor().toString().equals("PowerPC")) {
            return false;
        }
        long base = off & ~0xFFFFL;
        long rel = off - base;
        return (base == 0 || base == 0xFFF00000L || base == 0xFFFFFFFFFFF00000L) && 0x200 <= rel && rel < 0x3000 &&
            rel % 0x100 == 0;
    }

    static boolean isCallInsn(Instruction ins) {
        PcodeOp[] ops;
        try {
            ops = ins.getPcode(false);
        }
        catch (Exception e) {
            ops = ins.getPcode();
        }
        for (PcodeOp op : ops) {
            if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                return true;
            }
        }
        return false;
    }

    boolean isBranchInsn(Instruction ins) {
        ghidra.program.model.symbol.FlowType ft = ins.getFlowType();
        if (ft.isConditional() || !((ft.isJump() && !ft.isCall()) || (ft.isCall() && ft.isTerminal()))) {
            return false;
        }
        return !isCallInsn(ins);
    }

    Set<Long> findInterruptHandlers() {
        FunctionManager fm = program.getFunctionManager();
        ReferenceManager refs = program.getReferenceManager();
        Set<Long> eps = new HashSet<>(entryPoints);
        Set<Long> found = new HashSet<>();
        Set<Long> candidates = new HashSet<>();
        List<Function> all = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            if (!f.isExternal() && inSpace(f.getEntryPoint())) {
                all.add(f);
            }
        }
        // (every instruction of the program is read: in parallel)
        Set<Long> foundC = java.util.concurrent.ConcurrentHashMap.newKeySet();
        Set<Long> candC = java.util.concurrent.ConcurrentHashMap.newKeySet();
        all.parallelStream().forEach(f -> {
            long entry = f.getEntryPoint().getOffset();
            boolean tagged = false;
            for (FunctionTag t : f.getTags()) {
                if (t.getName().toUpperCase().equals("INTERRUPT")) {
                    tagged = true;
                }
            }
            if (tagged || (eps.contains(entry) && isVectorAddress(entry))) {
                foundC.add(entry);
                return;
            }
            for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
                if (IRQ_RETURN.matcher(ins.getMnemonicString()).matches()) {
                    candC.add(entry);
                    break;
                }
            }
        });
        found.addAll(foundC);
        candidates.addAll(candC);
        boolean changed = true;
        while (changed) {
            changed = false;
            for (long e : new TreeSet<>(found)) {
                Function f = fm.getFunctionAt(space.getAddress(e));
                if (f == null) {
                    continue;
                }
                for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
                    if (isBranchInsn(ins)) {
                        for (Address t : ins.getFlows()) {
                            if (fm.getFunctionAt(t) != null && !found.contains(t.getOffset())) {
                                candidates.add(t.getOffset());
                            }
                        }
                    }
                }
            }
            TreeSet<Long> todo = new TreeSet<>(candidates);
            todo.removeAll(found);
            for (long c : todo) {
                if (onlyFromHandlers(c, found, fm, refs)) {
                    found.add(c);
                    changed = true;
                }
            }
        }
        irqJumps = new HashMap<>();
        for (long src : found) {
            Function f = fm.getFunctionAt(space.getAddress(src));
            if (f == null) {
                continue;
            }
            for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
                if (isBranchInsn(ins)) {
                    for (Address t : ins.getFlows()) {
                        if (found.contains(t.getOffset()) && t.getOffset() != src) {
                            irqJumps.computeIfAbsent(t.getOffset(), x -> new ArrayList<>())
                                    .add(new long[] {src, ins.getAddress().getOffset()});
                        }
                    }
                }
            }
        }
        return found;
    }

    boolean onlyFromHandlers(long entry, Set<Long> found, FunctionManager fm, ReferenceManager refs) {
        for (Reference r : refs.getReferencesTo(space.getAddress(entry))) {
            if (!r.getReferenceType().isFlow()) {
                continue;
            }
            Address src = r.getFromAddress();
            Function g = fm.getFunctionContaining(src);
            if (g == null || !found.contains(g.getEntryPoint().getOffset())) {
                return false;
            }
            Instruction ins = listing.getInstructionAt(src);
            if (ins == null || isCallInsn(ins)) {
                return false;
            }
        }
        return true;
    }

    // -- names ------------------------------------------------------------------------

    List<String[]> collectQualifiedRenames() {
        if (!opts.sanitize_names) {
            return new ArrayList<>();
        }
        Map<String, String> out = new LinkedHashMap<>();
        SymbolIterator it = program.getSymbolTable().getAllSymbols(false);
        while (it.hasNext()) {
            Symbol sym = it.next();
            Namespace ns = sym.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                String q = sym.getName(true);
                if (!nm.apply(q).equals(q)) {
                    out.put(q, nm.apply(q));
                }
            }
        }
        List<String[]> l = new ArrayList<>();
        for (Map.Entry<String, String> e : out.entrySet()) {
            l.add(new String[] {e.getKey(), e.getValue()});
        }
        l.sort((a, b) -> Integer.compare(b[0].codePointCount(0, b[0].length()), a[0].codePointCount(0, a[0].length())));
        return l;
    }

    void renameInTypesHeader() {
        LinkedHashMap<String, String> pairs = new LinkedHashMap<>(nm.cache);
        pairs.putAll(nmType.cache);
        for (Map.Entry<String, String> e : new ArrayList<>(nmType.cache.entrySet())) {
            String o = e.getKey(), n = e.getValue();
            if (!o.equals(n) && !pairs.containsKey("P" + o)) {
                pairs.put("P" + o, "P" + n);
            }
        }
        List<String[]> renames = new ArrayList<>();
        for (Map.Entry<String, String> e : pairs.entrySet()) {
            if (!e.getKey().equals(e.getValue())) {
                renames.add(new String[] {e.getKey(), e.getValue()});
            }
        }
        renames.sort((a, b) -> Integer.compare(b[0].codePointCount(0, b[0].length()), a[0].codePointCount(0, a[0].length())));
        if (typesHeaderLines == null || renames.isEmpty()) {
            return;
        }
        Map<String, Pattern> pats = new HashMap<>();
        for (int i = typesHeaderLines[0]; i < typesHeaderLines[1]; i++) {
            String line = hLines.get(i);
            for (String[] r : renames) {
                if (line.contains(r[0])) {
                    Pattern pat = pats.computeIfAbsent(r[0],
                        o -> Pattern.compile("(?<![A-Za-z0-9_])" + Pattern.quote(o) + "(?![A-Za-z0-9_])"));
                    line = pat.matcher(line).replaceAll(Matcher.quoteReplacement(r[1]));
                }
            }
            hLines.set(i, line);
        }
    }

    String tokenText(ClangToken tok) {
        String text = tok.getText();
        if (tok instanceof ClangCommentToken) {
            return commentText(text);
        }
        if (!text.isEmpty() && "\"'-0123456789".indexOf(text.charAt(0)) < 0 &&
            (tok instanceof ClangVariableToken || tok instanceof ClangFuncNameToken || tok instanceof ClangFieldToken ||
                tok instanceof ClangTypeToken || tok instanceof ClangLabelToken)) {
            if (tok instanceof ClangTypeToken) {
                return nmType.apply(text);
            }
            return nm.apply(text);
        }
        return text;
    }

    // -- comment annotations ------------------------------------------------------------

    static final Pattern ANN_START = Pattern.compile("\\{@(\\w+)");
    static final Set<String> ANN_KINDS = Set.of("sym", "symbol", "address", "addr", "url", "hyperlink", "href", "link",
        "program", "variable", "var", "execute");

    static Integer annotationEnd(String text, int i) {
        boolean quoted = false;
        int j = i + 2;
        while (j < text.length()) {
            char c = text.charAt(j);
            if (c == '\\') {
                j += 2;
                continue;
            }
            if (c == '"') {
                quoted = !quoted;
            }
            else if (c == '}' && !quoted) {
                return j + 1;
            }
            j++;
        }
        return null;
    }

    String commentText(String text) {
        if (!annCarry.isEmpty()) {
            String rest = text.stripLeading();
            if (rest.startsWith("//")) {
                rest = rest.substring(2).stripLeading();
            }
            text = annCarry + rest;
            annCarry = "";
        }
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (true) {
            Matcher m = ANN_START.matcher(text);
            if (!m.find(i)) {
                out.append(text.substring(i));
                break;
            }
            if (!ANN_KINDS.contains(m.group(1).toLowerCase())) {
                out.append(text, i, m.end());
                i = m.end();
                continue;
            }
            Integer end = annotationEnd(text, m.start());
            if (end == null) {
                if (text.stripTrailing().endsWith("*/")) {
                    out.append(text.substring(i));
                }
                else {
                    out.append(text.substring(i, m.start()).stripTrailing());
                    annCarry = text.substring(m.start()) + " ";
                }
                break;
            }
            out.append(text, i, m.start());
            out.append(renderAnnotation(text.substring(m.start(), end)));
            i = end;
        }
        return out.toString();
    }

    String renderAnnotation(String raw) {
        String[] parts;
        try {
            parts = new Annotation(raw).getAnnotationParts();
        }
        catch (Exception e) {
            return raw;
        }
        String kind = parts.length > 0 ? parts[0].toLowerCase() : "";
        if ((kind.equals("sym") || kind.equals("symbol")) && parts.length > 1) {
            Symbol sym = annotatedSymbol(parts[1]);
            if (sym != null) {
                return nm.apply(Names.qualified(sym));
            }
        }
        else if (kind.equals("execute")) {
            String shown = String.join(" ", Arrays.asList(parts).subList(Math.min(2, parts.length), parts.length));
            return !shown.isEmpty() ? shown : (parts.length > 1 ? parts[1] : raw);
        }
        String shown;
        try {
            shown = CommentUtils.getDisplayString(raw, program);
        }
        catch (Exception e) {
            return raw;
        }
        if ((kind.equals("variable") || kind.equals("var")) && !shown.isEmpty() &&
            !shown.startsWith("Annotation Exception")) {
            shown = nm.apply(shown);
        }
        return shown;
    }

    Symbol annotatedSymbol(String text) {
        try {
            List<Symbol> syms = NamespaceUtils.getSymbols(text, program);
            if (!syms.isEmpty()) {
                return syms.get(0);
            }
            Address addr = program.getAddressFactory().getAddress(text);
            if (addr != null) {
                return program.getSymbolTable().getPrimarySymbol(addr);
            }
        }
        catch (Exception e) {
            // not a symbol
        }
        return null;
    }

    // -- decompilation --------------------------------------------------------------------

    synchronized DecompileOptions decompileOptions() {
        if (decOpts == null) {
            DecompileOptions o = new DecompileOptions();
            if (toolOptions != null) {
                o.grabFromToolAndProgram(toolOptions.apply("Listing Fields"), toolOptions.apply("Decompiler"), program);
            }
            else {
                o.grabFromProgram(program);
            }
            decOpts = o;
        }
        return decOpts;
    }

    /** (decompiler start-up isn't thread-safe in Ghidra: concurrent openProgram calls can fail) */
    private static final Object DECOMPILER_START = new Object();

    DecompInterface decompiler() {
        long t0 = System.nanoTime();
        try {
            synchronized (DECOMPILER_START) {
                return newDecompiler();
            }
        }
        finally {
            addWorkerTime("decompiler start", t0);
        }
    }

    private DecompInterface newDecompiler() {
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(decompileOptions());
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(true);
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(program)) {
            throw new IllegalStateException("decompiler failed to open program: " + ifc.getLastMessage());
        }
        return ifc;
    }

    /** Could the decompiled text depend on the decompiler process' history? */
    static boolean historyDependent(DecompileResults res) {
        HighFunction hf = res != null ? res.getHighFunction() : null;
        if (hf == null) {
            return false;
        }
        int n = 0;
        Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols();
        while (it.hasNext()) {
            HighSymbol sym = it.next();
            if (sym.isParameter()) {
                continue;
            }
            try {
                VariableStorage st = sym.getStorage();
                DataType dt = sym.getDataType();
                if (st.isCompoundStorage() || (dt != null && dt.getLength() != st.size())) {
                    n++;
                }
            }
            catch (Exception e) {
                n++;
            }
        }
        return n >= 2;
    }

    DecompileResults decompile(DecompInterface ifc, Function func, int timeout) {
        DecompileResults res = ifc.decompileFunction(func, timeout, monitor);
        boolean failed = res != null && !res.decompileCompleted() && !res.isTimedOut();
        if ((failed || historyDependent(res)) && !monitor.isCancelled()) {
            // (a failure may be transient -- Ghidra's decompiler has races
            // between concurrent processes -- so it gets a second chance in a
            // fresh process, as does a history-dependent result)
            DecompInterface fresh = decompiler();
            long t0 = System.nanoTime();
            try {
                res = fresh.decompileFunction(func, timeout, monitor);
                addWorkerTime(failed ? "decompile again (failed)" : "decompile again (history)", t0);
            }
            finally {
                fresh.dispose();
            }
        }
        return res;
    }

    boolean skipped(Function func) {
        return skip.contains(Names.qualified(func)) || skip.contains(func.getName()) ||
            skip.contains(func.getEntryPoint().toString());
    }

    void exportFunctions() throws Exception {
        FunctionManager fm = program.getFunctionManager();
        List<Function> funcs = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            if (!f.isExternal() && inSpace(f.getEntryPoint())) {
                funcs.add(f);
            }
        }
        int skippedN = fm.getFunctionCount() - funcs.size();
        if (skippedN != 0) {
            log("Skipping " + skippedN + " external/non-default-space functions");
        }
        monitor.initialize(funcs.size());
        monitor.setMessage("Decompiling functions");
        decompileOptions();
        int n = (int) opts.decompile_threads;
        if (n < 0) {
            n = Math.max(1, Math.min(16, Runtime.getRuntime().availableProcessors() - 1));
        }
        int timeout = (int) opts.decompile_timeout;
        DecompInterface[] serial = new DecompInterface[1];
        try {
            if (n <= 1) {
                for (int i = 0; i < funcs.size(); i++) {
                    Function func = funcs.get(i);
                    if (serial[0] == null) {
                        serial[0] = decompiler();
                    }
                    DecompileResults res = skipped(func) ? null : decompile(serial[0], func, timeout);
                    exportOne(i, funcs, func, prepare(func, res));
                }
                return;
            }
            List<DecompInterface> ifcs = Collections.synchronizedList(new ArrayList<>());
            ThreadLocal<DecompInterface> local = new ThreadLocal<>();
            ExecutorService ex = Executors.newFixedThreadPool(n);
            try {
                ArrayDeque<Object[]> window = new ArrayDeque<>();
                Iterator<Function> it = funcs.iterator();
                java.util.function.Function<Function, Future<Prepared>> submit = func -> ex.submit(() -> {
                    DecompInterface ifc = local.get();
                    if (ifc == null) {
                        ifc = decompiler();
                        local.set(ifc);
                        ifcs.add(ifc);
                    }
                    long t0 = System.nanoTime();
                    DecompileResults res = skipped(func) ? null : decompile(ifc, func, timeout);
                    addWorkerTime("decompile", t0);
                    t0 = System.nanoTime();
                    Prepared p = prepare(func, res);
                    addWorkerTime("analysis", t0);
                    return p;
                });
                // Functions in flight: enough to keep the workers busy past a slow
                // one, bounded by their code size (their decompilation and
                // per-instruction states are held until exported in order).
                int ahead = Integer.getInteger("dwarfexport.window", 16) * n;
                // (about 4 KB of heap per code byte in flight: 1/4096 of the heap)
                long budget = Long.getLong("dwarfexport.inflight", Math.max(64 * 1024, Runtime.getRuntime().maxMemory() / 4096));
                long[] inflight = {0};
                final int nThreads = n;
                java.util.function.Predicate<Integer> room = size -> window.size() < nThreads + 1 ||
                    (window.size() < ahead && inflight[0] + size <= budget);
                Function pendingF = it.hasNext() ? it.next() : null;
                while (pendingF != null && room.test(bodySize(pendingF))) {
                    inflight[0] += bodySize(pendingF);
                    window.add(new Object[] {pendingF, submit.apply(pendingF)});
                    pendingF = it.hasNext() ? it.next() : null;
                }
                int i = 0;
                while (!window.isEmpty()) {
                    Object[] w = window.poll();
                    Function func = (Function) w[0];
                    inflight[0] -= bodySize(func);
                    while (pendingF != null && room.test(bodySize(pendingF))) {
                        inflight[0] += bodySize(pendingF);
                        window.add(new Object[] {pendingF, submit.apply(pendingF)});
                        pendingF = it.hasNext() ? it.next() : null;
                    }
                    long tw = System.nanoTime();
                    @SuppressWarnings("unchecked")
                    Prepared prep = ((Future<Prepared>) w[1]).get();
                    addTime("worker wait", tw);
                    if (prep.res != null && prep.res.isTimedOut() && !monitor.isCancelled()) {
                        if (serial[0] == null) {
                            serial[0] = decompiler();
                        }
                        prep = prepare(func, decompile(serial[0], func, timeout));
                    }
                    exportOne(i++, funcs, func, prep);
                }
            }
            finally {
                synchronized (ifcs) {
                    for (DecompInterface ifc : ifcs) {
                        try {
                            ifc.stopProcess();
                        }
                        catch (Exception e) {
                            // shutting down
                        }
                    }
                }
                ex.shutdownNow();
                ex.awaitTermination(60, java.util.concurrent.TimeUnit.SECONDS);
                synchronized (ifcs) {
                    for (DecompInterface ifc : ifcs) {
                        ifc.dispose();
                    }
                }
            }
        }
        finally {
            if (serial[0] != null) {
                serial[0].dispose();
            }
        }
    }

    static int bodySize(Function f) {
        return (int) Math.min(f.getBody().getNumAddresses(), 1 << 24);
    }

    private void exportOne(int i, List<Function> funcs, Function func, Prepared prep) throws Exception {
        monitor.checkCancelled();
        monitor.setProgress(i);
        if (i % 200 == 0) {
            log("[" + i + "/" + funcs.size() + "] " + func.getName());
        }
        exportFunction(prep, func);
    }

    List<long[]> functionRanges(Function func) {
        long entry = func.getEntryPoint().getOffset();
        List<long[]> ranges = new ArrayList<>();
        long top = addrSize == 8 ? -1L : (1L << (8 * addrSize)) - 1;
        for (AddressRange r : func.getBody().getAddressRanges()) {
            if (!inSpace(r.getMinAddress())) {
                continue;
            }
            long hi = r.getMaxAddress().getOffset() + 1;
            if (addrSize == 4 && hi > top) {
                hi = top;
            }
            ranges.add(new long[] {r.getMinAddress().getOffset(), hi});
        }
        ranges.sort((a, b) -> a[0] != b[0] ? Long.compare(a[0], b[0]) : Long.compare(a[1], b[1]));
        long[] first = null;
        for (long[] r : ranges) {
            if (r[0] <= entry && entry < r[1]) {
                first = r;
                break;
            }
        }
        if (first != null && first[0] != entry) {
            ranges.remove(first);
            List<long[]> nr = new ArrayList<>();
            nr.add(new long[] {entry, first[1]});
            nr.addAll(ranges);
            nr.add(new long[] {first[0], entry});
            ranges = nr;
        }
        else if (first != null) {
            ranges.remove(first);
            ranges.add(0, first);
        }
        if (ranges.isEmpty()) {
            ranges.add(new long[] {entry, entry + 1});
        }
        return ranges;
    }

    // -- one function ---------------------------------------------------------------------

    void exportFunction(Prepared prep, Function func) {
        stat("functions");
        DecompileResults res = prep.res;
        String name = Names.qualified(func);
        long entry = func.getEntryPoint().getOffset();
        List<long[]> ranges = prep.ranges;
        boolean isSkipped = skipped(func);
        HighFunction hf = res != null ? res.getHighFunction() : null;
        ClangTokenGroup markup = res != null ? res.getCCodeMarkup() : null;

        Die die = dw.cu.child(C.DW_TAG_subprogram);
        dw.name(die, name);
        die.add(C.DW_AT_external, C.DW_FORM_flag_present);
        die.add(C.DW_AT_prototyped, C.DW_FORM_flag_present);
        if (ranges.size() == 1) {
            long lo = ranges.get(0)[0], hi = ranges.get(0)[1];
            die.add(C.DW_AT_low_pc, C.DW_FORM_addr, A(lo));
            die.add(C.DW_AT_high_pc, C.DW_FORM_data4, hi - lo);
        }
        else {
            List<long[]> rs = new ArrayList<>();
            for (long[] r : ranges) {
                rs.add(new long[] {A(r[0]), A(r[0]) + (r[1] - r[0])});
            }
            die.add(C.DW_AT_ranges, C.DW_FORM_sec_offset, (long) dw.addRanges(rs));
        }
        die.add(C.DW_AT_frame_base, C.DW_FORM_exprloc, dw.expr().callFrameCfa().bytes());
        for (long[] r : ranges) {
            funcRanges.add(new long[] {A(r[0]), A(r[0]) + (r[1] - r[0])});
        }
        long size = ranges.get(0)[1] - entry;
        if (!prep.missing.isEmpty()) {
            TreeSet<Address> ms = new TreeSet<>(prep.missing);
            List<String> shown = new ArrayList<>();
            for (Address a : ms) {
                if (shown.size() < 4) {
                    shown.add(a.toString());
                }
            }
            log("WARNING: " + name + ": switch cases at " + String.join(", ", shown) +
                " are not disassembled: no CFI or variable locations there. Disassemble them and re-export.");
        }
        FunctionFlow flow = prep.flow;
        if (prep.flowError != null) {
            log("WARNING: flow analysis failed for " + name + ": " + prep.flowError);
        }

        long tc = System.nanoTime();
        if (cfi != null) {
            cfi.add(prep.fdes);
        }
        addTime("cfi", tc);
        List<String> aliases = aliases(func.getEntryPoint(), func.getSymbol());
        if (isThumb(func.getEntryPoint())) {
            elfSymbols.add(new ElfSym(name, A(entry) | 1, size, C.STT_FUNC, 0, C.STB_GLOBAL));
            for (String a : aliases) {
                elfSymbols.add(new ElfSym(a, A(entry) | 1, 0, C.STT_FUNC, 0, C.STB_LOCAL));
            }
            elfSymbols.add(new ElfSym("$t", A(entry), 0, C.STT_NOTYPE, 0, C.STB_LOCAL));
        }
        else {
            int bits = symbolIsaBits(func);
            elfSymbols.add(new ElfSym(name, A(entry), size, C.STT_FUNC, bits, C.STB_GLOBAL));
            for (String a : aliases) {
                elfSymbols.add(new ElfSym(a, A(entry), 0, C.STT_FUNC, bits, C.STB_LOCAL));
            }
            if (lang.getProcessor().toString().equals("ARM")) {
                elfSymbols.add(new ElfSym("$a", A(entry), 0, C.STT_NOTYPE, 0, C.STB_LOCAL));
            }
        }

        List<String> flines = new ArrayList<>();
        flines.add("");
        flines.add("/* ---- " + nm.apply(name) + " @ " + func.getEntryPoint() + " ---- */");
        varDies = new ArrayList<>();
        codeDecls = new HashMap<>();
        annCarry = "";
        labels = new ArrayList<>();
        int base = flines.size();
        int sigLine;
        Map<Long, Integer> addrLines;
        Function target;

        if (markup == null || hf == null) {
            stat("decompile_failed");
            String msg = res != null ? String.valueOf(res.getErrorMessage())
                    : (isSkipped ? "skipped (skip_decompile)" : "no result");
            String sig = protoText(func);
            exportPrototypeParams(die, func, ranges, flow);
            msg = String.join(" ", Names.pySplit(msg));
            flines.add(sig + " /* decompilation failed: " + msg.replace("*/", "* /") + " */");
            sigLine = base + 1;
            types.ref(die, func.getReturnType());
            addrLines = new LinkedHashMap<>();
        }
        else if ((target = thunkTarget(func)) != null) {
            String tname = nm.apply(Names.qualified(target));
            LocalSymbolMap lsm = hf.getLocalSymbolMap();
            List<HighSymbol> hparams = new ArrayList<>();
            for (int i = 0; i < lsm.getNumParams(); i++) {
                HighSymbol p = lsm.getParamSymbol(i);
                if (p != null) {
                    hparams.add(p);
                }
            }
            List<String> argNames = new ArrayList<>();
            for (HighSymbol p : hparams) {
                argNames.add(nm.apply(p.getName()));
            }
            DataType ret = func.getReturnType();
            boolean isVoid = ret == null || ret instanceof VoidDataType || ret.getLength() <= 0;
            String sigText = protoText(func);
            if (!hparams.isEmpty() && func.getParameters().length == 0) {
                FunctionPrototype proto = hf.getFunctionPrototype();
                DataType rt = proto != null ? proto.getReturnType() : func.getReturnType();
                List<String> ps = new ArrayList<>();
                for (HighSymbol p : hparams) {
                    ps.add(nmType.apply(p.getDataType().getDisplayName()) + " " + nm.apply(p.getName()));
                }
                sigText = (rt != null ? nmType.apply(rt.getDisplayName()) : "void") + " " +
                    nm.apply(Names.qualified(func)) + "(" + String.join(", ", ps) + ")";
            }
            flines.add(sigText);
            flines.add("{");
            flines.add("  " + (isVoid ? "" : "return ") + tname + "(" + String.join(", ", argNames) + ");   /* thunk */");
            flines.add("}");
            sigLine = base + 1;
            addrLines = new LinkedHashMap<>();
            for (Instruction ins : listing.getInstructions(func.getBody(), true)) {
                addrLines.put(ins.getAddress().getOffset(), base + 3);
            }
            FunctionPrototype proto = hf.getFunctionPrototype();
            types.ref(die, proto != null ? proto.getReturnType() : ret);
            exportVariables(die, prep.vars);
        }
        else {
            codeDecls = findCodeDecls(markup);
            annCarry = "";
            List<ClangLine> lines = DecompilerUtils.toLines(markup);
            addrLines = new LinkedHashMap<>();
            TreeMap<Long, TreeSet<Integer>> claims = new TreeMap<>();
            Map<Long, Set<Integer>> retClaims = new HashMap<>();
            Map<Long, Integer> callClaims = new HashMap<>();
            Integer sig = null;
            int carryAt = -1;
            for (ClangLine cl : lines) {
                List<ClangToken> toks = cl.getAllTokens();
                boolean hasComment = false;
                for (ClangToken t : toks) {
                    if (t instanceof ClangCommentToken) {
                        hasComment = true;
                        break;
                    }
                }
                if (!annCarry.isEmpty() && !hasComment) {
                    flines.set(carryAt, flines.get(carryAt) + " " + annCarry.stripTrailing());
                    annCarry = "";
                }
                StringBuilder tb = new StringBuilder(cl.getIndentString());
                for (ClangToken t : toks) {
                    tb.append(tokenText(t));
                }
                String text = tb.toString();
                if (!annCarry.isEmpty()) {
                    carryAt = flines.size();
                }
                if (!qualifiedRenames.isEmpty() && text.contains("::")) {
                    for (String[] q : qualifiedRenames) {
                        if (text.contains(q[0])) {
                            text = text.replace(q[0], q[1]);
                        }
                    }
                }
                flines.add(text);
                int gline = base + cl.getLineNumber();
                List<ClangToken> shown = new ArrayList<>();
                for (ClangToken t : toks) {
                    if (!t.getText().strip().isEmpty()) {
                        shown.add(t);
                    }
                }
                if (shown.size() == 2 && shown.get(0) instanceof ClangLabelToken && shown.get(1).getText().equals(":") &&
                    shown.get(0).getMinAddress() != null && inSpace(shown.get(0).getMinAddress())) {
                    labels.add(new Object[] {tokenText(shown.get(0)), shown.get(0).getMinAddress().getOffset(), gline});
                }
                for (ClangToken tok : toks) {
                    if (sig == null && tok instanceof ClangFuncNameToken) {
                        sig = gline;
                    }
                    if (tok instanceof ClangCommentToken || tok instanceof ClangLabelToken || tok instanceof ClangCaseToken) {
                        continue;
                    }
                    Address a = tok.getMinAddress();
                    if (a == null || !inSpace(a)) {
                        continue;
                    }
                    long ao = a.getOffset();
                    claims.computeIfAbsent(ao, x -> new TreeSet<>()).add(gline);
                    if (tok.getText().equals("return")) {
                        retClaims.computeIfAbsent(ao, x -> new HashSet<>()).add(gline);
                    }
                    if (tok instanceof ClangFuncNameToken && (sig == null || gline != sig)) {
                        callClaims.putIfAbsent(ao, gline);
                    }
                }
            }
            if (!annCarry.isEmpty()) {
                flines.set(carryAt, flines.get(carryAt) + " " + annCarry.stripTrailing());
                annCarry = "";
            }
            Integer closing = null;
            for (int i = 0; i < flines.size(); i++) {
                if (flines.get(i).strip().equals("}")) {
                    closing = i + 1;
                }
            }
            Set<Long> sharedRet = duplicatedReturnCode(hf, flow);
            for (Map.Entry<Long, TreeSet<Integer>> e : claims.entrySet()) {
                long off = e.getKey();
                Set<Integer> rets = retClaims.getOrDefault(off, Collections.emptySet());
                if ((rets.size() > 1 || sharedRet.contains(off)) && closing != null) {
                    addrLines.put(off, closing);
                }
                else {
                    addrLines.put(off, e.getValue().first());
                }
                FunctionFlow.Insn d = flow != null ? flow.decoded.get(off) : null;
                if (callClaims.containsKey(off) && d != null && d.isCall) {
                    addrLines.put(off, callClaims.get(off));
                }
            }
            if (flow != null) {
                List<Long> ins = flow.insns;
                Set<Long> targets = new HashSet<>();
                for (long o : ins) {
                    FunctionFlow.Insn d = flow.decoded.get(o);
                    if (d != null && d.isJump) {
                        for (long t : d.succs) {
                            if (d.fallInBody == null || t != d.fallInBody) {
                                targets.add(t);
                            }
                        }
                    }
                }
                for (int i = 0; i < ins.size(); i++) {
                    long o = ins.get(i);
                    if (addrLines.containsKey(o) || i == 0) {
                        continue;
                    }
                    FunctionFlow.Insn pd = flow.decoded.get(ins.get(i - 1));
                    if (pd != null && pd.fallInBody != null && pd.fallInBody == o && !targets.contains(o)) {
                        continue;
                    }
                    Integer line = null;
                    for (int j = i; j < ins.size(); j++) {
                        long o2 = ins.get(j);
                        if (addrLines.containsKey(o2)) {
                            line = addrLines.get(o2);
                            break;
                        }
                        FunctionFlow.Insn d2 = flow.decoded.get(o2);
                        if (d2 == null || d2.isCall) {
                            break;
                        }
                        if (d2.isJump && d2.fallInBody == null) {
                            List<Long> tgt = new ArrayList<>();
                            for (long t : d2.succs) {
                                if (addrLines.containsKey(t)) {
                                    tgt.add(t);
                                }
                            }
                            if (tgt.size() == 1) {
                                line = addrLines.get(tgt.get(0));
                            }
                            break;
                        }
                        if (d2.isTerminal && d2.fallInBody == null) {
                            break;
                        }
                    }
                    if (line == null) {
                        line = closing;
                    }
                    if (line != null) {
                        addrLines.put(o, line);
                    }
                }
            }
            sigLine = sig != null ? sig : base + 1;
            FunctionPrototype proto = hf.getFunctionPrototype();
            types.ref(die, proto != null ? proto.getReturnType() : func.getReturnType());
            exportVariables(die, prep.vars);
        }
        if (func.hasVarArgs()) {
            die.child(C.DW_TAG_unspecified_parameters);
        }

        Object[] placed = placeFunction(flines);
        CFile cfile = (CFile) placed[0];
        int off = (Integer) placed[1];
        sigLine += off;
        Map<Long, Integer> al = new LinkedHashMap<>();
        for (Map.Entry<Long, Integer> e : addrLines.entrySet()) {
            al.put(e.getKey(), e.getValue() + off);
        }
        addrLines = al;
        addDeclLines(flines, sigLine, off, cfile.fileNo);
        addLabels(die, labels, off, cfile.fileNo, ranges);
        die.add(C.DW_AT_decl_file, C.DW_FORM_udata, (long) cfile.fileNo);
        die.add(C.DW_AT_decl_line, C.DW_FORM_udata, (long) sigLine);

        long localEntry = lang.getProcessor().toString().equals("PowerPC") && addrSize == 8 ? ppc64LocalEntry(func) : 0;
        Long pe = null;
        if (flow != null) {
            Set<Long> body = new HashSet<>();
            for (Map.Entry<Long, Integer> e : addrLines.entrySet()) {
                if (e.getValue() != sigLine) {
                    body.add(e.getKey());
                }
            }
            pe = flow.prologueEnd(localEntry, body);
        }
        if (pe != null && interrupts.contains(entry) && cfi != null) {
            pe = afterIrqSave(flow, pe);
        }
        if (flow != null) {
            for (int i = 0; i < flow.insns.size(); i++) {
                long o = flow.insns.get(i);
                FunctionFlow.Insn d = flow.decoded.get(o);
                if (d != null && d.delay != 0 && addrLines.containsKey(o)) {
                    for (int j = i + 1; j < Math.min(flow.insns.size(), i + 1 + d.delay); j++) {
                        addrLines.put(flow.insns.get(j), addrLines.get(o));
                    }
                }
            }
        }
        if (pe != null) {
            List<Long> run = new ArrayList<>();
            int i = FunctionContext.bisectLeft(flow.insns, pe);
            while (i < flow.insns.size() && ranges.get(0)[0] <= flow.insns.get(i) && flow.insns.get(i) < ranges.get(0)[1]) {
                long o = flow.insns.get(i);
                run.add(o);
                FunctionFlow.Insn d = flow.decoded.get(o);
                if (d == null || d.isCall || d.isJump || d.isTerminal) {
                    break;
                }
                i++;
            }
            Integer bodyLine = null;
            for (long a : run) {
                Integer l = addrLines.get(a);
                if (l != null && l != sigLine && (bodyLine == null || l < bodyLine)) {
                    bodyLine = l;
                }
            }
            if (bodyLine == null) {
                bodyLine = addrLines.get(pe);
            }
            if (bodyLine == null) {
                Long minLater = null;
                for (long a : addrLines.keySet()) {
                    if (a > pe && ranges.get(0)[0] <= a && a < ranges.get(0)[1] && (minLater == null || a < minLater)) {
                        minLater = a;
                    }
                }
                bodyLine = minLater != null ? addrLines.get(minLater) : sigLine;
            }
            addrLines.put(pe, bodyLine);
            if (pe != entry) {
                for (long a : new ArrayList<>(addrLines.keySet())) {
                    if (entry <= a && a < pe) {
                        addrLines.put(a, sigLine);
                    }
                }
                addrLines.put(entry, sigLine);
            }
        }
        else {
            addrLines.put(entry, sigLine);
        }
        TreeMap<Long, Integer> sortedLines = new TreeMap<>(addrLines);
        for (long[] r : ranges) {
            long lo = r[0], hi = r[1];
            List<long[]> rows = new ArrayList<>();
            for (Map.Entry<Long, Integer> e : sortedLines.subMap(lo, true, hi, false).entrySet()) {
                rows.add(new long[] {e.getKey(), e.getValue()});
            }
            if (rows.isEmpty() || rows.get(0)[0] != lo) {
                Map.Entry<Long, Integer> prev = sortedLines.lowerEntry(lo);
                rows.add(0, new long[] {lo, prev != null ? prev.getValue() : sigLine});
            }
            List<long[]> compact = new ArrayList<>();
            for (long[] row : rows) {
                if (compact.isEmpty() || compact.get(compact.size() - 1)[1] != row[1] || (pe != null && row[0] == pe)) {
                    compact.add(row);
                }
            }
            List<Row> outRows = new ArrayList<>();
            for (long[] row : compact) {
                outRows.add(new Row(A(row[0]), row[1], pe != null && row[0] == pe ? DwarfBuilder.ROW_PROLOGUE_END : 0));
            }
            if (opts.frameless_rows && pe != null && pe == entry && lo == entry && !outRows.isEmpty() &&
                outRows.get(0).line != sigLine) {
                outRows.add(0, new Row(A(entry), sigLine, 0));
            }
            stats.merge("line_rows", (long) outRows.size(), Long::sum);
            dw.addSequence(outRows, A(lo) + (hi - lo), cfile.fileNo);
        }
    }

    long afterIrqSave(FunctionFlow flow, long pe) {
        Object[] irq = cfi.irqReturnReg(flow);
        if (irq == null) {
            return pe;
        }
        Val want = Val.init((Key) irq[0]);
        int i = FunctionContext.bisectLeft(flow.insns, pe);
        while (i < flow.insns.size()) {
            long o = flow.insns.get(i);
            State st = flow.stateIn.get(o);
            if (st != null) {
                for (State.Slot s : st.mem.values()) {
                    if (want.equals(s.v)) {
                        return o;
                    }
                }
            }
            FunctionFlow.Insn d = flow.decoded.get(o);
            if (d == null || d.isCall || d.isJump || d.isTerminal) {
                break;
            }
            i++;
        }
        return pe;
    }

    static final Pattern RESTGPR = Pattern.compile("^_restgpr_(\\d+)_x$");

    /** PPC32 "_restgpr_N_x" epilogue helper: r11 is the CFA, LR at 4(r11), rN..r31 below. */
    State helperEntryState(Function func) {
        Matcher m = RESTGPR.matcher(func.getName());
        if (!m.matches() || !lang.getProcessor().toString().equals("PowerPC") || addrSize != 4) {
            return null;
        }
        int first = Integer.parseInt(m.group(1));
        Key r11 = regKey("r11"), lr = machine.raKey;
        if (r11 == null || lr == null || first < 13 || first > 31) {
            return null;
        }
        State st = new State();
        st.put(machine, r11, Val.sp(0));
        st.put(machine, machine.spKey, null);
        st.put(machine, lr, null);
        st.mem.put(4L, new State.Slot(4, Val.init(lr)));
        for (int n = first; n < 32; n++) {
            Key k = regKey("r" + n);
            st.put(machine, k, null);
            st.mem.put((long) (-4 * (32 - n)), new State.Slot(4, Val.init(k)));
        }
        return st;
    }

    Key regKey(String name) {
        Register r = lang.getRegister(name);
        return r != null ? Key.reg(r.getAddress().getOffset(), r.getMinimumByteSize()) : null;
    }

    /** For a handler entered only by branches from other handlers: the state at those branches. */
    State irqEntryState(Function func) {
        long entry = func.getEntryPoint().getOffset();
        List<long[]> srcs = irqJumps.get(entry);
        if (srcs == null || srcs.isEmpty() || entryPoints.contains(entry)) {
            return null;
        }
        FunctionManager fm = program.getFunctionManager();
        List<State> states = new ArrayList<>();
        for (long[] so : srcs) {
            FunctionFlow sf;
            try {
                sf = new FunctionFlow(machine, fm.getFunctionAt(space.getAddress(so[0])), null, null);
            }
            catch (Exception e) {
                return null;
            }
            State st = sf.stateOut.get(so[1]);
            if (st == null) {
                return null;
            }
            states.add(st);
        }
        State first = states.get(0);
        Key sp = machine.spKey;
        for (State s : states.subList(1, states.size())) {
            if (!java.util.Objects.equals(s.get(machine, sp), first.get(machine, sp)) || !s.mem.equals(first.mem)) {
                return null;
            }
        }
        return first;
    }

    /** Names of the other user/analysis labels at addr (not primary), sorted. */
    List<String> aliases(Address addr, Symbol primary) {
        List<String> out = new ArrayList<>();
        for (Symbol s : program.getSymbolTable().getSymbols(addr)) {
            if (s.isDynamic() || s.getSource() == SourceType.DEFAULT || s.equals(primary)) {
                continue;
            }
            if (s.getSymbolType() != SymbolType.LABEL && s.getSymbolType() != SymbolType.FUNCTION) {
                continue;
            }
            String n = Names.qualified(s);
            if (!out.contains(n)) {
                out.add(n);
            }
        }
        out.sort(Exporter::pyCompare);
        return out;
    }

    /** Python's str order (code points). */
    static int pyCompare(String a, String b) {
        int i = 0, j = 0;
        while (i < a.length() && j < b.length()) {
            int ca = a.codePointAt(i), cb = b.codePointAt(j);
            if (ca != cb) {
                return Integer.compare(ca, cb);
            }
            i += Character.charCount(ca);
            j += Character.charCount(cb);
        }
        return Integer.compare(a.length() - i, b.length() - j);
    }

    static final Pattern DECL_TAIL = Pattern.compile("^(.*?)((?:\\s*\\*|\\[\\d*\\])*)$", Pattern.DOTALL);

    String protoText(Function func) {
        java.util.function.Function<DataType, String> tn = dt -> {
            if (dt == null) {
                return "void";
            }
            Matcher m = DECL_TAIL.matcher(dt.getDisplayName());
            m.matches();
            return nmType.apply(m.group(1).strip()) + m.group(2);
        };
        List<String> params = new ArrayList<>();
        for (Parameter p : func.getParameters()) {
            params.add(tn.apply(p.getDataType()) + " " + nm.apply(p.getName()));
        }
        if (func.hasVarArgs()) {
            params.add("...");
        }
        return tn.apply(func.getReturnType()) + " " + nm.apply(Names.qualified(func)) + "(" +
            (params.isEmpty() ? "void" : String.join(", ", params)) + ")";
    }

    void exportEquates() {
        SymbolTable st = program.getSymbolTable();
        List<Object[]> found = new ArrayList<>();
        Iterator<Equate> it = program.getEquateTable().getEquates();
        while (it.hasNext()) {
            Equate e = it.next();
            String name = e.getName();
            try {
                if (e.isEnumBased()) {
                    continue;
                }
            }
            catch (Exception ex) {
                // older API
            }
            if (name.isEmpty() || !(Character.isLetter(name.codePointAt(0)) || name.charAt(0) == '_')) {
                continue;
            }
            if (st.getGlobalSymbols(name).size() > 0) {
                continue;
            }
            found.add(new Object[] {name, e.getValue()});
        }
        if (found.isEmpty()) {
            return;
        }
        Die die = dw.cu.child(C.DW_TAG_enumeration_type);
        die.add(C.DW_AT_byte_size, C.DW_FORM_udata, 8L);
        Die under = types.baseOfSize(8, true);
        if (under != null) {
            die.add(C.DW_AT_type, C.DW_FORM_ref4, under);
        }
        found.sort((a, b) -> {
            int c = pyCompare((String) a[0], (String) b[0]);
            return c != 0 ? c : Long.compare((Long) a[1], (Long) b[1]);
        });
        for (Object[] f : found) {
            Die e = die.child(C.DW_TAG_enumerator);
            dw.name(e, (String) f[0]);
            e.add(C.DW_AT_const_value, C.DW_FORM_sdata, f[1]);
        }
        stats.put("equates", (long) found.size());
    }

    void addLabels(Die die, List<Object[]> labels, int off, int fileNo, List<long[]> ranges) {
        for (Object[] l : labels) {
            long addr = (Long) l[1];
            boolean inside = false;
            for (long[] r : ranges) {
                if (r[0] <= addr && addr < r[1]) {
                    inside = true;
                }
            }
            if (!inside) {
                continue;
            }
            Die lab = die.child(C.DW_TAG_label);
            dw.name(lab, (String) l[0], true);
            lab.add(C.DW_AT_decl_file, C.DW_FORM_udata, (long) fileNo);
            lab.add(C.DW_AT_decl_line, C.DW_FORM_udata, (long) ((Integer) l[2] + off));
            lab.add(C.DW_AT_low_pc, C.DW_FORM_addr, A(addr));
        }
    }

    void addDeclLines(List<String> flines, int sigLine, int off, int fileNo) {
        List<Object[]> body = null;
        for (Object[] vd : varDies) {
            Die die = (Die) vd[0];
            String vname = (String) vd[1];
            boolean isParam = (Boolean) vd[2];
            Integer line = null;
            if (isParam) {
                line = sigLine;
            }
            else {
                if (body == null) {
                    body = new ArrayList<>();
                    for (int i = sigLine - off; i < flines.size(); i++) {
                        if (!body.isEmpty() && flines.get(i).strip().isEmpty()) {
                            break;
                        }
                        body.add(new Object[] {i + 1 + off, flines.get(i)});
                    }
                }
                Pattern pat = Pattern.compile("(?<![\\w?:'$])" + Pattern.quote(nm.apply(vname)) +
                    "(?![\\w?:'$])\\s*(\\[[^\\]]*\\]\\s*)*;", Pattern.UNICODE_CHARACTER_CLASS);
                for (Object[] b : body) {
                    if (pat.matcher((String) b[1]).find()) {
                        line = (Integer) b[0];
                        break;
                    }
                }
            }
            if (line != null) {
                die.add(C.DW_AT_decl_file, C.DW_FORM_udata, (long) fileNo);
                die.add(C.DW_AT_decl_line, C.DW_FORM_udata, (long) line);
            }
        }
    }

    void exportPrototypeParams(Die die, Function func, List<long[]> ranges, FunctionFlow flow) {
        FunctionContext ctx = new FunctionContext(this, func, null, ranges, flow);
        for (Parameter p : func.getParameters()) {
            stat("variables");
            Die pd = die.child(C.DW_TAG_formal_parameter);
            varDies.add(new Object[] {pd, p.getName(), true});
            dw.name(pd, p.getName());
            types.ref(pd, p.getDataType());
            FunctionContext.Location loc;
            try {
                loc = ctx.entryValueLocation(p.getVariableStorage());
            }
            catch (Exception e) {
                log("WARNING: " + func.getName() + "/" + p.getName() + ": location failed: " + e);
                loc = null;
            }
            if (loc == null) {
                continue;
            }
            stat("variables_located");
            addLocation(pd, loc);
        }
    }

    void addLocation(Die die, FunctionContext.Location loc) {
        if (loc.expr != null) {
            die.add(C.DW_AT_location, C.DW_FORM_exprloc, loc.expr);
        }
        else {
            List<Object[]> entries = new ArrayList<>();
            for (FunctionContext.Span s : loc.list) {
                entries.add(new Object[] {s.start, s.end, s.expr});
            }
            die.add(C.DW_AT_location, C.DW_FORM_sec_offset, (long) dw.addLoclist(entries));
        }
    }

    static final Pattern ADDI_R2 = Pattern.compile("^(addi|subi|addic) r2,r2,");
    static final Pattern GLOBAL_ENTRY = Pattern.compile("^(addis r2,r12,|lis r2,)");

    Function thunkTarget(Function func) {
        if (func.isThunk()) {
            return func.getThunkedFunction(true);
        }
        List<Instruction> insns = new ArrayList<>();
        for (Instruction ins : listing.getInstructions(func.getBody(), true)) {
            insns.add(ins);
            if (insns.size() > 3) {
                return null;
            }
        }
        if (insns.isEmpty()) {
            return null;
        }
        Instruction last = insns.get(insns.size() - 1);
        ghidra.program.model.symbol.FlowType ft = last.getFlowType();
        if (ft.isConditional() || !(ft.isJump() || (ft.isCall() && ft.isTerminal()))) {
            return null;
        }
        List<Address> flows = new ArrayList<>();
        for (Address t : last.getFlows()) {
            if (t != null) {
                flows.add(t);
            }
        }
        if (flows.size() != 1) {
            return null;
        }
        FunctionManager fm = program.getFunctionManager();
        Function target = fm.getFunctionAt(flows.get(0));
        boolean ppc64 = lang.getProcessor().toString().equals("PowerPC") && addrSize == 8;
        if (target == null && ppc64) {
            target = fm.getFunctionContaining(flows.get(0));
            if (target != null &&
                flows.get(0).getOffset() - target.getEntryPoint().getOffset() != ppc64LocalEntry(target)) {
                target = null;
            }
        }
        if (target == null || target.equals(func)) {
            return null;
        }
        for (Instruction ins : insns.subList(0, insns.size() - 1)) {
            Register r = ins.getRegister(0);
            if (!ppc64 || r == null || !r.toString().equals("r2")) {
                return null;
            }
        }
        return target;
    }

    /**
     * The function's variables in export order (parameters, then the other
     * symbols sorted by name and storage), each with its location or the
     * error computing it: {HighSymbol, Boolean is param, Location, error}.
     */
    List<Object[]> variableLocations(Function func, HighFunction hf, List<long[]> ranges, FunctionFlow flow,
            boolean paramsOnly) {
        LocalSymbolMap lsm = hf.getLocalSymbolMap();
        List<HighSymbol> params = new ArrayList<>();
        for (int i = 0; i < lsm.getNumParams(); i++) {
            HighSymbol s = lsm.getParamSymbol(i);
            if (s != null) {
                params.add(s);
            }
        }
        Set<Long> paramIds = new HashSet<>();
        for (HighSymbol s : params) {
            paramIds.add(s.getId());
        }
        List<HighSymbol> others = new ArrayList<>();
        Iterator<HighSymbol> it = lsm.getSymbols();
        while (it.hasNext()) {
            HighSymbol s = it.next();
            if (!paramIds.contains(s.getId())) {
                others.add(s);
            }
        }
        others.sort((a, b) -> {
            int c = pyCompare(a.getName(), b.getName());
            return c != 0 ? c : pyCompare(String.valueOf(a.getStorage()), String.valueOf(b.getStorage()));
        });
        FunctionContext ctx = new FunctionContext(this, func, hf, ranges, flow);
        List<Object[]> out = new ArrayList<>();
        List<Object[]> order = new ArrayList<>();
        for (HighSymbol sym : params) {
            order.add(new Object[] {sym, true});
        }
        if (!paramsOnly) {
            for (HighSymbol sym : others) {
                order.add(new Object[] {sym, sym.isParameter()});
            }
        }
        for (Object[] o : order) {
            HighSymbol sym = (HighSymbol) o[0];
            FunctionContext.Location loc = null;
            String err = null;
            try {
                loc = ctx.symbolLocation(sym);
            }
            catch (Exception e) {
                err = String.valueOf(e);
            }
            out.add(new Object[] {sym, o[1], loc, err});
        }
        return out;
    }

    void exportVariables(Die funcDie, List<Object[]> vars) {
        long tv = System.nanoTime();
        for (Object[] v : vars) {
            exportVariable(funcDie, (HighSymbol) v[0], (Boolean) v[1], (FunctionContext.Location) v[2], (String) v[3]);
        }
        addTime("variables", tv);
    }

    static Set<Long> duplicatedReturnCode(HighFunction hf, FunctionFlow flow) {
        Set<Long> none = new HashSet<>();
        if (flow == null || hf == null) {
            return none;
        }
        Map<Long, Integer> seen = new HashMap<>();
        Set<Long> rets = new HashSet<>();
        for (PcodeBlockBasic b : hf.getBasicBlocks()) {
            AddressSet cover = FunctionContext.blockCover(b);
            if (cover == null) {
                return none;
            }
            List<Long> offs = FunctionContext.coverOffsets(cover, flow.insns);
            for (long o : offs) {
                seen.merge(o, 1, Integer::sum);
            }
            if (b.getOutSize() == 0) {
                rets.addAll(offs);
            }
        }
        Set<Long> out = new HashSet<>();
        for (long o : rets) {
            if (seen.get(o) > 1 && !splits(flow, o)) {
                out.add(o);
            }
        }
        return out;
    }

    private static boolean splits(FunctionFlow flow, long o) {
        FunctionFlow.Insn d = flow.decoded.get(o);
        if (d == null) {
            return false;
        }
        if (d.isTerminal && d.fallInBody != null) {
            return true;
        }
        for (Op op : d.ops) {
            // (a p-code-relative branch, or one to the instruction's own
            // fall-through: Thumb IT-block predication)
            if ((op.opc == PcodeOp.CBRANCH || op.opc == PcodeOp.BRANCH) && op.i0 != null && (op.i0.kind == 'c' ||
                (op.i0.kind == 'a' && (op.i0.off == d.nxt || op.i0.off == d.fallOrNext)))) {
                return true;
            }
        }
        return false;
    }

    static final Pattern CODE_DECL = Pattern.compile("\\s*code\\s*(\\*+)");

    /** {variable name: pointer depth} for variables declared "code *". */
    static Map<String, Integer> findCodeDecls(ClangTokenGroup markup) {
        Map<String, Integer> out = new HashMap<>();
        ArrayDeque<ClangNode> stack = new ArrayDeque<>();
        stack.push(markup);
        while (!stack.isEmpty()) {
            ClangNode node = stack.pop();
            if (node instanceof ClangVariableDecl) {
                Matcher m = CODE_DECL.matcher(node.toString());
                HighSymbol hs = ((ClangVariableDecl) node).getHighSymbol();
                if (m.lookingAt() && hs != null) {
                    out.put(hs.getName(), m.group(1).length());
                }
                continue;
            }
            if (node instanceof ClangTokenGroup) {
                ClangTokenGroup g = (ClangTokenGroup) node;
                for (int i = 0; i < g.numChildren(); i++) {
                    stack.push(g.Child(i));
                }
            }
        }
        return out;
    }

    void exportVariable(Die funcDie, HighSymbol sym, boolean isParam, FunctionContext.Location loc, String err) {
        stat("variables");
        int tag = isParam ? C.DW_TAG_formal_parameter : C.DW_TAG_variable;
        Die die = funcDie.child(tag);
        dw.name(die, sym.getName());
        varDies.add(new Object[] {die, sym.getName(), isParam});
        Integer depth = codeDecls.get(sym.getName());
        if (depth != null && depth != 0 && Names.classify(sym.getDataType()).equals("ptr")) {
            die.add(C.DW_AT_type, C.DW_FORM_ref4, types.codePointer(depth));
        }
        else {
            types.ref(die, sym.getDataType());
        }
        if (err != null) {
            log("WARNING: " + sym.getHighFunction().getFunction().getName() + "/" + sym.getName() +
                ": location failed: " + err);
            return;
        }
        if (loc == null) {
            return;
        }
        stat("variables_located");
        addLocation(die, loc);
    }

    // -- globals -------------------------------------------------------------------------

    void exportGlobals() throws Exception {
        monitor.setMessage("Exporting global data");
        Set<Long> seen = new HashSet<>();
        DataIterator it = listing.getDefinedData(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Data data = it.next();
            Address addr = data.getAddress();
            if (!inSpace(addr)) {
                continue;
            }
            Symbol sym = data.getPrimarySymbol();
            if (sym == null) {
                continue;
            }
            String name = Names.qualified(sym);
            DataType dt = data.getDataType();
            int length = data.getLength();
            Die typeDie = null;
            if (dt != null && dt.getLength() > 0) {
                typeDie = types.get(dt);
            }
            else if (length > 0) {
                Die arr = dw.cu.child(C.DW_TAG_array_type);
                DataType elem = Names.stringCharType(data);
                long count;
                if (elem != null && length % elem.getLength() == 0) {
                    types.ref(arr, elem);
                    count = length / elem.getLength();
                }
                else {
                    arr.add(C.DW_AT_type, C.DW_FORM_ref4, types.baseOfSize(1, false));
                    count = length;
                }
                arr.child(C.DW_TAG_subrange_type).add(C.DW_AT_count, C.DW_FORM_udata, count);
                typeDie = arr;
            }
            byte[] location = dw.expr().addr(A(addr.getOffset())).bytes();
            List<String> names = new ArrayList<>();
            names.add(name);
            names.addAll(aliases(addr, sym));
            for (int i = 0; i < names.size(); i++) {
                Die die = dw.cu.child(C.DW_TAG_variable);
                dw.name(die, names.get(i));
                die.add(C.DW_AT_external, C.DW_FORM_flag_present);
                if (typeDie != null) {
                    die.add(C.DW_AT_type, C.DW_FORM_ref4, typeDie);
                }
                die.add(C.DW_AT_location, C.DW_FORM_exprloc, location);
                if (i == 0) {
                    elfSymbols.add(new ElfSym(names.get(i), A(addr.getOffset()), length, C.STT_OBJECT, 0, C.STB_GLOBAL));
                }
            }
            seen.add(addr.getOffset());
            stat("globals");
        }
        SymbolIterator sit = program.getSymbolTable().getAllSymbols(true);
        while (sit.hasNext()) {
            Symbol s = sit.next();
            if (s.getSymbolType() != SymbolType.LABEL) {
                continue;
            }
            Address addr = s.getAddress();
            if (!inSpace(addr) || seen.contains(addr.getOffset())) {
                continue;
            }
            if (listing.getInstructionContaining(addr) != null) {
                continue;
            }
            if (s.isDynamic() && listing.getDefinedDataContaining(addr) != null) {
                continue;
            }
            elfSymbols.add(new ElfSym(Names.qualified(s), A(addr.getOffset()), 0, C.STT_NOTYPE, 0, C.STB_GLOBAL));
        }
    }

    void exportAllTypes() {
        Iterator<DataType> it = program.getDataTypeManager().getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (dt instanceof Structure || dt instanceof Union || dt instanceof ghidra.program.model.data.Enum ||
                dt instanceof TypeDef) {
                types.get(dt);
            }
        }
    }

    // -- ELF -----------------------------------------------------------------------------

    long[] elfMachine() {
        String proc = lang.getProcessor().toString();
        int[] pair = C.ELF_MACHINES.get(proc);
        if (pair == null) {
            log("WARNING: no ELF machine for processor " + proc + "; using EM_NONE (use 'set architecture' in GDB)");
            return new long[] {0, 0};
        }
        long machineNo = addrSize == 8 ? pair[1] : pair[0];
        if (opts.elf_flags >= 0) {
            return new long[] {machineNo, opts.elf_flags};
        }
        return new long[] {machineNo, elfFlags(proc)};
    }

    byte[] armAttributes(long flags) {
        DwarfBuilder.Buf attrs = new DwarfBuilder.Buf().add(DwarfBuilder.uleb(28)).add(DwarfBuilder.uleb((flags & 0x400) != 0 ? 1 : 0));
        byte[] a = attrs.bytes();
        DwarfBuilder.Buf fileSub = new DwarfBuilder.Buf().add(1).add(DwarfBuilder.pack(5 + a.length, 4, bigEndian)).add(a);
        byte[] fs = fileSub.bytes();
        DwarfBuilder.Buf vendor = new DwarfBuilder.Buf().add("aeabi".getBytes(StandardCharsets.US_ASCII)).add(0).add(fs);
        byte[] v = vendor.bytes();
        return new DwarfBuilder.Buf().add('A').add(DwarfBuilder.pack(4 + v.length, 4, bigEndian)).add(v).bytes();
    }

    boolean isThumb(Address addr) {
        if (!lang.getProcessor().toString().equals("ARM")) {
            return false;
        }
        ProgramContext ctx = program.getProgramContext();
        Register treg = ctx.getRegister("TMode");
        if (treg == null) {
            return false;
        }
        java.math.BigInteger v = ctx.getValue(treg, addr, false);
        return v != null && v.intValue() == 1;
    }

    int symbolIsaBits(Function func) {
        if (lang.getProcessor().toString().equals("PowerPC") && addrSize == 8) {
            if (ppc64LocalEntry(func) != 0) {
                return 3 << 5;
            }
        }
        return 0;
    }

    static final Pattern FP_REG = Pattern.compile("^[sdf]\\d+$");

    boolean floatRegsForArgs() {
        ghidra.program.model.lang.CompilerSpec cspec = program.getCompilerSpec();
        LinkedHashMap<String, Integer> used = new LinkedHashMap<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (!f.isExternal()) {
                used.merge(String.valueOf(f.getCallingConventionName()), 1, Integer::sum);
            }
        }
        List<Map.Entry<String, Integer>> common = new ArrayList<>(used.entrySet());
        common.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));
        PrototypeModel cc = null;
        for (Map.Entry<String, Integer> e : common) {
            cc = cspec.getCallingConvention(e.getKey());
            if (cc != null) {
                break;
            }
        }
        if (cc == null) {
            cc = cspec.getDefaultCallingConvention();
        }
        try {
            for (VariableStorage st : cc.getPotentialInputRegisterStorage(program)) {
                for (Varnode vn : st.getVarnodes()) {
                    Register reg = program.getRegister(vn);
                    if (reg != null && FP_REG.matcher(reg.getName()).matches()) {
                        return true;
                    }
                }
            }
        }
        catch (Exception e) {
            // no information
        }
        return false;
    }

    long elfFlags(String proc) {
        ghidra.program.model.lang.LanguageDescription desc = lang.getLanguageDescription();
        if (proc.equals("ARM")) {
            long flags = 0x05000000L;
            if (bigEndian && desc.getInstructionEndian() == Endian.LITTLE) {
                flags |= 0x00800000L;
            }
            flags |= floatRegsForArgs() ? 0x400 : 0x200;
            return flags;
        }
        if (proc.equals("MIPS")) {
            if (addrSize == 8) {
                return 0x80000000L;
            }
            String cspec = program.getCompilerSpec().getCompilerSpecID().toString();
            Register a0 = lang.getRegister("a0");
            if (a0 != null && a0.getMinimumByteSize() == 8) {
                if (cspec.contains("n32")) {
                    return 0x80000000L | 0x20;
                }
                if (cspec.contains("o32")) {
                    return 0x80000000L | 0x1000;
                }
                return 0x80000000L | 0x2000;
            }
            long abi = cspec.contains("eabi") ? 0x3000 : 0x1000;
            return 0x70000000L | abi;
        }
        if (proc.equals("PowerPC") && addrSize == 8) {
            if (!bigEndian || ppc64HasGlobalEntries()) {
                return 2;
            }
            return 1;
        }
        return 0;
    }

    long ppc64LocalEntry(Function func) {
        Instruction ins = listing.getInstructionAt(func.getEntryPoint());
        if (ins == null || !GLOBAL_ENTRY.matcher(ins.toString()).lookingAt()) {
            return 0;
        }
        Instruction nxt = ins.getNext();
        if (nxt == null || !ADDI_R2.matcher(nxt.toString()).lookingAt()) {
            return 0;
        }
        return 8;
    }

    boolean ppc64HasGlobalEntries() {
        if (ppc64Ge == null) {
            ppc64Ge = false;
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (!f.isExternal() && ppc64LocalEntry(f) != 0) {
                    ppc64Ge = true;
                    break;
                }
            }
        }
        return ppc64Ge;
    }

    /** Sorted, merged [(lo, hi)] Ghidra offsets covered by function bodies. */
    List<long[]> codeRanges() {
        List<long[]> rs = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.isExternal()) {
                continue;
            }
            for (AddressRange r : f.getBody().getAddressRanges()) {
                if (inSpace(r.getMinAddress())) {
                    rs.add(new long[] {r.getMinAddress().getOffset(), r.getMaxAddress().getOffset() + 1});
                }
            }
        }
        rs.sort((a, b) -> a[0] != b[0] ? Long.compare(a[0], b[0]) : Long.compare(a[1], b[1]));
        List<long[]> merged = new ArrayList<>();
        for (long[] r : rs) {
            if (!merged.isEmpty() && r[0] <= merged.get(merged.size() - 1)[1] + 16) {
                long[] last = merged.get(merged.size() - 1);
                merged.set(merged.size() - 1, new long[] {last[0], Math.max(r[1], last[1])});
            }
            else {
                merged.add(r);
            }
        }
        return merged;
    }

    static final int MAX_SECTION_RUNS = 20000;
    static final int SECTION_BUDGET = 60000;

    /** Partition [lo, hi) into [(start, end, kind)] runs: kind 1 code, 0 data. */
    List<long[]> splitRuns(long lo, long hi, List<long[]> code) {
        List<long[]> runs = new ArrayList<>();
        long pos = lo;
        int i = 0;
        // bisect_left(code, (lo, lo))
        int a = 0, b = code.size();
        while (a < b) {
            int mid = (a + b) >>> 1;
            long[] c = code.get(mid);
            if (c[0] < lo || (c[0] == lo && c[1] < lo)) {
                a = mid + 1;
            }
            else {
                b = mid;
            }
        }
        i = a;
        if (i > 0 && code.get(i - 1)[1] > lo) {
            i--;
        }
        while (i < code.size() && code.get(i)[0] < hi) {
            long clo = Math.max(code.get(i)[0], lo), chi = Math.min(code.get(i)[1], hi);
            if (clo > pos) {
                runs.add(new long[] {pos, clo, 0});
            }
            if (chi > clo) {
                runs.add(new long[] {Math.max(clo, pos), chi, 1});
                pos = chi;
            }
            i++;
        }
        if (pos < hi) {
            runs.add(new long[] {pos, hi, 0});
        }
        if (runs.size() > Math.min(MAX_SECTION_RUNS, SECTION_BUDGET - runsUsed) || runs.isEmpty()) {
            if (!runs.isEmpty()) {
                log(String.format("WARNING: too many code/data runs in block at 0x%x; exporting it as one code section",
                    lo));
            }
            List<long[]> one = new ArrayList<>();
            one.add(new long[] {lo, hi, 1});
            return one;
        }
        runsUsed += runs.size();
        return runs;
    }

    byte[] readBytes(long lo, long hi) throws Exception {
        byte[] buf = new byte[(int) (hi - lo)];
        memory.getBytes(space.getAddress(lo), buf);
        return buf;
    }

    /** Split runs around .opd regions (kind 2). */
    static List<long[]> carveOpd(List<long[]> runs, List<long[]> opd) {
        if (opd.isEmpty()) {
            return runs;
        }
        List<long[]> out = new ArrayList<>();
        for (long[] r : runs) {
            long lo = r[0], hi = r[1], kind = r[2];
            long pos = lo;
            for (long[] o : opd) {
                if (o[1] <= pos || o[0] >= hi) {
                    continue;
                }
                if (o[0] > pos) {
                    out.add(new long[] {pos, o[0], kind});
                }
                out.add(new long[] {Math.max(o[0], pos), Math.min(o[1], hi), 2});
                pos = Math.min(o[1], hi);
            }
            if (pos < hi) {
                out.add(new long[] {pos, hi, kind});
            }
        }
        return out;
    }

    long word(long off) throws Exception {
        byte[] b = readBytes(off, off + 8);
        long v = 0;
        for (int i = 0; i < 8; i++) {
            int idx = bigEndian ? i : 7 - i;
            v = (v << 8) | (b[idx] & 0xFF);
        }
        return v;
    }

    /** PPC64 ELFv1: .opd descriptor arrays; [(lo, hi)] Ghidra offsets. */
    List<long[]> findOpd(long flags) throws Exception {
        List<long[]> none = new ArrayList<>();
        if (!(lang.getProcessor().toString().equals("PowerPC") && addrSize == 8 && flags == 1)) {
            return none;
        }
        Set<Long> entries = new HashSet<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (!f.isExternal() && inSpace(f.getEntryPoint())) {
                entries.add(f.getEntryPoint().getOffset());
            }
        }
        List<long[]> codeRanges = codeRanges();
        List<long[]> codeBlocks = new ArrayList<>();
        for (MemoryBlock blk : memory.getBlocks()) {
            if (!inSpace(blk.getStart())) {
                continue;
            }
            long s = blk.getStart().getOffset(), e = blk.getEnd().getOffset();
            boolean hasCode = false;
            for (long[] c : codeRanges) {
                if (c[0] <= e && s < c[1]) {
                    hasCode = true;
                }
            }
            if (blk.isExecute() || hasCode) {
                codeBlocks.add(new long[] {s, e + 1});
            }
        }
        List<long[]> cands = new ArrayList<>();
        List<long[]> weak = new ArrayList<>();
        for (MemoryBlock blk : memory.getBlocks()) {
            if (!blk.isInitialized() || !inSpace(blk.getStart()) || blk.isOverlay()) {
                continue;
            }
            long lo = blk.getStart().getOffset();
            long hi = lo + blk.getSize();
            long first = (lo + 7) & ~7L;
            byte[] data = readBytes(first, hi);
            int n = data.length / 8;
            long[] words = new long[n];
            for (int i = 0; i < n; i++) {
                long v = 0;
                for (int k = 0; k < 8; k++) {
                    int idx = 8 * i + (bigEndian ? k : 7 - k);
                    v = (v << 8) | (data[idx] & 0xFF);
                }
                words[i] = v;
            }
            for (int i = 0; i < n - 2; i++) {
                long w = words[i];
                if (entries.contains(w)) {
                    cands.add(new long[] {first + 8L * i, words[i + 1], words[i + 2]});
                }
                else if (words[i + 2] == 0 && (w & 3) == 0 && w >= 0) {
                    for (long[] c : codeBlocks) {
                        if (c[0] <= w && w < c[1]) {
                            weak.add(new long[] {first + 8L * i, words[i + 1], 0});
                            break;
                        }
                    }
                }
            }
        }
        if (cands.isEmpty()) {
            return none;
        }
        LinkedHashMap<Long, Integer> counts = new LinkedHashMap<>();
        for (long[] c : cands) {
            if (c[1] != 0) {
                counts.merge(c[1], 1, Integer::sum);
            }
        }
        Long toc = null;
        int best = 0;
        for (Map.Entry<Long, Integer> e : counts.entrySet()) {
            if (e.getValue() > best) {
                best = e.getValue();
                toc = e.getKey();
            }
        }
        TreeSet<Long> descs = new TreeSet<>();
        for (long[] c : cands) {
            if (toc != null && c[1] == toc && c[2] == 0) {
                descs.add(c[0]);
            }
        }
        Set<Long> strong = new HashSet<>(descs);
        for (long[] w : weak) {
            if (toc != null && w[1] == toc && (strong.contains(w[0] - 24) || strong.contains(w[0] + 24))) {
                descs.add(w[0]);
            }
        }
        List<long[]> regions = new ArrayList<>();
        for (long a : descs) {
            if (!regions.isEmpty() && a == regions.get(regions.size() - 1)[1]) {
                regions.get(regions.size() - 1)[1] = a + 24;
            }
            else if (!regions.isEmpty() && a < regions.get(regions.size() - 1)[1]) {
                continue;
            }
            else {
                regions.add(new long[] {a, a + 24});
            }
        }
        for (long a : descs) {
            opdDescriptors.add(new long[] {a, word(a)});
        }
        log("PPC64 ELFv1: " + descs.size() + " function descriptors in " + regions.size() + " .opd region(s)");
        return regions;
    }

    void writeElf() throws Exception {
        long[] mf = elfMachine();
        int machineNo = (int) mf[0];
        long flags = mf[1];
        long entry = 0;
        AddressIterator eps = program.getSymbolTable().getExternalEntryPointIterator();
        while (eps.hasNext()) {
            Address a = eps.next();
            if (inSpace(a)) {
                entry = A(a.getOffset());
                break;
            }
        }
        ElfWriter elf = new ElfWriter(addrSize == 8, bigEndian, machineNo, flags, entry);
        List<long[]> code = codeRanges();
        List<long[]> opd = findOpd(flags);
        Long textLo = null;
        long bestLen = -1;
        for (long[] r : code) {
            if (r[1] - r[0] > bestLen) {
                bestLen = r[1] - r[0];
                textLo = r[0];
            }
        }
        boolean textDone = false;
        boolean arm = lang.getProcessor().toString().equals("ARM");
        for (MemoryBlock block : memory.getBlocks()) {
            Address start = block.getStart();
            if (!block.isLoaded() || block.isOverlay() || !inSpace(start) || block.isExternalBlock()) {
                continue;
            }
            long baseFlags = C.SHF_ALLOC | (block.isWrite() ? C.SHF_WRITE : 0);
            long lo = start.getOffset();
            long hi = lo + block.getSize();
            String name = block.getName();
            boolean hasCode = false;
            for (long[] c : code) {
                if (c[0] < hi && lo < c[1]) {
                    hasCode = true;
                }
            }
            if (hasCode && !block.isExecute()) {
                log("WARNING: memory block " + name + " holds functions but is not executable; " +
                    "exporting its code as executable");
            }
            boolean execLike = block.isExecute() || hasCode;
            List<long[]> runs;
            if (execLike && opts.split_sections) {
                runs = splitRuns(lo, hi, code);
            }
            else {
                runs = new ArrayList<>();
                runs.add(new long[] {lo, hi, execLike ? 1 : 0});
            }
            runs = carveOpd(runs, opd);
            byte[] data = null;
            if (opts.embed_bytes && block.isInitialized()) {
                data = new byte[(int) (hi - lo)];
                block.getBytes(start, data);
            }
            for (long[] r : runs) {
                long rlo = r[0], rhi = r[1];
                if (r[2] == 2) {
                    elf.addSection(new ElfWriter.Section(".opd", C.SHT_PROGBITS, C.SHF_ALLOC | C.SHF_WRITE, A(rlo),
                        readBytes(rlo, rhi), null, 0, 0, 8, 0));
                    continue;
                }
                boolean isCode = r[2] == 1;
                if (!isCode && execLike && arm) {
                    elf.addSymbol("$d", A(rlo), 0, C.STT_NOTYPE, C.STB_LOCAL, C.SHN_ABS, 0);
                }
                long sflags = baseFlags | (isCode ? C.SHF_EXECINSTR : 0);
                String sname;
                if (isCode && textLo != null && rlo <= textLo && textLo < rhi && !textDone) {
                    sname = ".text";
                    textDone = true;
                }
                else if (isCode) {
                    sname = name + ".text";
                }
                else if (execLike) {
                    sname = name + ".data";
                }
                else {
                    sname = name;
                }
                ElfWriter.Section sec;
                if (data != null) {
                    sec = new ElfWriter.Section(sname, C.SHT_PROGBITS, sflags, A(rlo),
                        Arrays.copyOfRange(data, (int) (rlo - lo), (int) (rhi - lo)), null, 0, 0, 1, 0);
                }
                else {
                    sec = new ElfWriter.Section(sname, C.SHT_NOBITS, sflags, A(rlo), null, rhi - rlo, 0, 0, 1, 0);
                }
                elf.addSection(sec);
            }
        }
        for (Object[] sec : dw.build()) {
            elf.addSection(new ElfWriter.Section((String) sec[0], C.SHT_PROGBITS, 0, 0, (byte[]) sec[1], null, 0, 0, 1, 0));
        }
        if (arm) {
            elf.addSection(new ElfWriter.Section(".ARM.attributes", 0x70000003L, 0, 0, armAttributes(flags), null, 0, 0,
                1, 0));
        }
        FunctionManager fm = program.getFunctionManager();
        for (long[] d : opdDescriptors) {
            Function f = fm.getFunctionAt(space.getAddress(d[1]));
            if (f != null) {
                elfSymbols.add(new ElfSym(Names.qualified(f), A(d[0]), 24, C.STT_OBJECT, 0, C.STB_GLOBAL));
            }
        }
        for (ElfSym s : elfSymbols) {
            String name = s.name.startsWith("$") ? s.name : nm.apply(s.name);
            elf.addSymbol(name, s.value, s.size, s.type, s.bind, elf.sectionIndexFor(s.value), s.other);
        }
        elf.write(elfPath.toString());
    }
}
