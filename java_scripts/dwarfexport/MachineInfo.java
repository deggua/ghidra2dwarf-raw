package dwarfexport;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;

/** Calling-convention facts needed by the flow analysis. */
public final class MachineInfo {
    /** Link register per Ghidra processor, for compiler specs without one. */
    static final Map<String, String> LINK_REGISTERS = Map.of("PowerPC", "LR", "ARM", "lr", "AARCH64", "x30",
        "MIPS", "ra", "RISCV", "ra", "SuperH", "pr", "SuperH4", "pr", "Xtensa", "a0");

    /** Interrupt return registers per processor, with their CFI column. */
    static final Map<String, Object[][]> IRQ_RETURN_REGS = Map.of(
        "PowerPC", new Object[][] {{"SRR0", 100 + 26}, {"CSRR0", 100 + 58}, {"MCSRR0", 100 + 570}},
        "MIPS", new Object[][] {{"EPC", 80}, {"ErrorEPC", 81}},
        "AARCH64", new Object[][] {{"elr_el1", 33}, {"elr_el2", 34}, {"elr_el3", 35}});

    /** GCC/compiler register save and restore helpers. */
    static final Pattern HELPER_RE = Pattern.compile(
        "^_+(save|rest)(gpr|fpr|vr|_?gpr|_?fpr)[01]?_?\\d+(_[a-z])?$|^_+(save|rest)_?(gp)?r(eg)?s?_?\\d+$");

    public final Program program;
    public final Listing listing;
    public final Language lang;
    public final RegisterIndex regs;
    public final long stackshift;
    public final Consumer<String> log;
    public final int ptrSize;
    public final Key spKey;
    public final Integer spDwarf;
    public final Set<Key> unaffected = new HashSet<>();
    public final Key raKey;
    public final Long raStack;
    public final Integer raDwarf;
    public final boolean bigEndian;
    /** Every register with a DWARF number, in index order. */
    public final List<Key> mapped = new ArrayList<>();
    /** Interrupt return registers and their CFI columns. */
    public final List<Key> irqRetKeys = new ArrayList<>();
    public final List<Integer> irqRetCols = new ArrayList<>();
    public final Set<Key> irqKeys = new HashSet<>();
    public final List<Key> volatileRegs = new ArrayList<>();
    public final Set<Key> volatileSet = new HashSet<>();

    // (concurrent: the analysis of several functions runs in worker threads)
    private final Map<Key, Integer> dwarfCache = new ConcurrentHashMap<>();
    private final Map<Key, List<Key>> containersCache = new ConcurrentHashMap<>();
    private final Map<Long, Integer> purgeCache = new ConcurrentHashMap<>();
    private final Map<Long, Integer> argsCache = new ConcurrentHashMap<>();
    private final Map<Long, Optional<List<Op>>> inlineCache = new ConcurrentHashMap<>();
    private static final Integer NONE = Integer.MIN_VALUE;

    public MachineInfo(Program program, RegisterIndex regIndex, long stackshift, Consumer<String> log) {
        this.program = program;
        this.listing = program.getListing();
        this.lang = program.getLanguage();
        this.regs = regIndex;
        Vn.resetSpaces();
        this.stackshift = stackshift;
        this.log = log;
        this.ptrSize = program.getDefaultPointerSize();

        CompilerSpec cspec = program.getCompilerSpec();
        Register spReg = cspec.getStackPointer();
        spKey = Key.reg(spReg.getAddress().getOffset(), spReg.getMinimumByteSize());
        spDwarf = dwarfOf(spKey);

        PrototypeModel cc = cspec.getDefaultCallingConvention();
        if (cc != null) {
            for (Varnode vn : cc.getUnaffectedList()) {
                if (vn.isRegister()) {
                    unaffected.add(Key.reg(vn.getOffset(), vn.getSize()));
                }
            }
        }
        Key ra = null;
        Long raSt = null;
        Varnode[] rav = cc != null ? cc.getReturnAddress() : null;
        if (rav != null && rav.length == 1) {
            Varnode vn = rav[0];
            if (vn.isRegister()) {
                ra = Key.reg(vn.getOffset(), vn.getSize());
            }
            else if (vn.getAddress().isStackAddress()) {
                raSt = vn.getOffset();
            }
        }
        if (ra == null && raSt == null) {
            String name = LINK_REGISTERS.get(lang.getProcessor().toString());
            Register reg = name != null ? lang.getRegister(name) : null;
            if (reg != null) {
                ra = Key.reg(reg.getAddress().getOffset(), reg.getMinimumByteSize());
            }
        }
        raKey = ra;
        raStack = raSt;
        raDwarf = raKey != null ? dwarfOf(raKey) : pcColumn(lang);

        bigEndian = lang.isBigEndian();
        for (RegisterIndex.Entry e : regIndex.entries) {
            mapped.add(Key.reg(e.start, e.size));
        }
        Object[][] irq = IRQ_RETURN_REGS.get(lang.getProcessor().toString());
        if (irq != null) {
            for (Object[] nc : irq) {
                Register reg = lang.getRegister((String) nc[0]);
                if (reg != null) {
                    Key k = Key.reg(reg.getAddress().getOffset(), reg.getMinimumByteSize());
                    irqRetKeys.add(k);
                    irqRetCols.add((Integer) nc[1]);
                    irqKeys.add(k);
                }
            }
        }
        for (Key k : mapped) {
            if (!k.equals(spKey) && !unaffected.contains(k) && !k.equals(raKey)) {
                volatileRegs.add(k);
                volatileSet.add(k);
            }
        }
    }

    static Integer pcColumn(Language lang) {
        String proc = lang.getProcessor().toString();
        int size = lang.getDefaultSpace().getPointerSize();
        if (proc.equals("x86")) {
            return size == 8 ? 16 : 8;
        }
        return null;
    }

    /** DWARF number of the register exactly matching key, else null. */
    public Integer dwarfOf(Key key) {
        if (key == null || !key.isReg()) {
            return null;
        }
        Integer hit = dwarfCache.get(key);
        if (hit != null) {
            return hit == NONE ? null : hit;
        }
        Integer num = null;
        long[] l = regs.lookup(key.off, key.size);
        if (l != null && l[1] == key.off && l[2] == key.size) {
            num = (int) l[0];
        }
        dwarfCache.put(key, num == null ? NONE : num);
        return num;
    }

    /** Mapped registers strictly containing register bytes key. */
    public List<Key> containers(Key key) {
        List<Key> hit = containersCache.get(key);
        if (hit == null) {
            hit = new ArrayList<>();
            for (Key mk : mapped) {
                if (!mk.equals(key) && mk.contains(key)) {
                    hit.add(mk);
                }
            }
            containersCache.put(key, hit);
        }
        return hit;
    }

    /** Bytes the callee at target pops (beyond the return address). */
    public long stackPurge(Address target) {
        if (target == null) {
            return 0;
        }
        return purgeCache.computeIfAbsent(target.getOffset(), off -> {
            Function f = program.getFunctionManager().getFunctionAt(target);
            int p = f != null ? f.getStackPurgeSize() : 0;
            return 0 < p && p < 0x10000 ? p : 0;
        });
    }

    /** Bytes above the SP at a call that belong to the callee. */
    public long calleeArea(Address target) {
        String proc = lang.getProcessor().toString();
        long area;
        if (proc.equals("PowerPC")) {
            area = ptrSize == 4 ? 8 : 32;
        }
        else if (proc.equals("MIPS") && regsSize() == 4) {
            area = 16;
        }
        else {
            area = 0;
        }
        return Math.max(area, stackArgsExtent(target));
    }

    private long stackArgsExtent(Address target) {
        if (target == null) {
            return 0;
        }
        return argsCache.computeIfAbsent(target.getOffset(), off -> {
            long ext = 0;
            Function f = program.getFunctionManager().getFunctionAt(target);
            if (f != null) {
                for (Parameter p : f.getParameters()) {
                    VariableStorage stg = p.getVariableStorage();
                    if (stg.isStackStorage()) {
                        ext = Math.max(ext, stg.getStackOffset() + stg.size() - stackshift);
                    }
                }
            }
            return (int) Math.min(Math.max(ext, 0), 4096);
        });
    }

    /** Size of a general register (MIPS: 8 for n32 although pointers are 4). */
    public int regsSize() {
        Register sp = lang.getRegister("sp");
        if (sp == null) {
            sp = lang.getRegister("r1");
        }
        return sp != null ? sp.getMinimumByteSize() : ptrSize;
    }

    /**
     * Decoded data p-code of a register save/restore helper called at target
     * (by name, or a function Ghidra marks inline), else null.
     */
    public List<Op> inlineBody(Address target) {
        if (target == null) {
            return null;
        }
        long off = target.getOffset();
        Optional<List<Op>> hit = inlineCache.get(off);
        if (hit != null) {
            return hit.orElse(null);
        }
        List<Op> body = null;
        Function f = program.getFunctionManager().getFunctionAt(target);
        if (f != null && (f.isInline() || HELPER_RE.matcher(f.getName()).find())) {
            List<Op> ops = new ArrayList<>();
            boolean ok = false;
            int n = 0;
            InstructionIterator it = listing.getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction ins = it.next();
                n++;
                FlowType ft = ins.getFlowType();
                if (n > 64 || ft.isCall() || ft.isConditional()) {
                    ops = null;
                    break;
                }
                for (PcodeOp op : ins.getPcode()) {
                    int opc = op.getOpcode();
                    if (opc == PcodeOp.RETURN || opc == PcodeOp.BRANCH || opc == PcodeOp.BRANCHIND ||
                        opc == PcodeOp.CBRANCH) {
                        continue;
                    }
                    ops.add(Op.decode(op));
                }
                if (ft.isTerminal()) {
                    ok = true;
                    break;
                }
            }
            if (ops != null && ok) {
                body = ops;
            }
        }
        inlineCache.put(off, Optional.ofNullable(body));
        return body;
    }

    /** Is the register (or one containing it) preserved across calls? */
    public boolean isPreserved(Key key) {
        if (key.equals(spKey) || unaffected.contains(key)) {
            return true;
        }
        for (Key c : containers(key)) {
            if (unaffected.contains(c)) {
                return true;
            }
        }
        return false;
    }
}
