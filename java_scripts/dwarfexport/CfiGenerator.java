package dwarfexport;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.LongUnaryOperator;

import dwarfexport.DwarfBuilder.Buf;
import dwarfexport.DwarfBuilder.CfiRow;
import dwarfexport.DwarfBuilder.CommonInformation;
import dwarfexport.DwarfBuilder.FrameDescription;

/** Emits a CIE and per-function FDEs from FunctionFlow states (a port of flow.py's CfiGenerator). */
public final class CfiGenerator {
    /** A CFA rule: the CFA register and offset, and saved registers. */
    static final class Rule {
        final int reg;
        final long off;
        /** dwarf number -> stack offset (Long) or register (RegSave). */
        final TreeMap<Integer, Object> saved;

        Rule(int reg, long off, TreeMap<Integer, Object> saved) {
            this.reg = reg;
            this.off = off;
            this.saved = saved;
        }
    }

    /** ("reg", n): saved in register n. */
    static final class RegSave {
        final int reg;

        RegSave(int reg) {
            this.reg = reg;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof RegSave && ((RegSave) o).reg == reg;
        }

        @Override
        public int hashCode() {
            return reg;
        }
    }

    final boolean irqSignalFrame;
    final MachineInfo m;
    final DwarfBuilder dw;
    final LongUnaryOperator A;
    final Set<Long> entryPoints;
    public boolean ok;
    private final Map<Integer, Integer> irqCies = new HashMap<>();
    private List<Key> tracked;

    public CfiGenerator(MachineInfo machine, DwarfBuilder dw, LongUnaryOperator addressMapper, List<Long> entryPoints,
            boolean irqSignalFrame) {
        this.irqSignalFrame = irqSignalFrame;
        this.m = machine;
        this.dw = dw;
        this.A = addressMapper;
        this.entryPoints = new HashSet<>(entryPoints);
        if (machine.spDwarf == null) {
            machine.log.accept("WARNING: stack pointer has no DWARF register number; no CFI generated");
            return;
        }
        if (machine.raDwarf == null) {
            machine.log.accept("WARNING: cannot determine the return address register; no CFI generated");
            return;
        }
        Buf init = new Buf();
        init.add(C.DW_CFA_def_cfa).add(DwarfBuilder.uleb(machine.spDwarf)).add(DwarfBuilder.uleb(machine.stackshift));
        if (machine.raStack != null) {
            init.add(C.DW_CFA_offset_extended_sf).add(DwarfBuilder.uleb(machine.raDwarf))
                    .add(DwarfBuilder.sleb(machine.raStack - machine.stackshift));
        }
        for (Key k : machine.volatileRegs) {
            Integer num = machine.dwarfOf(k);
            if (num != null && !num.equals(machine.raDwarf)) {
                init.add(C.DW_CFA_undefined).add(DwarfBuilder.uleb(num));
            }
        }
        dw.cie = new CommonInformation(1, 1, machine.raDwarf, init.bytes(), "");
        ok = true;
    }

    int irqCie(int col) {
        Integer idx = irqCies.get(col);
        if (idx == null) {
            Buf init = new Buf();
            init.add(C.DW_CFA_def_cfa).add(DwarfBuilder.uleb(m.spDwarf)).add(DwarfBuilder.uleb(m.stackshift));
            init.add(C.DW_CFA_undefined).add(DwarfBuilder.uleb(col));
            idx = dw.addCie(new CommonInformation(1, 1, col, init.bytes(), irqSignalFrame ? "S" : ""));
            irqCies.put(col, idx);
        }
        return idx;
    }

    /** The interrupt return register (key, column) a handler saves. */
    public Object[] irqReturnReg(FunctionFlow flow) {
        for (int i = 0; i < m.irqRetKeys.size(); i++) {
            Val want = Val.init(m.irqRetKeys.get(i));
            for (State st : flow.stateIn.values()) {
                for (State.Slot s : st.mem.values()) {
                    if (want.equals(s.v)) {
                        return new Object[] {m.irqRetKeys.get(i), m.irqRetCols.get(i)};
                    }
                }
            }
        }
        return m.irqRetKeys.isEmpty() ? null : new Object[] {m.irqRetKeys.get(0), m.irqRetCols.get(0)};
    }

    Rule rule(FunctionFlow flow, State st, Object[] irq) {
        Integer cfaReg = null;
        long cfaOff = 0;
        Val sp = flow.regValue(st, m.spKey);
        if (sp != null && sp.kind == Val.SP) {
            cfaReg = m.spDwarf;
            cfaOff = m.stackshift - sp.n;
        }
        else {
            List<Map.Entry<Key, Val>> regs = new ArrayList<>();
            for (Map.Entry<Key, Val> e : st.regs.entrySet()) {
                if (!e.getKey().isU()) {
                    regs.add(e);
                }
            }
            regs.sort((x, y) -> x.getKey().compareTo(y.getKey()));
            for (Map.Entry<Key, Val> e : regs) {
                Val v = e.getValue();
                Key k = e.getKey();
                if (v != null && v.kind == Val.SP && (m.isPreserved(k) || flow.isLeaf)) {
                    Integer num = m.dwarfOf(k);
                    if (num != null) {
                        cfaReg = num;
                        cfaOff = m.stackshift - v.n;
                        break;
                    }
                }
            }
        }
        if (cfaReg == null) {
            return null;
        }
        // entry values in stack slots: the first slot of each, in the state's order
        Map<Key, long[]> slots = new HashMap<>();
        for (Map.Entry<Long, State.Slot> e : st.mem.entrySet()) {
            Val v = e.getValue().v;
            if (v != null && v.kind == Val.INIT && !slots.containsKey(v.key)) {
                slots.put(v.key, new long[] {e.getKey(), e.getValue().size});
            }
        }
        TreeMap<Integer, Object> saved = new TreeMap<>();
        if (irq != null) {
            Key retKey = (Key) irq[0];
            int col = (Integer) irq[1];
            long[] slot = slots.get(retKey);
            if (slot != null && slot[1] == retKey.size) {
                saved.put(col, slot[0] - m.stackshift);
            }
            else if (st.saved.containsKey(retKey)) {
                saved.put(col, st.saved.get(retKey) - m.stackshift);
            }
            for (Key k : m.mapped) {
                Integer num = m.dwarfOf(k);
                if (num == null || k.equals(m.spKey)) {
                    continue;
                }
                long[] s = slots.get(k);
                if (s != null && s[1] == k.size) {
                    saved.put(num, s[0] - m.stackshift);
                }
            }
            return new Rule(cfaReg, cfaOff, saved);
        }
        for (Key k : trackedRegs()) {
            Integer num = m.dwarfOf(k);
            if (num == null || k.equals(m.spKey)) {
                continue;
            }
            long[] slot = slots.get(k);
            if (slot != null && slot[1] != k.size) {
                slot = null;
            }
            boolean holdsEntry = Val.init(k).equals(flow.regValue(st, k));
            if (k.equals(m.raKey)) {
                if (slot != null && !(holdsEntry && sp != null && sp.kind == Val.SP && slot[0] < sp.n)) {
                    saved.put(num, slot[0] - m.stackshift);
                    continue;
                }
                Integer other = registerHolding(flow, st, Val.init(k), true);
                if (other != null && !other.equals(num)) {
                    saved.put(num, new RegSave(other));
                    continue;
                }
            }
            else if (!holdsEntry && slot != null) {
                saved.put(num, slot[0] - m.stackshift);
                continue;
            }
            if (!holdsEntry) {
                Integer other = registerHolding(flow, st, Val.init(k), false);
                if (other != null) {
                    saved.put(num, new RegSave(other));
                }
            }
        }
        return new Rule(cfaReg, cfaOff, saved);
    }

    Integer registerHolding(FunctionFlow flow, State st, Val value, boolean preservedOnly) {
        int bestRank = Integer.MAX_VALUE, bestNum = Integer.MAX_VALUE;
        boolean found = false;
        for (Map.Entry<Key, Val> e : st.regs.entrySet()) {
            Key k = e.getKey();
            Val v = e.getValue();
            if (!Objects.equals(v, value) || k.isU() || k.equals(m.spKey) || k.equals(value.key)) {
                continue;
            }
            if (preservedOnly && !m.isPreserved(k)) {
                continue;
            }
            Integer num = m.dwarfOf(k);
            if (num == null) {
                continue;
            }
            int rank = m.isPreserved(k) ? 0 : 1;
            if (!found || rank < bestRank || (rank == bestRank && num < bestNum)) {
                bestRank = rank;
                bestNum = num;
                found = true;
            }
        }
        return found ? bestNum : null;
    }

    List<Key> trackedRegs() {
        if (tracked == null) {
            TreeSet<Key> keys = new TreeSet<>();
            for (Key k : m.unaffected) {
                if (m.dwarfOf(k) != null) {
                    keys.add(k);
                }
            }
            if (m.raKey != null) {
                keys.add(m.raKey);
            }
            tracked = new ArrayList<>(keys);
        }
        return tracked;
    }

    static byte[] encode(Rule prev, Rule cur, Set<Integer> undefinedCols) {
        Buf ops = new Buf();
        if (prev == null || prev.reg != cur.reg || prev.off != cur.off) {
            if (cur.off >= 0) {
                if (prev != null && prev.reg == cur.reg) {
                    ops.add(C.DW_CFA_def_cfa_offset).add(DwarfBuilder.uleb(cur.off));
                }
                else {
                    ops.add(C.DW_CFA_def_cfa).add(DwarfBuilder.uleb(cur.reg)).add(DwarfBuilder.uleb(cur.off));
                }
            }
            else {
                ops.add(0x12).add(DwarfBuilder.uleb(cur.reg)).add(DwarfBuilder.sleb(cur.off));
            }
        }
        Map<Integer, Object> prevSaved = prev != null ? prev.saved : new TreeMap<>();
        for (Map.Entry<Integer, Object> e : cur.saved.entrySet()) {
            int reg = e.getKey();
            Object off = e.getValue();
            if (!Objects.equals(prevSaved.get(reg), off)) {
                if (off instanceof RegSave) {
                    ops.add(C.DW_CFA_register).add(DwarfBuilder.uleb(reg)).add(DwarfBuilder.uleb(((RegSave) off).reg));
                }
                else {
                    ops.add(C.DW_CFA_offset_extended_sf).add(DwarfBuilder.uleb(reg)).add(DwarfBuilder.sleb((Long) off));
                }
            }
        }
        for (int reg : new TreeSet<>(prevSaved.keySet())) {
            if (!cur.saved.containsKey(reg)) {
                ops.add(undefinedCols.contains(reg) ? C.DW_CFA_undefined : C.DW_CFA_same_value)
                        .add(DwarfBuilder.uleb(reg));
            }
        }
        return ops.bytes();
    }

    public void addFunction(FunctionFlow flow, List<long[]> ranges, boolean interrupt) {
        if (!ok) {
            return;
        }
        Object[] irq = interrupt ? irqReturnReg(flow) : null;
        int cie = irq != null ? irqCie((Integer) irq[1]) : 0;
        Set<Integer> undefinedCols = new HashSet<>();
        if (irq != null) {
            undefinedCols.add((Integer) irq[1]);
        }
        boolean outermost = irq == null && entryPoints.contains(flow.func.getEntryPoint().getOffset());
        for (long[] r : ranges) {
            long lo = r[0], hi = r[1];
            Long start = null;
            List<CfiRow> rows = new ArrayList<>();
            Rule prev = null;
            Long end = null;
            for (long off : flow.insns) {
                if (off < lo || off >= hi) {
                    continue;
                }
                if (start != null && off != end) {
                    dw.fdes.add(new FrameDescription(A.applyAsLong(start), A.applyAsLong(end), rows, cie));
                    start = null;
                }
                State st = flow.stateIn.get(off);
                Rule rl = st != null ? rule(flow, st, irq) : null;
                if (rl == null) {
                    if (start != null) {
                        dw.fdes.add(new FrameDescription(A.applyAsLong(start), A.applyAsLong(off), rows, cie));
                        start = null;
                    }
                    continue;
                }
                end = off + flow.insnLen.get(off);
                if (start == null) {
                    start = off;
                    rows = new ArrayList<>();
                    prev = new Rule(m.spDwarf, m.stackshift, new TreeMap<>());
                    if (outermost && off == lo) {
                        Buf b = new Buf().add(C.DW_CFA_undefined).add(DwarfBuilder.uleb(m.raDwarf));
                        rows.add(new CfiRow(A.applyAsLong(off), b.bytes()));
                    }
                }
                byte[] ops = encode(prev, rl, undefinedCols);
                if (ops.length > 0) {
                    rows.add(new CfiRow(A.applyAsLong(off), ops));
                }
                prev = rl;
            }
            if (start != null) {
                dw.fdes.add(new FrameDescription(A.applyAsLong(start), A.applyAsLong(lo) + (Math.min(end, hi) - lo), rows,
                    cie));
            }
        }
    }
}
