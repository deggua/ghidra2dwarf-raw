package dwarfexport;

import java.lang.reflect.Field;
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
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

import dwarfexport.DwarfBuilder.Buf;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Computes DWARF locations for decompiler variables of one function (a port
 * of ghidra_export.py's _FunctionContext; see there for the design).
 */
public final class FunctionContext {
    /** A location: one expression, or a list of (start, end, expression). */
    public static final class Location {
        public final byte[] expr;
        public final List<Span> list;

        Location(byte[] expr, List<Span> list) {
            this.expr = expr;
            this.list = list;
        }
    }

    /** [start, end) with an expression. */
    public static final class Span {
        public final long start, end;
        public final byte[] expr;

        Span(long start, long end, byte[] expr) {
            this.start = start;
            this.end = end;
            this.expr = expr;
        }
    }

    final Exporter exp;
    final FunctionFlow flow;
    final Function func;
    final HighFunction hf;
    final List<long[]> ranges;
    final long entry;
    final PcodeBlockBasic entryBlock;
    private final Map<Integer, List<long[]>> seqCache = new HashMap<>();
    private LinkedHashMap<Integer, BlockInfo> binfo;

    public FunctionContext(Exporter exp, Function func, HighFunction hf, List<long[]> ranges, FunctionFlow flow) {
        this.exp = exp;
        this.flow = flow;
        this.func = func;
        this.hf = hf;
        this.ranges = ranges;
        this.entry = func.getEntryPoint().getOffset();
        List<PcodeBlockBasic> blocks = hf != null ? hf.getBasicBlocks() : null;
        this.entryBlock = blocks != null && !blocks.isEmpty() ? blocks.get(0) : null;
    }

    // -- storage -> expression ----------------------------------------------------

    static long signedBits(long value, int size) {
        return FunctionFlow.signedRaw(value, size);
    }

    private static final byte[] NO_EXPR = new byte[0];

    /** DWARF expression for register-space bytes [off, off+size) (cached per exporter). */
    public byte[] regExpr(long off, int size) {
        byte[] e = exp.regExprCache.computeIfAbsent(Key.reg(off, size), k -> {
            byte[] r = computeRegExpr(off, size);
            return r != null ? r : NO_EXPR;
        });
        return e == NO_EXPR ? null : e;
    }

    private byte[] computeRegExpr(long off, int size) {
        long[] hit = exp.regs.lookup(off, size);
        if (hit == null) {
            return multiRegExpr(off, size);
        }
        int regno = (int) hit[0];
        long roff = hit[1], rsize = hit[2];
        DwarfBuilder.Expr e = exp.dw.expr().reg(regno);
        if (size == rsize) {
            return e.bytes();
        }
        boolean lowPart = exp.bigEndian ? off + size == roff + rsize : off == roff;
        if (lowPart) {
            return e.bytes();
        }
        long shift = exp.bigEndian ? (roff + rsize - (off + size)) * 8 : (off - roff) * 8;
        return e.bitPiece(size * 8L, shift).bytes();
    }

    byte[] multiRegExpr(long off, int size) {
        Buf out = new Buf();
        long pos = off, end = off + size;
        Map<Long, long[]> byStart = new HashMap<>();
        for (RegisterIndex.Entry en : exp.regs.entries) {
            long[] cur = byStart.get(en.start);
            if (cur == null || en.size > cur[0]) {
                if (en.start + en.size <= end) {
                    byStart.put(en.start, new long[] {en.size, en.num});
                }
            }
        }
        while (pos < end) {
            long[] hit = byStart.get(pos);
            if (hit == null) {
                return null;
            }
            out.add(exp.dw.expr().reg((int) hit[1]).piece(hit[0]).bytes());
            pos += hit[0];
        }
        return out.length() > 0 ? out.bytes() : null;
    }

    /** DWARF expression for a single varnode, or null. */
    public byte[] varnodeExpr(Varnode vn) {
        Address addr = vn.getAddress();
        AddressSpace space = addr.getAddressSpace();
        int size = vn.getSize();
        if (space.isRegisterSpace()) {
            return regExpr(addr.getOffset(), size);
        }
        if (space.isStackSpace()) {
            int bytes = space.getSize() / 8;
            long off = signedBits(addr.getOffset(), bytes != 0 ? bytes : 4);
            return exp.dw.expr().fbreg(off - exp.stackshift).bytes();
        }
        if (space.equals(exp.space)) {
            return exp.dw.expr().addr(exp.A(addr.getOffset())).bytes();
        }
        return null;
    }

    /** Expression for a (possibly compound) VariableStorage. */
    public byte[] storageExpr(VariableStorage storage) {
        List<Varnode> vns = new ArrayList<>(Arrays.asList(storage.getVarnodes()));
        if (vns.isEmpty()) {
            return null;
        }
        if (vns.size() == 1) {
            return varnodeExpr(vns.get(0));
        }
        if (!exp.bigEndian) {
            Collections.reverse(vns);
        }
        Buf out = new Buf();
        for (Varnode vn : vns) {
            byte[] e = varnodeExpr(vn);
            if (e == null) {
                return null;
            }
            out.add(e).add(C.DW_OP_piece).add(DwarfBuilder.uleb(vn.getSize()));
        }
        return out.bytes();
    }

    // -- liveness -----------------------------------------------------------------

    private static Field coverField;
    private static boolean coverTried;

    /** The decompiler basic block's AddressSet of instructions (private "cover"). */
    static synchronized AddressSet blockCover(PcodeBlockBasic block) {
        if (!coverTried) {
            coverTried = true;
            try {
                coverField = PcodeBlockBasic.class.getDeclaredField("cover");
                coverField.setAccessible(true);
            }
            catch (Exception e) {
                coverField = null;
            }
        }
        if (coverField == null) {
            return null;
        }
        try {
            return (AddressSet) coverField.get(block);
        }
        catch (Exception e) {
            return null;
        }
    }

    /** The instruction offsets (of the sorted list insns) in an AddressSet. */
    static List<Long> coverOffsets(AddressSet cover, List<Long> insns) {
        List<Long> out = new ArrayList<>();
        AddressRangeIterator it = cover.getAddressRanges();
        while (it.hasNext()) {
            AddressRange r = it.next();
            long lo = r.getMinAddress().getOffset(), hi = r.getMaxAddress().getOffset();
            int i = bisectLeft(insns, lo);
            while (i < insns.size() && insns.get(i) <= hi) {
                out.add(insns.get(i));
                i++;
            }
        }
        return out;
    }

    static int bisectLeft(List<Long> a, long x) {
        int lo = 0, hi = a.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (a.get(mid) < x) {
                lo = mid + 1;
            }
            else {
                hi = mid;
            }
        }
        return lo;
    }

    /** The block's code as [(lo, hi)] pieces in execution order (entry piece first). */
    List<long[]> blockSeq(PcodeBlockBasic block) {
        int idx = block.getIndex();
        List<long[]> hit = seqCache.get(idx);
        if (hit != null) {
            return hit;
        }
        List<long[]> pieces = null;
        AddressSet cover = blockCover(block);
        if (cover != null) {
            pieces = new ArrayList<>();
            AddressRangeIterator it = cover.getAddressRanges();
            while (it.hasNext()) {
                AddressRange r = it.next();
                if (exp.inSpace(r.getMinAddress())) {
                    pieces.add(new long[] {r.getMinAddress().getOffset(), exp.insnEnd(r.getMaxAddress())});
                }
            }
        }
        if (pieces == null || pieces.isEmpty()) {
            Address start = block.getStart(), stop = block.getStop();
            pieces = new ArrayList<>();
            if (start != null && stop != null) {
                pieces.add(new long[] {start.getOffset(), exp.insnEnd(stop)});
            }
        }
        PcodeOp first = !pieces.isEmpty() ? block.getFirstOp() : null;
        if (first != null && pieces.size() > 1) {
            long e = first.getSeqnum().getTarget().getOffset();
            int head = -1;
            for (int i = 0; i < pieces.size(); i++) {
                if (pieces.get(i)[0] <= e && e < pieces.get(i)[1]) {
                    head = i;
                    break;
                }
            }
            if (head >= 0) {
                List<long[]> np = new ArrayList<>();
                np.add(pieces.get(head));
                for (int i = 0; i < pieces.size(); i++) {
                    if (i != head) {
                        np.add(pieces.get(i));
                    }
                }
                pieces = np;
            }
        }
        seqCache.put(idx, pieces);
        return pieces;
    }

    /** Execution-order position of addr inside the block: {piece index, addr}. */
    long[] blockPos(PcodeBlockBasic block, long addr) {
        List<long[]> seq = blockSeq(block);
        for (int i = 0; i < seq.size(); i++) {
            if (seq.get(i)[0] <= addr && addr < seq.get(i)[1]) {
                return new long[] {i, addr};
            }
        }
        return new long[] {seq.size(), addr};
    }

    static int cmpPos(long[] a, long[] b) {
        return a[0] != b[0] ? Long.compare(a[0], b[0]) : Long.compare(a[1], b[1]);
    }

    List<long[]> blockSpans(PcodeBlockBasic block, Long start, Long endAddr, Long end, Long startAddr) {
        List<long[]> seq = blockSeq(block);
        List<long[]> out = new ArrayList<>();
        int i0 = start != null ? (int) blockPos(block, startAddr != null ? startAddr : start)[0] : 0;
        int i1 = endAddr != null ? (int) blockPos(block, endAddr)[0] : seq.size() - 1;
        for (int i = i0; i <= Math.min(i1, seq.size() - 1); i++) {
            long lo = seq.get(i)[0], hi = seq.get(i)[1];
            if (i == i0 && start != null) {
                lo = Math.max(lo, start);
            }
            if (i == i1 && end != null) {
                hi = Math.min(hi, end);
            }
            if (lo < hi) {
                out.add(new long[] {lo, hi});
            }
        }
        return out;
    }

    /** [(start, end)] Ghidra offsets where the varnode holds its value. */
    List<long[]> liveIntervals(Varnode vn) {
        List<long[]> out = new ArrayList<>();
        PcodeOp defop = vn.getDef();
        PcodeBlockBasic dblock;
        long dpoint, daddr;
        if (defop == null) {
            if (!vn.isInput() || entryBlock == null) {
                return out;
            }
            dblock = entryBlock;
            dpoint = daddr = entry;
        }
        else {
            dblock = defop.getParent();
            Address target = defop.getSeqnum().getTarget();
            daddr = target.getOffset();
            dpoint = defop.getOpcode() == PcodeOp.MULTIEQUAL ? daddr : exp.insnEnd(target);
        }
        int dindex = dblock.getIndex();
        Set<Integer> visited = new HashSet<>();
        List<PcodeBlock> work = new ArrayList<>();
        Iterator<PcodeOp> uses = vn.getDescendants();
        while (uses.hasNext()) {
            PcodeOp op = uses.next();
            if (op.getOpcode() == PcodeOp.MULTIEQUAL) {
                PcodeBlockBasic parent = op.getParent();
                for (int slot = 0; slot < op.getNumInputs(); slot++) {
                    Varnode inp = op.getInput(slot);
                    if (inp != null && inp.equals(vn) && slot < parent.getInSize()) {
                        work.add(parent.getIn(slot));
                    }
                }
                continue;
            }
            PcodeBlockBasic ublock = op.getParent();
            long uaddr = op.getSeqnum().getTarget().getOffset();
            long uend = exp.insnEnd(op.getSeqnum().getTarget());
            boolean sameInsnAfter = defop != null && daddr == uaddr &&
                defop.getSeqnum().getOrder() < op.getSeqnum().getOrder();
            if (ublock.getIndex() == dindex && (cmpPos(blockPos(ublock, daddr), blockPos(ublock, uaddr)) < 0 ||
                sameInsnAfter || ((defop == null || defop.getOpcode() == PcodeOp.MULTIEQUAL) && daddr == uaddr))) {
                out.addAll(blockSpans(ublock, dpoint, uaddr, uend, daddr));
            }
            else {
                if (blockSeq(ublock).isEmpty()) {
                    continue;
                }
                out.addAll(blockSpans(ublock, null, uaddr, uend, null));
                for (int i = 0; i < ublock.getInSize(); i++) {
                    work.add(ublock.getIn(i));
                }
            }
        }
        while (!work.isEmpty()) {
            PcodeBlockBasic block = (PcodeBlockBasic) work.remove(work.size() - 1);
            int idx = block.getIndex();
            if (!visited.add(idx)) {
                continue;
            }
            if (blockSeq(block).isEmpty()) {
                continue;
            }
            if (idx == dindex) {
                out.addAll(blockSpans(block, dpoint, null, null, daddr));
                continue;
            }
            out.addAll(blockSeq(block));
            for (int i = 0; i < block.getInSize(); i++) {
                work.add(block.getIn(i));
            }
        }
        return out;
    }

    // -- physical location of values ---------------------------------------------

    /** Register a temporary (unique) decompiler instance was physically written to. */
    Key uniqueHome(Varnode vn) {
        PcodeOp d = vn.getDef();
        if (d == null || flow == null || d.getOpcode() == PcodeOp.MULTIEQUAL) {
            return null;
        }
        long off = d.getSeqnum().getTarget().getOffset();
        FunctionFlow.Insn dec = flow.decoded.get(off);
        if (dec == null) {
            return null;
        }
        MachineInfo m = exp.machine;
        boolean isCall = dec.isCall;
        int size = vn.getSize();
        int dop = d.getOpcode();
        Map<Vn, Key> copies = new HashMap<>();
        for (Op op : dec.ops) {
            if (op.opc == PcodeOp.COPY && op.out != null && op.out.kind == 'r' && op.i0 != null && op.i0.kind == 'u') {
                copies.putIfAbsent(op.i0, op.out.regKey());
            }
        }
        LinkedHashSet<Key> keys = new LinkedHashSet<>();
        for (Op op : dec.ops) {
            if (op.opc != dop || op.out == null || op.out.size != size || !inputsMatch(d, dop, op)) {
                continue;
            }
            Key k = op.out.kind == 'r' ? op.out.regKey() : op.out.kind == 'u' ? copies.get(op.out) : null;
            if (k != null && k.size == size && !(isCall && k.equals(m.raKey))) {
                keys.add(k);
            }
        }
        if (keys.size() == 1) {
            return keys.iterator().next();
        }
        if (!keys.isEmpty()) {
            return null;
        }
        boolean anyU = false;
        for (Op op : dec.ops) {
            if (op.opc == dop && op.out != null && op.out.kind == 'u' && op.out.size == size && inputsMatch(d, dop, op)) {
                anyU = true;
                break;
            }
        }
        if (!anyU) {
            return null;
        }
        LinkedHashSet<Key> wide = new LinkedHashSet<>();
        for (Op op : dec.ops) {
            if (op.out != null && op.out.kind == 'r' && op.out.size > size &&
                (op.opc == PcodeOp.INT_ZEXT || op.opc == PcodeOp.INT_SEXT || op.opc == PcodeOp.COPY)) {
                Key k = op.out.regKey();
                if (!(isCall && k.equals(m.raKey)) && m.dwarfOf(k) != null) {
                    wide.add(k);
                }
            }
        }
        if (wide.size() != 1) {
            return null;
        }
        Key w = wide.iterator().next();
        return Key.reg(w.off + (exp.bigEndian ? w.size - size : 0), size);
    }

    private static boolean inputsMatch(PcodeOp d, int dop, Op op) {
        Vn[] mins = {op.i0, op.i1, op.i2};
        for (int i = 0; i < Math.min(d.getNumInputs(), 3); i++) {
            if (i == 0 && (dop == PcodeOp.LOAD || dop == PcodeOp.STORE)) {
                continue;
            }
            Varnode dv = d.getInput(i);
            Vn mv = mins[i];
            if (dv == null || mv == null) {
                continue;
            }
            if (dv.isRegister()) {
                if (mv.kind == 'c' || (mv.kind == 'r' && (mv.off != dv.getOffset() || mv.size != dv.getSize()))) {
                    return false;
                }
            }
            else if (dv.isConstant()) {
                if (mv.kind == 'r' || (mv.kind == 'c' && mv.off != dv.getOffset())) {
                    return false;
                }
            }
            else if (dv.getAddress().isMemoryAddress()) {
                if (mv.kind != 'a' || mv.off != dv.getOffset()) {
                    return false;
                }
            }
        }
        return true;
    }

    /** FunctionFlow value id of a register varnode instance, or null. */
    Val instanceValue(Varnode vn) {
        if (flow == null) {
            return null;
        }
        if (vn.isUnique()) {
            PcodeOp d = vn.getDef();
            if (d != null && d.getOpcode() == PcodeOp.COPY && d.getInput(0) != null && d.getInput(0).isRegister()) {
                return instanceValue(d.getInput(0));
            }
            Key home = uniqueHome(vn);
            if (home == null) {
                return null;
            }
            return flow.valueAfter(vn.getDef().getSeqnum().getTarget().getOffset(), home);
        }
        if (!vn.isRegister()) {
            return null;
        }
        Key key = Key.reg(vn.getOffset(), vn.getSize());
        PcodeOp d = vn.getDef();
        if (d == null) {
            return vn.isInput() ? flow.defaultValue(key) : null;
        }
        if (d.getOpcode() == PcodeOp.MULTIEQUAL) {
            return flow.valueBefore(d.getSeqnum().getTarget().getOffset(), key);
        }
        return flow.valueAfter(d.getSeqnum().getTarget().getOffset(), key);
    }

    byte[] bestLocation(List<FunctionFlow.Loc> locs, Key own) {
        int bestRank = Integer.MAX_VALUE;
        byte[] best = null;
        MachineInfo m = exp.machine;
        for (FunctionFlow.Loc l : locs) {
            byte[] e;
            int rank;
            if (l.isReg()) {
                e = regExpr(l.reg.off, l.reg.size);
                if (e == null) {
                    continue;
                }
                rank = m.isPreserved(l.reg) ? 0 : (l.reg.equals(own) ? 2 : 3);
            }
            else {
                e = exp.dw.expr().fbreg(l.stack - exp.stackshift).bytes();
                rank = 1;
            }
            if (best == null || rank < bestRank || (rank == bestRank && Arrays.compareUnsigned(e, best) < 0)) {
                best = e;
                bestRank = rank;
            }
        }
        return best;
    }

    List<Span> locatedPcs(Varnode vn, Val value, List<Long> pcs) {
        Key own = vn.isRegister() ? Key.reg(vn.getOffset(), vn.getSize()) : null;
        List<Span> out = new ArrayList<>();
        for (long pc : pcs) {
            byte[] e = bestLocation(flow.locationsOf(pc, value, vn.getSize(), false), own);
            if (e != null) {
                out.add(new Span(pc, flow.insnEnd(pc), e));
            }
        }
        return out;
    }

    List<Long> pcsIn(List<long[]> spans) {
        List<Long> insns = flow.insns;
        List<Long> out = new ArrayList<>();
        for (long[] st : spans) {
            int i = bisectLeft(insns, st[0]);
            while (i < insns.size() && insns.get(i) < st[1]) {
                out.add(insns.get(i));
                i++;
            }
        }
        return out;
    }

    static final class BlockInfo {
        final long[] bounds;
        /** (position {piece, pc}, pc) in execution order */
        final List<long[]> pcs;
        final List<Integer> preds;
        final PcodeBlockBasic block;

        BlockInfo(long[] bounds, List<long[]> pcs, List<Integer> preds, PcodeBlockBasic block) {
            this.bounds = bounds;
            this.pcs = pcs;
            this.preds = preds;
            this.block = block;
        }
    }

    LinkedHashMap<Integer, BlockInfo> blockInfo() {
        if (binfo == null) {
            binfo = new LinkedHashMap<>();
            for (PcodeBlockBasic b : hf.getBasicBlocks()) {
                List<long[]> seq = blockSeq(b);
                long[] bounds = seq.isEmpty() ? null : seq.get(0);
                List<long[]> pcs = new ArrayList<>();
                for (int i = 0; i < seq.size(); i++) {
                    List<long[]> one = new ArrayList<>();
                    one.add(seq.get(i));
                    for (long pc : pcsIn(one)) {
                        pcs.add(new long[] {i, pc, pc});
                    }
                }
                List<Integer> preds = new ArrayList<>();
                for (int k = 0; k < b.getInSize(); k++) {
                    preds.add(b.getIn(k).getIndex());
                }
                binfo.put(b.getIndex(), new BlockInfo(bounds, pcs, preds, b));
            }
        }
        return binfo;
    }

    /** An event: position {piece, addr}, order, instance index. */
    private static final class Ev implements Comparable<Ev> {
        final long p0, p1;
        final long order;
        final int idx;

        Ev(long p0, long p1, long order, int idx) {
            this.p0 = p0;
            this.p1 = p1;
            this.order = order;
            this.idx = idx;
        }

        @Override
        public int compareTo(Ev o) {
            if (p0 != o.p0) {
                return Long.compare(p0, o.p0);
            }
            if (p1 != o.p1) {
                return Long.compare(p1, o.p1);
            }
            if (order != o.order) {
                return Long.compare(order, o.order);
            }
            return Integer.compare(idx, o.idx);
        }
    }

    private static final Integer TOP = Integer.MIN_VALUE;
    private static final Integer NONE = Integer.MIN_VALUE + 1;
    private static final Integer CONFLICT = Integer.MIN_VALUE + 2;

    /** {instance index: [pc]}: where each SSA instance is the current value (null: not available). */
    Map<Integer, List<Long>> reachingPcs(List<Varnode> instances) {
        if (flow == null || entryBlock == null) {
            return null;
        }
        LinkedHashMap<Integer, BlockInfo> bi = blockInfo();
        if (bi.isEmpty()) {
            return null;
        }
        int entryBi = entryBlock.getIndex();
        Map<Integer, List<Ev>> events = new LinkedHashMap<>();
        for (int k : bi.keySet()) {
            events.put(k, new ArrayList<>());
        }
        for (int i = 0; i < instances.size(); i++) {
            Varnode vn = instances.get(i);
            PcodeOp d = vn.getDef();
            if (d == null) {
                if (vn.isInput()) {
                    events.get(entryBi).add(new Ev(0, entry, -1, i));
                }
                continue;
            }
            int b = d.getParent().getIndex();
            if (!events.containsKey(b)) {
                continue;
            }
            BlockInfo info = bi.get(b);
            if (d.getOpcode() == PcodeOp.MULTIEQUAL) {
                if (info.bounds == null) {
                    continue;
                }
                events.get(b).add(new Ev(0, info.bounds[0], -1, i));
            }
            else {
                long t = d.getSeqnum().getTarget().getOffset();
                long[] pos = blockPos(info.block, t);
                events.get(b).add(new Ev(pos[0], exp.insnEnd(d.getSeqnum().getTarget()), d.getSeqnum().getOrder(), i));
            }
        }
        for (List<Ev> ev : events.values()) {
            Collections.sort(ev);
        }
        Map<Integer, Integer> outInst = new HashMap<>();
        for (int k : bi.keySet()) {
            outInst.put(k, TOP);
        }
        Map<Integer, Integer> inInst = new HashMap<>();
        for (int round = 0; round < 4 * bi.size() + 4; round++) {
            boolean changed = false;
            for (Map.Entry<Integer, BlockInfo> e : bi.entrySet()) {
                int b = e.getKey();
                Integer inn;
                if (b == entryBi) {
                    inn = NONE;
                }
                else {
                    Set<Integer> vals = new HashSet<>();
                    for (int pb : e.getValue().preds) {
                        Integer v = outInst.get(pb);
                        vals.add(v == null ? NONE : v);
                    }
                    vals.remove(TOP);
                    inn = vals.size() == 1 ? vals.iterator().next() : (vals.isEmpty() ? TOP : NONE);
                }
                inInst.put(b, inn);
                List<Ev> ev = events.get(b);
                Integer out = !ev.isEmpty() ? Integer.valueOf(ev.get(ev.size() - 1).idx) : inn;
                if (!out.equals(outInst.get(b))) {
                    outInst.put(b, out);
                    changed = true;
                }
            }
            if (!changed) {
                break;
            }
        }
        // {pc: the instance current there, CONFLICT if several (blocks sharing an instruction)}
        HashMap<Long, Integer> perPc = new HashMap<>();
        for (Map.Entry<Integer, BlockInfo> e : bi.entrySet()) {
            BlockInfo info = e.getValue();
            if (info.bounds == null) {
                continue;
            }
            Integer cur = inInst.get(e.getKey());
            if (cur == null || cur.equals(TOP)) {
                cur = NONE;
            }
            List<Ev> ev = events.get(e.getKey());
            int j = 0;
            for (long[] pp : info.pcs) {
                while (j < ev.size() && (ev.get(j).p0 < pp[0] || (ev.get(j).p0 == pp[0] && ev.get(j).p1 <= pp[1]))) {
                    cur = ev.get(j).idx;
                    j++;
                }
                Integer prev = perPc.putIfAbsent(pp[2], cur);
                if (prev != null && !prev.equals(cur)) {
                    perPc.put(pp[2], CONFLICT);
                }
            }
        }
        Map<Integer, List<Long>> result = new HashMap<>();
        for (Map.Entry<Long, Integer> e : perPc.entrySet()) {
            Integer cur = e.getValue();
            if (!cur.equals(NONE) && !cur.equals(CONFLICT)) {
                result.computeIfAbsent(cur, x -> new ArrayList<>()).add(e.getKey());
            }
        }
        for (List<Long> pcs : result.values()) {
            pcs.sort(null);
        }
        return result;
    }

    Location unusedParamLocation(HighSymbol sym, VariableStorage storage) {
        if (!sym.isParameter()) {
            return null;
        }
        return entryValueLocation(storage);
    }

    /** Where a parameter's entry value still physically exists. */
    public Location entryValueLocation(VariableStorage storage) {
        if (flow == null || storage == null || storage.isBadStorage() || storage.isUnassignedStorage()) {
            return null;
        }
        Varnode[] vns = storage.getVarnodes();
        if (vns.length == 1 && vns[0].getAddress().isStackAddress()) {
            byte[] e = storageExpr(storage);
            return e != null ? new Location(e, null) : null;
        }
        List<Long> pcs = new ArrayList<>(flow.insns);
        List<Span> entries;
        boolean allRegs = true;
        for (Varnode v : vns) {
            if (!v.isRegister()) {
                allRegs = false;
            }
        }
        if (vns.length == 1 && vns[0].isRegister()) {
            Key key = Key.reg(vns[0].getOffset(), vns[0].getSize());
            entries = locatedPcs(vns[0], flow.defaultValue(key), pcs);
        }
        else if (allRegs) {
            entries = compoundInputPcs(storage, pcs);
        }
        else {
            return null;
        }
        if (entries.isEmpty()) {
            return null;
        }
        List<Span> sorted = new ArrayList<>(entries);
        sorted.sort((a, b) -> {
            int c = Arrays.compareUnsigned(a.expr, b.expr);
            return c != 0 ? c : Long.compare(a.start, b.start);
        });
        List<Span> merged = new ArrayList<>();
        for (Span s : sorted) {
            Span last = merged.isEmpty() ? null : merged.get(merged.size() - 1);
            if (last != null && Arrays.equals(last.expr, s.expr) && s.start <= last.end) {
                merged.set(merged.size() - 1, new Span(last.start, Math.max(s.end, last.end), s.expr));
            }
            else {
                merged.add(s);
            }
        }
        merged.sort((a, b) -> Long.compare(a.start, b.start));
        List<Span> out = new ArrayList<>();
        for (Span s : merged) {
            out.add(new Span(exp.A(s.start), exp.A(s.start) + (s.end - s.start), s.expr));
        }
        return new Location(null, out);
    }

    /** [(pc, end, expr)] for a join-space instance, or null if not applicable. */
    List<Span> joinPcs(Varnode vn, VariableStorage storage, List<Long> pcs) {
        PcodeOp d = vn.getDef();
        Varnode[] pieces = storage.getVarnodes();
        if (d == null || pieces.length == 0) {
            return null;
        }
        for (Varnode p : pieces) {
            if (!p.isRegister()) {
                return null;
            }
        }
        long off = d.getSeqnum().getTarget().getOffset();
        List<Key> keys = new ArrayList<>();
        List<Val> vals = new ArrayList<>();
        for (Varnode p : pieces) {
            Key k = Key.reg(p.getOffset(), p.getSize());
            keys.add(k);
            vals.add(flow.valueAfter(off, k));
        }
        for (Val v : vals) {
            if (v == null) {
                return new ArrayList<>();
            }
        }
        List<Integer> order = new ArrayList<>();
        for (int i = 0; i < pieces.length; i++) {
            order.add(i);
        }
        if (pieces.length > 1 && !exp.bigEndian) {
            Collections.reverse(order);
        }
        List<Span> out = new ArrayList<>();
        for (long pc : pcs) {
            List<byte[]> exprs = new ArrayList<>();
            List<Integer> sizes = new ArrayList<>();
            boolean complete = true;
            for (int i : order) {
                int size = pieces.length == 1 && vn.getSize() < keys.get(i).size ? vn.getSize() : 0;
                byte[] e = bestLocation(flow.locationsOf(pc, vals.get(i), size, size != 0), keys.get(i));
                if (e == null) {
                    complete = false;
                    break;
                }
                exprs.add(e);
                sizes.add(keys.get(i).size);
            }
            if (!complete) {
                continue;
            }
            byte[] expr;
            if (exprs.size() == 1) {
                expr = exprs.get(0);
            }
            else {
                Buf buf = new Buf();
                for (int i = 0; i < exprs.size(); i++) {
                    buf.add(exprs.get(i)).add(C.DW_OP_piece).add(DwarfBuilder.uleb(sizes.get(i)));
                }
                expr = buf.bytes();
            }
            out.add(new Span(pc, flow.insnEnd(pc), expr));
        }
        return out;
    }

    /** Spans where every register piece of an input still holds its entry value. */
    List<Span> compoundInputPcs(VariableStorage storage, List<Long> pcs) {
        byte[] e = storageExpr(storage);
        if (e == null) {
            return new ArrayList<>();
        }
        List<Key> keys = new ArrayList<>();
        for (Varnode p : storage.getVarnodes()) {
            if (p.isRegister()) {
                keys.add(Key.reg(p.getOffset(), p.getSize()));
            }
            else if (!p.getAddress().isStackAddress()) {
                return new ArrayList<>();
            }
        }
        List<Span> out = new ArrayList<>();
        for (long pc : pcs) {
            State st = flow.stateIn.get(pc);
            if (st == null) {
                continue;
            }
            boolean all = true;
            for (Key k : keys) {
                if (!Val.init(k).equals(flow.regValue(st, k))) {
                    all = false;
                    break;
                }
            }
            if (all) {
                out.add(new Span(pc, flow.insnEnd(pc), e));
            }
        }
        return out;
    }

    // -- main -------------------------------------------------------------------------

    /** The location of a decompiler symbol, or null. */
    public Location symbolLocation(HighSymbol sym) {
        VariableStorage storage = sym.getStorage();
        if (storage != null && !storage.isBadStorage() && !storage.isUnassignedStorage()) {
            if (storage.isStackStorage() || storage.isMemoryStorage()) {
                byte[] e = storageExpr(storage);
                if (e != null) {
                    return new Location(e, null);
                }
            }
        }
        HighVariable hv = sym.getHighVariable();
        if (hv == null) {
            return unusedParamLocation(sym, storage);
        }
        List<Span> entries = new ArrayList<>();
        List<Varnode> instances = Arrays.asList(hv.getInstances());
        Map<Integer, List<Long>> reaching = reachingPcs(instances);
        for (int idx = 0; idx < instances.size(); idx++) {
            Varnode vn = instances.get(idx);
            AddressSpace space = vn.getAddress().getAddressSpace();
            if (vn.isConstant()) {
                continue;
            }
            if (vn.isUnique()) {
                Val value = instanceValue(vn);
                if (value != null && reaching != null) {
                    entries.addAll(locatedPcs(vn, value, reaching.getOrDefault(idx, new ArrayList<>())));
                }
                continue;
            }
            if (space.isStackSpace()) {
                byte[] e = varnodeExpr(vn);
                if (e != null) {
                    for (long[] r : ranges) {
                        entries.add(new Span(r[0], r[1], e));
                    }
                }
                continue;
            }
            List<Long> pcs;
            if (reaching != null) {
                pcs = reaching.getOrDefault(idx, new ArrayList<>());
            }
            else if (flow != null) {
                pcs = pcsIn(liveIntervals(vn));
            }
            else {
                pcs = null;
            }
            if (vn.isRegister() && pcs != null) {
                Val value = instanceValue(vn);
                if (value != null) {
                    entries.addAll(locatedPcs(vn, value, pcs));
                }
                continue;
            }
            List<long[]> spans = liveIntervals(vn);
            byte[] e;
            if (vn.isRegister() || space.equals(exp.space)) {
                e = varnodeExpr(vn);
            }
            else if (storage != null && storage.getVarnodes().length > 0 &&
                (storage.isCompoundStorage() || vn.getSize() <= storage.size())) {
                if (vn.isInput() && pcs != null) {
                    entries.addAll(compoundInputPcs(storage, pcs));
                    continue;
                }
                if (pcs != null && flow != null) {
                    List<Span> joined = joinPcs(vn, storage, pcs);
                    if (joined != null) {
                        entries.addAll(joined);
                        continue;
                    }
                }
                e = storageExpr(storage);
            }
            else {
                e = null;
            }
            if (e == null) {
                continue;
            }
            for (long[] s : spans) {
                if (s[1] > s[0]) {
                    entries.add(new Span(s[0], s[1], e));
                }
            }
        }
        if (entries.isEmpty()) {
            return unusedParamLocation(sym, storage);
        }
        entries.sort((a, b) -> {
            int c = Arrays.compareUnsigned(a.expr, b.expr);
            return c != 0 ? c : Long.compare(a.start, b.start);
        });
        List<Span> merged = new ArrayList<>();
        for (Span s : entries) {
            Span last = merged.isEmpty() ? null : merged.get(merged.size() - 1);
            if (last != null && Arrays.equals(last.expr, s.expr) && s.start <= last.end) {
                if (s.end > last.end) {
                    merged.set(merged.size() - 1, new Span(last.start, s.end, s.expr));
                }
            }
            else {
                merged.add(s);
            }
        }
        merged.sort((a, b) -> a.start != b.start ? Long.compare(a.start, b.start) : Long.compare(a.end, b.end));
        List<Span> out = new ArrayList<>();
        for (Span s : merged) {
            out.add(new Span(exp.A(s.start), exp.A(s.start) + (s.end - s.start), s.expr));
        }
        return new Location(null, out);
    }

    static boolean eq(Object a, Object b) {
        return Objects.equals(a, b);
    }
}
