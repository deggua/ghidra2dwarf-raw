package dwarfexport;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;

/**
 * Machine-level data flow over raw p-code, shared by CFI generation and
 * variable location tracking (a port of flow.py's FunctionFlow; see there for
 * the design). For every instruction of a function: the abstract machine
 * state on entry ({@link #stateIn}) and after it ({@link #stateOut}).
 */
public final class FunctionFlow {
    public static final int MAX_STEPS = 500000;

    /** An instruction decoded once. */
    public static final class Insn {
        public boolean isCall;
        public boolean isJump;
        public boolean isTerminal;
        public int delay;
        public final List<Long> succs = new ArrayList<>();
        public final List<Op> ops = new ArrayList<>();
        /** The next instruction's offset, and the fall-through (or next). */
        public long nxt, fallOrNext;
        public boolean openJump;
        /** The fall-through if inside the body, else null. */
        public Long fallInBody;
    }

    public final MachineInfo m;
    public final Function func;
    final Map<Long, List<Long>> extraEdges;
    final State initState;
    final Listing listing;
    public final Map<Long, State> stateIn = new HashMap<>();
    public final Map<Long, State> stateOut = new HashMap<>();
    final Map<Long, State> stateTaken = new HashMap<>();
    State taken;
    public final Map<Long, Integer> insnLen = new HashMap<>();
    public final List<Long> insns = new ArrayList<>();
    public boolean converged = true;
    public final Map<Long, Insn> decoded = new HashMap<>();
    public final Map<Long, Address> callTargets = new HashMap<>();
    public boolean isLeaf;
    boolean sideEffect;
    private final Set<Key> universe = new LinkedHashSet<>();
    private final Map<Key, List<Key>> ovl = new HashMap<>();

    public FunctionFlow(MachineInfo machine, Function func, Map<Long, List<Long>> extraEdges, State initState) {
        this.m = machine;
        this.func = func;
        this.extraEdges = extraEdges != null ? extraEdges : new HashMap<>();
        this.initState = initState;
        this.listing = machine.listing;
        universe.addAll(machine.mapped);
        universe.add(machine.spKey);
        if (machine.raKey != null) {
            universe.add(machine.raKey);
        }
        run();
    }

    // -- value access ---------------------------------------------------------

    public Val defaultValue(Key key) {
        Key sp = m.spKey;
        if (key.equals(sp)) {
            return Val.sp(0);
        }
        if (key.isReg() && sp.contains(key) && isLowPart(key, sp)) {
            return Val.sp(0); // low half of a 64-bit SP (n32 address arithmetic)
        }
        return Val.init(key);
    }

    /** Is register bytes k the low-order part of register c? */
    public boolean isLowPart(Key k, Key c) {
        if (m.bigEndian) {
            return k.off + k.size == c.off + c.size;
        }
        return k.off == c.off;
    }

    /** The same value id, for another (narrower or wider) view. */
    public static Val rekey(Val value, Key key) {
        if (value.kind == Val.INIT) {
            return Val.init(key);
        }
        if (value.kind == Val.DEF) {
            return Val.def(value.n, key);
        }
        if (value.kind == Val.PHI) {
            return Val.phi(value.join, key);
        }
        return null;
    }

    /** Value id of the low-order size bytes of value. */
    public Val narrow(Val value, int size) {
        if (value == null || size <= 0) {
            return null;
        }
        if (value.kind == Val.SP) {
            return value;
        }
        if (value.kind == Val.CONST) {
            return Val.cnst(value.bigValue().and(mask(size)), size);
        }
        Key key = value.originKey();
        if (key == null || !key.isReg()) {
            return null;
        }
        if (size >= key.size) {
            return value;
        }
        long lo = key.off + (m.bigEndian ? key.size - size : 0);
        return rekey(value, Key.reg(lo, size));
    }

    private List<Key> overlaps(Key key) {
        List<Key> hit = ovl.get(key);
        if (hit == null) {
            hit = new ArrayList<>();
            for (Key rk : universe) {
                if (rk.overlaps(key)) {
                    hit.add(rk);
                }
            }
            ovl.put(key, hit);
        }
        return hit;
    }

    private void noteKey(Key k) {
        if (universe.add(k)) {
            ovl.clear();
        }
    }

    public Val regValue(State st, Key key) {
        LinkedHashMap<Key, Val> regs = st.regs;
        if (regs.containsKey(key)) {
            return regs.get(key);
        }
        Key only = null;
        int count = 0;
        for (Key rk : overlaps(key)) {
            if (regs.containsKey(rk)) {
                count++;
                only = rk;
                if (count > 1) {
                    break;
                }
            }
        }
        if (count == 0) {
            return defaultValue(key);
        }
        if (count == 1) {
            Val v = regs.get(only);
            if (v != null && only.contains(key) && isLowPart(key, only)) {
                return narrow(v, key.size);
            }
            return null;
        }
        for (Map.Entry<Key, Val> e : regs.entrySet()) {
            Key rk = e.getKey();
            if (!rk.isU() && rk.overlaps(key)) {
                // overwritten through another view: the first in the state's order
                Val v = e.getValue();
                if (v != null && rk.contains(key) && isLowPart(key, rk)) {
                    return narrow(v, key.size);
                }
                return null;
            }
        }
        return defaultValue(key);
    }

    Val get(State st, Vn d) {
        switch (d.kind) {
            case 'c':
                return Val.cnst(d.off, d.size);
            case 'r':
                return regValue(st, d.regKey());
            case 'u':
                return st.regs.get(d.uKey());
            default:
                return null;
        }
    }

    void set(State st, Vn d, Val value, long insOff) {
        if (d.kind == 'r') {
            Key k = d.regKey();
            if (!universe.contains(k)) {
                noteKey(k);
            }
            if (value == null) {
                value = Val.def(insOff, k);
            }
            List<Key> others = new ArrayList<>();
            for (Key o : st.regs.keySet()) {
                if (!o.isU() && !o.equals(k) && o.overlaps(k)) {
                    others.add(o);
                }
            }
            for (Key other : others) {
                if (k.contains(other)) {
                    // a view inside the written register: regValue derives it from the new value
                    st.regs.remove(other);
                }
                else {
                    st.regs.put(other, null);
                }
            }
            for (Key mk : m.containers(k)) {
                if (!st.regs.containsKey(mk)) {
                    st.regs.put(mk, null);
                }
            }
            st.regs.put(k, value);
        }
        else if (d.kind == 'u') {
            st.regs.put(d.uKey(), value);
        }
    }

    // -- integers with Python semantics ----------------------------------------

    static BigInteger mask(int size) {
        return BigInteger.ONE.shiftLeft(8 * size).subtract(BigInteger.ONE);
    }

    /** The two's-complement value of c's low size bytes. */
    static long signed(Val c, int size) {
        if (c.big == null && size == 8) {
            return c.n;
        }
        if (c.big == null && size < 8 && size > 0) {
            int bits = 8 * size;
            long x = c.n & ((1L << bits) - 1);
            return (x >>> (bits - 1)) != 0 ? x - (1L << bits) : x;
        }
        int bits = 8 * size;
        BigInteger x = c.bigValue().and(mask(size));
        if (bits > 0 && x.testBit(bits - 1)) {
            x = x.subtract(BigInteger.ONE.shiftLeft(bits));
        }
        return x.longValue();
    }

    static long signedRaw(long v, int size) {
        if (size >= 8 || size <= 0) {
            return v;
        }
        int bits = 8 * size;
        long x = v & ((1L << bits) - 1);
        return (x >>> (bits - 1)) != 0 ? x - (1L << bits) : x;
    }

    static boolean isArith(int opc) {
        return opc == PcodeOp.INT_ADD || opc == PcodeOp.INT_SUB || opc == PcodeOp.INT_OR ||
            opc == PcodeOp.INT_AND || opc == PcodeOp.INT_XOR || opc == PcodeOp.INT_LEFT ||
            opc == PcodeOp.INT_RIGHT || opc == PcodeOp.INT_SRIGHT || opc == PcodeOp.INT_MULT;
    }

    Val arith(int opc, Val a, Val b) {
        if (a == null || b == null) {
            return null;
        }
        if ((opc == PcodeOp.INT_OR || opc == PcodeOp.INT_AND) && a.equals(b)) {
            return a;
        }
        if (opc == PcodeOp.INT_OR || opc == PcodeOp.INT_XOR || opc == PcodeOp.INT_ADD ||
            opc == PcodeOp.INT_SUB || opc == PcodeOp.INT_LEFT || opc == PcodeOp.INT_RIGHT ||
            opc == PcodeOp.INT_SRIGHT) {
            if (b.isConstZero()) {
                return a;
            }
            if (a.isConstZero() && opc != PcodeOp.INT_SUB) {
                return b;
            }
        }
        if (opc == PcodeOp.INT_ADD) {
            if (a.kind == Val.SP && b.kind == Val.CONST) {
                return Val.sp(a.n + signed(b, b.size));
            }
            if (b.kind == Val.SP && a.kind == Val.CONST) {
                return Val.sp(b.n + signed(a, a.size));
            }
        }
        else if (opc == PcodeOp.INT_SUB) {
            if (a.kind == Val.SP && b.kind == Val.CONST) {
                return Val.sp(a.n - signed(b, b.size));
            }
        }
        if (a.kind == Val.CONST && b.kind == Val.CONST) {
            int size = a.size;
            BigInteger x = a.bigValue(), y = b.bigValue();
            BigInteger r;
            if (opc == PcodeOp.INT_ADD) {
                r = x.add(y);
            }
            else if (opc == PcodeOp.INT_SUB) {
                r = x.subtract(y);
            }
            else if (opc == PcodeOp.INT_OR) {
                r = x.or(y);
            }
            else if (opc == PcodeOp.INT_AND) {
                r = x.and(y);
            }
            else if (opc == PcodeOp.INT_XOR) {
                r = x.xor(y);
            }
            else if (opc == PcodeOp.INT_LEFT) {
                r = y.compareTo(BigInteger.valueOf(64)) < 0 ? x.shiftLeft(y.intValue()) : BigInteger.ZERO;
            }
            else if (opc == PcodeOp.INT_RIGHT) {
                r = y.compareTo(BigInteger.valueOf(64)) < 0 ? x.shiftRight(y.intValue()) : BigInteger.ZERO;
            }
            else if (opc == PcodeOp.INT_SRIGHT) {
                BigInteger s = x.and(mask(size));
                if (size > 0 && s.testBit(8 * size - 1)) {
                    s = s.subtract(BigInteger.ONE.shiftLeft(8 * size));
                }
                r = s.shiftRight(Math.min(y.min(BigInteger.valueOf(63)).intValue(), 63));
            }
            else if (opc == PcodeOp.INT_MULT) {
                r = x.multiply(y);
            }
            else {
                return null;
            }
            return Val.cnst(r.and(mask(size)), size);
        }
        return null;
    }

    // -- transfer function ----------------------------------------------------

    private static final Integer NEXT = Val.Join.NEXT;

    /**
     * Where a branch op at p-code index i goes inside the instruction: an op
     * index, NEXT (fall through), or null (a real branch).
     */
    static Integer localTarget(int i, Vn i0, Insn d, int n) {
        if (i0 == null) {
            return null;
        }
        if (i0.kind == 'c') {
            long t = i + signedRaw(i0.off, i0.size != 0 ? i0.size : 8);
            return t >= n ? NEXT : (t > i ? Integer.valueOf((int) t) : null);
        }
        if (i0.kind == 'a' && (i0.off == d.nxt || i0.off == d.fallOrNext)) {
            return NEXT;
        }
        return null;
    }

    /** Applies the instruction at offset off to st in place. */
    public void step(State st, long off) {
        Insn d = decoded.get(off);
        List<Op> ops = d.ops;
        Val spBefore = regValue(st, m.spKey);
        Set<Key> written = new HashSet<>();
        sideEffect = false;
        Map<Integer, State> pend = new HashMap<>();
        boolean alive = true;
        boolean left = false;
        int n = ops.size();
        for (int idx = 0; idx < n; idx++) {
            Op op = ops.get(idx);
            int opc = op.opc;
            if (pend.containsKey(idx)) {
                State other = pend.remove(idx);
                if (alive) {
                    st.assign(merge(st, other, Val.Join.pcode(off, idx)));
                }
                else {
                    st.assign(other);
                    alive = true;
                    left = false;
                }
            }
            if (!alive) {
                continue;
            }
            if (opc == PcodeOp.CBRANCH || opc == PcodeOp.BRANCH) {
                Integer tgt = localTarget(idx, op.i0, d, n);
                if (tgt != null) {
                    State snap = st.copy();
                    if (pend.containsKey(tgt)) {
                        snap = merge(pend.get(tgt), snap, Val.Join.pcode(off, tgt));
                    }
                    pend.put(tgt, snap);
                    if (opc == PcodeOp.BRANCH) {
                        alive = false;
                    }
                    continue;
                }
                if (opc == PcodeOp.BRANCH) {
                    left = true;
                }
                continue;
            }
            if (opc == PcodeOp.RETURN || opc == PcodeOp.BRANCHIND) {
                left = true;
                continue;
            }
            apply(st, op, off, written);
        }

        taken = null;
        State skipped = pend.remove(NEXT);
        if (skipped != null) {
            if (!alive || left) {
                if (alive) {
                    taken = st.copy();
                }
                st.assign(skipped);
            }
            else {
                st.assign(merge(st, skipped, Val.Join.pcode(off, NEXT)));
            }
        }

        st.regs.keySet().removeIf(Key::isU);

        if (d.isCall) {
            Address target = callTargets.get(off);
            List<Op> body = m.inlineBody(target);
            if (body != null) {
                for (Op op : body) {
                    apply(st, op, off, written);
                }
                st.regs.keySet().removeIf(Key::isU);
            }
            else {
                callEffects(st, off, target, spBefore, written);
            }
        }

        // Registers reloaded with their entry value are "restored".
        for (Iterator<Key> it = st.saved.keySet().iterator(); it.hasNext();) {
            Key k = it.next();
            if (written.contains(k) && Val.init(k).equals(st.regs.get(k))) {
                it.remove();
            }
        }
    }

    boolean isSaveSlot(Val value) {
        if (value == null || value.kind != Val.INIT) {
            return false;
        }
        Key k = value.key;
        return k.kind == Key.RA || k.equals(m.raKey) || (k.isReg() && m.isPreserved(k));
    }

    void clobberEscaped(State st) {
        if (st.esc == null) {
            return;
        }
        long esc = st.esc;
        st.mem.entrySet().removeIf(e -> e.getKey() >= esc && !isSaveSlot(e.getValue().v));
    }

    void callEffects(State st, long off, Address target, Val spBefore, Set<Key> written) {
        for (Map.Entry<Key, Val> e : st.regs.entrySet()) {
            Key k = e.getKey();
            Val v = e.getValue();
            if (v != null && v.kind == Val.SP && !k.isU() && !k.equals(m.spKey) && !m.isPreserved(k)) {
                st.esc = State.minEsc(st.esc, v.n);
            }
        }
        if (spBefore != null && spBefore.kind == Val.SP) {
            long lo = spBefore.n, hi = spBefore.n + m.calleeArea(target);
            st.mem.entrySet().removeIf(e -> lo <= e.getKey() && e.getKey() < hi && !isSaveSlot(e.getValue().v));
        }
        clobberEscaped(st);
        if (spBefore != null) {
            if (spBefore.kind == Val.SP) {
                st.regs.put(m.spKey, Val.sp(spBefore.n + m.stackPurge(target)));
            }
            else {
                st.regs.put(m.spKey, spBefore);
            }
        }
        for (Key k : m.volatileRegs) {
            st.regs.put(k, Val.def(off, k));
        }
        for (Key k : new ArrayList<>(st.regs.keySet())) {
            if (!k.isU() && !m.volatileSet.contains(k) && !k.equals(m.raKey) && !m.isPreserved(k)) {
                st.regs.put(k, Val.def(off, k));
            }
        }
        if (m.raKey != null && written.contains(m.raKey)) {
            st.regs.put(m.raKey, Val.def(off, m.raKey));
        }
    }

    /** One data p-code op (no control flow). */
    void apply(State st, Op op, long off, Set<Key> written) {
        int opc = op.opc;
        Vn out = op.out, i0 = op.i0, i1 = op.i1, i2 = op.i2;
        if (out != null && out.kind == 'r') {
            written.add(out.regKey());
        }
        if (opc == PcodeOp.STORE) {
            Val addr = get(st, i1);
            Val val = get(st, i2);
            if (val != null && val.kind == Val.SP && !(addr != null && addr.kind == Val.SP)) {
                st.esc = State.minEsc(st.esc, val.n);
            }
            if (addr != null && addr.kind == Val.SP) {
                long soff = addr.n;
                int size = i2.sized() ? i2.size : 0;
                st.mem.entrySet().removeIf(e -> e.getKey() < soff + size && soff < e.getKey() + e.getValue().size);
                st.mem.put(soff, new State.Slot(size, val));
                if (val != null && val.kind == Val.INIT && !st.saved.containsKey(val.key) &&
                    (m.dwarfOf(val.key) != null || m.irqKeys.contains(val.key))) {
                    st.saved.put(val.key, soff);
                }
            }
            else {
                sideEffect = true;
                clobberEscaped(st);
            }
            return;
        }
        if (out == null) {
            return;
        }
        Val val;
        if (opc == PcodeOp.COPY) {
            val = get(st, i0);
        }
        else if (isArith(opc)) {
            val = arith(opc, get(st, i0), get(st, i1));
        }
        else if (opc == PcodeOp.LOAD) {
            val = null;
            Val addr = get(st, i1);
            if (addr != null && addr.kind == Val.SP) {
                State.Slot slot = st.mem.get(addr.n);
                if (slot != null && out.sized() && slot.size == out.size) {
                    val = slot.v;
                }
            }
            else {
                sideEffect = true;
            }
        }
        else if (opc == PcodeOp.SUBPIECE && i1 != null && i1.kind == 'c' && i1.off == 0) {
            val = narrow(get(st, i0), out.sized() ? out.size : 0);
        }
        else if (opc == PcodeOp.FLOAT_FLOAT2FLOAT) {
            Val inner = get(st, i0);
            val = inner != null && inner.kind != Val.CVT && out.sized() ? Val.cvt(inner, out.size) : null;
        }
        else if ((opc == PcodeOp.INT_ZEXT || opc == PcodeOp.INT_SEXT) && out.kind == 'r' &&
            (i0.kind == 'r' || i0.kind == 'u')) {
            Val inner = get(st, i0);
            set(st, out, inner != null && inner.kind == Val.SP ? inner : null, off);
            if (inner != null && i0.size < out.size) {
                long lo = !m.bigEndian ? out.off : out.off + out.size - i0.size;
                Key lk = Key.reg(lo, i0.size);
                noteKey(lk);
                st.regs.put(lk, inner);
            }
            return;
        }
        else {
            val = null;
        }
        set(st, out, val, off);
    }

    // -- join -------------------------------------------------------------------

    public State merge(State a, State b, Val.Join join) {
        LinkedHashMap<Key, Val> regs = new LinkedHashMap<>();
        LinkedHashMap<Key, Val> ar = a.regs, br = b.regs;
        for (Map.Entry<Key, Val> e : ar.entrySet()) {
            Key k = e.getKey();
            Val va = e.getValue();
            Val vb = br.containsKey(k) ? br.get(k) : (k.isU() ? null : regValue(b, k));
            mergeOne(regs, k, va, vb, join);
        }
        for (Map.Entry<Key, Val> e : br.entrySet()) {
            Key k = e.getKey();
            if (ar.containsKey(k)) {
                continue;
            }
            Val vb = e.getValue();
            Val va = k.isU() ? null : regValue(a, k);
            mergeOne(regs, k, va, vb, join);
        }
        LinkedHashMap<Long, State.Slot> mem = new LinkedHashMap<>();
        for (Map.Entry<Long, State.Slot> e : a.mem.entrySet()) {
            Long o = e.getKey();
            State.Slot sb = b.mem.get(o);
            if (sb == null) {
                continue;
            }
            State.Slot sa = e.getValue();
            if (sa.size != sb.size) {
                continue;
            }
            if (java.util.Objects.equals(sa.v, sb.v)) {
                mem.put(o, sa);
            }
            else if (sa.v != null && sb.v != null) {
                mem.put(o, new State.Slot(sa.size, Val.phi(join, Key.mem(o))));
            }
        }
        LinkedHashMap<Key, Long> saved = new LinkedHashMap<>();
        for (Map.Entry<Key, Long> e : a.saved.entrySet()) {
            if (e.getValue().equals(b.saved.get(e.getKey()))) {
                saved.put(e.getKey(), e.getValue());
            }
        }
        return new State(regs, mem, saved, State.minEsc(a.esc, b.esc));
    }

    private static void mergeOne(LinkedHashMap<Key, Val> regs, Key k, Val va, Val vb, Val.Join join) {
        if (java.util.Objects.equals(va, vb)) {
            regs.put(k, va);
        }
        else if (va == null || vb == null) {
            regs.put(k, null);
        }
        else {
            regs.put(k, Val.phi(join, k));
        }
    }

    /** Keeps a join's state monotone so the fixpoint iteration terminates. */
    public State stabilize(State old, State nw, Val.Join join) {
        for (Map.Entry<Key, Val> e : old.regs.entrySet()) {
            Key k = e.getKey();
            Val ov = e.getValue();
            Val nv = nw.regs.containsKey(k) ? nw.regs.get(k) : (!k.isU() ? regValue(nw, k) : null);
            if (ov == null) {
                nw.regs.put(k, null);
            }
            else if (ov.equals(Val.phi(join, k)) && nv != null) {
                nw.regs.put(k, ov);
            }
        }
        for (Long o : new ArrayList<>(nw.mem.keySet())) {
            State.Slot os = old.mem.get(o);
            if (os == null) {
                nw.mem.remove(o);
            }
            else {
                State.Slot ns = nw.mem.get(o);
                if (os.size != ns.size || os.v == null) {
                    if (os.size == ns.size) {
                        nw.mem.put(o, new State.Slot(ns.size, null));
                    }
                    else {
                        nw.mem.remove(o);
                    }
                }
                else if (os.v.equals(Val.phi(join, Key.mem(o))) && ns.v != null) {
                    nw.mem.put(o, new State.Slot(ns.size, os.v));
                }
            }
        }
        LinkedHashMap<Key, Long> saved = new LinkedHashMap<>();
        for (Map.Entry<Key, Long> e : nw.saved.entrySet()) {
            if (e.getValue().equals(old.saved.get(e.getKey()))) {
                saved.put(e.getKey(), e.getValue());
            }
        }
        nw.saved = saved;
        nw.esc = State.minEsc(old.esc, nw.esc);
        return nw;
    }

    // -- driver -----------------------------------------------------------------

    private void run() {
        AddressSetView body = func.getBody();
        Address entry = func.getEntryPoint();
        InstructionIterator it = listing.getInstructions(body, true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            long o = ins.getAddress().getOffset();
            insns.add(o);
            insnLen.put(o, ins.getLength());
            FlowType ft = ins.getFlowType();
            Insn d = new Insn();
            for (PcodeOp op : ins.getPcode()) {
                d.ops.add(Op.decode(op));
            }
            Address[] flows = ins.getFlows();
            if (ft.isCall()) {
                List<Address> tg = new ArrayList<>();
                for (Address t : flows) {
                    if (t != null) {
                        tg.add(t);
                    }
                }
                if (tg.size() == 1) {
                    callTargets.put(o, tg.get(0));
                }
            }
            Address fall = ins.getFallThrough();
            if (fall != null && body.contains(fall)) {
                d.succs.add(fall.getOffset());
            }
            boolean isCall = ft.isCall();
            boolean intoBody = false;
            for (Address t : flows) {
                if (t != null && body.contains(t)) {
                    intoBody = true;
                }
            }
            boolean tailJump = isCall && ft.isTerminal() && intoBody;
            if (ft.isJump() || tailJump) {
                for (Address t : flows) {
                    if (t != null && body.contains(t)) {
                        d.succs.add(t.getOffset());
                    }
                }
            }
            List<Long> extra = extraEdges.get(o);
            if (extra != null) {
                for (long t : extra) {
                    if (!d.succs.contains(t) && body.contains(entry.getNewAddress(t))) {
                        d.succs.add(t);
                    }
                }
            }
            if (tailJump) {
                isCall = false;
            }
            long nxt = o + ins.getLength();
            d.isCall = isCall;
            d.isJump = ft.isJump();
            d.isTerminal = ft.isTerminal();
            d.delay = ins.getDelaySlotDepth();
            d.nxt = nxt;
            d.fallOrNext = fall != null ? fall.getOffset() : nxt;
            d.openJump = ft.isComputed() && ft.isJump() && !isCall && !ft.isConditional() && !intoBody &&
                (extra == null || extra.isEmpty());
            d.fallInBody = fall != null && body.contains(fall) ? fall.getOffset() : null;
            decoded.put(o, d);
        }
        insns.sort(null);
        isLeaf = true;
        for (Insn d : decoded.values()) {
            if (d.isCall) {
                isLeaf = false;
            }
        }

        State init;
        if (initState != null) {
            init = initState.copy();
        }
        else {
            init = new State();
            if (m.raStack != null) {
                init.mem.put(m.raStack, new State.Slot(m.ptrSize, Val.init(Key.RA_KEY)));
            }
        }
        long entryOff = entry.getOffset();
        stateIn.put(entryOff, init);
        Map<Long, TreeSet<Long>> preds = new HashMap<>();
        ArrayList<Long> work = new ArrayList<>();
        work.add(entryOff);
        Set<Long> queued = new HashSet<>();
        queued.add(entryOff);
        int steps = 0;
        int maxRounds = insns.size() + 1;
        boolean broke = false;
        for (int round = 0; round < maxRounds; round++) {
            while (!work.isEmpty()) {
                long aoff = work.remove(work.size() - 1);
                queued.remove(aoff);
                steps++;
                if (steps > MAX_STEPS) {
                    converged = false;
                    m.log.accept("WARNING: flow analysis of " + func.getName() + " did not converge");
                    break;
                }
                Insn d = decoded.get(aoff);
                if (d == null) {
                    continue;
                }
                State st = stateIn.get(aoff).copy();
                step(st, aoff);
                stateOut.put(aoff, st);
                if (taken != null) {
                    stateTaken.put(aoff, taken);
                }
                else {
                    stateTaken.remove(aoff);
                }
                for (long k : d.succs) {
                    TreeSet<Long> pk = preds.computeIfAbsent(k, x -> new TreeSet<>());
                    pk.add(aoff);
                    State nw = null;
                    Val.Join kj = Val.Join.at(k);
                    for (long p : pk) {
                        State ps = stateOut.get(p);
                        if (stateTaken.containsKey(p) && k != decoded.get(p).fallOrNext) {
                            ps = stateTaken.get(p);
                        }
                        if (ps == null) {
                            continue;
                        }
                        nw = nw == null ? ps : merge(nw, ps, kj);
                    }
                    if (k == entryOff) {
                        nw = merge(init, nw, kj);
                    }
                    State old = stateIn.get(k);
                    if (old != null && pk.size() > 1) {
                        nw = stabilize(old, nw, kj);
                    }
                    if (old == null || !nw.equals(old)) {
                        stateIn.put(k, nw);
                        if (queued.add(k)) {
                            work.add(k);
                        }
                    }
                }
            }
            if (!converged) {
                broke = true;
                break;
            }
            List<Map.Entry<Long, State>> seeds = unreachedSeeds();
            if (seeds.isEmpty()) {
                broke = true;
                break;
            }
            for (Map.Entry<Long, State> s : seeds) {
                stateIn.put(s.getKey(), s.getValue());
                if (queued.add(s.getKey())) {
                    work.add(s.getKey());
                }
            }
        }
        if (!broke) {
            m.log.accept("WARNING: " + func.getName() + ": code behind unresolved computed jumps not fully analyzed");
        }

        // Delay slots: the branch's out-state.
        for (int i = 0; i < insns.size(); i++) {
            long o = insns.get(i);
            int depth = decoded.get(o).delay;
            if (depth != 0 && stateIn.containsKey(o)) {
                State after = stateOut.containsKey(o) ? stateOut.get(o) : stateIn.get(o);
                for (int j = i + 1; j < Math.min(insns.size(), i + 1 + depth); j++) {
                    long ds = insns.get(j);
                    if (!stateIn.containsKey(ds)) {
                        stateIn.put(ds, after);
                        stateOut.put(ds, after);
                    }
                }
            }
        }
    }

    private Long spDelta(State st) {
        Val v = regValue(st, m.spKey);
        return v != null && v.kind == Val.SP ? v.n : null;
    }

    private List<Map.Entry<Long, State>> unreachedSeeds() {
        List<Map.Entry<Long, State>> seeds = new ArrayList<>();
        List<Long> jumps = new ArrayList<>();
        for (long o : insns) {
            if (decoded.get(o).openJump && stateOut.containsKey(o)) {
                jumps.add(o);
            }
        }
        if (jumps.isEmpty()) {
            return seeds;
        }
        boolean hasFrame = false;
        for (State st : stateIn.values()) {
            Long d = spDelta(st);
            if ((d == null ? 0 : d) < 0) {
                hasFrame = true;
                break;
            }
        }
        if (hasFrame) {
            jumps.removeIf(o -> {
                Long d = spDelta(stateIn.get(o));
                return d != null && d == 0;
            });
        }
        if (jumps.isEmpty()) {
            return seeds;
        }
        Set<Long> slots = new HashSet<>();
        for (int i = 0; i < insns.size(); i++) {
            int depth = decoded.get(insns.get(i)).delay;
            for (int j = i + 1; j < Math.min(insns.size(), i + 1 + depth); j++) {
                slots.add(insns.get(j));
            }
        }
        Set<Long> fallsInto = new HashSet<>();
        for (long o : insns) {
            Insn d = decoded.get(o);
            if (!slots.contains(o) && d.fallInBody != null) {
                fallsInto.add(d.fallInBody);
            }
        }
        long minJump = Long.MAX_VALUE;
        for (long j : jumps) {
            minJump = Math.min(minJump, j);
        }
        for (long o : insns) {
            if (stateIn.containsKey(o) || slots.contains(o) || fallsInto.contains(o)) {
                continue;
            }
            long src = Long.MIN_VALUE;
            for (long j : jumps) {
                if (j < o) {
                    src = Math.max(src, j);
                }
            }
            if (src == Long.MIN_VALUE) {
                src = minJump;
            }
            seeds.add(Map.entry(o, stateOut.get(src).copy()));
        }
        return seeds;
    }

    // -- prologue -----------------------------------------------------------------

    boolean isPrologueInsn(Instruction ins, State stIn) {
        State st = stIn.copy();
        step(st, ins.getAddress().getOffset());
        if (sideEffect) {
            return false;
        }
        boolean setup = false;
        Set<Key> keys = new LinkedHashSet<>(st.regs.keySet());
        keys.addAll(stIn.regs.keySet());
        for (Key k : keys) {
            if (k.isU() || (m.dwarfOf(k) == null && m.containers(k).isEmpty())) {
                continue;
            }
            Val before = stIn.regs.containsKey(k) ? stIn.regs.get(k) : defaultValue(k);
            Val after = st.regs.containsKey(k) ? st.regs.get(k) : defaultValue(k);
            if (java.util.Objects.equals(before, after)) {
                continue;
            }
            if (after != null && after.kind == Val.SP && (k.equals(m.spKey) || m.isPreserved(k))) {
                setup = true;
                continue;
            }
            if (m.raKey != null && Val.init(m.raKey).equals(after)) {
                setup = true;
                continue;
            }
            return false;
        }
        for (Map.Entry<Long, State.Slot> e : st.mem.entrySet()) {
            State.Slot s = e.getValue();
            if (s.equals(stIn.mem.get(e.getKey()))) {
                continue;
            }
            if (s.v == null || (s.v.kind != Val.INIT && s.v.kind != Val.SP)) {
                return false;
            }
            setup = true;
        }
        return setup;
    }

    /** Offset of the first instruction after the frame setup. */
    public long prologueEnd(long skip, Set<Long> body) {
        long entry = func.getEntryPoint().getOffset();
        long off = entry + skip;
        Address addr = func.getEntryPoint().add(skip);
        while (true) {
            State st = stateIn.get(off);
            Instruction ins = listing.getInstructionAt(addr);
            if (st == null || ins == null) {
                break;
            }
            FlowType ft = ins.getFlowType();
            if (ft.isJump() || ft.isCall() || ft.isTerminal() || ins.getDelaySlotDepth() > 0) {
                break;
            }
            if (body.contains(off) || !isPrologueInsn(ins, st)) {
                break;
            }
            Address nxt = ins.getFallThrough();
            if (nxt == null || !func.getBody().contains(nxt)) {
                break;
            }
            addr = nxt;
            off = nxt.getOffset();
        }
        return off;
    }

    /** Drops what only the worker-side analysis needs (out-states, the holder index). */
    public void releaseAnalysisState() {
        stateOut.clear();
        stateTaken.clear();
        holdersCache.clear();
    }

    // -- queries ------------------------------------------------------------------

    public long insnEnd(long off) {
        Integer len = insnLen.get(off);
        return off + (len != null ? len : 1);
    }

    public Val valueAfter(long off, Key key) {
        State st = stateOut.get(off);
        return st != null ? regValue(st, key) : null;
    }

    public Val valueBefore(long off, Key key) {
        State st = stateIn.get(off);
        return st != null ? regValue(st, key) : null;
    }

    /** Inverted index of a state, in the state's own order (cached). */
    static final class Holders {
        final Map<Val, List<Key>> regs = new HashMap<>();
        final Map<Val, List<Long>> mem = new HashMap<>();
    }

    private final IdentityHashMap<State, Holders> holdersCache = new IdentityHashMap<>();

    Holders holders(State st) {
        Holders h = holdersCache.get(st);
        if (h != null) {
            return h;
        }
        h = new Holders();
        for (Map.Entry<Key, Val> e : st.regs.entrySet()) {
            if (!e.getKey().isU()) {
                h.regs.computeIfAbsent(e.getValue(), x -> new ArrayList<>()).add(e.getKey());
            }
        }
        for (Map.Entry<Long, State.Slot> e : st.mem.entrySet()) {
            h.mem.computeIfAbsent(e.getValue().v, x -> new ArrayList<>()).add(e.getKey());
        }
        holdersCache.put(st, h);
        return h;
    }

    /** A place holding a value: a register (key) or a stack slot (SP offset). */
    public static final class Loc {
        public final Key reg;
        public final long stack;

        Loc(Key reg, long stack) {
            this.reg = reg;
            this.stack = stack;
        }

        public boolean isReg() {
            return reg != null;
        }
    }

    /**
     * All places holding value on entry to instruction off. With the
     * variable's size: also stack slots holding the value converted to a
     * float of that size; exact: only stack slots of that size.
     */
    public List<Loc> locationsOf(long off, Val value, int size, boolean exact) {
        List<Loc> out = new ArrayList<>();
        State st = stateIn.get(off);
        if (st == null || value == null) {
            return out;
        }
        Holders h = holders(st);
        List<Key> byVal = h.regs.get(value);
        if (byVal != null) {
            for (Key k : byVal) {
                out.add(new Loc(k, 0));
            }
        }
        Key vkey = value.originKey();
        if (vkey != null && vkey.isReg()) {
            for (Key c : m.containers(vkey)) {
                if (!isLowPart(vkey, c)) {
                    continue;
                }
                Val wide = rekey(value, c);
                List<Key> ks = h.regs.get(wide);
                if (ks != null) {
                    for (Key k : ks) {
                        if (k.size == c.size) {
                            long lo = k.off + (m.bigEndian ? k.size - vkey.size : 0);
                            out.add(new Loc(Key.reg(lo, vkey.size), 0));
                        }
                    }
                }
                if (wide.equals(Val.init(c)) && !st.regs.containsKey(c) && wide.equals(regValue(st, c))) {
                    long lo = c.off + (m.bigEndian ? c.size - vkey.size : 0);
                    out.add(new Loc(Key.reg(lo, vkey.size), 0));
                }
            }
        }
        if (value.kind == Val.INIT && !st.regs.containsKey(value.key) && value.key.isReg()) {
            if (value.equals(regValue(st, value.key))) {
                out.add(new Loc(value.key, 0));
            }
        }
        List<Long> slots = h.mem.get(value);
        if (slots != null) {
            for (long o : slots) {
                if (!(exact && size != 0 && st.mem.get(o).size != size)) {
                    out.add(new Loc(null, o));
                }
            }
        }
        if (size != 0) {
            List<Long> cs = h.mem.get(Val.cvt(value, size));
            if (cs != null) {
                for (long o : cs) {
                    out.add(new Loc(null, o));
                }
            }
        }
        return out;
    }
}
