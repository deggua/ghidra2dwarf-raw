package dwarfexport;

import java.math.BigInteger;

/**
 * An abstract value id of the flow analysis (immutable, structural equality):
 * <ul>
 * <li>SP(delta): an address relative to the entry SP</li>
 * <li>INIT(key): a register's value at function entry</li>
 * <li>DEF(addr, key): whatever instruction addr wrote to key</li>
 * <li>PHI(join, key): a merge of different values at a join</li>
 * <li>CONST(value, size): a known constant (the exact integer: a long, or a
 * BigInteger when it doesn't fit, as Python's unbounded ints)</li>
 * <li>CVT(inner, size): inner converted to a float of size bytes</li>
 * </ul>
 */
public final class Val {
    public static final int SP = 0, INIT = 1, DEF = 2, PHI = 3, CONST = 4, CVT = 5;
    private static final String[] TAG = {"sp", "init", "def", "phi", "const", "cvt"};

    public final int kind;
    public final long n;           // SP delta, DEF address, CONST value (if big == null), CVT size
    public final int size;         // CONST size
    public final Key key;          // INIT/DEF/PHI
    public final Join join;        // PHI
    public final BigInteger big;   // CONST value outside the long range
    public final Val inner;        // CVT
    private final int hash;

    private Val(int kind, long n, int size, Key key, Join join, BigInteger big, Val inner) {
        this.kind = kind;
        this.n = n;
        this.size = size;
        this.key = key;
        this.join = join;
        this.big = big;
        this.inner = inner;
        int h = kind;
        h = h * 31 + Long.hashCode(n);
        h = h * 31 + size;
        h = h * 31 + (key == null ? 0 : key.hashCode());
        h = h * 31 + (join == null ? 0 : join.hashCode());
        h = h * 31 + (big == null ? 0 : big.hashCode());
        h = h * 31 + (inner == null ? 0 : inner.hashCode());
        this.hash = h;
    }

    public static Val sp(long delta) {
        return new Val(SP, delta, 0, null, null, null, null);
    }

    public static Val init(Key k) {
        return new Val(INIT, 0, 0, k, null, null, null);
    }

    public static Val def(long addr, Key k) {
        return new Val(DEF, addr, 0, k, null, null, null);
    }

    public static Val phi(Join j, Key k) {
        return new Val(PHI, 0, 0, k, j, null, null);
    }

    public static Val cnst(long v, int size) {
        return new Val(CONST, v, size, null, null, null, null);
    }

    /** A constant from an exact integer (long when it fits). */
    public static Val cnst(BigInteger v, int size) {
        if (v.bitLength() < 64) {
            return new Val(CONST, v.longValue(), size, null, null, null, null);
        }
        return new Val(CONST, 0, size, null, null, v, null);
    }

    public static Val cvt(Val inner, int size) {
        return new Val(CVT, size, 0, null, null, null, inner);
    }

    /** The exact value of a CONST. */
    public BigInteger bigValue() {
        return big != null ? big : BigInteger.valueOf(n);
    }

    public boolean isConstZero() {
        return kind == CONST && big == null && n == 0;
    }

    /** The key of INIT/DEF/PHI values (Python: value[1] or value[2]). */
    public Key originKey() {
        return (kind == INIT || kind == DEF || kind == PHI) ? key : null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Val)) {
            return false;
        }
        Val v = (Val) o;
        if (v.hash != hash || v.kind != kind) {
            return false;
        }
        switch (kind) {
            case SP:
                return v.n == n;
            case INIT:
                return v.key.equals(key);
            case DEF:
                return v.n == n && v.key.equals(key);
            case PHI:
                return v.join.equals(join) && v.key.equals(key);
            case CONST:
                return v.size == size && v.n == n && java.util.Objects.equals(v.big, big);
            default:
                return v.n == n && v.inner.equals(inner);
        }
    }

    @Override
    public int hashCode() {
        return hash;
    }

    @Override
    public String toString() {
        switch (kind) {
            case SP:
                return "(sp," + n + ")";
            case INIT:
                return "(init," + key + ")";
            case DEF:
                return "(def," + n + "," + key + ")";
            case PHI:
                return "(phi," + join + "," + key + ")";
            case CONST:
                return "(const," + (big != null ? big.toString() : Long.toString(n)) + "," + size + ")";
            default:
                return "(" + TAG[kind] + "," + inner + "," + n + ")";
        }
    }

    public static String str(Val v) {
        return v == null ? "N" : v.toString();
    }

    /**
     * Where a PHI was created: an instruction offset (a join of the control
     * flow) or a point inside an instruction's p-code (index, or NEXT for its
     * fall-through).
     */
    public static final class Join {
        public static final int NEXT = -1;
        public final long off;
        public final boolean pcode;
        public final int idx;

        private Join(long off, boolean pcode, int idx) {
            this.off = off;
            this.pcode = pcode;
            this.idx = idx;
        }

        public static Join at(long off) {
            return new Join(off, false, 0);
        }

        public static Join pcode(long off, int idx) {
            return new Join(off, true, idx);
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Join)) {
                return false;
            }
            Join j = (Join) o;
            return j.off == off && j.pcode == pcode && j.idx == idx;
        }

        @Override
        public int hashCode() {
            return Long.hashCode(off) * 31 + (pcode ? 7 + idx : 0);
        }

        @Override
        public String toString() {
            if (!pcode) {
                return Long.toString(off);
            }
            return "(pcode," + off + "," + (idx == NEXT ? "next" : Integer.toString(idx)) + ")";
        }
    }
}
