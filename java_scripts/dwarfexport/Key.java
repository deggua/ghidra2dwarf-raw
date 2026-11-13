package dwarfexport;

/**
 * A location key of the flow analysis: a register's bytes (offset, size), a
 * p-code temporary ("u", offset, size), the return address slot ("ra",) or a
 * stack slot of a merge ("m", offset). Immutable, structural equality.
 */
public final class Key implements Comparable<Key> {
    public static final int REG = 0, U = 1, RA = 2, MEM = 3;

    public final int kind;
    public final long off;
    public final int size;
    private final int hash;

    private Key(int kind, long off, int size) {
        this.kind = kind;
        this.off = off;
        this.size = size;
        this.hash = (int) (kind * 31 + off * 1000003 + size);
    }

    public static Key reg(long off, int size) {
        return new Key(REG, off, size);
    }

    public static Key u(long off, int size) {
        return new Key(U, off, size);
    }

    public static final Key RA_KEY = new Key(RA, 0, 0);

    public static Key mem(long off) {
        return new Key(MEM, off, 0);
    }

    public boolean isReg() {
        return kind == REG;
    }

    public boolean isU() {
        return kind == U;
    }

    /** Do the register bytes overlap? (REG keys) */
    public boolean overlaps(Key o) {
        return o.off < off + size && off < o.off + o.size;
    }

    /** Is o inside this register's bytes? */
    public boolean contains(Key o) {
        return off <= o.off && o.off + o.size <= off + size;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Key)) {
            return false;
        }
        Key k = (Key) o;
        return k.kind == kind && k.off == off && k.size == size;
    }

    @Override
    public int hashCode() {
        return hash;
    }

    /** Python tuple order for register keys (off, size). */
    @Override
    public int compareTo(Key o) {
        if (kind != o.kind) {
            return Integer.compare(kind, o.kind);
        }
        if (off != o.off) {
            return Long.compare(off, o.off);
        }
        return Integer.compare(size, o.size);
    }

    @Override
    public String toString() {
        switch (kind) {
            case REG:
                return "(" + off + "," + size + ")";
            case U:
                return "(u," + off + "," + size + ")";
            case RA:
                return "(ra)";
            default:
                return "(m," + off + ")";
        }
    }
}
