package dwarfexport;

import java.util.concurrent.ConcurrentHashMap;

import ghidra.program.model.pcode.Varnode;

/**
 * A p-code varnode decoded once: kind 'c' (constant), 'r' (register), 'u'
 * (unique), 'a' (memory: branch targets) or 'x' (other spaces), with offset
 * and size.
 */
public final class Vn {
    public final char kind;
    public final long off;
    public final int size;
    /** The register or temporary key ('r', 'u'), else null. */
    public final Key key;
    /** The register's id in a MachineInfo key table (-1: not resolved yet). */
    private volatile int id = -1;

    private static final ConcurrentHashMap<Integer, Character> SPACE_KIND = new ConcurrentHashMap<>();
    private static final Vn OTHER = new Vn('x', 0, 0);

    private Vn(char kind, long off, int size) {
        this.kind = kind;
        this.off = off;
        this.size = size;
        this.key = kind == 'r' ? Key.reg(off, size) : kind == 'u' ? Key.u(off, size) : null;
    }

    /** The register's key id (kind 'r'). */
    public int id(MachineInfo m) {
        int i = id;
        if (i < 0) {
            i = id = m.keys.id(key);
        }
        return i;
    }

    public static void resetSpaces() {
        SPACE_KIND.clear();
    }

    public static Vn decode(Varnode vn) {
        if (vn == null) {
            return null;
        }
        int sid = vn.getSpace();
        Character kind = SPACE_KIND.get(sid);
        if (kind == null) {
            if (vn.isConstant()) {
                kind = 'c';
            }
            else if (vn.isRegister()) {
                kind = 'r';
            }
            else if (vn.isUnique()) {
                kind = 'u';
            }
            else if (vn.getAddress().isMemoryAddress()) {
                kind = 'a';
            }
            else {
                kind = 'x';
            }
            SPACE_KIND.put(sid, kind);
        }
        if (kind == 'x') {
            return OTHER;
        }
        return new Vn(kind, vn.getOffset(), vn.getSize());
    }

    /** Python: len(vn) > 2 (has a size). */
    public boolean sized() {
        return kind != 'x';
    }

    public Key regKey() {
        return key;
    }

    public Key uKey() {
        return key;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Vn)) {
            return false;
        }
        Vn v = (Vn) o;
        return v.kind == kind && v.off == off && v.size == size;
    }

    @Override
    public int hashCode() {
        return kind * 31 + Long.hashCode(off) * 17 + size;
    }
}
