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

    private static final ConcurrentHashMap<Integer, Character> SPACE_KIND = new ConcurrentHashMap<>();
    private static final Vn OTHER = new Vn('x', 0, 0);

    private Vn(char kind, long off, int size) {
        this.kind = kind;
        this.off = off;
        this.size = size;
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
        return Key.reg(off, size);
    }

    public Key uKey() {
        return Key.u(off, size);
    }
}
