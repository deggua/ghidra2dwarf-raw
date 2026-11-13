package dwarfexport;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Abstract machine state on entry to (or after) an instruction: register
 * values in an array indexed by the machine's register key ids (ABSENT: not
 * in the state; null: unknown), p-code temporaries, stack slots (in the order
 * they were stored: CFI takes the first slot holding a saved register), the
 * registers saved for the caller, and the lowest escaped stack offset.
 */
public final class State {
    /** A stack slot: its size and value (null: unknown). */
    public static final class Slot {
        public final int size;
        public final Val v;

        public Slot(int size, Val v) {
            this.size = size;
            this.v = v;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Slot)) {
                return false;
            }
            Slot s = (Slot) o;
            return s.size == size && Objects.equals(s.v, v);
        }

        @Override
        public int hashCode() {
            return size * 31 + Objects.hashCode(v);
        }

        @Override
        public String toString() {
            return "(" + size + "," + Val.str(v) + ")";
        }
    }

    /** Marks a register that isn't in the state (its value derives from others or its default). */
    public static final Val ABSENT = Val.sp(Long.MIN_VALUE);
    private static final Val[] EMPTY = new Val[0];

    /** Register values by key id; entries past the end are ABSENT. */
    Val[] r;
    /** p-code temporaries (null: none). */
    HashMap<Key, Val> u;
    public LinkedHashMap<Long, Slot> mem;
    public LinkedHashMap<Key, Long> saved;
    /** Lowest SP offset whose address escaped (null: none). */
    public Long esc;

    public State() {
        this(EMPTY, null, new LinkedHashMap<>(), new LinkedHashMap<>(), null);
    }

    State(Val[] r, HashMap<Key, Val> u, LinkedHashMap<Long, Slot> mem, LinkedHashMap<Key, Long> saved, Long esc) {
        this.r = r;
        this.u = u;
        this.mem = mem;
        this.saved = saved;
        this.esc = esc;
    }

    public State copy() {
        return new State(r.clone(), u != null ? new HashMap<>(u) : null, new LinkedHashMap<>(mem),
            new LinkedHashMap<>(saved), esc);
    }

    public void assign(State o) {
        r = o.r;
        u = o.u;
        mem = o.mem;
        saved = o.saved;
        esc = o.esc;
    }

    // -- registers by id ---------------------------------------------------------

    public Val get(int id) {
        return id < r.length ? r[id] : ABSENT;
    }

    public boolean has(int id) {
        return id < r.length && r[id] != ABSENT;
    }

    public void put(int id, Val v) {
        if (id >= r.length) {
            int old = r.length;
            r = Arrays.copyOf(r, Math.max(id + 1, old * 2 + 8));
            Arrays.fill(r, old, r.length, ABSENT);
        }
        r[id] = v;
    }

    public void remove(int id) {
        if (id < r.length) {
            r[id] = ABSENT;
        }
    }

    /** One past the highest id that may be present. */
    public int idLimit() {
        return r.length;
    }

    // -- registers by key (for callers outside the analysis) ---------------------

    public boolean has(MachineInfo m, Key k) {
        return has(m.keys.id(k));
    }

    /** The register's value (null: unknown or not in the state). */
    public Val get(MachineInfo m, Key k) {
        Val v = get(m.keys.id(k));
        return v == ABSENT ? null : v;
    }

    public void put(MachineInfo m, Key k, Val v) {
        put(m.keys.id(k), v);
    }

    // -- temporaries ---------------------------------------------------------------

    Val getU(Key k) {
        return u != null ? u.get(k) : null;
    }

    boolean hasU(Key k) {
        return u != null && u.containsKey(k);
    }

    void putU(Key k, Val v) {
        if (u == null) {
            u = new HashMap<>();
        }
        u.put(k, v);
    }

    void clearU() {
        u = null;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof State)) {
            return false;
        }
        State s = (State) o;
        int n = Math.max(r.length, s.r.length);
        for (int i = 0; i < n; i++) {
            Val a = get(i), b = s.get(i);
            if (a != b && (a == null || !a.equals(b))) {
                return false;
            }
        }
        Map<Key, Val> ua = u != null ? u : Map.of(), ub = s.u != null ? s.u : Map.of();
        return ua.equals(ub) && mem.equals(s.mem) && saved.equals(s.saved) && Objects.equals(esc, s.esc);
    }

    @Override
    public int hashCode() {
        return mem.hashCode();
    }

    public static Long minEsc(Long a, Long b) {
        return a == null ? b : (b == null ? a : Long.valueOf(Math.min(a, b)));
    }

    /** A readable dump (debugging). */
    public String dump(MachineInfo m) {
        StringBuilder sb = new StringBuilder("R{");
        for (int i = 0; i < r.length; i++) {
            if (r[i] != ABSENT) {
                sb.append(m.keys.key(i)).append('=').append(Val.str(r[i])).append(';');
            }
        }
        if (u != null) {
            for (Map.Entry<Key, Val> e : u.entrySet()) {
                sb.append(e.getKey()).append('=').append(Val.str(e.getValue())).append(';');
            }
        }
        sb.append("}M{");
        for (Map.Entry<Long, Slot> e : mem.entrySet()) {
            sb.append(e.getKey()).append('=').append(e.getValue()).append(';');
        }
        sb.append("}S{");
        for (Map.Entry<Key, Long> e : saved.entrySet()) {
            sb.append(e.getKey()).append('=').append(e.getValue()).append(';');
        }
        sb.append("}E").append(esc == null ? "N" : esc.toString());
        return sb.toString();
    }
}
