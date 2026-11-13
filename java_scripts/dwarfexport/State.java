package dwarfexport;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Abstract machine state on entry to (or after) an instruction. The maps keep
 * insertion order, as Python dicts do (some lookups take "the first in the
 * state's order"); a null register value means unknown.
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

    public LinkedHashMap<Key, Val> regs;
    public LinkedHashMap<Long, Slot> mem;
    public LinkedHashMap<Key, Long> saved;
    /** Lowest SP offset whose address escaped (null: none). */
    public Long esc;

    public State() {
        this(new LinkedHashMap<>(), new LinkedHashMap<>(), new LinkedHashMap<>(), null);
    }

    public State(LinkedHashMap<Key, Val> regs, LinkedHashMap<Long, Slot> mem, LinkedHashMap<Key, Long> saved,
            Long esc) {
        this.regs = regs;
        this.mem = mem;
        this.saved = saved;
        this.esc = esc;
    }

    public State copy() {
        return new State(new LinkedHashMap<>(regs), new LinkedHashMap<>(mem), new LinkedHashMap<>(saved), esc);
    }

    public void assign(State o) {
        regs = o.regs;
        mem = o.mem;
        saved = o.saved;
        esc = o.esc;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof State)) {
            return false;
        }
        State s = (State) o;
        return regs.equals(s.regs) && mem.equals(s.mem) && saved.equals(s.saved) && Objects.equals(esc, s.esc);
    }

    @Override
    public int hashCode() {
        return regs.hashCode();
    }

    public static Long minEsc(Long a, Long b) {
        return a == null ? b : (b == null ? a : Long.valueOf(Math.min(a, b)));
    }

    /** The format of the comparison dump (test/flow_dump.py). */
    public String dump() {
        StringBuilder sb = new StringBuilder("R{");
        for (Map.Entry<Key, Val> e : regs.entrySet()) {
            sb.append(e.getKey()).append('=').append(Val.str(e.getValue())).append(';');
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
