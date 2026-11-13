package dwarfexport;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import java.util.LinkedHashMap;
import java.util.function.Consumer;

import ghidra.app.util.bin.format.dwarf.DWARFRegisterMappings;
import ghidra.app.util.bin.format.dwarf.DWARFRegisterMappingsManager;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

/** Finds the DWARF register containing a register-space varnode. */
public final class RegisterIndex {
    /** (offset, size, dwarf number), sorted. */
    public static final class Entry {
        public final long start;
        public final int size;
        public final int num;

        Entry(long start, int size, int num) {
            this.start = start;
            this.size = size;
            this.num = num;
        }
    }

    public final List<Entry> entries = new ArrayList<>();

    public RegisterIndex(Language lang, Map<String, Integer> regmap) {
        for (Map.Entry<String, Integer> e : regmap.entrySet()) {
            Register reg = lang.getRegister(e.getKey());
            if (reg == null) {
                continue;
            }
            entries.add(new Entry(reg.getAddress().getOffset(), reg.getMinimumByteSize(), e.getValue()));
        }
        entries.sort((a, b) -> a.start != b.start ? Long.compare(a.start, b.start)
                : a.size != b.size ? Integer.compare(a.size, b.size) : Integer.compare(a.num, b.num));
    }

    /** GDB/GCC DWARF numbering for (32/64-bit) PowerPC. */
    static Map<String, Integer> ppcRegisterMap() {
        Map<String, Integer> m = new LinkedHashMap<>();
        for (int i = 0; i < 32; i++) {
            m.put("r" + i, i);
            m.put("f" + i, 32 + i);
            m.put("vr" + i, 1124 + i);
        }
        m.put("LR", 65);
        m.put("CTR", 66);
        m.put("XER", 76);
        return m;
    }

    /** {Ghidra register name: DWARF number}; sp[0] = the SP's number (or null). */
    public static Map<String, Integer> buildRegisterMap(Language lang, Integer[] sp, Consumer<String> log) {
        String proc = lang.getProcessor().toString();
        Map<String, Integer> names = new LinkedHashMap<>();
        sp[0] = null;
        try {
            DWARFRegisterMappings mapping = DWARFRegisterMappingsManager.getMappingForLang(lang);
            sp[0] = mapping.getDWARFStackPointerRegNum();
            for (int i = 0; i < 1300; i++) {
                Register reg = mapping.getGhidraReg(i);
                if (reg != null) {
                    names.putIfAbsent(reg.getName(), i);
                }
            }
        }
        catch (Exception e) {
            log.accept("WARNING: no DWARF register mapping for " + lang.getLanguageID() + " (" + e +
                "); register variables will have no location");
        }
        if (proc.equals("PowerPC")) {
            names = ppcRegisterMap();
            sp[0] = 1;
        }
        return names;
    }

    /**
     * The smallest mapped register fully containing [offset, offset+size):
     * {dwarf number, register offset, register size}, or null.
     */
    public long[] lookup(long offset, int size) {
        long[] best = null;
        for (Entry e : entries) {
            if (e.start > offset) {
                break;
            }
            if (offset + size <= e.start + e.size) {
                if (best == null || e.size < best[2]) {
                    best = new long[] {e.num, e.start, e.size};
                }
            }
        }
        return best;
    }
}
