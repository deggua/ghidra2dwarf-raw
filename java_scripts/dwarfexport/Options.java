package dwarfexport;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Exporter options; all can be passed as key=value script arguments (see README). */
public final class Options {
    /** Added to every address. */
    public long address_offset = 0;
    /** Put the bytes of initialized memory blocks in the ELF (PROGBITS). */
    public boolean embed_bytes = false;
    /** Write the program's data types as C to basename.types.h. */
    public boolean types_header = true;
    /** Emit DWARF for every structure/union/enum/typedef. */
    public boolean all_types = true;
    /** Synthesize .debug_frame from p-code. */
    public boolean cfi = true;
    /** Per-function decompiler timeout in seconds. */
    public long decompile_timeout = 60;
    /** Output base name (default: program name). */
    public String basename = null;
    /** Rewrite every exported name into a plain C identifier. */
    public boolean sanitize_names = false;
    /** (internal) split executable blocks into code/data sections. */
    public boolean split_sections = true;
    /** (internal) GCC-style double rows at frameless function entries. */
    public boolean frameless_rows = true;
    /** Mark interrupt handler frames as signal frames (CIE augmentation "S"). */
    public boolean irq_signal_frame = true;
    /** Start a new .c file beyond this many bytes (0: no limit). */
    public long c_max_bytes = 100000;
    /** The same limit in lines. */
    public long c_max_lines = 100000;
    /** Decompiler worker threads; -1 = min(8, CPUs - 1). */
    public long decompile_threads = -1;
    /** ELF header e_flags; -1 = derive. */
    public long elf_flags = -1;
    /** Comma-separated function names (or entry addresses) not to decompile. */
    public String skip_decompile = "";

    /** The options not shown in the GUI dialog. */
    public static final List<String> INTERNAL = List.of("split_sections", "frameless_rows");

    /** Valid ranges of the numeric options (null: unbounded). */
    static final Map<String, BigInteger[]> RANGES = new LinkedHashMap<>();
    static {
        BigInteger two64 = BigInteger.ONE.shiftLeft(64);
        RANGES.put("address_offset", new BigInteger[] {two64.negate().add(BigInteger.ONE), two64.subtract(BigInteger.ONE)});
        RANGES.put("decompile_timeout", new BigInteger[] {BigInteger.ONE, null});
        RANGES.put("c_max_bytes", new BigInteger[] {BigInteger.ZERO, null});
        RANGES.put("c_max_lines", new BigInteger[] {BigInteger.ZERO, null});
        RANGES.put("decompile_threads", new BigInteger[] {BigInteger.valueOf(-1), BigInteger.valueOf(256)});
        RANGES.put("elf_flags", new BigInteger[] {BigInteger.valueOf(-1), BigInteger.valueOf(0xffffffffL)});
    }

    /** The option names, in declaration order. */
    public static List<String> names() {
        List<String> out = new ArrayList<>();
        for (Field f : Options.class.getFields()) {
            if (!java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                out.add(f.getName());
            }
        }
        return out;
    }

    public boolean has(String key) {
        return names().contains(key);
    }

    public Object get(String key) {
        try {
            return Options.class.getField(key).get(this);
        }
        catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException("unknown option '" + key + "'");
        }
    }

    public Class<?> type(String key) {
        try {
            return Options.class.getField(key).getType();
        }
        catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException("unknown option '" + key + "'");
        }
    }

    /** Python int(s, 0): decimal, 0x hex, 0o octal, 0b binary, with sign and underscores. */
    static BigInteger parseInt(String s) {
        String t = s.trim().replace("_", "");
        boolean neg = false;
        if (t.startsWith("-") || t.startsWith("+")) {
            neg = t.startsWith("-");
            t = t.substring(1);
        }
        String lower = t.toLowerCase();
        BigInteger v;
        if (lower.startsWith("0x")) {
            v = new BigInteger(t.substring(2), 16);
        }
        else if (lower.startsWith("0o")) {
            v = new BigInteger(t.substring(2), 8);
        }
        else if (lower.startsWith("0b")) {
            v = new BigInteger(t.substring(2), 2);
        }
        else {
            if (t.length() > 1 && t.startsWith("0") && !t.matches("0+")) {
                throw new NumberFormatException("invalid literal: " + s);
            }
            v = new BigInteger(t);
        }
        return neg ? v.negate() : v;
    }

    public void set(String key, String value) {
        Field f;
        try {
            f = Options.class.getField(key);
        }
        catch (NoSuchFieldException e) {
            throw new IllegalArgumentException("unknown option '" + key + "'");
        }
        try {
            if (f.getType() == boolean.class) {
                String v = value.toLowerCase();
                f.setBoolean(this, v.equals("1") || v.equals("true") || v.equals("yes") || v.equals("on"));
            }
            else if (f.getType() == long.class) {
                BigInteger v = parseInt(value);
                BigInteger[] r = RANGES.get(key);
                if (r != null && ((r[0] != null && v.compareTo(r[0]) < 0) || (r[1] != null && v.compareTo(r[1]) > 0))) {
                    throw new IllegalArgumentException(String.format("%s must be in %s..%s, not %s", key, r[0],
                        r[1] == null ? "" : r[1], v));
                }
                f.setLong(this, v.longValue());
            }
            else if (key.equals("basename")) {
                if (value.isEmpty() || value.contains("/") || value.contains("\\") || value.equals(".") ||
                    value.equals("..")) {
                    throw new IllegalArgumentException("a file name without directories is needed, not '" + value + "'");
                }
                f.set(this, value);
            }
            else {
                f.set(this, value);
            }
        }
        catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }
}
