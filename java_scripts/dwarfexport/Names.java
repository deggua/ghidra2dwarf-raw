package dwarfexport;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;

import ghidra.program.database.data.PointerTypedefInspector;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

/** Name handling and data type classification (helpers of ghidra_export.py). */
public final class Names {
    private Names() {
    }

    static final Set<String> C_KEYWORDS = Set.of(("auto break case char const continue default do double " +
        "else enum extern float for goto if inline int long register restrict return " +
        "short signed sizeof static struct switch typedef union unsigned void volatile " +
        "while _Bool _Complex _Alignas _Alignof _Atomic _Generic _Noreturn " +
        "_Static_assert _Thread_local").split(" "));

    static final Set<String> C_TYPE_WORDS =
        Set.of("void char short int long float double signed unsigned _Bool _Complex bool".split(" "));

    /** A name filter with a cache of its results (see Options.sanitize_names). */
    public static final class NameFilter implements UnaryOperator<String> {
        final boolean sanitize, forTypes;
        /** name -> exported name, in first-use order. */
        public final Map<String, String> cache = new LinkedHashMap<>();

        NameFilter(boolean sanitize, boolean forTypes) {
            this.sanitize = sanitize;
            this.forTypes = forTypes;
        }

        @Override
        public synchronized String apply(String name) {
            String out = cache.get(name);
            if (out == null) {
                out = compute(name);
                cache.put(name, out);
            }
            return out;
        }

        private String compute(String name) {
            if (!sanitize) {
                String s = replaceCodePoints(name, false);
                return s.isEmpty() ? "_" : s;
            }
            String[] words = pySplit(name);
            if (forTypes && words.length > 0) {
                boolean all = true;
                for (String w : words) {
                    if (!C_TYPE_WORDS.contains(w)) {
                        all = false;
                        break;
                    }
                }
                if (all) {
                    return String.join(" ", words);
                }
            }
            String out = replaceCodePoints(name, true);
            if (out.isEmpty()) {
                out = "_";
            }
            if (Character.isDigit(out.charAt(0))) {
                out = "_" + out;
            }
            if (C_KEYWORDS.contains(out)) {
                out += "_";
            }
            return out;
        }
    }

    /** Python str.split(): on runs of whitespace, no empty words. */
    static String[] pySplit(String s) {
        String t = s.strip();
        return t.isEmpty() ? new String[0] : t.split("\\s+");
    }

    /**
     * Each code point that may not appear becomes '_' (all but [A-Za-z0-9_]
     * when sanitizing, else ' and control characters).
     */
    static String replaceCodePoints(String s, boolean any) {
        StringBuilder sb = new StringBuilder(s.length());
        s.codePoints().forEach(cp -> {
            boolean bad;
            if (any) {
                bad = !((cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z') || (cp >= '0' && cp <= '9') || cp == '_');
            }
            else {
                bad = cp == '\'' || cp <= 0x1f || cp == 0x7f;
            }
            if (bad) {
                sb.append('_');
            }
            else {
                sb.appendCodePoint(cp);
            }
        });
        return sb.toString();
    }

    public static NameFilter makeNameFilter(boolean sanitize, boolean forTypes) {
        return new NameFilter(sanitize, forTypes);
    }

    /** Name as the decompiler prints it: namespace-qualified unless global. */
    public static String qualified(Symbol s) {
        Namespace ns = s.getParentNamespace();
        if (ns == null || ns.isGlobal()) {
            return s.getName();
        }
        return s.getName(true);
    }

    public static String qualified(Function f) {
        Namespace ns = f.getParentNamespace();
        if (ns == null || ns.isGlobal()) {
            return f.getName();
        }
        return f.getName(true);
    }

    /** Pointer typedefs with settings DWARF cannot express. */
    static boolean isSpecialPointerTypedef(DataType dt) {
        try {
            TypeDef td = (TypeDef) dt;
            if (PointerTypedefInspector.getPointerComponentOffset(td) != 0) {
                return true;
            }
            if (PointerTypedefInspector.hasPointerBitShift(td) || PointerTypedefInspector.hasPointerBitMask(td)) {
                return true;
            }
            if (PointerTypedefInspector.getPointerType(td) != PointerType.DEFAULT) {
                return true;
            }
            DataTypeManager dtm = dt.getDataTypeManager();
            Program prog = dtm instanceof ProgramBasedDataTypeManager
                    ? ((ProgramBasedDataTypeManager) dtm).getProgram() : null;
            if (prog != null) {
                AddressSpace space = PointerTypedefInspector.getPointerAddressSpace(td, prog.getAddressFactory());
                if (space != null && !space.equals(prog.getAddressFactory().getDefaultAddressSpace())) {
                    return true;
                }
            }
        }
        catch (Exception e) {
            return false;
        }
        return false;
    }

    public static String sanitizeBasename(String name) {
        StringBuilder sb = new StringBuilder();
        name.codePoints().forEach(cp -> {
            if (Character.isLetterOrDigit(cp) || cp == '-' || cp == '_' || cp == '.') {
                sb.appendCodePoint(cp);
            }
            else {
                sb.append('_');
            }
        });
        return sb.length() > 0 ? sb.toString() : "program";
    }

    /** Character type of a C-style string data item (null for other data). */
    static DataType stringCharType(Data data) {
        DataType dt = data.getDataType();
        if (dt == null || dt.getClass().getSimpleName().contains("Pascal")) {
            return null;
        }
        StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
        if (sdi == null || sdi == StringDataInstance.NULL_INSTANCE) {
            return null;
        }
        switch (charsetUnit(sdi.getCharsetName())) {
            case 1:
                return CharDataType.dataType;
            case 2:
                return WideChar16DataType.dataType;
            case 4:
                return WideChar32DataType.dataType;
            default:
                return null;
        }
    }

    static int charsetUnit(String cs) {
        cs = cs.toUpperCase();
        if (cs.contains("32") && (cs.contains("UTF") || cs.contains("UCS"))) {
            return 4;
        }
        if (cs.contains("16") || cs.startsWith("UCS-2")) {
            return 2;
        }
        return 1;
    }

    public static String classify(DataType dt) {
        if (dt == null) {
            return "void";
        }
        if (dt instanceof BitFieldDataType) {
            return "bitfield";
        }
        if (dt instanceof Pointer) {
            return "ptr";
        }
        if (dt instanceof TypeDef) {
            if (((TypeDef) dt).getBaseDataType() instanceof Pointer && isSpecialPointerTypedef(dt)) {
                return "rawptr";
            }
            return "typedef";
        }
        if (dt instanceof Structure) {
            return "struct";
        }
        if (dt instanceof Union) {
            return "union";
        }
        if (dt instanceof ghidra.program.model.data.Enum) {
            return "enum";
        }
        if (dt instanceof Array) {
            return "array";
        }
        if (dt instanceof FunctionDefinition) {
            return "func";
        }
        if (dt instanceof VoidDataType) {
            return "void";
        }
        if (dt instanceof BooleanDataType || dt instanceof AbstractIntegerDataType ||
            dt instanceof AbstractFloatDataType || dt instanceof AbstractComplexDataType || dt instanceof Undefined ||
            dt instanceof DefaultDataType || dt instanceof CharDataType || dt instanceof WideCharDataType ||
            dt instanceof WideChar16DataType || dt instanceof WideChar32DataType) {
            return dt.getLength() > 0 ? "base" : "void";
        }
        if (dt.getLength() > 0) {
            return "blob";
        }
        return "void";
    }
}
