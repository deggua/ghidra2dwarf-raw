package dwarfexport;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;

import dwarfexport.DwarfBuilder.Die;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

/**
 * Converts Ghidra DataTypes to DWARF type DIEs (deduplicated). DIEs are
 * created as shells and filled from a work list (see ghidra_export.py).
 */
public final class TypeBuilder {
    static final class Entry {
        final String kind;
        final Die die;
        final DataType dt;

        Entry(String kind, Die die, DataType dt) {
            this.kind = kind;
            this.die = die;
            this.dt = dt;
        }
    }

    final DwarfBuilder dw;
    final Die cu;
    final Program program;
    final DataTypeManager dtm;
    final int ptrSize;
    final boolean bigEndian;
    /** (kind, path, length) -> entry, in creation order. */
    final LinkedHashMap<String, Entry> cache = new LinkedHashMap<>();
    final List<Entry> pending = new ArrayList<>();
    public UnaryOperator<String> typeNameFilter;
    private Map<Integer, Die> code;

    public TypeBuilder(DwarfBuilder dw, Program program) {
        this.dw = dw;
        this.cu = dw.cu;
        this.program = program;
        this.dtm = program.getDataTypeManager();
        this.ptrSize = program.getDefaultPointerSize();
        this.bigEndian = program.getLanguage().isBigEndian();
    }

    void tname(Die die, String name) {
        if (typeNameFilter != null) {
            name = typeNameFilter.apply(name);
        }
        dw.name(die, name, true);
    }

    public void ref(Die die, DataType dt) {
        Die t = get(dt);
        if (t != null) {
            die.add(C.DW_AT_type, C.DW_FORM_ref4, t);
        }
    }

    static int tagOf(String kind) {
        switch (kind) {
            case "ptr":
                return C.DW_TAG_pointer_type;
            case "typedef":
            case "blob":
            case "rawptr":
                return C.DW_TAG_typedef;
            case "struct":
                return C.DW_TAG_structure_type;
            case "union":
                return C.DW_TAG_union_type;
            case "enum":
                return C.DW_TAG_enumeration_type;
            case "array":
                return C.DW_TAG_array_type;
            case "func":
                return C.DW_TAG_subroutine_type;
            default:
                return C.DW_TAG_base_type;
        }
    }

    public Die get(DataType dt) {
        String kind = Names.classify(dt);
        if (kind.equals("void") || kind.equals("bitfield")) {
            return null;
        }
        String key = kind + "\u0000" + dt.getPathName() + "\u0000" + dt.getLength();
        Entry e = cache.get(key);
        if (e != null) {
            return e.die;
        }
        Die die = cu.child(tagOf(kind));
        e = new Entry(kind, die, dt);
        cache.put(key, e);
        pending.add(e);
        return die;
    }

    String nameOf(DataType dt) {
        String n = dt.getName();
        return typeNameFilter != null ? typeNameFilter.apply(n) : n;
    }

    /** "typedef struct msg msg;" for each tag name no typedef already has. */
    public void addTagTypedefs() {
        Set<String> taken = new HashSet<>();
        for (Entry e : cache.values()) {
            if (e.kind.equals("typedef") || e.kind.equals("blob") || e.kind.equals("rawptr") || e.kind.equals("base")) {
                taken.add(nameOf(e.dt));
            }
        }
        for (Entry e : new ArrayList<>(cache.values())) {
            if (!(e.kind.equals("struct") || e.kind.equals("union") || e.kind.equals("enum"))) {
                continue;
            }
            String n = nameOf(e.dt);
            if (!taken.add(n)) {
                continue;
            }
            Die td = cu.child(C.DW_TAG_typedef);
            dw.name(td, n, true);
            td.add(C.DW_AT_type, C.DW_FORM_ref4, e.die);
        }
    }

    /** All entries (key -> (kind, die, dt)), in creation order. */
    public List<Entry> entries() {
        return new ArrayList<>(cache.values());
    }

    /** Pointer^depth to Ghidra's "code" (function of unknown type). */
    public Die codePointer(int depth) {
        if (code == null) {
            Die fn = cu.child(C.DW_TAG_subroutine_type);
            fn.child(C.DW_TAG_unspecified_parameters);
            Die td = cu.child(C.DW_TAG_typedef);
            dw.name(td, "code", true);
            td.add(C.DW_AT_type, C.DW_FORM_ref4, fn);
            code = new HashMap<>();
            code.put(0, td);
        }
        if (!code.containsKey(depth)) {
            Die inner = codePointer(depth - 1);
            Die p = cu.child(C.DW_TAG_pointer_type);
            p.add(C.DW_AT_byte_size, C.DW_FORM_udata, (long) ptrSize);
            p.add(C.DW_AT_type, C.DW_FORM_ref4, inner);
            code.put(depth, p);
        }
        return code.get(depth);
    }

    public Die baseOfSize(int size, boolean signed) {
        DataType dt = signed ? AbstractIntegerDataType.getSignedDataType(size, dtm)
                : AbstractIntegerDataType.getUnsignedDataType(size, dtm);
        return get(dt);
    }

    public void flush() {
        while (!pending.isEmpty()) {
            Entry e = pending.remove(pending.size() - 1);
            switch (e.kind) {
                case "base":
                    fillBase(e.die, e.dt);
                    break;
                case "blob":
                    fillBlob(e.die, e.dt);
                    break;
                case "ptr":
                    fillPtr(e.die, (Pointer) e.dt);
                    break;
                case "rawptr":
                    fillRawptr(e.die, e.dt);
                    break;
                case "typedef":
                    fillTypedef(e.die, (TypeDef) e.dt);
                    break;
                case "array":
                    fillArray(e.die, (Array) e.dt);
                    break;
                case "func":
                    fillFunc(e.die, (FunctionDefinition) e.dt);
                    break;
                case "enum":
                    fillEnum(e.die, (ghidra.program.model.data.Enum) e.dt);
                    break;
                case "struct":
                    fillComposite(e.die, (Composite) e.dt, ((Structure) e.dt).getDefinedComponents());
                    break;
                case "union":
                    fillComposite(e.die, (Composite) e.dt, ((Union) e.dt).getComponents());
                    break;
                default:
                    throw new IllegalStateException(e.kind);
            }
        }
    }

    void fillBase(Die die, DataType dt) {
        if (dt instanceof WideChar16DataType) {
            tname(die, "char16_t");
        }
        else if (dt instanceof WideChar32DataType) {
            tname(die, "char32_t");
        }
        else {
            tname(die, dt.getName());
        }
        die.add(C.DW_AT_byte_size, C.DW_FORM_udata, (long) dt.getLength());
        int enc;
        if (dt instanceof BooleanDataType) {
            enc = C.DW_ATE_boolean;
        }
        else if (dt instanceof WideCharDataType || dt instanceof WideChar16DataType || dt instanceof WideChar32DataType) {
            enc = C.DW_ATE_UTF;
        }
        else if (dt instanceof CharDataType) {
            enc = ((CharDataType) dt).isSigned() ? C.DW_ATE_signed_char : C.DW_ATE_unsigned_char;
        }
        else if (dt instanceof AbstractIntegerDataType) {
            enc = ((AbstractIntegerDataType) dt).isSigned() ? C.DW_ATE_signed : C.DW_ATE_unsigned;
        }
        else if (dt instanceof AbstractFloatDataType) {
            enc = C.DW_ATE_float;
        }
        else if (dt instanceof AbstractComplexDataType) {
            enc = C.DW_ATE_complex_float;
        }
        else {
            enc = C.DW_ATE_unsigned;
        }
        die.add(C.DW_AT_encoding, C.DW_FORM_data1, (long) enc);
    }

    void fillBlob(Die die, DataType dt) {
        tname(die, dt.getName());
        Die arr = cu.child(C.DW_TAG_array_type);
        arr.add(C.DW_AT_type, C.DW_FORM_ref4, baseOfSize(1, false));
        Die sub = arr.child(C.DW_TAG_subrange_type);
        sub.add(C.DW_AT_count, C.DW_FORM_udata, (long) dt.getLength());
        die.add(C.DW_AT_type, C.DW_FORM_ref4, arr);
    }

    void fillPtr(Die die, Pointer dt) {
        int size = dt.getLength();
        die.add(C.DW_AT_byte_size, C.DW_FORM_udata, (long) (size > 0 ? size : ptrSize));
        ref(die, dt.getDataType());
    }

    void fillRawptr(Die die, DataType dt) {
        tname(die, dt.getName());
        int size = dt.getLength() > 0 ? dt.getLength() : ptrSize;
        die.add(C.DW_AT_type, C.DW_FORM_ref4, baseOfSize(size, false));
    }

    void fillTypedef(Die die, TypeDef dt) {
        tname(die, dt.getName());
        ref(die, dt.getDataType());
    }

    void fillArray(Die die, Array dt) {
        ref(die, dt.getDataType());
        Die sub = die.child(C.DW_TAG_subrange_type);
        if (dt.getNumElements() > 0) {
            sub.add(C.DW_AT_count, C.DW_FORM_udata, (long) dt.getNumElements());
        }
    }

    void fillFunc(Die die, FunctionDefinition dt) {
        die.add(C.DW_AT_prototyped, C.DW_FORM_flag_present);
        ref(die, dt.getReturnType());
        for (ParameterDefinition arg : dt.getArguments()) {
            Die p = die.child(C.DW_TAG_formal_parameter);
            ref(p, arg.getDataType());
        }
        if (dt.hasVarArgs()) {
            die.child(C.DW_TAG_unspecified_parameters);
        }
    }

    void fillEnum(Die die, ghidra.program.model.data.Enum dt) {
        tname(die, dt.getName());
        int size = dt.getLength();
        die.add(C.DW_AT_byte_size, C.DW_FORM_udata, (long) size);
        Die under = baseOfSize(size, dt.isSigned());
        if (under != null) {
            die.add(C.DW_AT_type, C.DW_FORM_ref4, under);
        }
        for (String name : dt.getNames()) {
            Die e = die.child(C.DW_TAG_enumerator);
            dw.name(e, name);
            e.add(C.DW_AT_const_value, C.DW_FORM_sdata, dt.getValue(name));
        }
    }

    void fillComposite(Die die, Composite dt, DataTypeComponent[] components) {
        tname(die, dt.getName());
        if (dt.isNotYetDefined()) {
            die.add(C.DW_AT_declaration, C.DW_FORM_flag_present);
            return;
        }
        die.add(C.DW_AT_byte_size, C.DW_FORM_udata, (long) (!dt.isZeroLength() ? dt.getLength() : 0));
        for (DataTypeComponent comp : components) {
            DataType cdt = comp.getDataType();
            String name = comp.getFieldName();
            if (name == null || name.isEmpty()) {
                name = comp.getDefaultFieldName();
            }
            Die m = die.child(C.DW_TAG_member);
            dw.name(m, name);
            if (cdt instanceof BitFieldDataType) {
                BitFieldDataType bf = (BitFieldDataType) cdt;
                int bits = bf.getBitSize();
                int storage = bf.getStorageSize();
                int bitoff = bf.getBitOffset();
                int rel = bigEndian ? storage * 8 - bitoff - bits : bitoff;
                ref(m, bf.getBaseDataType());
                m.add(C.DW_AT_bit_size, C.DW_FORM_udata, (long) bits);
                m.add(C.DW_AT_data_bit_offset, C.DW_FORM_udata, (long) comp.getOffset() * 8 + rel);
            }
            else {
                ref(m, cdt);
                m.add(C.DW_AT_data_member_location, C.DW_FORM_udata, (long) comp.getOffset());
            }
        }
    }
}
