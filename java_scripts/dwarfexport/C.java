package dwarfexport;

/** DWARF and ELF constants (a port of consts.py). */
public final class C {
    private C() {
    }

    // --- DWARF tags -------------------------------------------------------------
    public static final int DW_TAG_array_type = 0x01;
    public static final int DW_TAG_enumeration_type = 0x04;
    public static final int DW_TAG_formal_parameter = 0x05;
    public static final int DW_TAG_lexical_block = 0x0B;
    public static final int DW_TAG_member = 0x0D;
    public static final int DW_TAG_pointer_type = 0x0F;
    public static final int DW_TAG_compile_unit = 0x11;
    public static final int DW_TAG_structure_type = 0x13;
    public static final int DW_TAG_subroutine_type = 0x15;
    public static final int DW_TAG_typedef = 0x16;
    public static final int DW_TAG_union_type = 0x17;
    public static final int DW_TAG_unspecified_parameters = 0x18;
    public static final int DW_TAG_label = 0x0a;
    public static final int DW_TAG_variable = 0x34;
    public static final int DW_TAG_subrange_type = 0x21;
    public static final int DW_TAG_base_type = 0x24;
    public static final int DW_TAG_const_type = 0x26;
    public static final int DW_TAG_enumerator = 0x28;
    public static final int DW_TAG_subprogram = 0x2E;
    public static final int DW_TAG_volatile_type = 0x35;
    public static final int DW_TAG_unspecified_type = 0x3B;
    // --- DWARF attributes -------------------------------------------------------
    public static final int DW_AT_location = 0x02;
    public static final int DW_AT_name = 0x03;
    public static final int DW_AT_byte_size = 0x0B;
    public static final int DW_AT_stmt_list = 0x10;
    public static final int DW_AT_low_pc = 0x11;
    public static final int DW_AT_high_pc = 0x12;
    public static final int DW_AT_language = 0x13;
    public static final int DW_AT_comp_dir = 0x1B;
    public static final int DW_AT_const_value = 0x1C;
    public static final int DW_AT_upper_bound = 0x2F;
    public static final int DW_AT_producer = 0x25;
    public static final int DW_AT_prototyped = 0x27;
    public static final int DW_AT_count = 0x37;
    public static final int DW_AT_data_member_location = 0x38;
    public static final int DW_AT_decl_file = 0x3A;
    public static final int DW_AT_decl_line = 0x3B;
    public static final int DW_AT_declaration = 0x3C;
    public static final int DW_AT_encoding = 0x3E;
    public static final int DW_AT_external = 0x3F;
    public static final int DW_AT_frame_base = 0x40;
    public static final int DW_AT_type = 0x49;
    public static final int DW_AT_ranges = 0x55;
    public static final int DW_AT_data_bit_offset = 0x6B;
    public static final int DW_AT_bit_size = 0x0D;
    public static final int DW_AT_linkage_name = 0x6E;
    // --- DWARF forms ------------------------------------------------------------
    public static final int DW_FORM_addr = 0x01;
    public static final int DW_FORM_data2 = 0x05;
    public static final int DW_FORM_data4 = 0x06;
    public static final int DW_FORM_data8 = 0x07;
    public static final int DW_FORM_string = 0x08;
    public static final int DW_FORM_data1 = 0x0B;
    public static final int DW_FORM_flag = 0x0C;
    public static final int DW_FORM_sdata = 0x0D;
    public static final int DW_FORM_strp = 0x0E;
    public static final int DW_FORM_udata = 0x0F;
    public static final int DW_FORM_ref4 = 0x13;
    public static final int DW_FORM_sec_offset = 0x17;
    public static final int DW_FORM_exprloc = 0x18;
    public static final int DW_FORM_flag_present = 0x19;
    // --- DWARF location expression operations ----------------------------------
    public static final int DW_OP_addr = 0x03;
    public static final int DW_OP_const1u = 0x08;
    public static final int DW_OP_plus_uconst = 0x23;
    public static final int DW_OP_reg0 = 0x50;
    public static final int DW_OP_breg0 = 0x70;
    public static final int DW_OP_regx = 0x90;
    public static final int DW_OP_fbreg = 0x91;
    public static final int DW_OP_bregx = 0x92;
    public static final int DW_OP_piece = 0x93;
    public static final int DW_OP_call_frame_cfa = 0x9C;
    public static final int DW_OP_bit_piece = 0x9D;
    public static final int DW_OP_stack_value = 0x9F;
    // --- Base type encodings ---------------------------------------------------
    public static final int DW_ATE_address = 0x01;
    public static final int DW_ATE_boolean = 0x02;
    public static final int DW_ATE_complex_float = 0x03;
    public static final int DW_ATE_float = 0x04;
    public static final int DW_ATE_signed = 0x05;
    public static final int DW_ATE_signed_char = 0x06;
    public static final int DW_ATE_unsigned = 0x07;
    public static final int DW_ATE_unsigned_char = 0x08;
    public static final int DW_ATE_UTF = 0x10;
    public static final int DW_LANG_C99 = 0x0C;
    // --- Line number program ---------------------------------------------------
    public static final int DW_LNS_copy = 0x01;
    public static final int DW_LNS_advance_pc = 0x02;
    public static final int DW_LNS_advance_line = 0x03;
    public static final int DW_LNS_set_file = 0x04;
    public static final int DW_LNS_set_column = 0x05;
    public static final int DW_LNS_negate_stmt = 0x06;
    public static final int DW_LNS_set_basic_block = 0x07;
    public static final int DW_LNS_const_add_pc = 0x08;
    public static final int DW_LNS_fixed_advance_pc = 0x09;
    public static final int DW_LNS_set_prologue_end = 0x0A;
    public static final int DW_LNS_set_epilogue_begin = 0x0B;
    public static final int DW_LNS_set_isa = 0x0C;
    public static final int DW_LNE_end_sequence = 0x01;
    public static final int DW_LNE_set_address = 0x02;
    public static final int DW_CHILDREN_no = 0;
    public static final int DW_CHILDREN_yes = 1;
    // --- Call frame information -------------------------------------------------
    public static final int DW_CFA_advance_loc = 0x40;
    public static final int DW_CFA_offset = 0x80;
    public static final int DW_CFA_restore = 0xC0;
    public static final int DW_CFA_nop = 0x00;
    public static final int DW_CFA_advance_loc1 = 0x02;
    public static final int DW_CFA_advance_loc2 = 0x03;
    public static final int DW_CFA_advance_loc4 = 0x04;
    public static final int DW_CFA_offset_extended = 0x05;
    public static final int DW_CFA_restore_extended = 0x06;
    public static final int DW_CFA_undefined = 0x07;
    public static final int DW_CFA_same_value = 0x08;
    public static final int DW_CFA_register = 0x09;
    public static final int DW_CFA_def_cfa = 0x0C;
    public static final int DW_CFA_def_cfa_register = 0x0D;
    public static final int DW_CFA_def_cfa_offset = 0x0E;
    public static final int DW_CFA_offset_extended_sf = 0x11;
    // --- ELF ---------------------------------------------------------------------
    public static final int ET_EXEC = 2;
    public static final int SHT_NULL = 0;
    public static final int SHT_PROGBITS = 1;
    public static final int SHT_SYMTAB = 2;
    public static final int SHT_STRTAB = 3;
    public static final int SHT_NOBITS = 8;
    public static final int SHF_WRITE = 0x1;
    public static final int SHF_ALLOC = 0x2;
    public static final int SHF_EXECINSTR = 0x4;
    public static final int SHN_UNDEF = 0;
    public static final int SHN_ABS = 0xFFF1;
    public static final int STB_LOCAL = 0;
    public static final int STB_GLOBAL = 1;
    public static final int STT_NOTYPE = 0;
    public static final int STT_OBJECT = 1;
    public static final int STT_FUNC = 2;
    public static final int STT_SECTION = 3;
    public static final int STT_FILE = 4;
    // Ghidra processor name -> (e_machine for 32-bit, e_machine for 64-bit)

    /** Ghidra processor -> (e_machine for 32-bit, for 64-bit). */
    public static final java.util.Map<String, int[]> ELF_MACHINES = java.util.Map.ofEntries(
        java.util.Map.entry("x86", new int[] {3, 62}),
        java.util.Map.entry("PowerPC", new int[] {20, 21}),
        java.util.Map.entry("ARM", new int[] {40, 40}),
        java.util.Map.entry("AARCH64", new int[] {183, 183}),
        java.util.Map.entry("AArch64", new int[] {183, 183}),
        java.util.Map.entry("MIPS", new int[] {8, 8}),
        java.util.Map.entry("Sparc", new int[] {2, 43}),
        java.util.Map.entry("68000", new int[] {4, 4}),
        java.util.Map.entry("SuperH", new int[] {42, 42}),
        java.util.Map.entry("SuperH4", new int[] {42, 42}),
        java.util.Map.entry("RISCV", new int[] {243, 243}),
        java.util.Map.entry("AVR8", new int[] {83, 83}),
        java.util.Map.entry("MSP430", new int[] {105, 105}),
        java.util.Map.entry("MSP430X", new int[] {105, 105}),
        java.util.Map.entry("TriCore", new int[] {44, 44}),
        java.util.Map.entry("V850", new int[] {87, 87}),
        java.util.Map.entry("Xtensa", new int[] {94, 94}),
        java.util.Map.entry("HCS12", new int[] {53, 53}),
        java.util.Map.entry("M16C/60", new int[] {117, 117}),
        java.util.Map.entry("M16C/80", new int[] {117, 117}),
        java.util.Map.entry("Loongarch", new int[] {258, 258}));
}
