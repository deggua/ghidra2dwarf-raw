"""DWARF (v4 subset) and ELF constants used by the exporter."""

# --- DWARF tags -------------------------------------------------------------
DW_TAG_array_type = 0x01
DW_TAG_enumeration_type = 0x04
DW_TAG_formal_parameter = 0x05
DW_TAG_lexical_block = 0x0B
DW_TAG_member = 0x0D
DW_TAG_pointer_type = 0x0F
DW_TAG_compile_unit = 0x11
DW_TAG_structure_type = 0x13
DW_TAG_subroutine_type = 0x15
DW_TAG_typedef = 0x16
DW_TAG_union_type = 0x17
DW_TAG_unspecified_parameters = 0x18
DW_TAG_variable = 0x34
DW_TAG_subrange_type = 0x21
DW_TAG_base_type = 0x24
DW_TAG_const_type = 0x26
DW_TAG_enumerator = 0x28
DW_TAG_subprogram = 0x2E
DW_TAG_volatile_type = 0x35
DW_TAG_unspecified_type = 0x3B

# --- DWARF attributes -------------------------------------------------------
DW_AT_location = 0x02
DW_AT_name = 0x03
DW_AT_byte_size = 0x0B
DW_AT_stmt_list = 0x10
DW_AT_low_pc = 0x11
DW_AT_high_pc = 0x12
DW_AT_language = 0x13
DW_AT_comp_dir = 0x1B
DW_AT_const_value = 0x1C
DW_AT_upper_bound = 0x2F
DW_AT_producer = 0x25
DW_AT_prototyped = 0x27
DW_AT_count = 0x37
DW_AT_data_member_location = 0x38
DW_AT_decl_file = 0x3A
DW_AT_decl_line = 0x3B
DW_AT_declaration = 0x3C
DW_AT_encoding = 0x3E
DW_AT_external = 0x3F
DW_AT_frame_base = 0x40
DW_AT_type = 0x49
DW_AT_ranges = 0x55
DW_AT_data_bit_offset = 0x6B
DW_AT_bit_size = 0x0D
DW_AT_linkage_name = 0x6E

# --- DWARF forms ------------------------------------------------------------
DW_FORM_addr = 0x01
DW_FORM_data2 = 0x05
DW_FORM_data4 = 0x06
DW_FORM_data8 = 0x07
DW_FORM_string = 0x08
DW_FORM_data1 = 0x0B
DW_FORM_flag = 0x0C
DW_FORM_sdata = 0x0D
DW_FORM_strp = 0x0E
DW_FORM_udata = 0x0F
DW_FORM_ref4 = 0x13
DW_FORM_sec_offset = 0x17
DW_FORM_exprloc = 0x18
DW_FORM_flag_present = 0x19

# --- DWARF location expression operations ----------------------------------
DW_OP_addr = 0x03
DW_OP_const1u = 0x08
DW_OP_plus_uconst = 0x23
DW_OP_reg0 = 0x50
DW_OP_breg0 = 0x70
DW_OP_regx = 0x90
DW_OP_fbreg = 0x91
DW_OP_bregx = 0x92
DW_OP_piece = 0x93
DW_OP_call_frame_cfa = 0x9C
DW_OP_bit_piece = 0x9D
DW_OP_stack_value = 0x9F

# --- Base type encodings ---------------------------------------------------
DW_ATE_address = 0x01
DW_ATE_boolean = 0x02
DW_ATE_complex_float = 0x03
DW_ATE_float = 0x04
DW_ATE_signed = 0x05
DW_ATE_signed_char = 0x06
DW_ATE_unsigned = 0x07
DW_ATE_unsigned_char = 0x08
DW_ATE_UTF = 0x10

DW_LANG_C99 = 0x0C

# --- Line number program ---------------------------------------------------
DW_LNS_copy = 0x01
DW_LNS_advance_pc = 0x02
DW_LNS_advance_line = 0x03
DW_LNS_set_file = 0x04
DW_LNS_set_column = 0x05
DW_LNS_negate_stmt = 0x06
DW_LNS_set_basic_block = 0x07
DW_LNS_const_add_pc = 0x08
DW_LNS_fixed_advance_pc = 0x09
DW_LNS_set_prologue_end = 0x0A
DW_LNS_set_epilogue_begin = 0x0B
DW_LNS_set_isa = 0x0C

DW_LNE_end_sequence = 0x01
DW_LNE_set_address = 0x02

DW_CHILDREN_no = 0
DW_CHILDREN_yes = 1

# --- Call frame information -------------------------------------------------
DW_CFA_advance_loc = 0x40
DW_CFA_offset = 0x80
DW_CFA_restore = 0xC0
DW_CFA_nop = 0x00
DW_CFA_advance_loc1 = 0x02
DW_CFA_advance_loc2 = 0x03
DW_CFA_advance_loc4 = 0x04
DW_CFA_offset_extended = 0x05
DW_CFA_restore_extended = 0x06
DW_CFA_undefined = 0x07
DW_CFA_same_value = 0x08
DW_CFA_register = 0x09
DW_CFA_def_cfa = 0x0C
DW_CFA_def_cfa_register = 0x0D
DW_CFA_def_cfa_offset = 0x0E
DW_CFA_offset_extended_sf = 0x11

# --- ELF ---------------------------------------------------------------------
ET_EXEC = 2

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

SHN_UNDEF = 0
SHN_ABS = 0xFFF1

STB_LOCAL = 0
STB_GLOBAL = 1

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4

# Ghidra processor name -> (e_machine for 32-bit, e_machine for 64-bit)
ELF_MACHINES = {
    "x86": (3, 62),
    "PowerPC": (20, 21),
    "ARM": (40, 40),
    "AARCH64": (183, 183),
    "AArch64": (183, 183),
    "MIPS": (8, 8),
    "Sparc": (2, 43),
    "68000": (4, 4),
    "SuperH": (42, 42),
    "SuperH4": (42, 42),
    "RISCV": (243, 243),
    "AVR8": (83, 83),
    "MSP430": (105, 105),
    "MSP430X": (105, 105),
    "TriCore": (44, 44),
    "V850": (87, 87),
    "Xtensa": (94, 94),
    "HCS12": (53, 53),
    "M16C/60": (117, 117),
    "M16C/80": (117, 117),
    "Loongarch": (258, 258),
}
