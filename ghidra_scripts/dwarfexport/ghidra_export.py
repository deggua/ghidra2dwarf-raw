"""Ghidra -> DWARF/ELF exporter (runs inside PyGhidra).

Turns the state of a Ghidra program (functions, decompiled code, data types,
global data, labels, memory map) into:

  * <name>.c    pseudo-C source made of the decompiler output of every function
                (optionally preceded by the program's data type definitions);
  * <name>.elf  an ELF with section headers mirroring the program's memory
                map, a symbol table, and DWARF 4 debug info whose line table
                points into <name>.c.

Load the ELF into GDB with ``symbol-file`` (or ``add-symbol-file``) while
attached to the real target or an emulator to get source-level debugging of
the decompiled code.
"""

import bisect
import os
import re
import time

from java.io import StringWriter
from ghidra.app.decompiler import (DecompInterface, DecompileOptions, ClangFuncNameToken,
                                   ClangCommentToken)
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.app.util.bin.format.dwarf import DWARFRegisterMappingsManager
from ghidra.program.database.data import PointerTypedefInspector
from ghidra.program.model.data import (
    AbstractComplexDataType, AbstractFloatDataType, AbstractIntegerDataType,
    Array, BitFieldDataType, BooleanDataType, CharDataType, DataTypeWriter,
    DefaultDataType, Enum, FunctionDefinition, Pointer, PointerType, Structure, TypeDef,
    Undefined, Union, VoidDataType, WideCharDataType, WideChar16DataType,
    WideChar32DataType,
)
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import SymbolType

from . import consts as C
from .dwarf import DwarfBuilder, uleb, ROW_PROLOGUE_END
from .elf import ElfWriter, Section
from .flow import MachineInfo, FunctionFlow, CfiGenerator

PRODUCER = "ghidra2dwarf-raw"


class Options(object):
    """Exporter options. All can be passed as ``key=value`` script args."""

    def __init__(self):
        # Added to every address (use when the Ghidra image base differs from
        # where the code lives at runtime).
        self.address_offset = 0
        # Put the bytes of initialized memory blocks in the ELF (PROGBITS) so
        # objdump / gdb can disassemble offline. Off: NOBITS placeholders.
        self.embed_bytes = False
        # Write the program's data types as C at the top of the .c file.
        self.types_header = True
        # Emit DWARF for every structure/union/enum/typedef in the program,
        # not only the ones referenced by functions/globals.
        self.all_types = True
        # Synthesize .debug_frame (call frame information) from p-code so GDB
        # can unwind optimized code (bt / finish / up).
        self.cfi = True
        # Per-function decompiler timeout in seconds.
        self.decompile_timeout = 60
        # Output base name (default: program name).
        self.basename = None
        # Rewrite every exported name (DWARF, ELF symbols and the .c file)
        # into a plain C identifier ("Foo::init" -> "Foo__init",
        # "Get?Value" -> "Get_Value"), so GDB never needs quoting. When off,
        # names are kept verbatim (GDB accepts them in 'single quotes') and
        # only characters that cannot be quoted at all (' and control
        # characters) are replaced with '_'.
        self.sanitize_names = False
        # (internal) split executable blocks into code/data sections, and
        # emit GCC-style double rows at frameless function entries
        self.split_sections = True
        self.frameless_rows = True
        # ELF header e_flags; -1 = derive from the language / compiler spec
        # (ARM EABI/BE8/float ABI, MIPS ABI+ISA, PPC64 ELFv1/ELFv2).
        self.elf_flags = -1
        # Comma-separated function names (or entry addresses) not to
        # decompile, e.g. functions that hang the decompiler. They still get
        # symbols, ranges, CFI and a one-line prototype in the .c file.
        self.skip_decompile = ""

    def set(self, key, value):
        if not hasattr(self, key):
            raise KeyError("unknown option %r" % key)
        cur = getattr(self, key)
        if isinstance(cur, bool):
            value = str(value).lower() in ("1", "true", "yes", "on")
        elif isinstance(cur, int):
            value = int(str(value), 0)
        setattr(self, key, value)


_C_KEYWORDS = frozenset("""auto break case char const continue default do double
    else enum extern float for goto if inline int long register restrict return
    short signed sizeof static struct switch typedef union unsigned void volatile
    while _Bool _Complex _Alignas _Alignof _Atomic _Generic _Noreturn
    _Static_assert _Thread_local""".split())


_C_TYPE_WORDS = frozenset("void char short int long float double signed unsigned _Bool _Complex bool".split())


def make_name_filter(sanitize, for_types=False):
    """Returns f(name) -> exported name (see Options.sanitize_names).

    Type names keep C's multi-word base type spellings ("unsigned int") and
    the type keywords themselves; anything else that is a C keyword gets a
    trailing '_' (a variable named "switch" -> "switch_")."""
    cache = {}
    bad_any = re.compile(r"[^A-Za-z0-9_]")
    bad_quoted = re.compile(r"['\x00-\x1f\x7f]")

    def f(name):
        out = cache.get(name)
        if out is None:
            if not sanitize:
                out = bad_quoted.sub("_", name) or "_"
            elif for_types and name.split() and all(w in _C_TYPE_WORDS for w in name.split()):
                out = " ".join(name.split())
            else:
                out = bad_any.sub("_", name) or "_"
                if out[0].isdigit():
                    out = "_" + out
                if out in _C_KEYWORDS:
                    out += "_"
            cache[name] = out
        return out

    f.cache = cache
    return f


def _qualified(symbol_or_func):
    """Name as the decompiler prints it: namespace-qualified unless global."""
    ns = symbol_or_func.getParentNamespace()
    if ns is None or ns.isGlobal():
        return str(symbol_or_func.getName())
    return str(symbol_or_func.getName(True))


def _is_special_pointer_typedef(dt):
    """Ghidra pointer typedefs with settings DWARF cannot express (component
    offset, bit shift/mask, relative/image-base pointers, other spaces)."""
    try:
        if PointerTypedefInspector.getPointerComponentOffset(dt) != 0:
            return True
        if PointerTypedefInspector.hasPointerBitShift(dt) or PointerTypedefInspector.hasPointerBitMask(dt):
            return True
        if PointerTypedefInspector.getPointerType(dt) != PointerType.DEFAULT:
            return True
        dtm = dt.getDataTypeManager()
        prog = dtm.getProgram() if hasattr(dtm, "getProgram") else None
        if prog is not None:
            space = PointerTypedefInspector.getPointerAddressSpace(dt, prog.getAddressFactory())
            if space is not None and not space.equals(prog.getAddressFactory().getDefaultAddressSpace()):
                return True
    except Exception:
        return False
    return False


def _sanitize_basename(name):
    out = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)
    return out or "program"


# ----------------------------------------------------------------------------
# Register mapping
# ----------------------------------------------------------------------------

def _ppc_register_map():
    """GDB/GCC DWARF numbering for (32/64-bit) PowerPC.

    Ghidra's ppc.dwarf uses the 'ABI supplement' numbers for LR/CTR/MSR
    (108/109/66) which collide with what GCC emits and GDB expects
    (LR=65, CTR=66, XER=76)."""
    m = {}
    for i in range(32):
        m["r%d" % i] = i
        m["f%d" % i] = 32 + i
        m["vr%d" % i] = 1124 + i
    m["LR"] = 65
    m["CTR"] = 66
    m["XER"] = 76
    return m


def build_register_map(lang):
    """Returns ({ghidra register name: dwarf regno}, stack pointer regno)."""
    proc = str(lang.getProcessor())
    sp = None
    names = {}
    try:
        mapping = DWARFRegisterMappingsManager.getMappingForLang(lang)
        sp = int(mapping.getDWARFStackPointerRegNum())
        for i in range(0, 1300):
            reg = mapping.getGhidraReg(i)
            if reg is not None:
                names.setdefault(str(reg.getName()), i)
    except Exception as e:  # language without a .dwarf mapping file
        print("WARNING: no DWARF register mapping for %s (%s); register "
              "variables will have no location" % (lang.getLanguageID(), e))
    if proc == "PowerPC":
        names = _ppc_register_map()
        sp = 1
    return names, sp


class RegisterIndex(object):
    """Finds the DWARF register containing a register-space varnode."""

    def __init__(self, lang, regmap):
        self.entries = []
        for name, num in regmap.items():
            reg = lang.getRegister(name)
            if reg is None:
                continue
            addr = reg.getAddress()
            self.entries.append((int(addr.getOffset()), int(reg.getMinimumByteSize()), num))
        self.entries.sort()

    def lookup(self, offset, size):
        """Returns (dwarf_regno, reg_offset, reg_size) of the smallest mapped
        register fully containing [offset, offset+size)."""
        best = None
        for start, rsize, num in self.entries:
            if start > offset:
                break
            if offset + size <= start + rsize:
                if best is None or rsize < best[2]:
                    best = (num, start, rsize)
        return best


# ----------------------------------------------------------------------------
# Data types
# ----------------------------------------------------------------------------

def classify(dt):
    if dt is None:
        return "void"
    if isinstance(dt, BitFieldDataType):
        return "bitfield"
    if isinstance(dt, Pointer):
        return "ptr"
    if isinstance(dt, TypeDef):
        if isinstance(dt.getBaseDataType(), Pointer) and _is_special_pointer_typedef(dt):
            return "rawptr"
        return "typedef"
    if isinstance(dt, Structure):
        return "struct"
    if isinstance(dt, Union):
        return "union"
    if isinstance(dt, Enum):
        return "enum"
    if isinstance(dt, Array):
        return "array"
    if isinstance(dt, FunctionDefinition):
        return "func"
    if isinstance(dt, VoidDataType):
        return "void"
    if isinstance(dt, (BooleanDataType, AbstractIntegerDataType, AbstractFloatDataType,
                       AbstractComplexDataType, Undefined, DefaultDataType)):
        return "base" if dt.getLength() > 0 else "void"
    if dt.getLength() > 0:
        return "blob"
    return "void"


class TypeBuilder(object):
    """Converts Ghidra DataTypes to DWARF type DIEs (deduplicated).

    DIEs are created as shells and filled from a work list so that
    arbitrarily deep / recursive type graphs do not hit the recursion limit."""

    def __init__(self, dw, program):
        self.dw = dw
        self.cu = dw.cu
        self.program = program
        self.dtm = program.getDataTypeManager()
        self.ptr_size = program.getDefaultPointerSize()
        self.big_endian = program.getLanguage().isBigEndian()
        self.cache = {}
        self.pending = []
        self.by_name = {}

    type_name_filter = None

    def tname(self, die, name):
        """DW_AT_name for a type (type-name rules, see make_name_filter)."""
        name = str(name)
        if self.type_name_filter is not None:
            name = self.type_name_filter(name)
        self.dw.name(die, name, raw=True)

    def ref(self, die, dt):
        t = self.get(dt)
        if t is not None:
            die.add(C.DW_AT_type, C.DW_FORM_ref4, t)

    def get(self, dt):
        kind = classify(dt)
        if kind in ("void", "bitfield"):
            return None
        key = (kind, str(dt.getPathName()), int(dt.getLength()))
        die = self.cache.get(key)
        if die is not None:
            return die
        tag = {
            "ptr": C.DW_TAG_pointer_type, "typedef": C.DW_TAG_typedef,
            "struct": C.DW_TAG_structure_type, "union": C.DW_TAG_union_type,
            "enum": C.DW_TAG_enumeration_type, "array": C.DW_TAG_array_type,
            "func": C.DW_TAG_subroutine_type, "base": C.DW_TAG_base_type,
            "blob": C.DW_TAG_typedef, "rawptr": C.DW_TAG_typedef,
        }[kind]
        die = self.cu.child(tag)
        self.cache[key] = die
        self.pending.append((kind, die, dt))
        return die

    def code_pointer(self, depth):
        """Pointer^depth to Ghidra's "code" (function of unknown type)."""
        if not hasattr(self, "_code"):
            fn = self.cu.child(C.DW_TAG_subroutine_type)
            fn.child(C.DW_TAG_unspecified_parameters)
            td = self.cu.child(C.DW_TAG_typedef)
            self.dw.name(td, "code", raw=True)
            td.add(C.DW_AT_type, C.DW_FORM_ref4, fn)
            self._code = {0: td}
        if depth not in self._code:
            inner = self.code_pointer(depth - 1)
            p = self.cu.child(C.DW_TAG_pointer_type)
            p.add(C.DW_AT_byte_size, C.DW_FORM_udata, self.ptr_size)
            p.add(C.DW_AT_type, C.DW_FORM_ref4, inner)
            self._code[depth] = p
        return self._code[depth]

    def base_of_size(self, size, signed):
        if signed:
            dt = AbstractIntegerDataType.getSignedDataType(size, self.dtm)
        else:
            dt = AbstractIntegerDataType.getUnsignedDataType(size, self.dtm)
        return self.get(dt)

    def flush(self):
        while self.pending:
            kind, die, dt = self.pending.pop()
            getattr(self, "_fill_" + kind)(die, dt)

    # -- fillers ---------------------------------------------------------------
    def _fill_base(self, die, dt):
        self.tname(die, dt.getName())
        die.add(C.DW_AT_byte_size, C.DW_FORM_udata, int(dt.getLength()))
        if isinstance(dt, BooleanDataType):
            enc = C.DW_ATE_boolean
        elif isinstance(dt, (WideCharDataType, WideChar16DataType, WideChar32DataType)):
            enc = C.DW_ATE_UTF
        elif isinstance(dt, CharDataType):
            enc = C.DW_ATE_signed_char if dt.isSigned() else C.DW_ATE_unsigned_char
        elif isinstance(dt, AbstractIntegerDataType):
            enc = C.DW_ATE_signed if dt.isSigned() else C.DW_ATE_unsigned
        elif isinstance(dt, AbstractFloatDataType):
            enc = C.DW_ATE_float
        elif isinstance(dt, AbstractComplexDataType):
            enc = C.DW_ATE_complex_float
        else:  # undefined, undefined1..8
            enc = C.DW_ATE_unsigned
        die.add(C.DW_AT_encoding, C.DW_FORM_data1, enc)

    def _fill_blob(self, die, dt):
        # Opaque fixed-size type (strings, unknown builtins): typedef to a
        # byte array so its size and name are preserved.
        self.tname(die, dt.getName())
        arr = self.cu.child(C.DW_TAG_array_type)
        arr.add(C.DW_AT_type, C.DW_FORM_ref4, self.base_of_size(1, False))
        sub = arr.child(C.DW_TAG_subrange_type)
        sub.add(C.DW_AT_count, C.DW_FORM_udata, int(dt.getLength()))
        die.add(C.DW_AT_type, C.DW_FORM_ref4, arr)

    def _fill_ptr(self, die, dt):
        size = dt.getLength()
        die.add(C.DW_AT_byte_size, C.DW_FORM_udata, int(size if size > 0 else self.ptr_size))
        self.ref(die, dt.getDataType())

    def _fill_rawptr(self, die, dt):
        # A pointer DWARF can't describe (e.g. "int *32 __((offset(-0x4)))"):
        # keep the name but make it a plain integer, so GDB shows the raw
        # value instead of dereferencing the wrong address.
        self.tname(die, dt.getName())
        size = int(dt.getLength()) if dt.getLength() > 0 else self.ptr_size
        die.add(C.DW_AT_type, C.DW_FORM_ref4, self.base_of_size(size, False))

    def _fill_typedef(self, die, dt):
        self.tname(die, dt.getName())
        self.ref(die, dt.getDataType())

    def _fill_array(self, die, dt):
        self.ref(die, dt.getDataType())
        sub = die.child(C.DW_TAG_subrange_type)
        sub.add(C.DW_AT_count, C.DW_FORM_udata, int(dt.getNumElements()))

    def _fill_func(self, die, dt):
        die.add(C.DW_AT_prototyped, C.DW_FORM_flag_present)
        self.ref(die, dt.getReturnType())
        for arg in dt.getArguments():
            p = die.child(C.DW_TAG_formal_parameter)
            self.ref(p, arg.getDataType())
        if dt.hasVarArgs():
            die.child(C.DW_TAG_unspecified_parameters)

    def _fill_enum(self, die, dt):
        self.tname(die, dt.getName())
        size = int(dt.getLength())
        die.add(C.DW_AT_byte_size, C.DW_FORM_udata, size)
        signed = bool(dt.isSigned())
        under = self.base_of_size(size, signed)
        if under is not None:
            die.add(C.DW_AT_type, C.DW_FORM_ref4, under)
        for name in dt.getNames():
            e = die.child(C.DW_TAG_enumerator)
            self.dw.name(e, str(name))
            e.add(C.DW_AT_const_value, C.DW_FORM_sdata, int(dt.getValue(name)))

    def _fill_composite(self, die, dt, components):
        self.tname(die, dt.getName())
        if dt.isNotYetDefined():
            die.add(C.DW_AT_declaration, C.DW_FORM_flag_present)
            return
        die.add(C.DW_AT_byte_size, C.DW_FORM_udata, int(dt.getLength()) if not dt.isZeroLength() else 0)
        for comp in components:
            cdt = comp.getDataType()
            name = comp.getFieldName() or comp.getDefaultFieldName()
            m = die.child(C.DW_TAG_member)
            self.dw.name(m, str(name))
            if isinstance(cdt, BitFieldDataType):
                bits = int(cdt.getBitSize())
                storage = int(cdt.getStorageSize())
                bitoff = int(cdt.getBitOffset())  # from the storage unit's LSB
                if self.big_endian:
                    rel = storage * 8 - bitoff - bits
                else:
                    rel = bitoff
                self.ref(m, cdt.getBaseDataType())
                m.add(C.DW_AT_bit_size, C.DW_FORM_udata, bits)
                m.add(C.DW_AT_data_bit_offset, C.DW_FORM_udata, int(comp.getOffset()) * 8 + rel)
            else:
                self.ref(m, cdt)
                m.add(C.DW_AT_data_member_location, C.DW_FORM_udata, int(comp.getOffset()))

    def _fill_struct(self, die, dt):
        self._fill_composite(die, dt, dt.getDefinedComponents())

    def _fill_union(self, die, dt):
        self._fill_composite(die, dt, dt.getComponents())


# ----------------------------------------------------------------------------
# The exporter
# ----------------------------------------------------------------------------

class Exporter(object):
    def __init__(self, program, monitor, out_dir, options=None):
        self.program = program
        self.monitor = monitor
        self.opts = options or Options()
        self.out_dir = os.path.abspath(out_dir)
        base = self.opts.basename or _sanitize_basename(str(program.getName()))
        self.c_path = os.path.join(self.out_dir, base + ".c")
        self.elf_path = os.path.join(self.out_dir, base + ".elf")

        self.lang = program.getLanguage()
        self.listing = program.getListing()
        self.memory = program.getMemory()
        self.space = program.getAddressFactory().getDefaultAddressSpace()
        self.addr_size = int(self.space.getPointerSize())
        if self.addr_size not in (4, 8):
            # 16-bit (or odd) targets: DWARF/ELF still need 4-byte addresses.
            self.addr_size = 4 if self.addr_size < 4 else 8
        self.addr_mask = (1 << (8 * self.addr_size)) - 1
        self.big_endian = bool(self.lang.isBigEndian())

        self.dw = DwarfBuilder(self.addr_size, self.big_endian)
        self.nm = make_name_filter(self.opts.sanitize_names)
        self.nm_type = make_name_filter(self.opts.sanitize_names, for_types=True)
        self.dw.name_filter = self.nm
        self.skip = set(s.strip() for s in str(self.opts.skip_decompile).split(",") if s.strip())
        self.types = TypeBuilder(self.dw, program)
        self.types.type_name_filter = self.nm_type
        regmap, self.sp_regno = build_register_map(self.lang)
        self.regs = RegisterIndex(self.lang, regmap)
        cc = program.getCompilerSpec().getDefaultCallingConvention()
        self.stackshift = int(cc.getStackshift()) if cc is not None else 0

        self.machine = MachineInfo(program, self.regs, self.stackshift, self.log)
        self.entry_points = []
        eps = program.getSymbolTable().getExternalEntryPointIterator()
        while eps.hasNext():
            a = eps.next()
            if self.in_space(a):
                self.entry_points.append(int(a.getOffset()))
        self.cfi = None
        if self.opts.cfi:
            self.cfi = CfiGenerator(self.machine, self.dw, self.A, self.entry_points)
        self.c_lines = []
        self.func_ranges = []
        self.elf_symbols = []   # (name, addr, size, type)
        self.stats = {"functions": 0, "decompile_failed": 0, "globals": 0,
                      "variables": 0, "variables_located": 0, "line_rows": 0}
        self._insn_end_cache = {}

    # -- helpers --------------------------------------------------------------
    def A(self, off):
        """Ghidra offset -> target address."""
        return (int(off) + self.opts.address_offset) & self.addr_mask

    def in_space(self, addr):
        return addr is not None and addr.getAddressSpace().equals(self.space)

    def insn_end(self, addr):
        """Offset just past the instruction containing addr (and past its
        delay slot(s), which execute with it)."""
        off = int(addr.getOffset())
        end = self._insn_end_cache.get(off)
        if end is None:
            ins = self.listing.getInstructionContaining(addr)
            end = int(ins.getMaxAddress().getOffset()) + 1 if ins is not None else off + 1
            depth = ins.getDelaySlotDepth() if ins is not None else 0
            while depth > 0 and ins is not None:
                ins = ins.getNext()
                if ins is None:
                    break
                end = int(ins.getMaxAddress().getOffset()) + 1
                depth -= 1
            self._insn_end_cache[off] = end
        return end

    def log(self, msg):
        print(msg)

    # -- main entry -------------------------------------------------------------
    def run(self):
        t0 = time.time()
        os.makedirs(self.out_dir, exist_ok=True)
        dw = self.dw
        cu = dw.cu
        dw.name(cu, os.path.basename(self.c_path), raw=True)
        cu.add(C.DW_AT_producer, C.DW_FORM_strp, PRODUCER)
        cu.add(C.DW_AT_language, C.DW_FORM_data2, C.DW_LANG_C99)
        cu.add(C.DW_AT_comp_dir, C.DW_FORM_strp, self.out_dir)
        cu.add(C.DW_AT_low_pc, C.DW_FORM_addr, 0)
        self.file_no = dw.add_file(os.path.basename(self.c_path))

        self.qualified_renames = self._collect_qualified_renames()
        self._write_c_preamble()
        self._export_functions()
        self._export_globals()
        if self.opts.all_types:
            self._export_all_types()
        self.types.flush()

        ranges = sorted(self.func_ranges)
        cu.add(C.DW_AT_ranges, C.DW_FORM_sec_offset, dw.add_ranges(ranges))
        cu.add(C.DW_AT_stmt_list, C.DW_FORM_sec_offset, 0)
        dw.aranges.extend(ranges)

        self._rename_in_types_header()
        with open(self.c_path, "w", encoding="utf-8", errors="replace") as f:
            f.write("\n".join(self.c_lines))
            f.write("\n")

        self._write_elf()
        self.log("ghidra2dwarf-raw: %s" % ", ".join("%s=%d" % kv for kv in sorted(self.stats.items())))
        self.log("ghidra2dwarf-raw: wrote %s and %s in %.1fs" % (self.elf_path, self.c_path, time.time() - t0))

    # -- C file -----------------------------------------------------------------
    def _write_c_preamble(self):
        p = self.program
        self.c_lines += [
            "/*",
            " * Pseudo-C generated by %s from the Ghidra decompiler output." % PRODUCER,
            " *   program:  %s" % p.getName(),
            " *   language: %s (%s)" % (p.getLanguageID(), p.getCompilerSpec().getCompilerSpecID()),
            " * Line numbers in this file are referenced by the DWARF line table",
            " * of %s -- do not edit it." % os.path.basename(self.elf_path),
            " */",
            "",
        ]
        if self.opts.types_header:
            try:
                sw = StringWriter()
                DataTypeWriter(p.getDataTypeManager(), sw, False).write(
                    p.getDataTypeManager().getAllDataTypes(), self.monitor)
                text = str(sw.toString())
            except Exception:
                # Older API: write(List, monitor)
                from java.util import ArrayList
                lst = ArrayList()
                it = p.getDataTypeManager().getAllDataTypes()
                while it.hasNext():
                    lst.add(it.next())
                sw = StringWriter()
                DataTypeWriter(p.getDataTypeManager(), sw, False).write(lst, self.monitor)
                text = str(sw.toString())
            self.c_lines.append("/* ---- Data types ---- */")
            first = len(self.c_lines)
            self.c_lines += text.replace("\r\n", "\n").split("\n")
            self.types_header_lines = (first, len(self.c_lines))
            self.c_lines.append("")

    def _collect_qualified_renames(self):
        """[(qualified name, exported name)] for namespaced symbols whose
        exported name differs (sanitize_names), longest first."""
        if not self.opts.sanitize_names:
            return []
        out = {}
        it = self.program.getSymbolTable().getAllSymbols(False)
        while it.hasNext():
            sym = it.next()
            ns = sym.getParentNamespace()
            if ns is not None and not ns.isGlobal():
                q = str(sym.getName(True))
                if self.nm(q) != q:
                    out[q] = self.nm(q)
        return sorted(out.items(), key=lambda qn: -len(qn[0]))

    def _rename_in_types_header(self):
        """Apply the name filter to the DataTypeWriter output too, so the
        type definitions match the (renamed) DWARF type/field names."""
        span = getattr(self, "types_header_lines", None)
        pairs = dict(self.nm.cache)
        pairs.update(self.nm_type.cache)
        renames = sorted(((o, n) for o, n in pairs.items() if o != n),
                         key=lambda on: -len(on[0]))
        if span is None or not renames:
            return
        for i in range(span[0], span[1]):
            line = self.c_lines[i]
            for o, n in renames:
                if o in line:
                    line = line.replace(o, n)
            self.c_lines[i] = line

    _NAME_TOKENS = None

    def _token_text(self, tok):
        """Token text, with identifiers passed through the name filter."""
        text = str(tok.getText())
        if Exporter._NAME_TOKENS is None:
            from ghidra.app.decompiler import (ClangVariableToken, ClangFieldToken,
                                               ClangTypeToken, ClangLabelToken)
            Exporter._NAME_TOKENS = (ClangVariableToken, ClangFuncNameToken, ClangFieldToken,
                                     ClangTypeToken, ClangLabelToken)
        if (text and text[0] not in "\"'-0123456789" and isinstance(tok, Exporter._NAME_TOKENS)):
            if isinstance(tok, Exporter._NAME_TOKENS[3]):  # ClangTypeToken
                return self.nm_type(text)
            return self.nm(text)
        return text

    # -- functions --------------------------------------------------------------
    def _decompiler(self):
        ifc = DecompInterface()
        opts = DecompileOptions()
        opts.grabFromProgram(self.program)
        ifc.setOptions(opts)
        ifc.toggleCCode(True)
        ifc.toggleSyntaxTree(True)
        ifc.setSimplificationStyle("decompile")
        if not ifc.openProgram(self.program):
            raise RuntimeError("decompiler failed to open program: %s" % ifc.getLastMessage())
        return ifc

    def _export_functions(self):
        fm = self.program.getFunctionManager()
        funcs = [f for f in fm.getFunctions(True)
                 if not f.isExternal() and self.in_space(f.getEntryPoint())]
        skipped = fm.getFunctionCount() - len(funcs)
        if skipped:
            self.log("Skipping %d external/non-default-space functions" % skipped)
        self.monitor.initialize(len(funcs))
        self.monitor.setMessage("Decompiling functions")
        ifc = self._decompiler()
        try:
            for i, func in enumerate(funcs):
                self.monitor.checkCancelled()
                self.monitor.setProgress(i)
                if i % 200 == 0:
                    self.log("[%d/%d] %s" % (i, len(funcs), func.getName()))
                self._export_function(ifc, func)
        finally:
            ifc.dispose()

    def _function_ranges(self, func):
        entry = int(func.getEntryPoint().getOffset())
        ranges = []
        for r in func.getBody().getAddressRanges():
            if not self.in_space(r.getMinAddress()):
                continue
            ranges.append((int(r.getMinAddress().getOffset()), int(r.getMaxAddress().getOffset()) + 1))
        ranges.sort()
        # The range holding the entry point goes first: GDB uses the start of
        # the first DW_AT_ranges entry as a non-contiguous function's entry.
        first = [r for r in ranges if r[0] <= entry < r[1]]
        if first and first[0][0] != entry:
            lo, hi = first[0]
            ranges.remove(first[0])
            ranges = [(entry, hi)] + ranges + [(lo, entry)]
        elif first:
            ranges.remove(first[0])
            ranges = first + ranges
        if not ranges:
            ranges = [(entry, entry + 1)]
        return ranges

    def _export_function(self, ifc, func):
        dw = self.dw
        self.stats["functions"] += 1
        name = _qualified(func)
        entry = int(func.getEntryPoint().getOffset())
        ranges = self._function_ranges(func)

        skipped = (name in self.skip or str(func.getName()) in self.skip
                   or str(func.getEntryPoint()) in self.skip)
        if skipped:
            res = None
        else:
            res = ifc.decompileFunction(func, self.opts.decompile_timeout, self.monitor)
        hf = res.getHighFunction() if res is not None else None
        markup = res.getCCodeMarkup() if res is not None else None

        die = dw.cu.child(C.DW_TAG_subprogram)
        dw.name(die, name)
        die.add(C.DW_AT_external, C.DW_FORM_flag_present)
        die.add(C.DW_AT_prototyped, C.DW_FORM_flag_present)
        if len(ranges) == 1:
            lo, hi = ranges[0]
            die.add(C.DW_AT_low_pc, C.DW_FORM_addr, self.A(lo))
            die.add(C.DW_AT_high_pc, C.DW_FORM_data4, hi - lo)
        else:
            die.add(C.DW_AT_ranges, C.DW_FORM_sec_offset,
                    dw.add_ranges([(self.A(a), self.A(a) + (b - a)) for a, b in ranges]))
        die.add(C.DW_AT_frame_base, C.DW_FORM_exprloc, dw.expr().call_frame_cfa().bytes())
        for lo, hi in ranges:
            self.func_ranges.append((self.A(lo), self.A(lo) + (hi - lo)))

        size = ranges[0][1] - entry
        try:
            flow = FunctionFlow(self.machine, func)
        except Exception as e:
            self.log("WARNING: flow analysis failed for %s: %s" % (name, e))
            flow = None
        if self.cfi is not None and flow is not None:
            self.cfi.add_function(flow, ranges)
        if self._is_thumb(func.getEntryPoint()):
            # ARM ELF: Thumb function symbols have bit 0 set, and mapping
            # symbols ($t/$a) tell GDB the instruction set of each region.
            self.elf_symbols.append((name, self.A(entry) | 1, size, C.STT_FUNC))
            self.elf_symbols.append(("$t", self.A(entry), 0, C.STT_NOTYPE, 0, C.STB_LOCAL))
        else:
            self.elf_symbols.append((name, self.A(entry), size, C.STT_FUNC) + self._symbol_isa_bits(func))
            if str(self.lang.getProcessor()) == "ARM":
                self.elf_symbols.append(("$a", self.A(entry), 0, C.STT_NOTYPE, 0, C.STB_LOCAL))

        self.c_lines.append("")
        self.c_lines.append("/* ---- %s @ %s ---- */" % (self.nm(name), func.getEntryPoint()))
        base = len(self.c_lines)  # line N of the function text -> base + N

        if markup is None or hf is None:
            self.stats["decompile_failed"] += 1
            msg = res.getErrorMessage() if res is not None else (
                "skipped (skip_decompile)" if skipped else "no result")
            sig = str(func.getSignature().getPrototypeString())
            self.c_lines.append("%s /* decompilation failed: %s */" % (sig, str(msg).strip().replace("*/", "* /")))
            sig_line = base + 1
            self.types.ref(die, func.getReturnType())
            addr_lines = {}
        else:
            self._code_decls = self._find_code_decls(markup)
            lines = DecompilerUtils.toLines(markup)
            addr_lines = {}
            sig_line = None
            for cl in lines:
                text = str(cl.getIndentString()) + "".join(self._token_text(t) for t in cl.getAllTokens())
                if self.qualified_renames and "::" in text:
                    # the decompiler emits "Ns::name" as several tokens
                    for q, new in self.qualified_renames:
                        if q in text:
                            text = text.replace(q, new)
                self.c_lines.append(text)
                gline = base + int(cl.getLineNumber())
                for tok in cl.getAllTokens():
                    if sig_line is None and isinstance(tok, ClangFuncNameToken):
                        sig_line = gline
                    if isinstance(tok, ClangCommentToken):
                        continue  # "/* WARNING: ... */" comments carry addresses too
                    a = tok.getMinAddress()
                    if a is None or not self.in_space(a):
                        continue
                    off = int(a.getOffset())
                    prev = addr_lines.get(off)
                    if prev is None or gline < prev:
                        addr_lines[off] = gline
            if sig_line is None:
                sig_line = base + 1
            proto = hf.getFunctionPrototype()
            self.types.ref(die, proto.getReturnType() if proto is not None else func.getReturnType())
            self._export_variables(die, func, hf, ranges, flow)
        if func.hasVarArgs():
            die.child(C.DW_TAG_unspecified_parameters)

        die.add(C.DW_AT_decl_file, C.DW_FORM_udata, self.file_no)
        die.add(C.DW_AT_decl_line, C.DW_FORM_udata, sig_line)

        # Line rows: the frame setup maps to the signature line, and the first
        # body instruction is flagged prologue_end so GDB (>= 13) places
        # "break func" there -- for frameless functions that is the entry
        # point itself, with all arguments still in their registers.
        local_entry = (self._ppc64_local_entry(func)
                       if str(self.lang.getProcessor()) == "PowerPC" and self.addr_size == 8 else 0)
        pe = flow.prologue_end(local_entry) if flow is not None else None
        if pe is not None:
            body_line = addr_lines.get(pe)
            if body_line is None:
                later = [a for a in addr_lines if a > pe and ranges[0][0] <= a < ranges[0][1]]
                body_line = addr_lines[min(later)] if later else sig_line
            addr_lines[pe] = body_line
            if pe != entry:
                addr_lines[entry] = sig_line
        else:
            addr_lines[entry] = sig_line
        for lo, hi in ranges:
            rows = sorted((a, l) for a, l in addr_lines.items() if lo <= a < hi)
            if not rows or rows[0][0] != lo:
                prev = [l for a, l in sorted(addr_lines.items()) if a < lo]
                rows.insert(0, (lo, prev[-1] if prev else sig_line))
            compact = []
            for a, l in rows:
                if not compact or compact[-1][1] != l or a == pe:
                    compact.append((a, l))
            out_rows = [(self.A(a), l, ROW_PROLOGUE_END if a == pe else 0) for a, l in compact]
            if (self.opts.frameless_rows and pe == entry and lo == entry and out_rows
                    and out_rows[0][1] != sig_line):
                # Frameless function: like GCC, emit the signature line and
                # the first statement at the same (entry) address. GDB's
                # line-based prologue skipping (used when stepping into a
                # function) then stops at the entry instead of running an
                # architecture prologue analyzer over real code.
                out_rows.insert(0, (self.A(entry), sig_line, 0))
            self.stats["line_rows"] += len(out_rows)
            self.dw.add_sequence(out_rows, self.A(lo) + (hi - lo))

    # -- variables -------------------------------------------------------------
    def _export_variables(self, func_die, func, hf, ranges, flow):
        lsm = hf.getLocalSymbolMap()
        params = []
        for i in range(lsm.getNumParams()):
            s = lsm.getParamSymbol(i)
            if s is not None:
                params.append(s)
        param_ids = set(int(s.getId()) for s in params)
        others = []
        it = lsm.getSymbols()
        while it.hasNext():
            s = it.next()
            if int(s.getId()) not in param_ids:
                others.append(s)

        ctx = _FunctionContext(self, func, hf, ranges, flow)
        for sym in params:
            self._export_variable(func_die, sym, ctx, True)
        for sym in others:
            self._export_variable(func_die, sym, ctx, sym.isParameter())

    @staticmethod
    def _find_code_decls(markup):
        """{variable name: pointer depth} for variables the decompiler
        declares as "code *" -- its placeholder for function pointers of
        unknown type, which the Java API reports as plain "undefined *"."""
        from ghidra.app.decompiler import ClangVariableDecl, ClangTokenGroup
        out = {}
        stack = [markup]
        while stack:
            node = stack.pop()
            if isinstance(node, ClangVariableDecl):
                m = re.match(r"\s*code\s*(\*+)", str(node.toString()))
                hs = node.getHighSymbol()
                if m and hs is not None:
                    out[str(hs.getName())] = len(m.group(1))
                continue
            if isinstance(node, ClangTokenGroup):
                for i in range(node.numChildren()):
                    stack.append(node.Child(i))
        return out

    def _export_variable(self, func_die, sym, ctx, is_param):
        self.stats["variables"] += 1
        tag = C.DW_TAG_formal_parameter if is_param else C.DW_TAG_variable
        die = func_die.child(tag)
        self.dw.name(die, str(sym.getName()))
        depth = getattr(self, "_code_decls", {}).get(str(sym.getName()))
        if depth and classify(sym.getDataType()) == "ptr":
            die.add(C.DW_AT_type, C.DW_FORM_ref4, self.types.code_pointer(depth))
        else:
            self.types.ref(die, sym.getDataType())
        try:
            loc = ctx.symbol_location(sym)
        except Exception as e:  # never let one odd variable kill the export
            self.log("WARNING: %s/%s: location failed: %s" % (ctx.func.getName(), sym.getName(), e))
            loc = None
        if loc is None:
            return
        self.stats["variables_located"] += 1
        kind, value = loc
        if kind == "expr":
            die.add(C.DW_AT_location, C.DW_FORM_exprloc, value)
        else:
            die.add(C.DW_AT_location, C.DW_FORM_sec_offset, self.dw.add_loclist(value))

    # -- globals ---------------------------------------------------------------
    def _export_globals(self):
        self.monitor.setMessage("Exporting global data")
        seen = set()
        it = self.listing.getDefinedData(True)
        while it.hasNext():
            self.monitor.checkCancelled()
            data = it.next()
            addr = data.getAddress()
            if not self.in_space(addr):
                continue
            sym = data.getPrimarySymbol()
            if sym is None:
                continue
            name = _qualified(sym)
            dt = data.getDataType()
            length = int(data.getLength())
            die = self.dw.cu.child(C.DW_TAG_variable)
            self.dw.name(die, name)
            die.add(C.DW_AT_external, C.DW_FORM_flag_present)
            if dt is not None and dt.getLength() > 0:
                self.types.ref(die, dt)
            elif length > 0:
                # dynamic-size data (strings, ...): byte array of the real size
                arr = self.dw.cu.child(C.DW_TAG_array_type)
                arr.add(C.DW_AT_type, C.DW_FORM_ref4, self.types.base_of_size(1, False))
                arr.child(C.DW_TAG_subrange_type).add(C.DW_AT_count, C.DW_FORM_udata, length)
                die.add(C.DW_AT_type, C.DW_FORM_ref4, arr)
            die.add(C.DW_AT_location, C.DW_FORM_exprloc,
                    self.dw.expr().addr(self.A(addr.getOffset())).bytes())
            self.elf_symbols.append((name, self.A(addr.getOffset()), length, C.STT_OBJECT))
            seen.add(int(addr.getOffset()))
            self.stats["globals"] += 1

        # Other (non-code) labels, e.g. on undefined memory: ELF symbols only.
        st = self.program.getSymbolTable()
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            s = sit.next()
            if s.getSymbolType() != SymbolType.LABEL:
                continue
            addr = s.getAddress()
            if not self.in_space(addr) or int(addr.getOffset()) in seen:
                continue
            if self.listing.getInstructionContaining(addr) is not None:
                continue  # code labels would confuse GDB's <func+off> display
            if s.isDynamic() and self.listing.getDefinedDataContaining(addr) is not None:
                continue
            self.elf_symbols.append((_qualified(s), self.A(addr.getOffset()), 0, C.STT_NOTYPE))

    def _export_all_types(self):
        it = self.program.getDataTypeManager().getAllDataTypes()
        while it.hasNext():
            dt = it.next()
            if isinstance(dt, (Structure, Union, Enum, TypeDef)):
                self.types.get(dt)

    # -- ELF ---------------------------------------------------------------
    def _elf_machine(self):
        proc = str(self.lang.getProcessor())
        pair = C.ELF_MACHINES.get(proc)
        if pair is None:
            self.log("WARNING: no ELF machine for processor %s; using EM_NONE "
                     "(use 'set architecture' in GDB)" % proc)
            return 0, 0
        machine = pair[1] if self.addr_size == 8 else pair[0]
        if self.opts.elf_flags >= 0:
            return machine, self.opts.elf_flags
        return machine, self._elf_flags(proc)

    def _arm_attributes(self, flags):
        """Minimal .ARM.attributes: GDB takes the float ABI (where float/double
        arguments and return values live) from Tag_ABI_VFP_args, not e_flags."""
        import struct
        from .dwarf import uleb
        end = ">" if self.big_endian else "<"
        attrs = uleb(28) + uleb(1 if flags & 0x400 else 0)        # Tag_ABI_VFP_args
        file_sub = bytes([1]) + struct.pack(end + "I", 5 + len(attrs)) + attrs   # Tag_File
        vendor = b"aeabi\0" + file_sub
        return b"A" + struct.pack(end + "I", 4 + len(vendor)) + vendor

    def _is_thumb(self, addr):
        if str(self.lang.getProcessor()) != "ARM":
            return False
        ctx = self.program.getProgramContext()
        treg = ctx.getRegister("TMode")
        if treg is None:
            return False
        v = ctx.getValue(treg, addr, False)
        return v is not None and v.intValue() == 1

    def _symbol_isa_bits(self, func):
        """Extra (st_other,) for a function symbol: PPC64 ELFv2 local entry."""
        if str(self.lang.getProcessor()) == "PowerPC" and self.addr_size == 8:
            le = self._ppc64_local_entry(func)
            if le:
                return ((3 << 5),)   # STO_PPC64_LOCAL: local entry at +8
        return ()

    def _float_regs_for_args(self):
        cc = self.program.getCompilerSpec().getDefaultCallingConvention()
        try:
            for st in cc.getPotentialInputRegisterStorage(self.program):
                for vn in st.getVarnodes():
                    reg = self.program.getRegister(vn)
                    if reg is not None and re.match(r"^[sdf]\d+$", str(reg.getName())):
                        return True
        except Exception:
            pass
        return False

    def _elf_flags(self, proc):
        """e_flags GDB uses to pick the ABI (it matters for return values,
        FPU register layout and instruction byte order)."""
        from ghidra.program.model.lang import Endian
        desc = self.lang.getLanguageDescription()
        if proc == "ARM":
            flags = 0x05000000                                  # EF_ARM_EABI_VER5
            if self.big_endian and desc.getInstructionEndian() == Endian.LITTLE:
                flags |= 0x00800000                             # EF_ARM_BE8
            flags |= 0x400 if self._float_regs_for_args() else 0x200   # ABI_FLOAT_HARD/SOFT
            return flags
        if proc == "MIPS":
            if self.addr_size == 8:
                return 0x80000000                               # EF_MIPS_ARCH_64R2 (n64)
            cspec = str(self.program.getCompilerSpec().getCompilerSpecID())
            abi = 0x3000 if "eabi" in cspec else 0x1000         # EABI32 / O32
            return 0x70000000 | abi                             # EF_MIPS_ARCH_32R2
        if proc == "PowerPC" and self.addr_size == 8:
            if not self.big_endian or self._ppc64_has_global_entries():
                return 2                                        # ELFv2
            return 1                                            # ELFv1 (function descriptors)
        return 0

    # ELFv2 global entry: TOC setup in r2, PC-relative (addis r2,r12,..) or
    # absolute in non-PIC code (lis r2,..), followed by addi r2,r2,..
    _GLOBAL_ENTRY = re.compile(r"^(addis r2,r12,|lis r2,)")

    def _ppc64_local_entry(self, func):
        """ELFv2: a function starting with a two-instruction TOC setup
        ("addis r2,r12,..; addi r2,r2,.." or "lis r2,..; addi r2,r2,..") has a
        local entry point 8 bytes in; local calls use it, so GDB must know
        (symbol st_other) to put breakpoints there."""
        ins = self.listing.getInstructionAt(func.getEntryPoint())
        if ins is None or not self._GLOBAL_ENTRY.match(str(ins)):
            return 0
        nxt = ins.getNext()
        if nxt is None or not re.match(r"^(addi|subi|addic) r2,r2,", str(nxt)):
            return 0
        return 8

    def _ppc64_has_global_entries(self):
        if not hasattr(self, "_ppc64_ge"):
            self._ppc64_ge = any(self._ppc64_local_entry(f) for f in
                                 self.program.getFunctionManager().getFunctions(True)
                                 if not f.isExternal())
        return self._ppc64_ge

    def _code_ranges(self):
        """Sorted, merged [(lo, hi)] Ghidra offsets covered by function bodies."""
        rs = []
        for f in self.program.getFunctionManager().getFunctions(True):
            if f.isExternal():
                continue
            for r in f.getBody().getAddressRanges():
                if self.in_space(r.getMinAddress()):
                    rs.append((int(r.getMinAddress().getOffset()), int(r.getMaxAddress().getOffset()) + 1))
        rs.sort()
        merged = []
        for lo, hi in rs:
            if merged and lo <= merged[-1][1] + 16:  # alignment padding between functions
                merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
            else:
                merged.append((lo, hi))
        return merged

    MAX_SECTION_RUNS = 20000

    def _split_runs(self, lo, hi, code):
        """Partition [lo, hi) into [(start, end, is_code)] runs."""
        runs = []
        pos = lo
        i = bisect.bisect_left(code, (lo, lo))
        if i > 0 and code[i - 1][1] > lo:
            i -= 1
        while i < len(code) and code[i][0] < hi:
            clo, chi = max(code[i][0], lo), min(code[i][1], hi)
            if clo > pos:
                runs.append((pos, clo, False))
            if chi > clo:
                runs.append((max(clo, pos), chi, True))
                pos = chi
            i += 1
        if pos < hi:
            runs.append((pos, hi, False))
        if len(runs) > self.MAX_SECTION_RUNS or not runs:
            return [(lo, hi, True)]
        return runs

    def _write_elf(self):
        machine, flags = self._elf_machine()
        entry = 0
        eps = self.program.getSymbolTable().getExternalEntryPointIterator()
        while eps.hasNext():
            a = eps.next()
            if self.in_space(a):
                entry = self.A(a.getOffset())
                break
        elf = ElfWriter(self.addr_size == 8, self.big_endian, machine, flags, entry)

        code = self._code_ranges()
        # the code run holding the most function bytes becomes ".text"
        text_lo = max(code, key=lambda r: r[1] - r[0])[0] if code else None
        text_done = False
        for block in self.memory.getBlocks():
            start = block.getStart()
            if not block.isLoaded() or block.isOverlay() or not self.in_space(start):
                continue
            base_flags = C.SHF_ALLOC | (C.SHF_WRITE if block.isWrite() else 0)
            lo = int(start.getOffset())
            hi = lo + int(block.getSize())
            name = str(block.getName())
            if block.isExecute() and self.opts.split_sections:
                # GDB classifies symbols (function vs data) by the flags of
                # their section, and raw dumps are often one RWX block: emit
                # code and data runs as separate sections.
                runs = self._split_runs(lo, hi, code)
            else:
                runs = [(lo, hi, bool(block.isExecute()))]
            data = None
            if self.opts.embed_bytes and block.isInitialized():
                import jpype
                buf = jpype.JArray(jpype.JByte)(hi - lo)
                block.getBytes(start, buf)
                data = memoryview(buf).cast("B").tobytes()
            for rlo, rhi, is_code in runs:
                if not is_code and block.isExecute() and str(self.lang.getProcessor()) == "ARM":
                    elf.add_symbol("$d", self.A(rlo), 0, C.STT_NOTYPE, C.STB_LOCAL, C.SHN_ABS)
                sflags = base_flags | (C.SHF_EXECINSTR if is_code else 0)
                if is_code and text_lo is not None and rlo <= text_lo < rhi and not text_done:
                    # GDB files its DWARF function symbols under the section
                    # named ".text" (falling back to a heuristic that can pick
                    # a data section, which breaks "list func"/"info line
                    # func"), so the main code run must be called .text.
                    sname = ".text"
                    text_done = True
                elif is_code:
                    sname = "%s.text" % name
                elif block.isExecute():
                    sname = "%s.data" % name
                else:
                    sname = name
                if data is not None:
                    sec = Section(sname, C.SHT_PROGBITS, sflags, self.A(rlo), data[rlo - lo:rhi - lo])
                else:
                    sec = Section(sname, C.SHT_NOBITS, sflags, self.A(rlo), size=rhi - rlo)
                elf.add_section(sec)

        for name, data in self.dw.build():
            elf.add_section(Section(name, C.SHT_PROGBITS, data=data))
        if str(self.lang.getProcessor()) == "ARM":
            elf.add_section(Section(".ARM.attributes", 0x70000003, data=self._arm_attributes(flags)))

        for sym in self.elf_symbols:
            name, value, size, stype = sym[:4]
            other = sym[4] if len(sym) > 4 else 0
            bind = sym[5] if len(sym) > 5 else C.STB_GLOBAL
            if not name.startswith("$"):
                name = self.nm(name)
            elf.add_symbol(name, value, size, stype, bind, elf.section_index_for(value), other)
        elf.write(self.elf_path)


# ----------------------------------------------------------------------------
# Per-function variable location computation
# ----------------------------------------------------------------------------

class _FunctionContext(object):
    """Computes DWARF locations for decompiler variables of one function.

    A decompiler HighVariable is a set of SSA varnode instances. For each
    instance we compute where its *value* is live from the decompiler's data
    flow (def -> uses over the basic-block graph). Because the decompiler
    copy-propagates away register moves and spills, the instance's own
    storage is often not where the value physically is (e.g. a parameter
    kept in a callee-saved register across calls), so at every PC in the
    live range we ask the machine-level FunctionFlow which registers / stack
    slots hold that value and pick the most robust one (call-preserved
    registers and stack slots first, so outer frames unwind correctly)."""

    def __init__(self, exp, func, hf, ranges, flow=None):
        self.exp = exp
        self.flow = flow
        self.func = func
        self.hf = hf
        self.ranges = ranges
        self.entry = int(func.getEntryPoint().getOffset())
        blocks = hf.getBasicBlocks()
        self.entry_block = blocks.get(0) if blocks.size() else None

    # -- storage -> expression ------------------------------------------------
    def _signed(self, value, size):
        bits = 8 * size
        value &= (1 << bits) - 1
        return value - (1 << bits) if value >> (bits - 1) else value

    def reg_expr(self, off, size):
        """DWARF expression for register-space bytes [off, off+size)."""
        exp = self.exp
        hit = exp.regs.lookup(off, size)
        if hit is None:
            return self._multi_reg_expr(off, size)
        regno, roff, rsize = hit
        e = exp.dw.expr().reg(regno)
        if size == rsize:
            return e.bytes()
        # Low-order part of a wider register: GDB right-justifies values
        # smaller than the register on big-endian targets, so a plain
        # DW_OP_reg is correct. Other parts need a bit_piece.
        low_part = (off + size == roff + rsize) if exp.big_endian else (off == roff)
        if low_part:
            return e.bytes()
        shift = (roff + rsize - (off + size)) * 8 if exp.big_endian else (off - roff) * 8
        return e.bit_piece(size * 8, shift).bytes()

    def _multi_reg_expr(self, off, size):
        """A value spanning several whole registers (e.g. a 64-bit value in
        r3:r4 on PPC32). Ghidra's register space lays registers out in
        memory byte order, so increasing offsets are DWARF piece order."""
        exp = self.exp
        out = bytearray()
        pos, end = off, off + size
        by_start = {}
        for start, rsize, num in exp.regs.entries:
            if start not in by_start or rsize > by_start[start][0]:
                if start + rsize <= end:
                    by_start[start] = (rsize, num)
        while pos < end:
            hit = by_start.get(pos)
            if hit is None:
                return None
            rsize, num = hit
            out += exp.dw.expr().reg(num).piece(rsize).bytes()
            pos += rsize
        return bytes(out) if len(out) else None

    def varnode_expr(self, vn):
        """DWARF expression for a single varnode, or None."""
        exp = self.exp
        addr = vn.getAddress()
        space = addr.getAddressSpace()
        size = int(vn.getSize())
        if space.isRegisterSpace():
            return self.reg_expr(int(addr.getOffset()), size)
        if space.isStackSpace():
            off = self._signed(int(addr.getOffset()), int(space.getSize()) // 8 or 4)
            return exp.dw.expr().fbreg(off - exp.stackshift).bytes()
        if space.equals(exp.space):
            return exp.dw.expr().addr(exp.A(addr.getOffset())).bytes()
        return None

    def storage_expr(self, storage):
        """Expression for a (possibly compound) VariableStorage."""
        vns = list(storage.getVarnodes())
        if not vns:
            return None
        if len(vns) == 1:
            return self.varnode_expr(vns[0])
        # Ghidra lists compound storage most-significant piece first; DWARF
        # pieces go in memory order.
        if not self.exp.big_endian:
            vns.reverse()
        out = bytearray()
        for vn in vns:
            e = self.varnode_expr(vn)
            if e is None:
                return None
            out += e
            out.append(C.DW_OP_piece)
            out += uleb(int(vn.getSize()))
        return bytes(out)

    # -- liveness ----------------------------------------------------------------
    def _block_bounds(self, block):
        start = block.getStart()
        stop = block.getStop()
        if start is None or stop is None:
            return None
        return int(start.getOffset()), self.exp.insn_end(stop)

    def live_intervals(self, vn):
        """[(start, end)] Ghidra offsets where the varnode holds its value."""
        out = []
        defop = vn.getDef()
        if defop is None:
            if not vn.isInput() or self.entry_block is None:
                return out
            dblock = self.entry_block
            dpoint = self.entry
        else:
            dblock = defop.getParent()
            target = defop.getSeqnum().getTarget()
            if defop.getOpcode() == PcodeOp.MULTIEQUAL:
                b = self._block_bounds(dblock)
                dpoint = b[0] if b else int(target.getOffset())
            else:
                dpoint = self.exp.insn_end(target)
        dindex = int(dblock.getIndex())

        visited = set()
        work = []

        def live_out(block):
            work.append(block)

        uses = vn.getDescendants()
        while uses.hasNext():
            op = uses.next()
            if op.getOpcode() == PcodeOp.MULTIEQUAL:
                parent = op.getParent()
                for slot in range(op.getNumInputs()):
                    inp = op.getInput(slot)
                    if inp is not None and inp.equals(vn) and slot < parent.getInSize():
                        live_out(parent.getIn(slot))
                continue
            ublock = op.getParent()
            uend = self.exp.insn_end(op.getSeqnum().getTarget())
            if int(ublock.getIndex()) == dindex and dpoint < uend:
                out.append((dpoint, uend))
            else:
                b = self._block_bounds(ublock)
                if b is None:
                    continue
                out.append((b[0], uend))
                for i in range(ublock.getInSize()):
                    live_out(ublock.getIn(i))

        while work:
            block = work.pop()
            idx = int(block.getIndex())
            if idx in visited:
                continue
            visited.add(idx)
            b = self._block_bounds(block)
            if b is None:
                continue
            if idx == dindex:
                out.append((dpoint, b[1]))
                continue
            out.append(b)
            for i in range(block.getInSize()):
                work.append(block.getIn(i))
        return out

    # -- physical location of values ------------------------------------------
    def _unique_home(self, vn):
        """Register a temporary (unique-space, HASH storage) decompiler
        instance was physically written to: the register of the same size
        that its defining instruction writes (same opcode preferred)."""
        d = vn.getDef()
        if d is None or self.flow is None or d.getOpcode() == PcodeOp.MULTIEQUAL:
            return None
        off = int(d.getSeqnum().getTarget().getOffset())
        dec = self.flow.decoded.get(off)
        if dec is None:
            return None
        size = int(vn.getSize())
        cands = [(opc, (out[1], out[2])) for opc, out, _, _, _ in dec[5]
                 if out is not None and out[0] == "r" and out[2] == size]
        same = [k for opc, k in cands if opc == d.getOpcode()]
        keys = same or [k for _, k in cands]
        keys = list(dict.fromkeys(keys))
        if keys:
            return keys[-1] if len(keys) == 1 or same else None
        # A 32-bit result written to a 64-bit register (AArch64 "add w0,.."
        # is X0 = zext(..), MIPS64/PPC64 sign-extend): the low part.
        wide = list(dict.fromkeys((out[1], out[2]) for opc, out, _, _, _ in dec[5]
                                  if out is not None and out[0] == "r" and out[2] > size
                                  and self.exp.machine.dwarf_of((out[1], out[2])) is not None))
        if len(wide) != 1:
            return None
        off_, sz = wide[0]
        return (off_ + (sz - size if self.exp.big_endian else 0), size)

    def instance_value(self, vn):
        """FunctionFlow value id of a register varnode instance, or None."""
        flow = self.flow
        if flow is None:
            return None
        if vn.isUnique():
            home = self._unique_home(vn)
            if home is None:
                return None
            return flow.value_after(int(vn.getDef().getSeqnum().getTarget().getOffset()), home)
        if not vn.isRegister():
            return None
        key = (int(vn.getOffset()), int(vn.getSize()))
        d = vn.getDef()
        if d is None:
            return flow.default(key) if vn.isInput() else None
        if d.getOpcode() == PcodeOp.MULTIEQUAL:
            b = self._block_bounds(d.getParent())
            return flow.value_before(b[0], key) if b else None
        return flow.value_after(int(d.getSeqnum().getTarget().getOffset()), key)

    def best_location(self, locs, own):
        best = None
        m = self.exp.machine
        for kind, where in locs:
            if kind == "reg":
                e = self.reg_expr(where[0], where[1])
                if e is None:
                    continue
                rank = 0 if m.is_preserved(where) else (2 if where == own else 3)
            else:
                e = self.exp.dw.expr().fbreg(where - self.exp.stackshift).bytes()
                rank = 1
            cand = (rank, e)
            if best is None or cand < best:
                best = cand
        return best[1] if best is not None else None

    def located_pcs(self, vn, value, pcs):
        flow = self.flow
        own = (int(vn.getOffset()), int(vn.getSize())) if vn.isRegister() else None
        out = []
        for pc in pcs:
            e = self.best_location(flow.locations_of(pc, value), own)
            if e is not None:
                out.append((pc, flow.insn_end(pc), e))
        return out

    def _pcs_in(self, spans):
        insns = self.flow.insns
        out = []
        for s, t in spans:
            i = bisect.bisect_left(insns, s)
            while i < len(insns) and insns[i] < t:
                out.append(insns[i])
                i += 1
        return out

    def _block_info(self):
        """{block index: (bounds, [pcs], [pred block indexes])}, cached."""
        if getattr(self, "_binfo", None) is None:
            info = {}
            for b in self.hf.getBasicBlocks():
                bounds = self._block_bounds(b)
                pcs = self._pcs_in([bounds]) if bounds is not None else []
                preds = [int(b.getIn(k).getIndex()) for k in range(b.getInSize())]
                info[int(b.getIndex())] = (bounds, pcs, preds)
            self._binfo = info
        return self._binfo

    def reaching_pcs(self, instances):
        """{instance index: [pc]} -- the PCs at which each SSA instance is
        the variable's current value (reaching definition over the
        decompiler's basic blocks). This shows a variable for as long as it
        has not been reassigned, not only while the decompiler still needs
        it; FunctionFlow then decides whether the value still physically
        exists."""
        flow = self.flow
        if flow is None or self.entry_block is None:
            return None
        binfo = self._block_info()
        if not binfo:
            return None
        entry_bi = int(self.entry_block.getIndex())
        events = dict((bi, []) for bi in binfo)
        for i, vn in enumerate(instances):
            d = vn.getDef()
            if d is None:
                if vn.isInput():
                    events[entry_bi].append((self.entry, -1, i))
                continue
            bi = int(d.getParent().getIndex())
            if bi not in events:
                continue
            if d.getOpcode() == PcodeOp.MULTIEQUAL:
                bb = binfo[bi][0]
                if bb is None:
                    continue
                events[bi].append((bb[0], -1, i))
            else:
                events[bi].append((self.exp.insn_end(d.getSeqnum().getTarget()),
                                   int(d.getSeqnum().getOrder()), i))
        for ev in events.values():
            ev.sort()

        TOP = "top"
        out_inst = dict((bi, TOP) for bi in binfo)
        in_inst = {}
        for _ in range(4 * len(binfo) + 4):
            changed = False
            for bi, (_, _, preds) in binfo.items():
                if bi == entry_bi:
                    inn = None
                else:
                    vals = set()
                    for pb in preds:
                        vals.add(out_inst.get(pb, None))
                    vals.discard(TOP)
                    inn = vals.pop() if len(vals) == 1 else (TOP if not vals else None)
                in_inst[bi] = inn
                out = events[bi][-1][2] if events[bi] else inn
                if out != out_inst[bi]:
                    out_inst[bi] = out
                    changed = True
            if not changed:
                break

        result = {}
        for bi, (bounds, pcs, _) in binfo.items():
            if bounds is None:
                continue
            cur = in_inst.get(bi)
            if cur == TOP:
                cur = None
            ev = events[bi]
            j = 0
            for pc in pcs:
                while j < len(ev) and ev[j][0] <= pc:
                    cur = ev[j][2]
                    j += 1
                if cur is not None:
                    result.setdefault(cur, []).append(pc)
        return result

    def _unused_param_location(self, sym, storage):
        """A parameter the decompiled code never reads (it may use the raw
        register under another name, e.g. MIPS64 "in_a0" for the 64-bit a0
        when the parameter is its 32-bit low part): show it wherever its
        entry value still physically exists."""
        if (self.flow is None or not sym.isParameter() or storage is None
                or storage.isBadStorage() or storage.isUnassignedStorage()):
            return None
        vns = list(storage.getVarnodes())
        pcs = list(self.flow.insns)
        if len(vns) == 1 and vns[0].isRegister():
            key = (int(vns[0].getOffset()), int(vns[0].getSize()))
            entries = self.located_pcs(vns[0], self.flow.default(key), pcs)
        elif all(v.isRegister() for v in vns):
            entries = self.compound_input_pcs(storage, pcs)
        else:
            return None
        if not entries:
            return None
        A = self.exp.A
        merged = []
        for st_, en, e in sorted(entries, key=lambda x: (x[2], x[0])):
            if merged and merged[-1][2] == e and st_ <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(en, merged[-1][1]), e)
            else:
                merged.append((st_, en, e))
        merged.sort(key=lambda x: x[0])
        return ("list", [(A(a), A(a) + (b - a), e) for a, b, e in merged])

    def compound_input_pcs(self, storage, pcs):
        """Spans where every register piece of an input still holds its
        entry value (a torn 64-bit value is worse than <optimized out>)."""
        flow = self.flow
        e = self.storage_expr(storage)
        if e is None:
            return []
        keys = []
        for p in storage.getVarnodes():
            if p.isRegister():
                keys.append((int(p.getOffset()), int(p.getSize())))
            elif not p.getAddress().isStackAddress():
                return []
        out = []
        for pc in pcs:
            st = flow.state_in.get(pc)
            if st is not None and all(flow.reg_value(st, k) == ("init", k) for k in keys):
                out.append((pc, flow.insn_end(pc), e))
        return out

    # -- main --------------------------------------------------------------------
    def symbol_location(self, sym):
        """Returns ("expr", bytes), ("list", [(start, end, bytes)]) or None."""
        storage = sym.getStorage()
        if storage is not None and not storage.isBadStorage() and not storage.isUnassignedStorage():
            # Stack variables and globals have one home for the whole function.
            if storage.isStackStorage() or storage.isMemoryStorage():
                e = self.storage_expr(storage)
                if e is not None:
                    return ("expr", e)

        hv = sym.getHighVariable()
        if hv is None:
            return self._unused_param_location(sym, storage)
        entries = []
        whole = [(lo, hi) for lo, hi in self.ranges]
        instances = list(hv.getInstances())
        reaching = self.reaching_pcs(instances)
        for idx, vn in enumerate(instances):
            space = vn.getAddress().getAddressSpace()
            if vn.isConstant():
                continue
            if vn.isUnique():
                # temporaries (HASH storage): follow the value from the
                # register their defining instruction wrote
                value = self.instance_value(vn)
                if value is not None and reaching is not None:
                    entries.extend(self.located_pcs(vn, value, reaching.get(idx, [])))
                continue
            if space.isStackSpace():
                e = self.varnode_expr(vn)
                if e is not None:
                    entries.extend((s, t, e) for s, t in whole)
                continue
            if reaching is not None:
                pcs = reaching.get(idx, [])
            elif self.flow is not None:
                pcs = self._pcs_in(self.live_intervals(vn))
            else:
                pcs = None
            if vn.isRegister() and pcs is not None:
                value = self.instance_value(vn)
                if value is not None:
                    entries.extend(self.located_pcs(vn, value, pcs))
                continue
            spans = self.live_intervals(vn)
            if vn.isRegister() or space.equals(self.exp.space):
                e = self.varnode_expr(vn)
            elif (storage is not None and len(storage.getVarnodes()) > 0
                  and (storage.isCompoundStorage() or int(vn.getSize()) <= int(storage.size()))):
                # Join-space value: split over several registers/stack slots
                # (a 64-bit parameter in r3:r4), or a narrower view of one
                # register (a float parameter in an 8-byte FPR -- GDB converts
                # the register format to the declared type itself).
                if vn.isInput() and pcs is not None:
                    entries.extend(self.compound_input_pcs(storage, pcs))
                    continue
                e = self.storage_expr(storage)
            else:
                e = None
            if e is None:
                continue
            entries.extend((s, t, e) for s, t in spans if t > s)
        if not entries:
            return self._unused_param_location(sym, storage)

        # Merge overlapping/adjacent spans that share a location.
        entries.sort(key=lambda x: (x[2], x[0]))
        merged = []
        for s, t, e in entries:
            if merged and merged[-1][2] == e and s <= merged[-1][1]:
                if t > merged[-1][1]:
                    merged[-1] = (merged[-1][0], t, e)
            else:
                merged.append((s, t, e))
        merged.sort(key=lambda x: (x[0], x[1]))
        A = self.exp.A
        return ("list", [(A(s), A(s) + (t - s), e) for s, t, e in merged])
