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
                                   ClangCommentToken, ClangLabelToken)
from ghidra.app.decompiler.component import DecompilerUtils
try:
    from ghidra.app.decompiler import ClangCaseToken
except ImportError:  # (older Ghidra)
    ClangCaseToken = ()
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
from ghidra.program.model.symbol import SourceType, SymbolType

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
        # Write the program's data types as C to <basename>.types.h (the .c
        # files include it).
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
        # Mark interrupt/exception handler frames as signal frames (CIE
        # augmentation "S"): GDB then looks up the interrupted frame at its
        # exact PC (instead of PC-1, which is wrong for an interrupt at a
        # function's first instruction or a line boundary) but labels the
        # handler frame "<signal handler called>" in backtraces.
        self.irq_signal_frame = True
        # The pseudo-C goes to <basename>.src/<basename>.<N>.c, a new file
        # whenever the next function would push the current one over either
        # limit (0 = no limit); data types go to <basename>.types.h.
        # (GDB's source highlighting stalls on huge files.)
        self.c_max_bytes = 100000
        self.c_max_lines = 100000
        # Decompiler worker threads; -1 = min(8, CPUs - 1). 1 = serial.
        self.decompile_threads = -1
        # ELF header e_flags; -1 = derive from the language / compiler spec
        # (ARM EABI/BE8/float ABI, MIPS ABI+ISA, PPC64 ELFv1/ELFv2).
        self.elf_flags = -1
        # Comma-separated function names (or entry addresses) not to
        # decompile, e.g. functions that hang the decompiler. They still get
        # symbols, ranges, CFI and a one-line prototype in the .c file.
        self.skip_decompile = ""

    # valid ranges of the numeric options (None: unbounded)
    _RANGES = {
        "address_offset": (-(1 << 64) + 1, (1 << 64) - 1),
        "decompile_timeout": (1, None),
        "c_max_bytes": (0, None),
        "c_max_lines": (0, None),
        "decompile_threads": (-1, 256),
        "elf_flags": (-1, 0xffffffff),
    }

    def set(self, key, value):
        if not hasattr(self, key):
            raise KeyError("unknown option %r" % key)
        cur = getattr(self, key)
        if isinstance(cur, bool):
            value = str(value).lower() in ("1", "true", "yes", "on")
        elif isinstance(cur, int):
            value = int(str(value), 0)
            lo, hi = self._RANGES.get(key, (None, None))
            if (lo is not None and value < lo) or (hi is not None and value > hi):
                raise ValueError("%s must be in %s..%s, not %d" % (key, lo, "" if hi is None else hi, value))
        elif key == "basename":
            value = str(value)
            if not value or "/" in value or "\\" in value or value in (".", ".."):
                raise ValueError("a file name without directories is needed, not %r" % value)
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

def _string_char_type(data):
    """Character type of a C-style string data item (None for other data,
    e.g. Pascal strings with a length prefix)."""
    from ghidra.program.model.data import StringDataInstance
    dt = data.getDataType()
    if dt is None or "Pascal" in dt.getClass().getSimpleName():
        return None
    sdi = StringDataInstance.getStringDataInstance(data)
    if sdi is None or sdi == StringDataInstance.NULL_INSTANCE:
        return None
    return {1: CharDataType.dataType, 2: WideChar16DataType.dataType,
            4: WideChar32DataType.dataType}.get(_charset_unit(str(sdi.getCharsetName())))


def _charset_unit(cs):
    cs = cs.upper()
    if "32" in cs and ("UTF" in cs or "UCS" in cs):
        return 4
    if "16" in cs or cs.startswith("UCS-2"):
        return 2
    return 1


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
                       AbstractComplexDataType, Undefined, DefaultDataType, CharDataType,
                       WideCharDataType, WideChar16DataType, WideChar32DataType)):
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
        if not hasattr(self, "_dts"):
            self._dts = {}
        self._dts[key] = dt
        self.pending.append((kind, die, dt))
        return die

    def add_tag_typedefs(self):
        """The pseudo-C (like Ghidra) uses struct/union/enum names without
        the tag keyword ("msg local_18;"); C's tag namespace would make GDB
        reject "p sizeof(msg)". Add "typedef struct msg msg;" for each tag
        name no typedef already has."""
        def name_of(dt):
            n = str(dt.getName())
            return self.type_name_filter(n) if self.type_name_filter is not None else n
        taken = set(name_of(dt) for (kind, _, _), (die, dt) in self._entries() if kind in
                    ("typedef", "blob", "rawptr", "base"))
        for (kind, _, _), (die, dt) in self._entries():
            if kind not in ("struct", "union", "enum"):
                continue
            n = name_of(dt)
            if n in taken:
                continue
            taken.add(n)
            td = self.cu.child(C.DW_TAG_typedef)
            self.dw.name(td, n, raw=True)
            td.add(C.DW_AT_type, C.DW_FORM_ref4, die)

    def _entries(self):
        dts = getattr(self, "_dts", {})
        return [(key, (die, dts[key])) for key, die in self.cache.items() if key in dts]

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
        if isinstance(dt, WideChar16DataType):
            self.tname(die, "char16_t")   # GDB's C printer keys UTF-16 strings on
        elif isinstance(dt, WideChar32DataType):
            self.tname(die, "char32_t")   # these names (u"..", U"..")
        else:
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
        if int(dt.getNumElements()) > 0:
            sub.add(C.DW_AT_count, C.DW_FORM_udata, int(dt.getNumElements()))
        # (no count: a flexible array member, "data[]")

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
    def __init__(self, program, monitor, out_dir, options=None, tool=None):
        self.program = program
        self.monitor = monitor
        # The tool (CodeBrowser) when run from the GUI: its decompiler display
        # options (line width, which comments, comment style, ...) shape the
        # C files the way the Decompiler window shows the code.
        self.tool = tool
        self._dec_opts = None
        self.opts = options or Options()
        self.out_dir = os.path.abspath(out_dir)
        base = self.opts.basename or _sanitize_basename(str(program.getName()))
        self.base = base
        self.src_dir_name = base + ".src"
        self.src_dir = os.path.join(self.out_dir, self.src_dir_name)
        self.h_name = base + ".types.h"
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
            self.cfi = CfiGenerator(self.machine, self.dw, self.A, self.entry_points,
                                    irq_signal_frame=self.opts.irq_signal_frame)
        self.c_files = []      # [{"name", "file_no", "lines", "bytes", "funcs"}]
        self.h_lines = []      # the types header
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
        dw.name(cu, "%s/%s.0.c" % (self.src_dir_name, self.base), raw=True)
        cu.add(C.DW_AT_producer, C.DW_FORM_strp, PRODUCER)
        cu.add(C.DW_AT_language, C.DW_FORM_data2, C.DW_LANG_C99)
        cu.add(C.DW_AT_comp_dir, C.DW_FORM_strp, self.out_dir)
        cu.add(C.DW_AT_low_pc, C.DW_FORM_addr, 0)
        self.src_dir_no = dw.add_dir(self.src_dir_name)   # (relative to DW_AT_comp_dir)
        self._new_c_file()

        self.qualified_renames = self._collect_qualified_renames()
        self.interrupts = self._find_interrupt_handlers()
        if self.interrupts:
            fm = self.program.getFunctionManager()
            self.log("Interrupt/exception handlers: %s" % ", ".join(sorted(
                str(fm.getFunctionAt(self.space.getAddress(o)).getName()) for o in self.interrupts)))
        self._write_types_header()
        self._export_functions()
        self._export_globals()
        self._export_equates()
        if self.opts.all_types:
            self._export_all_types()
        self.types.flush()
        self.types.add_tag_typedefs()
        self._add_type_decl_lines()

        ranges = sorted(self.func_ranges)
        cu.add(C.DW_AT_ranges, C.DW_FORM_sec_offset, dw.add_ranges(ranges))
        cu.add(C.DW_AT_stmt_list, C.DW_FORM_sec_offset, 0)
        dw.aranges.extend(ranges)

        self._rename_in_types_header()
        self._write_sources()

        self._write_elf()
        self.log("ghidra2dwarf-raw: %s" % ", ".join("%s=%d" % kv for kv in sorted(self.stats.items())))
        self.log("ghidra2dwarf-raw: wrote %s and %s/ (%d C files) in %.1fs" % (
            self.elf_path, self.src_dir, len(self.c_files), time.time() - t0))

    # -- C file -----------------------------------------------------------------
    def _add_type_decl_lines(self):
        """DW_AT_decl_file/line of struct/union/enum/typedef DIEs: their
        definitions in <name>.types.h (so "info types" shows lines and GDB
        can list the header)."""
        if not self.opts.types_header or not self.h_lines:
            return
        h_no = self.dw.add_file(self.h_name, self.src_dir_no)
        where = {}
        tag_re = re.compile(r"^\s*(?:typedef\s+)?(struct|union|enum)\s+([^\s{;]+)\s*\{")
        td_re = re.compile(r"^\s*typedef\s.*?([^\s*;()\[\]]+)\s*(?:\[[^\]]*\]\s*)*;\s*$")
        for i, text in enumerate(self.h_lines, 1):
            m = tag_re.match(text)
            if m:
                where.setdefault((m.group(1), m.group(2)), i)
                continue
            m = td_re.match(text)
            if m:
                where.setdefault(("typedef", m.group(1)), i)
        for (kind, _, _), (die, dt) in self.types._entries():
            if kind not in ("struct", "union", "enum", "typedef"):
                continue
            line = where.get((kind, str(dt.getName())))
            if line is not None:
                die.add(C.DW_AT_decl_file, C.DW_FORM_udata, h_no)
                die.add(C.DW_AT_decl_line, C.DW_FORM_udata, line)

    def _file_preamble(self, index):
        p = self.program
        return [
            "/*",
            " * Pseudo-C generated by %s from the Ghidra decompiler output" % PRODUCER,
            " * (part %d; the files are split between functions)." % index,
            " *   program:  %s" % p.getName(),
            " *   language: %s (%s)" % (p.getLanguageID(), p.getCompilerSpec().getCompilerSpecID()),
            " * Line numbers in this file are referenced by the DWARF line table",
            " * of %s -- do not edit it." % os.path.basename(self.elf_path),
            " */",
        ] + (['#include "%s"' % self.h_name] if self.opts.types_header else []) + [""]

    def _new_c_file(self):
        index = len(self.c_files)
        name = "%s.%d.c" % (self.base, index)
        lines = self._file_preamble(index)
        self.c_files.append({"name": name, "file_no": self.dw.add_file(name, self.src_dir_no),
                             "lines": lines, "bytes": sum(len(l.encode("utf-8", "replace")) + 1 for l in lines),
                             "funcs": 0})
        return self.c_files[-1]

    def _place_function(self, flines):
        """Appends a function's text to the current C file, or to a new one
        if it would exceed c_max_bytes / c_max_lines (a function is never
        split, so one larger than the limit gets a file of its own).
        Returns (file record, number of lines before the text)."""
        size = sum(len(l.encode("utf-8", "replace")) + 1 for l in flines)
        cur = self.c_files[-1]
        mb, ml = self.opts.c_max_bytes, self.opts.c_max_lines
        if cur["funcs"] and ((mb > 0 and cur["bytes"] + size > mb) or
                             (ml > 0 and len(cur["lines"]) + len(flines) > ml)):
            cur = self._new_c_file()
        off = len(cur["lines"])
        cur["lines"] += flines
        cur["bytes"] += size
        cur["funcs"] += 1
        return cur, off

    def _write_sources(self):
        os.makedirs(self.src_dir, exist_ok=True)
        # remove stale parts of an earlier, longer export
        keep = set(f["name"] for f in self.c_files)
        if self.opts.types_header:
            keep.add(self.h_name)
        ours = re.compile(r"^%s\.(\d+\.c|types\.h)$" % re.escape(self.base))
        for n in os.listdir(self.src_dir):
            if ours.match(n) and n not in keep:
                os.remove(os.path.join(self.src_dir, n))
        for f in self.c_files:
            with open(os.path.join(self.src_dir, f["name"]), "w", encoding="utf-8", errors="replace") as out:
                out.write("\n".join(f["lines"]))
                out.write("\n")
        if self.opts.types_header:
            with open(os.path.join(self.src_dir, self.h_name), "w", encoding="utf-8", errors="replace") as out:
                out.write("\n".join(self.h_lines))
                out.write("\n")

    def _write_types_header(self):
        if not self.opts.types_header:
            return
        p = self.program
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
        guard = re.sub(r"[^A-Za-z0-9]", "_", self.h_name).upper()
        self.h_lines += [
            "/* Data types of %s, generated by %s (included by the .c files). */" % (p.getName(), PRODUCER),
            "#ifndef %s" % guard, "#define %s" % guard, "",
        ]
        first = len(self.h_lines)
        self.h_lines += text.replace("\r\n", "\n").split("\n")
        self.types_header_lines = (first, len(self.h_lines))
        self.h_lines += ["", "#endif"]

    # Instructions returning from an interrupt/exception.
    _IRQ_RETURN = re.compile(r"^(rfi|rfid|hrfid|rfci|rfmci|rfdi|rfgi|eret|eretaa|eretab|deret|"
                             r"iret|iretd|iretq)$", re.I)

    def _is_vector_address(self, off):
        """Classic PowerPC exception vectors (0x200..0x2f00 above 0x0 or
        0xfff00000)."""
        if str(self.lang.getProcessor()) != "PowerPC":
            return False
        base = off & ~0xFFFF
        rel = off - base
        # 0x100 is system reset: no interrupted context to return to
        return base in (0, 0xFFF00000, 0xFFFFFFFFFFF00000) and 0x200 <= rel < 0x3000 and rel % 0x100 == 0

    @staticmethod
    def _is_call_insn(ins):
        """A real call (its own p-code has a CALL), whatever Ghidra's flow
        override or no-return typing makes of it."""
        try:
            ops = ins.getPcode(False)
        except Exception:  # noqa: BLE001
            ops = ins.getPcode()
        return any(int(op.getOpcode()) in (PcodeOp.CALL, PcodeOp.CALLIND) for op in ops)

    def _is_branch_insn(self, ins):
        """An unconditional branch ("b f"): after analysis Ghidra often types
        it as a CALL_TERMINATOR (tail call) -- but so is "bl f" to a no-return
        function, which is a call."""
        ft = ins.getFlowType()
        if ft.isConditional() or not (ft.isJump() and not ft.isCall() or ft.isCall() and ft.isTerminal()):
            return False
        return not self._is_call_insn(ins)

    def _find_interrupt_handlers(self):
        """Entry offsets of functions entered by the hardware, which get
        interrupt-frame CFI:
          * functions tagged INTERRUPT in Ghidra;
          * external entry points at exception vector addresses;
          * functions returning with rfi/rfid/rfci/rfmci, eret, iret, ...,
            and functions an interrupt handler branches (not calls) to --
            unless other code calls or branches to them too: a C function
            a vector stub jumps to that normal code also calls (a fatal
            error handler), or a function that returns with rfi to its
            caller ("mtsrr0 lr; mtsrr1 r3; rfi" to set the MSR), is an
            ordinary function."""
        fm = self.program.getFunctionManager()
        refs = self.program.getReferenceManager()
        eps = set(self.entry_points)
        found = set()
        candidates = set()
        funcs = [f for f in fm.getFunctions(True) if not f.isExternal() and self.in_space(f.getEntryPoint())]
        for f in funcs:
            entry = int(f.getEntryPoint().getOffset())
            tags = set(str(t.getName()).upper() for t in f.getTags())
            if "INTERRUPT" in tags or (entry in eps and self._is_vector_address(entry)):
                found.add(entry)
                continue
            for ins in self.listing.getInstructions(f.getBody(), True):
                if self._IRQ_RETURN.match(str(ins.getMnemonicString())):
                    candidates.add(entry)
                    break

        def only_from_handlers(entry):
            """Every code reference to the function is a branch from a
            handler (none at all: entered by the hardware only)."""
            for r in refs.getReferencesTo(self.space.getAddress(entry)):
                if not r.getReferenceType().isFlow():
                    continue
                src = r.getFromAddress()
                g = fm.getFunctionContaining(src)
                if g is None or int(g.getEntryPoint().getOffset()) not in found:
                    return False
                ins = self.listing.getInstructionAt(src)
                if ins is None or self._is_call_insn(ins):
                    return False
            return True

        changed = True
        while changed:
            changed = False
            for f in [fm.getFunctionAt(self.space.getAddress(e)) for e in sorted(found)]:
                if f is None:
                    continue
                for ins in self.listing.getInstructions(f.getBody(), True):
                    if self._is_branch_insn(ins):
                        for t in ins.getFlows():
                            if fm.getFunctionAt(t) is not None and int(t.getOffset()) not in found:
                                candidates.add(int(t.getOffset()))
            for c in sorted(candidates - found):
                if only_from_handlers(c):
                    found.add(c)
                    changed = True
        # Handlers entered by a branch from another handler (a shared exit
        # path "b irq_exit"): {target entry: [(source entry, branch offset)]}
        self.irq_jumps = {}
        for src in found:
            f = fm.getFunctionAt(self.space.getAddress(src))
            if f is None:
                continue
            for ins in self.listing.getInstructions(f.getBody(), True):
                if self._is_branch_insn(ins):
                    for t in ins.getFlows():
                        if int(t.getOffset()) in found and int(t.getOffset()) != src:
                            self.irq_jumps.setdefault(int(t.getOffset()), []).append(
                                (src, int(ins.getAddress().getOffset())))
        return found

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
        # (the writer's "typedef struct X X, *PX;" pointer names follow X)
        for o, n in list(self.nm_type.cache.items()):
            if o != n and "P" + o not in pairs:
                pairs["P" + o] = "P" + n
        renames = sorted(((o, n) for o, n in pairs.items() if o != n),
                         key=lambda on: -len(on[0]))
        if span is None or not renames:
            return
        # (whole names only: "default" -> "default_" must not touch a field
        # "default_mode")
        pats = {}
        for i in range(span[0], span[1]):
            line = self.h_lines[i]
            for o, n in renames:
                if o in line:
                    pat = pats.get(o)
                    if pat is None:
                        pat = pats[o] = re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(o))
                    line = pat.sub(lambda m, n=n: n, line)
            self.h_lines[i] = line

    _NAME_TOKENS = None

    def _token_text(self, tok):
        """Token text, with identifiers passed through the name filter and
        annotations in comments rendered."""
        text = str(tok.getText())
        if isinstance(tok, ClangCommentToken):
            return self._comment_text(text)
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

    # -- comment annotations ----------------------------------------------------
    # Ghidra comments can hold annotations ({@sym 00123456}, {@address ...},
    # {@url "..." text}, ...) that its listing renders as a name or text.
    _ANN_START = re.compile(r"\{@(\w+)")
    _ANN_KINDS = ("sym", "symbol", "address", "addr", "url", "hyperlink", "href", "link", "program",
                  "variable", "var", "execute")

    @staticmethod
    def _annotation_end(text, i):
        """Index after the "}" closing the annotation at text[i] (quotes and
        backslash escapes as Ghidra parses them); None if not closed."""
        quoted = False
        j = i + 2
        while j < len(text):
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c == '"':
                quoted = not quoted
            elif c == "}" and not quoted:
                return j + 1
            j += 1
        return None

    def _comment_text(self, text):
        """A decompiler comment line with its annotations rendered as Ghidra
        displays them, symbols by their exported names (what GDB knows). The
        decompiler wraps long comments at spaces, so an annotation can start
        on one comment line and end on the next: it is carried over."""
        if self._ann_carry:
            rest = text.lstrip()
            if rest.startswith("//"):             # ("Comment style": C++)
                rest = rest[2:].lstrip()
            text = self._ann_carry + rest
            self._ann_carry = ""
        out = []
        i = 0
        while True:
            m = self._ANN_START.search(text, i)
            if m is None:
                out.append(text[i:])
                break
            if m.group(1).lower() not in self._ANN_KINDS:
                out.append(text[i:m.end()])
                i = m.end()
                continue
            end = self._annotation_end(text, m.start())
            if end is None:
                if text.rstrip().endswith("*/"):      # (the comment ends here: leave it)
                    out.append(text[i:])
                else:
                    out.append(text[i:m.start()].rstrip())
                    self._ann_carry = text[m.start():] + " "
                break
            out.append(text[i:m.start()])
            out.append(self._render_annotation(text[m.start():end]))
            i = end
        return "".join(out)

    def _render_annotation(self, raw):
        from ghidra.app.util.viewer.field import Annotation, CommentUtils
        try:
            parts = [str(p) for p in Annotation(raw).getAnnotationParts()]
        except Exception:  # noqa: BLE001
            return raw
        kind = parts[0].lower() if parts else ""
        if kind in ("sym", "symbol") and len(parts) > 1:
            sym = self._annotated_symbol(parts[1])
            if sym is not None:
                return self.nm(_qualified(sym))
        elif kind == "execute":
            # (Ghidra's handler for it isn't available headless)
            return " ".join(parts[2:]) or (parts[1] if len(parts) > 1 else raw)
        try:
            shown = str(CommentUtils.getDisplayString(raw, self.program))
        except Exception:  # noqa: BLE001
            return raw
        if kind in ("variable", "var") and shown and not shown.startswith("Annotation Exception"):
            shown = self.nm(shown)
        return shown

    def _annotated_symbol(self, text):
        """The symbol a {@sym ...} annotation refers to: by (namespaced)
        name, else by address (its primary symbol)."""
        from ghidra.app.util import NamespaceUtils
        try:
            syms = list(NamespaceUtils.getSymbols(text, self.program))
            if syms:
                return syms[0]
            addr = self.program.getAddressFactory().getAddress(text)
            if addr is not None:
                return self.program.getSymbolTable().getPrimarySymbol(addr)
        except Exception:  # noqa: BLE001
            pass
        return None

    # -- functions --------------------------------------------------------------
    def _decompile_options(self):
        """The decompiler options: the tool's (as the Decompiler window
        uses them) when there is one, else Ghidra's defaults with the
        program's settings. Read once, on the main thread."""
        if self._dec_opts is None:
            opts = DecompileOptions()
            if self.tool is not None:
                opts.grabFromToolAndProgram(self.tool.getOptions("Listing Fields"),
                                            self.tool.getOptions("Decompiler"), self.program)
            else:
                opts.grabFromProgram(self.program)
            self._dec_opts = opts
        return self._dec_opts

    def _decompiler(self):
        ifc = DecompInterface()
        ifc.setOptions(self._decompile_options())
        ifc.toggleCCode(True)
        ifc.toggleSyntaxTree(True)
        ifc.setSimplificationStyle("decompile")
        if not ifc.openProgram(self.program):
            raise RuntimeError("decompiler failed to open program: %s" % ifc.getLastMessage())
        return ifc

    @staticmethod
    def _history_dependent(res):
        """Could the decompiled text depend on what this decompiler process
        decompiled before? The decompiler numbers locals (uVar3, fVar4) in
        storage order, and storage in its "join" space (a value over several
        registers, a float in a wider FPR) is allocated in the order the
        process first meets it. That matters with two or more such locals."""
        hf = res.getHighFunction() if res is not None else None
        if hf is None:
            return False
        n = 0
        for sym in hf.getLocalSymbolMap().getSymbols():
            if sym.isParameter():
                continue
            try:
                st = sym.getStorage()
                dt = sym.getDataType()
                if st.isCompoundStorage() or (dt is not None and dt.getLength() != st.size()):
                    n += 1
            except Exception:  # noqa: BLE001
                n += 1
        return n >= 2

    def _decompile(self, ifc, func, timeout):
        """Decompile; a function whose text could depend on the process'
        history is decompiled again in a fresh one, so the output doesn't
        depend on the order or the threads the functions were decompiled in."""
        res = ifc.decompileFunction(func, timeout, self.monitor)
        if self._history_dependent(res) and not self.monitor.isCancelled():
            fresh = self._decompiler()
            try:
                res = fresh.decompileFunction(func, timeout, self.monitor)
            finally:
                fresh.dispose()
        return res

    def _export_functions(self):
        fm = self.program.getFunctionManager()
        funcs = [f for f in fm.getFunctions(True)
                 if not f.isExternal() and self.in_space(f.getEntryPoint())]
        skipped = fm.getFunctionCount() - len(funcs)
        if skipped:
            self.log("Skipping %d external/non-default-space functions" % skipped)
        self.monitor.initialize(len(funcs))
        self.monitor.setMessage("Decompiling functions")
        for i, (func, res) in enumerate(self._decompiled(funcs)):
            self.monitor.checkCancelled()
            self.monitor.setProgress(i)
            if i % 200 == 0:
                self.log("[%d/%d] %s" % (i, len(funcs), func.getName()))
            self._export_function(res, func)

    def _skipped(self, func):
        return (_qualified(func) in self.skip or str(func.getName()) in self.skip
                or str(func.getEntryPoint()) in self.skip)

    def _decompiled(self, funcs):
        """Yields (function, DecompileResults or None) in order. Worker
        threads (one DecompInterface each; JPype releases the GIL during the
        Java calls) decompile ahead of the export, within a bounded window."""
        import collections
        import concurrent.futures
        import threading
        self._decompile_options()     # (read the tool options here, not in a worker)
        n = int(self.opts.decompile_threads)
        if n < 0:
            try:
                cpus = len(os.sched_getaffinity(0))      # (affinity/cgroup aware)
            except (AttributeError, OSError):
                cpus = os.cpu_count() or 2
            n = max(1, min(8, cpus - 1))
        timeout = self.opts.decompile_timeout
        serial = []

        def serial_ifc():
            if not serial:
                serial.append(self._decompiler())
            return serial[0]

        if n <= 1:
            try:
                for func in funcs:
                    yield func, (None if self._skipped(func) else
                                 self._decompile(serial_ifc(), func, timeout))
            finally:
                for ifc in serial:
                    ifc.dispose()
            return
        local = threading.local()
        ifcs = []
        lock = threading.Lock()

        def work(func):
            try:
                ifc = getattr(local, "ifc", None)
                if ifc is None:
                    ifc = local.ifc = self._decompiler()
                    with lock:
                        ifcs.append(ifc)
                return None if self._skipped(func) else self._decompile(ifc, func, timeout)
            finally:
                # JPype attached this pool thread to the JVM; detach it, or
                # every export leaks Java threads (GUI sessions)
                import java.lang
                if java.lang.Thread.isAttached():
                    java.lang.Thread.detach()

        ex = concurrent.futures.ThreadPoolExecutor(n)
        try:
            window = collections.deque()
            it = iter(funcs)
            for func in it:
                window.append((func, ex.submit(work, func)))
                if len(window) >= 2 * n:
                    break
            while window:
                func, fut = window.popleft()
                nxt = next(it, None)
                if nxt is not None:
                    window.append((nxt, ex.submit(work, nxt)))
                res = fut.result()
                if res is not None and res.isTimedOut() and not self.monitor.isCancelled():
                    # decompiles are slower under the pool's load: give a
                    # function that timed out there one serial attempt, so
                    # the result doesn't depend on machine load
                    res = self._decompile(serial_ifc(), func, timeout)
                yield func, res
        finally:
            for ifc in list(ifcs):
                try:
                    ifc.stopProcess()     # don't wait for in-flight decompiles
                except Exception:  # noqa: BLE001
                    pass
            try:
                ex.shutdown(wait=True, cancel_futures=True)
            finally:
                for ifc in ifcs + serial:
                    ifc.dispose()

    def _function_ranges(self, func):
        entry = int(func.getEntryPoint().getOffset())
        ranges = []
        for r in func.getBody().getAddressRanges():
            if not self.in_space(r.getMinAddress()):
                continue
            # (a function ending at the very top of the address space ends one
            # byte early: the exclusive end 2**32 doesn't fit a DWARF address)
            ranges.append((int(r.getMinAddress().getOffset()),
                           min(int(r.getMaxAddress().getOffset()) + 1, (1 << (8 * self.addr_size)) - 1)))
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

    def _export_function(self, res, func):
        dw = self.dw
        self.stats["functions"] += 1
        name = _qualified(func)
        entry = int(func.getEntryPoint().getOffset())
        ranges = self._function_ranges(func)

        skipped = self._skipped(func)
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
        extra = {}
        if hf is not None:
            # switch jump tables the decompiler recovered: edges the raw
            # computed jump doesn't show
            missing = []
            try:
                for jt in hf.getJumpTables():
                    sw = int(jt.getSwitchAddress().getOffset())
                    extra[sw] = [int(c.getOffset()) for c in jt.getCases()]
                    missing += [c for c in jt.getCases() if self.listing.getInstructionAt(c) is None]
            except Exception:  # noqa: BLE001
                pass
            if missing:
                # (the decompiler decodes them itself; everything else
                # works from the listing's instructions)
                self.log("WARNING: %s: switch cases at %s are not disassembled: no CFI or variable "
                         "locations there. Disassemble them and re-export." % (
                             name, ", ".join(str(c) for c in sorted(set(missing))[:4])))
        try:
            flow = FunctionFlow(self.machine, func, extra,
                                init_state=self._irq_entry_state(func) or self._helper_entry_state(func))
        except Exception as e:
            self.log("WARNING: flow analysis failed for %s: %s" % (name, e))
            flow = None
        if self.cfi is not None and flow is not None:
            self.cfi.add_function(flow, ranges, interrupt=entry in self.interrupts)
        # other labels at the entry (aliases): local zero-size symbols, so
        # "break alias" works while GDB keeps naming addresses by the
        # function (it passes over zero-size symbols for that)
        aliases = self._aliases(func.getEntryPoint(), func.getSymbol())
        if self._is_thumb(func.getEntryPoint()):
            # ARM ELF: Thumb function symbols have bit 0 set, and mapping
            # symbols ($t/$a) tell GDB the instruction set of each region.
            self.elf_symbols.append((name, self.A(entry) | 1, size, C.STT_FUNC))
            for a in aliases:
                self.elf_symbols.append((a, self.A(entry) | 1, 0, C.STT_FUNC, 0, C.STB_LOCAL))
            self.elf_symbols.append(("$t", self.A(entry), 0, C.STT_NOTYPE, 0, C.STB_LOCAL))
        else:
            bits = self._symbol_isa_bits(func)
            self.elf_symbols.append((name, self.A(entry), size, C.STT_FUNC) + bits)
            for a in aliases:
                self.elf_symbols.append((a, self.A(entry), 0, C.STT_FUNC, bits[0] if bits else 0,
                                         C.STB_LOCAL))
            if str(self.lang.getProcessor()) == "ARM":
                self.elf_symbols.append(("$a", self.A(entry), 0, C.STT_NOTYPE, 0, C.STB_LOCAL))

        # The function's text is assembled with line numbers relative to its
        # block, then placed in a C file and shifted (see _place_function).
        flines = ["", "/* ---- %s @ %s ---- */" % (self.nm(name), func.getEntryPoint())]
        self._var_dies = []      # (die, name, is_param): declaration lines added once placed
        self._code_decls = {}
        self._ann_carry = ""
        self._labels = []        # (name as in the C, address, line in the function text)
        base = len(flines)  # line N of the function text -> base + N

        if markup is None or hf is None:
            self.stats["decompile_failed"] += 1
            msg = res.getErrorMessage() if res is not None else (
                "skipped (skip_decompile)" if skipped else "no result")
            sig = self._proto_text(func)
            self._export_prototype_params(die, func, ranges, flow)
            msg = " ".join(str(msg).split())     # one line: the line table counts lines
            flines.append("%s /* decompilation failed: %s */" % (sig, msg.replace("*/", "* /")))
            sig_line = base + 1
            self.types.ref(die, func.getReturnType())
            addr_lines = {}
        elif self._thunk_target(func) is not None:
            # The decompiler shows the thunked function's body for a thunk:
            # write a forwarding call instead, and only the thunk's parameters.
            target = self._thunk_target(func)
            tname = self.nm(_qualified(target)) if target is not None else "?"
            # (the same parameters as its DWARF: the decompiler's)
            lsm = hf.getLocalSymbolMap()
            hparams = [lsm.getParamSymbol(i) for i in range(lsm.getNumParams())]
            hparams = [p for p in hparams if p is not None]
            args = ", ".join(self.nm(str(p.getName())) for p in hparams)
            ret = func.getReturnType()
            void = ret is None or isinstance(ret, VoidDataType) or ret.getLength() <= 0
            sig_text = self._proto_text(func)
            if hparams and not func.getParameters():
                # an unprototyped thunk: its signature from the decompiler
                proto = hf.getFunctionPrototype()
                rt = proto.getReturnType() if proto is not None else func.getReturnType()
                sig_text = "%s %s(%s)" % (self.nm_type(str(rt.getDisplayName())) if rt is not None else "void",
                                          self.nm(_qualified(func)),
                                          ", ".join("%s %s" % (self.nm_type(str(p.getDataType().getDisplayName())),
                                                               self.nm(str(p.getName()))) for p in hparams))
            flines += [sig_text, "{",
                             "  %s%s(%s);   /* thunk */" % ("" if void else "return ", tname, args), "}"]
            sig_line = base + 1
            addr_lines = {}
            for ins in self.listing.getInstructions(func.getBody(), True):
                addr_lines[int(ins.getAddress().getOffset())] = base + 3
            proto = hf.getFunctionPrototype()
            self.types.ref(die, proto.getReturnType() if proto is not None else ret)
            self._export_variables(die, func, hf, ranges, flow, params_only=True)
        else:
            self._code_decls = self._find_code_decls(markup)
            self._ann_carry = ""
            lines = DecompilerUtils.toLines(markup)
            addr_lines = {}
            claims = {}
            ret_claims = {}       # {offset: lines whose "return" keyword claims it}
            call_claims = {}
            sig_line = None
            carry_at = None
            for cl in lines:
                toks = cl.getAllTokens().toArray()   # (one Java array: no per-element iterator calls)
                if self._ann_carry and not any(isinstance(t, ClangCommentToken) for t in toks):
                    # the comment ended with an annotation still open: as is
                    flines[carry_at] += " " + self._ann_carry.rstrip()
                    self._ann_carry = ""
                text = str(cl.getIndentString()) + "".join(self._token_text(t) for t in toks)
                if self._ann_carry:
                    carry_at = len(flines)
                if self.qualified_renames and "::" in text:
                    # the decompiler emits "Ns::name" as several tokens
                    for q, new in self.qualified_renames:
                        if q in text:
                            text = text.replace(q, new)
                flines.append(text)
                gline = base + int(cl.getLineNumber())
                shown = [t for t in toks if str(t.getText()).strip()]
                if (len(shown) == 2 and isinstance(shown[0], ClangLabelToken) and str(shown[1].getText()) == ":"
                        and shown[0].getMinAddress() is not None and self.in_space(shown[0].getMinAddress())):
                    self._labels.append((self._token_text(shown[0]), int(shown[0].getMinAddress().getOffset()),
                                         gline))
                for tok in toks:
                    if sig_line is None and isinstance(tok, ClangFuncNameToken):
                        sig_line = gline
                    if isinstance(tok, (ClangCommentToken, ClangLabelToken)) or (
                            ClangCaseToken and isinstance(tok, ClangCaseToken)):
                        # "/* WARNING: ... */" comments carry addresses too; a
                        # "case N:" label carries its case's first operation,
                        # a label (and "goto label") its target's
                        continue
                    a = tok.getMinAddress()
                    if a is None or not self.in_space(a):
                        continue
                    claims.setdefault(int(a.getOffset()), set()).add(gline)
                    if str(tok.getText()) == "return":
                        ret_claims.setdefault(int(a.getOffset()), set()).add(gline)
                    if isinstance(tok, ClangFuncNameToken) and gline != sig_line:
                        # the callee's name in a call: the call's line
                        call_claims.setdefault(int(a.getOffset()), gline)
            if self._ann_carry:
                flines[carry_at] += " " + self._ann_carry.rstrip()
                self._ann_carry = ""
            # An address several lines claim gets the lowest one -- except a
            # shared epilogue the decompiler duplicated into several "return"
            # lines: that is the function's closing "}" (as with GCC), since
            # which return the code belongs to depends on the path taken.
            closing = max([i + 1 for i, t in enumerate(flines) if t.strip() == "}"] or [None])
            # Return code the decompiler duplicated into several blocks (an
            # epilogue shared by an early and the final return): which return
            # it belongs to depends on the path, even if only one of the
            # copies' statements carries its address.
            shared_ret = self._duplicated_return_code(hf, flow)
            for off in sorted(claims):
                lines_ = sorted(claims[off])
                # (the "return" keywords only: a value computed once for
                # several "return x;" is claimed by each of their "x")
                rets = ret_claims.get(off, ())
                if (len(rets) > 1 or off in shared_ret) and closing is not None:
                    addr_lines[off] = closing
                else:
                    addr_lines[off] = lines_[0]
                # a call instruction belongs to the call's line, even if the
                # code of another statement is folded into it (MIPS delay slot)
                d = flow.decoded.get(off) if flow is not None else None
                if off in call_claims and d is not None and d[0]:
                    addr_lines[off] = call_claims[off]
            if flow is not None:
                # An instruction no token claims, at a block start (the one
                # before doesn't fall through to it, or it is a jump target):
                # the line of the first claimed instruction of its run (else
                # the closing "}"), instead of the line of whatever precedes
                # it in memory.
                ins_ = flow.insns
                targets = set()
                for o in ins_:
                    d = flow.decoded.get(o)
                    if d is not None and d[1]:
                        targets.update(t for t in d[4] if t != d[8])
                for i, o in enumerate(ins_):
                    if o in addr_lines or i == 0:
                        continue
                    pd = flow.decoded.get(ins_[i - 1])
                    if pd is not None and pd[8] == o and o not in targets:
                        continue
                    # (through conditional branches; an unconditional jump
                    # takes its target's line -- a "goto" path; only a
                    # return leads to the closing "}")
                    line = None
                    for o2 in ins_[i:]:
                        if o2 in addr_lines:
                            line = addr_lines[o2]
                            break
                        d2 = flow.decoded.get(o2)
                        if d2 is None or d2[0]:
                            break
                        if d2[1] and d2[8] is None:
                            tgt = [t for t in d2[4] if t in addr_lines]
                            if len(tgt) == 1:
                                line = addr_lines[tgt[0]]
                            break
                        if d2[2] and d2[8] is None:
                            break
                    if line is None:
                        line = closing
                    if line is not None:
                        addr_lines[o] = line
            if sig_line is None:
                sig_line = base + 1
            proto = hf.getFunctionPrototype()
            self.types.ref(die, proto.getReturnType() if proto is not None else func.getReturnType())
            self._export_variables(die, func, hf, ranges, flow)
        if func.hasVarArgs():
            die.child(C.DW_TAG_unspecified_parameters)

        cfile, off = self._place_function(flines)
        sig_line += off
        addr_lines = dict((a, l + off) for a, l in addr_lines.items())
        self._add_decl_lines(flines, sig_line, off, cfile["file_no"])
        self._add_labels(die, self._labels, off, cfile["file_no"], ranges)
        die.add(C.DW_AT_decl_file, C.DW_FORM_udata, cfile["file_no"])
        die.add(C.DW_AT_decl_line, C.DW_FORM_udata, sig_line)

        # Line rows: the frame setup maps to the signature line, and the first
        # body instruction is flagged prologue_end so GDB (>= 13) places
        # "break func" there -- for frameless functions that is the entry
        # point itself, with all arguments still in their registers.
        local_entry = (self._ppc64_local_entry(func)
                       if str(self.lang.getProcessor()) == "PowerPC" and self.addr_size == 8 else 0)
        pe = flow.prologue_end(local_entry, body=self._statement_pcs(addr_lines, sig_line)) \
            if flow is not None else None
        if pe is not None and entry in self.interrupts and self.cfi is not None:
            pe = self._after_irq_save(flow, pe)
        if flow is not None:
            # A delay slot belongs to its branch's line: a caller frame's PC
            # is "return address - 1", inside the slot after a jal, and must
            # show the call's line (as with GCC).
            for i, o in enumerate(flow.insns):
                d = flow.decoded.get(o)
                if d is not None and d[3] and o in addr_lines:
                    for slot in flow.insns[i + 1:i + 1 + d[3]]:
                        addr_lines[slot] = addr_lines[o]
        if pe is not None:
            # The line shown when stepping into / breaking on the function:
            # the earliest statement whose code starts in the straight-line
            # run at the prologue end (compilers schedule instructions of a
            # later statement first; GCC's own line info shows the first).
            run = []
            i = bisect.bisect_left(flow.insns, pe)
            while i < len(flow.insns) and ranges[0][0] <= flow.insns[i] < ranges[0][1]:
                o = flow.insns[i]
                run.append(o)
                d = flow.decoded.get(o)
                if d is None or d[0] or d[1] or d[2]:      # call, jump, return
                    break
                i += 1
            cands = [addr_lines[a] for a in run if a in addr_lines and addr_lines[a] != sig_line]
            body_line = min(cands) if cands else addr_lines.get(pe)
            if body_line is None:
                later = [a for a in addr_lines if a > pe and ranges[0][0] <= a < ranges[0][1]]
                body_line = addr_lines[min(later)] if later else sig_line
            addr_lines[pe] = body_line
            if pe != entry:
                # the whole prologue is the signature line (as with GCC): the
                # decompiler may tie e.g. the PPC64 ELFv2 TOC setup to a
                # pseudo statement
                for a in [a for a in addr_lines if entry <= a < pe]:
                    addr_lines[a] = sig_line
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
            self.dw.add_sequence(out_rows, self.A(lo) + (hi - lo), cfile["file_no"])

    # -- variables -------------------------------------------------------------
    @staticmethod
    def _statement_pcs(addr_lines, sig_line):
        """Instructions the decompiler attributes to a statement (a line of
        the function body, not its signature)."""
        return set(a for a, l in addr_lines.items() if l != sig_line)

    def _after_irq_save(self, flow, pe):
        """An interrupt handler's breakpoint goes after it has stored its
        return register (SRR0, ...) if that happens before the first call or
        branch: from there the backtrace reaches the interrupted code."""
        irq = self.cfi._irq_return_reg(flow)
        if irq is None:
            return pe
        key = irq[0]
        i = bisect.bisect_left(flow.insns, pe)
        while i < len(flow.insns):
            o = flow.insns[i]
            st = flow.state_in.get(o)
            if st is not None and any(v == ("init", key) for _, v in st.mem.values()):
                return o
            d = flow.decoded.get(o)
            if d is None or d[0] or d[1] or d[2]:
                break
            i += 1
        return pe

    def _helper_entry_state(self, func):
        """PPC32 GCC-style epilogue helper "_restgpr_N_x", entered by a
        branch from a function's epilogue: r11 is that function's CFA, the
        return address is at 4(r11) and rN..r31 are saved just below r11.
        Its own analysis starts from that, so its CFI unwinds correctly."""
        from .flow import State, SP as FSP, INIT as FINIT
        m = re.match(r"^_restgpr_(\d+)_x$", str(func.getName()))
        if m is None or str(self.lang.getProcessor()) != "PowerPC" or self.addr_size != 4:
            return None
        first = int(m.group(1))
        lang = self.lang

        def key(name):
            r = lang.getRegister(name)
            return (int(r.getAddress().getOffset()), int(r.getMinimumByteSize())) if r is not None else None
        r11, lr = key("r11"), self.machine.ra_key
        if r11 is None or lr is None or not 13 <= first <= 31:
            return None
        st = State()
        st.regs[r11] = (FSP, 0)
        st.regs[self.machine.sp_key] = None
        st.regs[lr] = None
        st.mem[4] = (4, (FINIT, lr))
        for n in range(first, 32):
            k = key("r%d" % n)
            st.regs[k] = None
            st.mem[-4 * (32 - n)] = (4, (FINIT, k))
        return st

    def _irq_entry_state(self, func):
        """For a handler entered only by branches from other handlers (a
        shared exit path): the state at those branches, so its CFI knows the
        exception frame (where SRR0 and the interrupted registers are)."""
        entry = int(func.getEntryPoint().getOffset())
        srcs = getattr(self, "irq_jumps", {}).get(entry)
        if not srcs or entry in self.entry_points:
            return None
        fm = self.program.getFunctionManager()
        states = []
        for src, off in srcs:
            try:
                sf = FunctionFlow(self.machine, fm.getFunctionAt(self.space.getAddress(src)))
            except Exception:  # noqa: BLE001
                return None
            st = sf.state_out.get(off)
            if st is None:
                return None
            states.append(st)
        first = states[0]
        sp = self.machine.sp_key
        if any(s.regs.get(sp) != first.regs.get(sp) or s.mem != first.mem for s in states[1:]):
            return None        # the branches disagree on the frame: no guess
        return first

    def _aliases(self, addr, primary):
        """Names of the other user/analysis labels at addr (not primary)."""
        out = []
        for s in self.program.getSymbolTable().getSymbols(addr):
            if s.isDynamic() or s.getSource() == SourceType.DEFAULT or s.equals(primary):
                continue
            if s.getSymbolType() not in (SymbolType.LABEL, SymbolType.FUNCTION):
                continue
            n = _qualified(s)
            if n not in out:
                out.append(n)
        return sorted(out)

    def _proto_text(self, func):
        """C prototype with exported (name-filtered) names, for functions
        written without decompiler output."""
        def tn(dt):
            if dt is None:
                return "void"
            # sanitize the type name, keep pointer/array declarator parts
            m = re.match(r"^(.*?)((?:\s*\*|\[\d*\])*)$", str(dt.getDisplayName()))
            return self.nm_type(m.group(1).strip()) + m.group(2)
        params = ["%s %s" % (tn(p.getDataType()), self.nm(str(p.getName()))) for p in func.getParameters()]
        if func.hasVarArgs():
            params.append("...")
        return "%s %s(%s)" % (tn(func.getReturnType()), self.nm(_qualified(func)),
                              ", ".join(params) if params else "void")

    def _export_equates(self):
        """Equates (named constants set on operands) appear by name in the
        decompiled code: enumerators of an anonymous enum make the names
        usable in GDB expressions. Left out: equates based on an enum type
        (the decompiler prints the enum's member names, exported with the
        type), names that are literals ("Convert": 0x64, 'd', -5), and names
        of other global symbols."""
        st = self.program.getSymbolTable()
        found = []
        for e in self.program.getEquateTable().getEquates():
            name = str(e.getName())
            try:
                if e.isEnumBased():
                    continue
            except Exception:  # noqa: BLE001
                pass
            if not name or not (name[0].isalpha() or name[0] == "_"):
                continue
            if list(st.getGlobalSymbols(name)):
                continue
            found.append((name, int(e.getValue())))
        if not found:
            return
        die = self.dw.cu.child(C.DW_TAG_enumeration_type)
        die.add(C.DW_AT_byte_size, C.DW_FORM_udata, 8)
        under = self.types.base_of_size(8, True)
        if under is not None:
            die.add(C.DW_AT_type, C.DW_FORM_ref4, under)
        for name, value in sorted(found):
            e = die.child(C.DW_TAG_enumerator)
            self.dw.name(e, name)
            e.add(C.DW_AT_const_value, C.DW_FORM_sdata, value)
        self.stats["equates"] = len(found)

    def _add_labels(self, die, labels, off, file_no, ranges):
        """DW_TAG_label for the labels the C shows (goto targets: the user's
        name or LAB_<address>), so "break func:label" works."""
        for name, addr, line in labels:
            if not any(lo <= addr < hi for lo, hi in ranges):
                continue
            lab = die.child(C.DW_TAG_label)
            self.dw.name(lab, name, raw=True)
            lab.add(C.DW_AT_decl_file, C.DW_FORM_udata, file_no)
            lab.add(C.DW_AT_decl_line, C.DW_FORM_udata, line + off)
            lab.add(C.DW_AT_low_pc, C.DW_FORM_addr, self.A(addr))

    def _add_decl_lines(self, flines, sig_line, off, file_no):
        """DW_AT_decl_file/line for the function's variables: parameters on
        the signature line, locals on their declaration line."""
        body = None
        for die, vname, is_param in self._var_dies:
            line = None
            if is_param:
                line = sig_line           # (sig_line is already file-relative)
            else:
                if body is None:
                    # the declarations: from the line after the signature to
                    # the first empty line of the body
                    body = []
                    for i in range(sig_line - off, len(flines)):
                        if body and not flines[i].strip():
                            break
                        body.append((i + 1 + off, flines[i]))
                pat = re.compile(r"(?<![\w?:'$])%s(?![\w?:'$])\s*(\[[^\]]*\]\s*)*;" % re.escape(self.nm(vname)))
                for ln, text in body:
                    if pat.search(text):
                        line = ln
                        break
            if line is not None:
                die.add(C.DW_AT_decl_file, C.DW_FORM_udata, file_no)
                die.add(C.DW_AT_decl_line, C.DW_FORM_udata, line)

    def _export_prototype_params(self, die, func, ranges, flow):
        """Parameters of a function without decompiler output, from its
        Ghidra prototype (located where their entry values still are)."""
        ctx = _FunctionContext(self, func, None, ranges, flow)
        for p in func.getParameters():
            self.stats["variables"] += 1
            pd = die.child(C.DW_TAG_formal_parameter)
            self._var_dies.append((pd, str(p.getName()), True))
            self.dw.name(pd, str(p.getName()))
            self.types.ref(pd, p.getDataType())
            try:
                loc = ctx.entry_value_location(p.getVariableStorage())
            except Exception as e:  # noqa: BLE001
                self.log("WARNING: %s/%s: location failed: %s" % (func.getName(), p.getName(), e))
                loc = None
            if loc is None:
                continue
            self.stats["variables_located"] += 1
            kind, value = loc
            if kind == "expr":
                pd.add(C.DW_AT_location, C.DW_FORM_exprloc, value)
            else:
                pd.add(C.DW_AT_location, C.DW_FORM_sec_offset, self.dw.add_loclist(value))

    def _thunk_target(self, func):
        """The function a thunk forwards to: Ghidra's thunks, plus functions
        that only jump to another function (Ghidra doesn't flag PPC64 ones:
        ELFv1 "b f", ELFv2 TOC setup + "b f+8" to the local entry)."""
        if func.isThunk():
            return func.getThunkedFunction(True)
        insns = []
        for ins in self.listing.getInstructions(func.getBody(), True):
            insns.append(ins)
            if len(insns) > 3:
                return None
        if not insns:
            return None
        last = insns[-1]
        ft = last.getFlowType()
        if ft.isConditional() or not (ft.isJump() or (ft.isCall() and ft.isTerminal())):
            return None
        flows = [t for t in last.getFlows() if t is not None]
        if len(flows) != 1:
            return None
        fm = self.program.getFunctionManager()
        target = fm.getFunctionAt(flows[0])
        ppc64 = str(self.lang.getProcessor()) == "PowerPC" and self.addr_size == 8
        if target is None and ppc64:
            target = fm.getFunctionContaining(flows[0])
            if target is not None and int(flows[0].getOffset()) - int(target.getEntryPoint().getOffset()) \
                    != self._ppc64_local_entry(target):
                target = None
        if target is None or target == func:
            return None
        # anything before the jump may only set up the TOC (r2)
        for ins in insns[:-1]:
            if not ppc64 or str(ins.getRegister(0) or "") != "r2":
                return None
        return target

    def _export_variables(self, func_die, func, hf, ranges, flow, params_only=False):
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

        # (the decompiler's symbol order follows its temporary symbol ids,
        # which depend on what the same DecompInterface decompiled before:
        # sort, so the output doesn't depend on the decompiler threads)
        others.sort(key=lambda sym: (str(sym.getName()), str(sym.getStorage())))
        ctx = _FunctionContext(self, func, hf, ranges, flow)
        for sym in params:
            self._export_variable(func_die, sym, ctx, True)
        if params_only:
            return
        for sym in others:
            self._export_variable(func_die, sym, ctx, sym.isParameter())

    @staticmethod
    def _duplicated_return_code(hf, flow):
        """Offsets of instructions in more than one decompiler basic block,
        one of them a return block (no successors) -- other than instructions
        whose own p-code spans blocks: a conditional return (PPC beqlr, ARM
        bxeq lr / pople {..,pc}) or a conditionally executed instruction
        (ARM predication, AArch64 csel) is no shared epilogue."""
        if flow is None or hf is None:
            return set()

        def splits(o):
            d = flow.decoded.get(o)
            if d is None:
                return False
            if d[2] and d[8] is not None:
                return True
            return any(op[0] in (PcodeOp.CBRANCH, PcodeOp.BRANCH) and op[2] is not None and op[2][0] == "c"
                       for op in d[5])
        seen, rets = {}, set()
        for b in hf.getBasicBlocks():
            cover = _block_cover(b)
            if cover is None:
                return set()
            offs = _cover_offsets(cover, flow.insns)
            for o in offs:
                seen[o] = seen.get(o, 0) + 1
            if b.getOutSize() == 0:
                rets.update(offs)
        return set(o for o in rets if seen[o] > 1 and not splits(o))

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
        self._var_dies.append((die, str(sym.getName()), is_param))
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
            type_die = None
            if dt is not None and dt.getLength() > 0:
                type_die = self.types.get(dt)
            elif length > 0:
                # dynamic-size data: strings become arrays of their character
                # type (GDB prints them as strings), anything else a byte array
                arr = self.dw.cu.child(C.DW_TAG_array_type)
                elem = _string_char_type(data)
                if elem is not None and length % elem.getLength() == 0:
                    self.types.ref(arr, elem)
                    count = length // elem.getLength()
                else:
                    arr.add(C.DW_AT_type, C.DW_FORM_ref4, self.types.base_of_size(1, False))
                    count = length
                arr.child(C.DW_TAG_subrange_type).add(C.DW_AT_count, C.DW_FORM_udata, count)
                type_die = arr
            # The primary label, then any other labels on the same data
            # (aliases): each a variable of the same type and address. Only
            # the primary gets an ELF symbol, so GDB names the address by it
            # (with several symbols at one address its choice is arbitrary).
            location = self.dw.expr().addr(self.A(addr.getOffset())).bytes()
            for i, vname in enumerate([name] + self._aliases(addr, sym)):
                die = self.dw.cu.child(C.DW_TAG_variable)
                self.dw.name(die, vname)
                die.add(C.DW_AT_external, C.DW_FORM_flag_present)
                if type_die is not None:
                    die.add(C.DW_AT_type, C.DW_FORM_ref4, type_die)
                die.add(C.DW_AT_location, C.DW_FORM_exprloc, location)
                if i == 0:
                    self.elf_symbols.append((vname, self.A(addr.getOffset()), length, C.STT_OBJECT))
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
        """Does the program's predominant calling convention pass floating
        point arguments in FP registers (e.g. ARM hard-float vs softfp)?"""
        from collections import Counter
        cspec = self.program.getCompilerSpec()
        used = Counter(str(f.getCallingConventionName())
                       for f in self.program.getFunctionManager().getFunctions(True)
                       if not f.isExternal())
        cc = None
        for name, _ in used.most_common():
            cc = cspec.getCallingConvention(name)
            if cc is not None:
                break
        if cc is None:
            cc = cspec.getDefaultCallingConvention()
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
            a0 = self.lang.getRegister("a0")
            if a0 is not None and int(a0.getMinimumByteSize()) == 8:
                # 64-bit registers, 32-bit addresses
                if "n32" in cspec:
                    return 0x80000000 | 0x20                    # ARCH_64R2 | EF_MIPS_ABI2 (n32)
                if "o32" in cspec:
                    return 0x80000000 | 0x1000                  # ARCH_64R2 | O32
                return 0x80000000 | 0x2000                      # ARCH_64R2 | O64
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
    SECTION_BUDGET = 60000

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
        # Stay well below ELF's section index limit (elf.MAX_SECTIONS) over
        # all blocks: past the budget a block becomes one code section.
        used = getattr(self, "_runs_used", 0)
        if len(runs) > min(self.MAX_SECTION_RUNS, self.SECTION_BUDGET - used) or not runs:
            if runs:
                self.log("WARNING: too many code/data runs in block at 0x%x; exporting it as one "
                         "code section" % lo)
            return [(lo, hi, True)]
        self._runs_used = used + len(runs)
        return runs

    def _read_bytes(self, lo, hi):
        import jpype
        buf = jpype.JArray(jpype.JByte)(hi - lo)
        self.memory.getBytes(self.space.getAddress(lo), buf)
        return memoryview(buf).cast("B").tobytes()

    @staticmethod
    def _carve_opd(runs, opd):
        """Split [(lo, hi, is_code)] runs around .opd regions (is_code "opd")."""
        if not opd:
            return runs
        out = []
        for lo, hi, kind in runs:
            pos = lo
            for olo, ohi in opd:
                if ohi <= pos or olo >= hi:
                    continue
                if olo > pos:
                    out.append((pos, olo, kind))
                out.append((max(olo, pos), min(ohi, hi), "opd"))
                pos = min(ohi, hi)
            if pos < hi:
                out.append((pos, hi, kind))
        return out

    def _find_opd(self, flags):
        """PPC64 ELFv1: function pointers are addresses of function
        descriptors (code address, TOC base, environment) in .opd. A raw
        image has no section table, so find descriptor arrays: aligned
        doublewords pointing at function entries, followed by the program's
        (common) TOC value and 0. Returns [(lo, hi)] Ghidra offsets."""
        if not (str(self.lang.getProcessor()) == "PowerPC" and self.addr_size == 8 and flags == 1):
            return []
        import struct
        entries = set(int(f.getEntryPoint().getOffset())
                      for f in self.program.getFunctionManager().getFunctions(True)
                      if not f.isExternal() and self.in_space(f.getEntryPoint()))
        fmt = ">Q" if self.big_endian else "<Q"
        code_ranges = self._code_ranges()
        code_blocks = [(int(b.getStart().getOffset()), int(b.getEnd().getOffset()) + 1)
                       for b in self.memory.getBlocks() if self.in_space(b.getStart()) and (
                           b.isExecute() or any(clo <= int(b.getEnd().getOffset()) and int(b.getStart().getOffset()) < chi
                                                for clo, chi in code_ranges))]
        cands = []
        weak = []   # [code pointer, TOC?, 0] where the pointer isn't a function entry
        for block in self.memory.getBlocks():
            if not block.isInitialized() or not self.in_space(block.getStart()) or block.isOverlay():
                continue
            lo = int(block.getStart().getOffset())
            hi = lo + int(block.getSize())
            first = (lo + 7) & ~7
            data = self._read_bytes(first, hi)
            n = (len(data) // 8) * 8
            words = [w[0] for w in struct.iter_unpack(fmt, data[:n])]
            for i, w in enumerate(words[:-2]):
                if w in entries:
                    cands.append((first + 8 * i, words[i + 1], words[i + 2]))
                elif words[i + 2] == 0 and w & 3 == 0 and any(a <= w < b for a, b in code_blocks):
                    weak.append((first + 8 * i, words[i + 1], 0))
        if not cands:
            return []
        from collections import Counter
        toc, _ = Counter(c[1] for c in cands if c[1]).most_common(1)[0] if any(c[1] for c in cands) else (None, 0)
        descs = sorted(a for a, t, env in cands if t == toc and env == 0)
        # descriptors of code Ghidra doesn't treat as a function entry, if
        # they sit between real ones (same TOC, inside a descriptor array)
        strong = set(descs)
        for a, t, _ in weak:
            if t == toc and ((a - 24) in strong or (a + 24) in strong):
                descs.append(a)
        descs = sorted(set(descs))
        regions = []
        for a in descs:
            if regions and a == regions[-1][1]:
                regions[-1][1] = a + 24
            elif regions and a < regions[-1][1]:
                continue
            else:
                regions.append([a, a + 24])
        self.opd_descriptors = [(a, self._word(a)) for a in descs]
        self.log("PPC64 ELFv1: %d function descriptors in %d .opd region(s)" % (len(descs), len(regions)))
        return [tuple(r) for r in regions]

    def _word(self, off):
        import struct
        return struct.unpack(">Q" if self.big_endian else "<Q", self._read_bytes(off, off + 8))[0]

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
        opd = self._find_opd(flags)
        # the code run holding the most function bytes becomes ".text"
        text_lo = max(code, key=lambda r: r[1] - r[0])[0] if code else None
        text_done = False
        for block in self.memory.getBlocks():
            start = block.getStart()
            if (not block.isLoaded() or block.isOverlay() or not self.in_space(start)
                    or block.isExternalBlock()):     # (Ghidra's synthetic EXTERNAL block of imports)
                continue
            base_flags = C.SHF_ALLOC | (C.SHF_WRITE if block.isWrite() else 0)
            lo = int(start.getOffset())
            hi = lo + int(block.getSize())
            name = str(block.getName())
            # Treat a block holding functions as code even if the analyst's
            # memory map lacks the X flag: GDB only gives source-level
            # debugging to functions in an executable section.
            has_code = any(clo < hi and lo < chi for clo, chi in code)
            if has_code and not block.isExecute():
                self.log("WARNING: memory block %s holds functions but is not executable; "
                         "exporting its code as executable" % name)
            exec_like = bool(block.isExecute()) or has_code
            if exec_like and self.opts.split_sections:
                # GDB classifies symbols (function vs data) by the flags of
                # their section, and raw dumps are often one RWX block: emit
                # code and data runs as separate sections.
                runs = self._split_runs(lo, hi, code)
            else:
                runs = [(lo, hi, exec_like)]
            runs = self._carve_opd(runs, opd)
            data = None
            if self.opts.embed_bytes and block.isInitialized():
                import jpype
                buf = jpype.JArray(jpype.JByte)(hi - lo)
                block.getBytes(start, buf)
                data = memoryview(buf).cast("B").tobytes()
            for rlo, rhi, is_code in runs:
                if is_code == "opd":
                    # always with contents: GDB/BFD read descriptors from it
                    elf.add_section(Section(".opd", C.SHT_PROGBITS, C.SHF_ALLOC | C.SHF_WRITE,
                                            self.A(rlo), self._read_bytes(rlo, rhi), align=8))
                    continue
                if not is_code and exec_like and str(self.lang.getProcessor()) == "ARM":
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
                elif exec_like:
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

        # descriptor symbols: <function name> at the descriptor (STT_OBJECT,
        # so GDB keeps resolving code addresses to the code symbols)
        fm = self.program.getFunctionManager()
        for daddr, code_addr in getattr(self, "opd_descriptors", []):
            f = fm.getFunctionAt(self.space.getAddress(code_addr))
            if f is not None:
                self.elf_symbols.append((_qualified(f), self.A(daddr), 24, C.STT_OBJECT))
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

_COVER_FIELD = []


def _cover_offsets(cover, insns):
    """The instruction offsets (of the sorted list insns) in an AddressSet."""
    out = []
    it = cover.getAddressRanges()
    while it.hasNext():
        r = it.next()
        lo, hi = int(r.getMinAddress().getOffset()), int(r.getMaxAddress().getOffset())
        i = bisect.bisect_left(insns, lo)
        while i < len(insns) and insns[i] <= hi:
            out.append(insns[i])
            i += 1
    return out


def _block_cover(block):
    """The decompiler basic block's AddressSet of instructions (its private
    "cover" field; None if unavailable)."""
    if not _COVER_FIELD:
        try:
            from ghidra.program.model.pcode import PcodeBlockBasic
            f = PcodeBlockBasic.class_.getDeclaredField("cover")
            f.setAccessible(True)
            _COVER_FIELD.append(f)
        except Exception:  # noqa: BLE001
            _COVER_FIELD.append(None)
    f = _COVER_FIELD[0]
    if f is None:
        return None
    try:
        return f.get(block)
    except Exception:  # noqa: BLE001
        return None


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
        blocks = hf.getBasicBlocks() if hf is not None else None
        self.entry_block = blocks.get(0) if blocks is not None and blocks.size() else None

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
        """(entry, end) of the block's first piece (see _block_seq)."""
        seq = self._block_seq(block)
        return seq[0] if seq else None

    def _block_seq(self, block):
        """The block's code as [(lo, hi)] pieces in execution order (entry
        piece first). A decompiler block isn't always contiguous: an early
        "return x;" stub that branches back to the shared epilogue is one
        block of two distant pieces, and treating it as one address range
        would credit everything in between to it."""
        cache = self.__dict__.setdefault("_seq_cache", {})
        idx = int(block.getIndex())
        if idx in cache:
            return cache[idx]
        pieces = None
        cover = _block_cover(block)
        if cover is not None:
            pieces = [(int(r.getMinAddress().getOffset()), self.exp.insn_end(r.getMaxAddress()))
                      for r in cover.getAddressRanges() if self.exp.in_space(r.getMinAddress())]
        if not pieces:
            start, stop = block.getStart(), block.getStop()
            pieces = ([(int(start.getOffset()), self.exp.insn_end(stop))]
                      if start is not None and stop is not None else [])
        first = block.getFirstOp() if pieces else None
        if first is not None and len(pieces) > 1:
            entry = int(first.getSeqnum().getTarget().getOffset())
            head = [p for p in pieces if p[0] <= entry < p[1]]
            if head:
                pieces = head + [p for p in pieces if p is not head[0]]
        cache[idx] = pieces
        return pieces

    def _block_pos(self, block, addr):
        """Execution-order position of addr inside the block."""
        for i, (lo, hi) in enumerate(self._block_seq(block)):
            if lo <= addr < hi:
                return (i, addr)
        return (len(self._block_seq(block)), addr)

    def _block_spans(self, block, start=None, end_addr=None, end=None, start_addr=None):
        """Spans of the block from address start (default: its entry; in
        the piece holding start_addr, default start) to the instruction at
        end_addr, ending at end (default: block end)."""
        seq = self._block_seq(block)
        out = []
        i0 = (self._block_pos(block, start_addr if start_addr is not None else start)[0]
              if start is not None else 0)
        i1 = self._block_pos(block, end_addr)[0] if end_addr is not None else len(seq) - 1
        for i in range(i0, min(i1, len(seq) - 1) + 1):
            lo, hi = seq[i]
            if i == i0 and start is not None:
                lo = max(lo, start)
            if i == i1 and end is not None:
                hi = min(hi, end)
            if lo < hi:
                out.append((lo, hi))
        return out

    def live_intervals(self, vn):
        """[(start, end)] Ghidra offsets where the varnode holds its value."""
        out = []
        defop = vn.getDef()
        if defop is None:
            if not vn.isInput() or self.entry_block is None:
                return out
            dblock = self.entry_block
            dpoint = daddr = self.entry
        else:
            dblock = defop.getParent()
            target = defop.getSeqnum().getTarget()
            daddr = int(target.getOffset())
            if defop.getOpcode() == PcodeOp.MULTIEQUAL:
                dpoint = daddr                       # the block's entry
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
            uaddr = int(op.getSeqnum().getTarget().getOffset())
            uend = self.exp.insn_end(op.getSeqnum().getTarget())
            same_insn_after = (defop is not None and daddr == uaddr
                               and int(defop.getSeqnum().getOrder()) < int(op.getSeqnum().getOrder()))
            if (int(ublock.getIndex()) == dindex
                    and (self._block_pos(ublock, daddr) < self._block_pos(ublock, uaddr)
                         or same_insn_after
                         or (defop is None or defop.getOpcode() == PcodeOp.MULTIEQUAL) and daddr == uaddr)):
                out += self._block_spans(ublock, dpoint, uaddr, uend, start_addr=daddr)
            else:
                if not self._block_seq(ublock):
                    continue
                out += self._block_spans(ublock, None, uaddr, uend)
                for i in range(ublock.getInSize()):
                    live_out(ublock.getIn(i))

        while work:
            block = work.pop()
            idx = int(block.getIndex())
            if idx in visited:
                continue
            visited.add(idx)
            if not self._block_seq(block):
                continue
            if idx == dindex:
                out += self._block_spans(block, dpoint, start_addr=daddr)
                continue
            out += self._block_seq(block)
            for i in range(block.getInSize()):
                work.append(block.getIn(i))
        return out

    # -- physical location of values ------------------------------------------
    def _unique_home(self, vn):
        """Register a temporary (unique-space, HASH storage) decompiler
        instance was physically written to: the register its defining
        machine p-code op writes, if that op matches the decompiler's (same
        opcode, same register/constant inputs). Decompiler-synthesized ops
        (COPYs at call sites, PTRADDs, ...) have no such register: better
        no location than a coincidental one (a call's return address
        write)."""
        d = vn.getDef()
        if d is None or self.flow is None or d.getOpcode() == PcodeOp.MULTIEQUAL:
            return None
        off = int(d.getSeqnum().getTarget().getOffset())
        dec = self.flow.decoded.get(off)
        if dec is None:
            return None
        m = self.exp.machine
        is_call = dec[0]
        size = int(vn.getSize())
        dop = d.getOpcode()

        def inputs_match(op):
            for i in range(min(int(d.getNumInputs()), 3)):
                if i == 0 and dop in (PcodeOp.LOAD, PcodeOp.STORE):
                    continue    # address space id: encoded differently
                dv, mv = d.getInput(i), op[2 + i]
                if dv is None or mv is None:
                    continue
                # (a machine temporary matches anything: the instruction may
                # compute an operand the decompiler sees as a register)
                if dv.isRegister():
                    if mv[0] == "c" or (mv[0] == "r" and
                                        (mv[1], mv[2]) != (int(dv.getOffset()), int(dv.getSize()))):
                        return False
                elif dv.isConstant():
                    if mv[0] == "r" or (mv[0] == "c" and mv[1] != int(dv.getOffset())):
                        return False
                elif dv.getAddress().isMemoryAddress():
                    # a value read from memory (a global, a literal pool
                    # constant): only the same memory operand matches
                    if mv[0] != "a" or mv[1] != int(dv.getOffset()):
                        return False
            return True

        def usable(k):
            return not (is_call and k == m.ra_key)

        # the matching op's output register -- directly, or through a COPY of
        # its temporary result (x86 "mov rbp,[rdi+8]": U = LOAD ..; RBP = COPY U)
        copies = {}
        for opc, out, i0, _, _ in dec[5]:
            if opc == PcodeOp.COPY and out is not None and out[0] == "r" and i0 is not None and i0[0] == "u":
                copies.setdefault(i0, (out[1], out[2]))
        keys = []
        for op in dec[5]:
            opc, out = op[0], op[1]
            if opc != dop or out is None or out[2] != size or not inputs_match(op):
                continue
            k = (out[1], out[2]) if out[0] == "r" else copies.get(out) if out[0] == "u" else None
            if k is not None and k[1] == size and usable(k):
                keys.append(k)
        keys = list(dict.fromkeys(keys))
        if len(keys) == 1:
            return keys[0]
        if keys:
            return None
        # A 32-bit result written to a 64-bit register (AArch64 "add w0,.."
        # is X0 = zext(..), MIPS64/PPC64 sign-extend): the low part -- if the
        # machine op computing it matches.
        if not any(opc == dop and out is not None and out[0] == "u" and out[2] == size
                   and inputs_match(op) for op in dec[5] for opc, out in [op[:2]]):
            return None
        wide = list(dict.fromkeys((out[1], out[2]) for opc, out, _, _, _ in dec[5]
                                  if out is not None and out[0] == "r" and out[2] > size
                                  and opc in (PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.COPY)
                                  and usable((out[1], out[2]))
                                  and m.dwarf_of((out[1], out[2])) is not None))
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
            d = vn.getDef()
            if (d is not None and d.getOpcode() == PcodeOp.COPY and d.getInput(0) is not None
                    and d.getInput(0).isRegister()):
                # a copy of a register (e.g. at a call site): the same value
                return self.instance_value(d.getInput(0))
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
            # (at the block's entry: its first piece's start isn't the
            # lowest address for a non-contiguous block)
            return flow.value_before(int(d.getSeqnum().getTarget().getOffset()), key)
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
            e = self.best_location(flow.locations_of(pc, value, int(vn.getSize())), own)
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
                seq = self._block_seq(b)
                bounds = seq[0] if seq else None
                # pcs in execution order, with their position keys
                pcs = [((i, pc), pc) for i, piece in enumerate(seq) for pc in self._pcs_in([piece])]
                preds = [int(b.getIn(k).getIndex()) for k in range(b.getInSize())]
                info[int(b.getIndex())] = (bounds, pcs, preds, b)
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
                    events[entry_bi].append(((0, self.entry), -1, i))
                continue
            bi = int(d.getParent().getIndex())
            if bi not in events:
                continue
            blk = binfo[bi][3]
            if d.getOpcode() == PcodeOp.MULTIEQUAL:
                if binfo[bi][0] is None:
                    continue
                events[bi].append(((0, binfo[bi][0][0]), -1, i))
            else:
                # (takes effect after the defining instruction: position of
                # the instruction's end, within the same piece)
                t = int(d.getSeqnum().getTarget().getOffset())
                pos = self._block_pos(blk, t)
                events[bi].append(((pos[0], self.exp.insn_end(d.getSeqnum().getTarget())),
                                   int(d.getSeqnum().getOrder()), i))
        for ev in events.values():
            ev.sort()

        TOP = "top"
        out_inst = dict((bi, TOP) for bi in binfo)
        in_inst = {}
        for _ in range(4 * len(binfo) + 4):
            changed = False
            for bi, (_, _, preds, _) in binfo.items():
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

        per_pc = {}
        for bi, (bounds, pcs, _, _) in binfo.items():
            if bounds is None:
                continue
            cur = in_inst.get(bi)
            if cur == TOP:
                cur = None
            ev = events[bi]
            j = 0
            for pos, pc in pcs:
                while j < len(ev) and ev[j][0] <= pos:
                    cur = ev[j][2]
                    j += 1
                per_pc.setdefault(pc, set()).add(cur)
        # A PC in several decompiler blocks (the decompiler duplicates
        # shared return code and loop tests): only where they agree on the
        # current instance; otherwise the value depends on the path taken.
        result = {}
        for pc in sorted(per_pc):
            insts = per_pc[pc]
            if len(insts) == 1:
                cur = next(iter(insts))
                if cur is not None:
                    result.setdefault(cur, []).append(pc)
        return result

    def _unused_param_location(self, sym, storage):
        """A parameter the decompiled code never reads (it may use the raw
        register under another name, e.g. MIPS64 "in_a0" for the 64-bit a0
        when the parameter is its 32-bit low part): show it wherever its
        entry value still physically exists."""
        if not sym.isParameter():
            return None
        return self.entry_value_location(storage)

    def entry_value_location(self, storage):
        """Where a parameter's entry value still physically exists (also
        for functions without decompiler output); a stack parameter stays in
        its slot."""
        if self.flow is None or storage is None or storage.isBadStorage() or storage.isUnassignedStorage():
            return None
        vns = list(storage.getVarnodes())
        if len(vns) == 1 and vns[0].getAddress().isStackAddress():
            e = self.storage_expr(storage)
            return ("expr", e) if e is not None else None
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

    def join_pcs(self, vn, storage, pcs):
        """[(pc, end, expr)] for a join-space instance (a value split over
        several registers, or a float in a wider FPR) defined by a machine
        instruction: each piece located through the flow analysis. None if
        not applicable (pieces not all registers, no defining instruction)."""
        d = vn.getDef()
        pieces = list(storage.getVarnodes())
        if d is None or not pieces or not all(p.isRegister() for p in pieces):
            return None
        off = int(d.getSeqnum().getTarget().getOffset())
        keys = [(int(p.getOffset()), int(p.getSize())) for p in pieces]
        vals = [self.flow.value_after(off, k) for k in keys]
        if any(v is None for v in vals):
            return []
        order = list(range(len(pieces)))
        if len(pieces) > 1 and not self.exp.big_endian:
            order.reverse()          # DWARF pieces in memory order
        out = []
        for pc in pcs:
            exprs = []
            for i in order:
                # (a float in a wider FPR: also where it is stored converted)
                size = int(vn.getSize()) if len(pieces) == 1 and vn.getSize() < keys[i][1] else None
                e = self.best_location(self.flow.locations_of(pc, vals[i], size, exact=size is not None),
                                       keys[i])
                if e is None:
                    break
                exprs.append((e, keys[i][1]))
            else:
                if len(exprs) == 1:
                    expr = exprs[0][0]
                else:
                    buf = bytearray()
                    for e, size in exprs:
                        buf += e
                        buf.append(C.DW_OP_piece)
                        buf += uleb(size)
                    expr = bytes(buf)
                out.append((pc, self.flow.insn_end(pc), expr))
        return out

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
                if pcs is not None and self.flow is not None:
                    joined = self.join_pcs(vn, storage, pcs)
                    if joined is not None:
                        # (where every piece's value physically still is: a
                        # 64-bit call result moves out of r3:r4, a float out
                        # of f1, at the next call or reuse)
                        entries.extend(joined)
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
