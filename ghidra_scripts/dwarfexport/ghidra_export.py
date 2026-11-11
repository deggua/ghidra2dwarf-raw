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
import time

from java.io import StringWriter
from ghidra.app.decompiler import DecompInterface, DecompileOptions, ClangFuncNameToken
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.app.util.bin.format.dwarf import DWARFRegisterMappingsManager
from ghidra.program.model.address import AddressSpace
from ghidra.program.model.data import (
    AbstractComplexDataType, AbstractFloatDataType, AbstractIntegerDataType,
    Array, BitFieldDataType, BooleanDataType, CharDataType, DataTypeWriter,
    DefaultDataType, Enum, FunctionDefinition, Pointer, Structure, TypeDef,
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

    def set(self, key, value):
        if not hasattr(self, key):
            raise KeyError("unknown option %r" % key)
        cur = getattr(self, key)
        if isinstance(cur, bool):
            value = str(value).lower() in ("1", "true", "yes", "on")
        elif isinstance(cur, int):
            value = int(str(value), 0)
        setattr(self, key, value)


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
            "blob": C.DW_TAG_typedef,
        }[kind]
        die = self.cu.child(tag)
        self.cache[key] = die
        self.pending.append((kind, die, dt))
        return die

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
        self.dw.name(die, str(dt.getName()))
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
        self.dw.name(die, str(dt.getName()))
        arr = self.cu.child(C.DW_TAG_array_type)
        arr.add(C.DW_AT_type, C.DW_FORM_ref4, self.base_of_size(1, False))
        sub = arr.child(C.DW_TAG_subrange_type)
        sub.add(C.DW_AT_count, C.DW_FORM_udata, int(dt.getLength()))
        die.add(C.DW_AT_type, C.DW_FORM_ref4, arr)

    def _fill_ptr(self, die, dt):
        size = dt.getLength()
        die.add(C.DW_AT_byte_size, C.DW_FORM_udata, int(size if size > 0 else self.ptr_size))
        self.ref(die, dt.getDataType())

    def _fill_typedef(self, die, dt):
        self.dw.name(die, str(dt.getName()))
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
        self.dw.name(die, str(dt.getName()))
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
        self.dw.name(die, str(dt.getName()))
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
        self.types = TypeBuilder(self.dw, program)
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
        """Offset just past the instruction containing addr."""
        off = int(addr.getOffset())
        end = self._insn_end_cache.get(off)
        if end is None:
            ins = self.listing.getInstructionContaining(addr)
            end = int(ins.getMaxAddress().getOffset()) + 1 if ins is not None else off + 1
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
        dw.name(cu, os.path.basename(self.c_path))
        cu.add(C.DW_AT_producer, C.DW_FORM_strp, PRODUCER)
        cu.add(C.DW_AT_language, C.DW_FORM_data2, C.DW_LANG_C99)
        cu.add(C.DW_AT_comp_dir, C.DW_FORM_strp, self.out_dir)
        cu.add(C.DW_AT_low_pc, C.DW_FORM_addr, 0)
        self.file_no = dw.add_file(os.path.basename(self.c_path))

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
            self.c_lines += text.replace("\r\n", "\n").split("\n")
            self.c_lines.append("")

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
        name = str(func.getName())
        entry = int(func.getEntryPoint().getOffset())
        ranges = self._function_ranges(func)

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
        self.elf_symbols.append((name, self.A(entry), size, C.STT_FUNC))

        self.c_lines.append("")
        self.c_lines.append("/* ---- %s @ %s ---- */" % (name, func.getEntryPoint()))
        base = len(self.c_lines)  # line N of the function text -> base + N

        if markup is None or hf is None:
            self.stats["decompile_failed"] += 1
            msg = res.getErrorMessage() if res is not None else "no result"
            sig = str(func.getSignature().getPrototypeString())
            self.c_lines.append("%s /* decompilation failed: %s */" % (sig, str(msg).strip().replace("*/", "* /")))
            sig_line = base + 1
            self.types.ref(die, func.getReturnType())
            addr_lines = {}
        else:
            lines = DecompilerUtils.toLines(markup)
            addr_lines = {}
            sig_line = None
            for cl in lines:
                text = str(cl.getIndentString()) + "".join(str(t.getText()) for t in cl.getAllTokens())
                self.c_lines.append(text)
                gline = base + int(cl.getLineNumber())
                for tok in cl.getAllTokens():
                    if sig_line is None and isinstance(tok, ClangFuncNameToken):
                        sig_line = gline
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

        die.add(C.DW_AT_decl_file, C.DW_FORM_udata, self.file_no)
        die.add(C.DW_AT_decl_line, C.DW_FORM_udata, sig_line)

        # Line rows: the frame setup maps to the signature line, and the first
        # body instruction is flagged prologue_end so GDB (>= 13) places
        # "break func" there -- for frameless functions that is the entry
        # point itself, with all arguments still in their registers.
        pe = flow.prologue_end() if flow is not None else None
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
            self.stats["line_rows"] += len(compact)
            self.dw.add_sequence([(self.A(a), l, ROW_PROLOGUE_END if a == pe else 0)
                                  for a, l in compact], self.A(lo) + (hi - lo))

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

    def _export_variable(self, func_die, sym, ctx, is_param):
        self.stats["variables"] += 1
        tag = C.DW_TAG_formal_parameter if is_param else C.DW_TAG_variable
        die = func_die.child(tag)
        self.dw.name(die, str(sym.getName()))
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
            name = str(sym.getName())
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
            self.elf_symbols.append((str(s.getName()), self.A(addr.getOffset()), 0, C.STT_NOTYPE))

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
        flags = 0x05000000 if proc == "ARM" else 0  # EABI v5
        return machine, flags

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

        for block in self.memory.getBlocks():
            start = block.getStart()
            if not block.isLoaded() or block.isOverlay() or not self.in_space(start):
                continue
            sflags = C.SHF_ALLOC
            if block.isExecute():
                sflags |= C.SHF_EXECINSTR
            if block.isWrite():
                sflags |= C.SHF_WRITE
            size = int(block.getSize())
            name = str(block.getName())
            if self.opts.embed_bytes and block.isInitialized():
                import jpype
                buf = jpype.JArray(jpype.JByte)(size)
                block.getBytes(start, buf)
                data = memoryview(buf).cast("B").tobytes()
                sec = Section(name, C.SHT_PROGBITS, sflags, self.A(start.getOffset()), data)
            else:
                sec = Section(name, C.SHT_NOBITS, sflags, self.A(start.getOffset()), size=size)
            elf.add_section(sec)

        for name, data in self.dw.build():
            elf.add_section(Section(name, C.SHT_PROGBITS, data=data))

        for name, value, size, stype in self.elf_symbols:
            elf.add_symbol(name, value, size, stype, C.STB_GLOBAL, elf.section_index_for(value))
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
    def instance_value(self, vn):
        """FunctionFlow value id of a register varnode instance, or None."""
        flow = self.flow
        if flow is None or not vn.isRegister():
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

    def located_spans(self, vn, value, spans):
        flow = self.flow
        own = (int(vn.getOffset()), int(vn.getSize()))
        insns = flow.insns
        out = []
        for s, t in spans:
            i = bisect.bisect_left(insns, s)
            while i < len(insns) and insns[i] < t:
                pc = insns[i]
                e = self.best_location(flow.locations_of(pc, value), own)
                if e is not None:
                    out.append((pc, flow.insn_end(pc), e))
                i += 1
        return out

    def compound_input_spans(self, storage, spans):
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
        for s, t in spans:
            i = bisect.bisect_left(flow.insns, s)
            while i < len(flow.insns) and flow.insns[i] < t:
                pc = flow.insns[i]
                st = flow.state_in.get(pc)
                if st is not None and all(flow.reg_value(st, k) == ("init", k) for k in keys):
                    out.append((pc, flow.insn_end(pc), e))
                i += 1
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
            return None
        entries = []
        whole = [(lo, hi) for lo, hi in self.ranges]
        for vn in hv.getInstances():
            space = vn.getAddress().getAddressSpace()
            if vn.isConstant() or vn.isUnique():
                continue
            if space.isStackSpace():
                e = self.varnode_expr(vn)
                if e is not None:
                    entries.extend((s, t, e) for s, t in whole)
                continue
            spans = self.live_intervals(vn)
            if vn.isRegister() and self.flow is not None:
                value = self.instance_value(vn)
                if value is not None:
                    entries.extend(self.located_spans(vn, value, spans))
                continue
            if vn.isRegister() or space.equals(self.exp.space):
                e = self.varnode_expr(vn)
            elif (storage is not None and storage.isCompoundStorage()
                  and int(vn.getSize()) == int(storage.size())):
                # Join-space value split over several registers/stack slots
                # (e.g. a 64-bit parameter in r3:r4).
                if vn.isInput() and self.flow is not None:
                    entries.extend(self.compound_input_spans(storage, spans))
                    continue
                e = self.storage_expr(storage)
            else:
                e = None
            if e is None:
                continue
            entries.extend((s, t, e) for s, t in spans if t > s)
        if not entries:
            return None

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
