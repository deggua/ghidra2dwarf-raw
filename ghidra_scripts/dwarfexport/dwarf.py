"""Minimal pure-Python DWARF 4 producer.

Builds a single compile unit from a tree of :class:`Die` objects and emits
.debug_info, .debug_abbrev, .debug_str, .debug_line, .debug_loc,
.debug_ranges, .debug_aranges and (optionally) .debug_frame.

Nothing in here knows about Ghidra; it is unit-testable with plain CPython.
"""

import struct

from . import consts as C


# --------------------------------------------------------------------------
# LEB128
# --------------------------------------------------------------------------

def uleb(value):
    if value < 0:
        raise ValueError("uleb128 of negative value %d" % value)
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def sleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not (byte & 0x40)) or (value == -1 and (byte & 0x40))
        if done:
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


# --------------------------------------------------------------------------
# Location expressions
# --------------------------------------------------------------------------

class Expr(object):
    """Builder for DWARF location expressions."""

    def __init__(self, addr_size, big_endian):
        self.addr_size = addr_size
        self.end = ">" if big_endian else "<"
        self.buf = bytearray()

    def op(self, opcode):
        self.buf.append(opcode)
        return self

    def reg(self, regno):
        if regno < 32:
            self.buf.append(C.DW_OP_reg0 + regno)
        else:
            self.buf.append(C.DW_OP_regx)
            self.buf += uleb(regno)
        return self

    def breg(self, regno, offset):
        if regno < 32:
            self.buf.append(C.DW_OP_breg0 + regno)
        else:
            self.buf.append(C.DW_OP_bregx)
            self.buf += uleb(regno)
        self.buf += sleb(offset)
        return self

    def fbreg(self, offset):
        self.buf.append(C.DW_OP_fbreg)
        self.buf += sleb(offset)
        return self

    def addr(self, address):
        self.buf.append(C.DW_OP_addr)
        self.buf += struct.pack(self.end + ("I" if self.addr_size == 4 else "Q"), address)
        return self

    def piece(self, size):
        self.buf.append(C.DW_OP_piece)
        self.buf += uleb(size)
        return self

    def bit_piece(self, bits, offset):
        self.buf.append(C.DW_OP_bit_piece)
        self.buf += uleb(bits)
        self.buf += uleb(offset)
        return self

    def call_frame_cfa(self):
        self.buf.append(C.DW_OP_call_frame_cfa)
        return self

    def bytes(self):
        return bytes(self.buf)


# --------------------------------------------------------------------------
# DIEs
# --------------------------------------------------------------------------

class Die(object):
    __slots__ = ("tag", "attrs", "children", "offset", "_code", "_enc")

    def __init__(self, tag):
        self.tag = tag
        self.attrs = []
        self.children = []
        self.offset = None
        self._code = None
        self._enc = None

    def add(self, at, form, value=None):
        self.attrs.append((at, form, value))
        return self

    def child(self, tag):
        die = Die(tag)
        self.children.append(die)
        return die

    def __repr__(self):
        return "<Die tag=0x%x attrs=%d children=%d>" % (self.tag, len(self.attrs), len(self.children))


class StringTable(object):
    def __init__(self):
        self.buf = bytearray()
        self.index = {}

    def add(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8", "replace")
        off = self.index.get(s)
        if off is None:
            off = len(self.buf)
            self.index[s] = off
            self.buf += s + b"\0"
        return off


# --------------------------------------------------------------------------
# Line table
# --------------------------------------------------------------------------

LINE_BASE = -5
LINE_RANGE = 14
OPCODE_BASE = 13
STD_OPCODE_LENGTHS = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]


ROW_PROLOGUE_END = 1


class LineSequence(object):
    """A contiguous run of code: rows [(address, line[, flags])] sorted by
    address, terminated at ``end`` (exclusive). flags: ROW_PROLOGUE_END."""

    def __init__(self, rows, end):
        self.rows = rows
        self.end = end


# --------------------------------------------------------------------------
# Call frame information
# --------------------------------------------------------------------------

class FrameDescription(object):
    """An FDE: ``instructions`` is a list of (address, [cfa-op bytes]);
    ``cie`` indexes DwarfBuilder.cies."""

    def __init__(self, start, end, instructions, cie=0):
        self.start = start
        self.end = end
        self.instructions = instructions
        self.cie = cie


class CommonInformation(object):
    """A CIE. augmentation "S" marks signal/interrupt frames: GDB then uses
    the interrupted frame's exact PC (no "return address - 1")."""

    def __init__(self, code_align, data_align, ra_reg, initial_instructions, augmentation=""):
        self.code_align = code_align
        self.data_align = data_align
        self.ra_reg = ra_reg
        self.initial_instructions = initial_instructions
        self.augmentation = augmentation


# --------------------------------------------------------------------------
# The producer
# --------------------------------------------------------------------------

class DwarfBuilder(object):
    def __init__(self, addr_size, big_endian):
        if addr_size not in (4, 8):
            raise ValueError("unsupported address size %d" % addr_size)
        self.addr_size = addr_size
        self.big_endian = big_endian
        self.end = ">" if big_endian else "<"
        self.strtab = StringTable()
        self.cu = Die(C.DW_TAG_compile_unit)
        self.loc = bytearray()
        self.ranges = bytearray()
        self.files = []          # [(name, dir_index)]
        self.dirs = []           # include directories (index 1..n)
        self.sequences = []      # [LineSequence]
        self.aranges = []        # [(start, end)]
        self.cie = None      # the default CIE (index 0 of cies)
        self.cies = []       # additional CIEs (index 1..)
        self.fdes = []

    def add_cie(self, cie):
        """Registers an additional CIE; returns its index for FrameDescription."""
        self.cies.append(cie)
        return len(self.cies)

    # -- primitive packers ---------------------------------------------------
    def u8(self, v):
        return struct.pack("B", v)

    def u16(self, v):
        return struct.pack(self.end + "H", v)

    def u32(self, v):
        return struct.pack(self.end + "I", v)

    def u64(self, v):
        return struct.pack(self.end + "Q", v)

    def uaddr(self, v):
        return self.u32(v) if self.addr_size == 4 else self.u64(v)

    def expr(self):
        return Expr(self.addr_size, self.big_endian)

    # -- convenience ---------------------------------------------------------
    # Optional callable applied to every DW_AT_name (see ghidra_export).
    name_filter = None

    def name(self, die, s, raw=False):
        if not raw and self.name_filter is not None:
            s = self.name_filter(s)
        die.add(C.DW_AT_name, C.DW_FORM_strp, s)

    def add_file(self, name, dir_index=0):
        self.files.append((name, dir_index))
        return len(self.files)  # DWARF 4 file numbers are 1-based

    def add_dir(self, path):
        self.dirs.append(path)
        return len(self.dirs)

    def add_loclist(self, entries):
        """entries: [(start, end, expr_bytes)] absolute addresses (the CU base
        address is 0). Returns the offset into .debug_loc."""
        off = len(self.loc)
        for start, end, ex in entries:
            if end <= start:
                continue
            self.loc += self.uaddr(start) + self.uaddr(end)
            self.loc += self.u16(len(ex)) + ex
        self.loc += self.uaddr(0) + self.uaddr(0)
        return off

    def add_ranges(self, ranges):
        off = len(self.ranges)
        for start, end in ranges:
            if end <= start:
                continue
            self.ranges += self.uaddr(start) + self.uaddr(end)
        self.ranges += self.uaddr(0) + self.uaddr(0)
        return off

    def add_sequence(self, rows, end):
        if rows:
            self.sequences.append(LineSequence(rows, end))

    # -- attribute encoding --------------------------------------------------
    def _encode_attr(self, form, value):
        """Returns bytes, or an int size for forms that need a later fixup."""
        if form == C.DW_FORM_ref4:
            return 4
        if form == C.DW_FORM_strp:
            return self.u32(self.strtab.add(value))
        if form == C.DW_FORM_string:
            return value.encode("utf-8", "replace") + b"\0"
        if form == C.DW_FORM_addr:
            return self.uaddr(value)
        if form == C.DW_FORM_data1:
            return struct.pack("B", value & 0xFF)
        if form == C.DW_FORM_data2:
            return self.u16(value & 0xFFFF)
        if form == C.DW_FORM_data4 or form == C.DW_FORM_sec_offset:
            return self.u32(value & 0xFFFFFFFF)
        if form == C.DW_FORM_data8:
            return self.u64(value & 0xFFFFFFFFFFFFFFFF)
        if form == C.DW_FORM_udata:
            return uleb(value)
        if form == C.DW_FORM_sdata:
            return sleb(value)
        if form == C.DW_FORM_exprloc:
            return uleb(len(value)) + value
        if form == C.DW_FORM_flag_present:
            return b""
        if form == C.DW_FORM_flag:
            return struct.pack("B", 1 if value else 0)
        raise ValueError("unsupported form 0x%x" % form)

    # -- .debug_info / .debug_abbrev -----------------------------------------
    def _build_info(self):
        abbrevs = {}
        abbrev_buf = bytearray()

        # Iterative DFS to avoid Python recursion limits on huge programs.
        order = []
        stack = [self.cu]
        while stack:
            die = stack.pop()
            order.append(die)
            stack.extend(reversed(die.children))

        for die in order:
            key = (die.tag, bool(die.children), tuple((a, f) for a, f, _ in die.attrs))
            code = abbrevs.get(key)
            if code is None:
                code = len(abbrevs) + 1
                abbrevs[key] = code
                abbrev_buf += uleb(code) + uleb(die.tag)
                abbrev_buf.append(C.DW_CHILDREN_yes if die.children else C.DW_CHILDREN_no)
                for a, f, _ in die.attrs:
                    abbrev_buf += uleb(a) + uleb(f)
                abbrev_buf += b"\0\0"
            die._code = code
            die._enc = [self._encode_attr(f, v) for a, f, v in die.attrs]
        abbrev_buf += b"\0"

        # Assign offsets. Children are emitted right after their parent and
        # each sibling list is closed by a single 0 byte.
        header_size = 11  # unit_length(4) version(2) abbrev_off(4) addr_size(1)
        offset = header_size
        # Walk again in DFS order computing offsets, accounting for the null
        # terminators that close each children list.
        stack = [(self.cu, False)]
        while stack:
            die, closing = stack.pop()
            if closing:
                offset += 1
                continue
            die.offset = offset
            offset += len(uleb(die._code))
            for enc in die._enc:
                offset += enc if isinstance(enc, int) else len(enc)
            if die.children:
                stack.append((die, True))
                for ch in reversed(die.children):
                    stack.append((ch, False))
        total = offset

        body = bytearray()
        stack = [(self.cu, False)]
        while stack:
            die, closing = stack.pop()
            if closing:
                body.append(0)
                continue
            assert die.offset == header_size + len(body), "offset mismatch"
            body += uleb(die._code)
            for (a, f, v), enc in zip(die.attrs, die._enc):
                if f == C.DW_FORM_ref4:
                    if v.offset is None:
                        raise ValueError("reference to a DIE that is not in the tree: %r" % v)
                    body += self.u32(v.offset)
                else:
                    body += enc
            if die.children:
                stack.append((die, True))
                for ch in reversed(die.children):
                    stack.append((ch, False))

        info = bytearray()
        info += self.u32(total - 4)
        info += self.u16(4)
        info += self.u32(0)
        info += self.u8(self.addr_size)
        info += body
        assert len(info) == total
        return bytes(info), bytes(abbrev_buf)

    # -- .debug_line ----------------------------------------------------------
    def _build_line(self):
        hdr = bytearray()
        hdr.append(1)                 # minimum_instruction_length
        hdr.append(1)                 # maximum_operations_per_instruction
        hdr.append(1)                 # default_is_stmt
        hdr += struct.pack("b", LINE_BASE)
        hdr.append(LINE_RANGE)
        hdr.append(OPCODE_BASE)
        hdr += bytes(STD_OPCODE_LENGTHS)
        for d in self.dirs:
            hdr += d.encode("utf-8", "replace") + b"\0"
        hdr.append(0)
        for name, dir_index in self.files:
            hdr += name.encode("utf-8", "replace") + b"\0"
            hdr += uleb(dir_index) + uleb(0) + uleb(0)
        hdr.append(0)

        prog = bytearray()
        for seq in sorted(self.sequences, key=lambda s: s.rows[0][0]):
            addr = None
            line = 1
            for row in seq.rows:
                row_addr, row_line = row[0], row[1]
                flags = row[2] if len(row) > 2 else 0
                if flags & ROW_PROLOGUE_END:
                    prog.append(C.DW_LNS_set_prologue_end)
                if addr is None:
                    prog += b"\0" + uleb(1 + self.addr_size) + bytes([C.DW_LNE_set_address]) + self.uaddr(row_addr)
                    addr = row_addr
                addr_delta = row_addr - addr
                line_delta = row_line - line
                if addr_delta < 0:
                    raise ValueError("line rows not sorted")
                special = None
                if LINE_BASE <= line_delta < LINE_BASE + LINE_RANGE:
                    op = (line_delta - LINE_BASE) + LINE_RANGE * addr_delta + OPCODE_BASE
                    if op <= 255:
                        special = op
                if special is not None:
                    prog.append(special)
                else:
                    if line_delta:
                        prog.append(C.DW_LNS_advance_line)
                        prog += sleb(line_delta)
                    if addr_delta:
                        prog.append(C.DW_LNS_advance_pc)
                        prog += uleb(addr_delta)
                    prog.append(C.DW_LNS_copy)
                addr, line = row_addr, row_line
            if seq.end > addr:
                prog.append(C.DW_LNS_advance_pc)
                prog += uleb(seq.end - addr)
            prog += b"\0" + uleb(1) + bytes([C.DW_LNE_end_sequence])

        out = bytearray()
        out += self.u16(4)              # version
        out += self.u32(len(hdr))       # header_length
        out += hdr
        out += prog
        return self.u32(len(out)) + bytes(out)

    # -- .debug_aranges ------------------------------------------------------
    def _build_aranges(self):
        body = bytearray()
        body += self.u16(2)        # version
        body += self.u32(0)        # debug_info offset
        body.append(self.addr_size)
        body.append(0)             # segment selector size
        # Tuples must be aligned to 2*addr_size from the start of the unit.
        hdr_len = 4 + len(body)
        pad = (-hdr_len) % (2 * self.addr_size)
        body += b"\0" * pad
        for start, end in sorted(self.aranges):
            if end > start:
                body += self.uaddr(start) + self.uaddr(end - start)
        body += self.uaddr(0) + self.uaddr(0)
        return self.u32(len(body)) + bytes(body)

    # -- .debug_frame ----------------------------------------------------------
    def _build_frame(self):
        if self.cie is None:
            return None
        out = bytearray()

        def pad_entry(entry):
            # entry excludes the length field; total (length+entry) must be a
            # multiple of addr_size.
            while (len(entry) + 4) % self.addr_size:
                entry.append(C.DW_CFA_nop)
            return entry

        cie_offsets = []
        for cie in [self.cie] + self.cies:
            cie_offsets.append(len(out))
            body = bytearray()
            body += self.u32(0xFFFFFFFF)   # CIE_id
            body.append(4)                 # version (DWARF 4 .debug_frame)
            body += cie.augmentation.encode() + b"\0"
            body.append(self.addr_size)    # address_size
            body.append(0)                 # segment_size
            body += uleb(cie.code_align)
            body += sleb(cie.data_align)
            body += uleb(cie.ra_reg)
            body += cie.initial_instructions
            pad_entry(body)
            out += self.u32(len(body)) + body

        all_cies = [self.cie] + self.cies
        for fde in self.fdes:
            cie = all_cies[fde.cie]
            body = bytearray()
            body += self.u32(cie_offsets[fde.cie])   # CIE pointer
            body += self.uaddr(fde.start)
            body += self.uaddr(fde.end - fde.start)
            loc = fde.start
            for addr, ops in fde.instructions:
                delta = (addr - loc) // cie.code_align
                if delta < 0:
                    raise ValueError("CFI rows not sorted")
                if delta:
                    if delta < 0x40:
                        body.append(C.DW_CFA_advance_loc | delta)
                    elif delta <= 0xFF:
                        body.append(C.DW_CFA_advance_loc1)
                        body.append(delta)
                    elif delta <= 0xFFFF:
                        body.append(C.DW_CFA_advance_loc2)
                        body += self.u16(delta)
                    else:
                        body.append(C.DW_CFA_advance_loc4)
                        body += self.u32(delta)
                    loc = addr
                body += ops
            pad_entry(body)
            out += self.u32(len(body)) + body
        return bytes(out)

    # -- everything ---------------------------------------------------------
    def build(self):
        """Returns an ordered list of (section_name, bytes)."""
        info, abbrev = self._build_info()
        sections = [
            (".debug_info", info),
            (".debug_abbrev", abbrev),
            (".debug_line", self._build_line()),
            (".debug_str", bytes(self.strtab.buf)),
        ]
        if self.aranges:
            sections.append((".debug_aranges", self._build_aranges()))
        if self.loc:
            sections.append((".debug_loc", bytes(self.loc)))
        if self.ranges:
            sections.append((".debug_ranges", bytes(self.ranges)))
        frame = self._build_frame()
        if frame:
            sections.append((".debug_frame", frame))
        return sections
