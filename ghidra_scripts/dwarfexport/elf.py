"""Minimal ELF writer: an ET_EXEC with section headers only (no program
headers), suitable as a GDB ``symbol-file`` for a target whose real image is
not an ELF (raw firmware dumps, ROMs, ...).

Allocated sections mirror the target's memory map. By default they are
SHT_NOBITS (no file contents, so GDB always reads memory from the target);
optionally they can carry the actual bytes (SHT_PROGBITS) for offline
disassembly with objdump/gdb.
"""

import struct

from . import consts as C


class Section(object):
    def __init__(self, name, sh_type, flags=0, addr=0, data=b"", size=None,
                 link=0, info=0, align=1, entsize=0):
        self.name = name
        self.type = sh_type
        self.flags = flags
        self.addr = addr
        self.data = data if data is not None else b""
        self.size = size if size is not None else len(self.data)
        self.link = link
        self.info = info
        self.align = align
        self.entsize = entsize
        self.offset = 0
        self.name_offset = 0


class Symbol(object):
    def __init__(self, name, value, size, sym_type, bind, shndx, other=0):
        self.other = other
        self.name = name
        self.value = value
        self.size = size
        self.type = sym_type
        self.bind = bind
        self.shndx = shndx


class ElfWriter(object):
    def __init__(self, is64, big_endian, machine, flags=0, entry=0):
        self.is64 = is64
        self.end = ">" if big_endian else "<"
        self.big_endian = big_endian
        self.machine = machine
        self.flags = flags
        self.entry = entry
        self.sections = [Section("", C.SHT_NULL)]
        self.symbols = []

    def add_section(self, section):
        self.sections.append(section)
        return len(self.sections) - 1

    def add_symbol(self, name, value, size=0, sym_type=C.STT_NOTYPE,
                   bind=C.STB_GLOBAL, shndx=C.SHN_ABS, other=0):
        self.symbols.append(Symbol(name, value, size, sym_type, bind, shndx, other))

    def section_index_for(self, addr):
        """Index of the allocated section containing addr, else SHN_ABS."""
        import bisect
        n = len(self.sections)
        if getattr(self, "_index_n", None) != n:
            self._index = sorted((s.addr, s.addr + max(s.size, 1), i)
                                 for i, s in enumerate(self.sections) if s.flags & C.SHF_ALLOC)
            self._index_starts = [e[0] for e in self._index]
            self._index_n = n
        j = bisect.bisect_right(self._index_starts, addr) - 1
        if j >= 0 and self._index[j][0] <= addr < self._index[j][1]:
            return self._index[j][2]
        return C.SHN_ABS

    # ------------------------------------------------------------------
    def _build_symtab(self):
        strtab = bytearray(b"\0")
        names = {}

        def add_str(s):
            b = s.encode("utf-8", "replace")
            off = names.get(b)
            if off is None:
                off = len(strtab)
                names[b] = off
                strtab.extend(b + b"\0")
            return off

        # Locals must precede globals; sh_info = index of first non-local.
        syms = sorted(self.symbols, key=lambda s: (s.bind != C.STB_LOCAL, s.value))
        first_global = 1 + sum(1 for s in syms if s.bind == C.STB_LOCAL)

        out = bytearray()
        if self.is64:
            fmt = self.end + "IBBHQQ"
            out += struct.pack(fmt, 0, 0, 0, 0, 0, 0)
            for s in syms:
                out += struct.pack(fmt, add_str(s.name), (s.bind << 4) | s.type, s.other,
                                   s.shndx, s.value, s.size)
            entsize = 24
        else:
            fmt = self.end + "IIIBBH"
            out += struct.pack(fmt, 0, 0, 0, 0, 0, 0)
            for s in syms:
                out += struct.pack(fmt, add_str(s.name), s.value, s.size,
                                   (s.bind << 4) | s.type, s.other, s.shndx)
            entsize = 16
        return bytes(out), bytes(strtab), first_global, entsize

    def write(self, path):
        with open(path, "wb") as f:
            f.write(self.to_bytes())

    # Section indexes from SHN_LORESERVE (0xff00) on are reserved (SHN_ABS,
    # SHN_COMMON, ...); more sections would need SHN_XINDEX/SHT_SYMTAB_SHNDX.
    MAX_SECTIONS = 0xff00 - 4

    def to_bytes(self):
        word = 8 if self.is64 else 4
        if len(self.sections) + 3 > self.MAX_SECTIONS:
            raise ValueError("too many ELF sections (%d)" % len(self.sections))

        if self.symbols:
            symtab, strtab, first_global, entsize = self._build_symtab()
            strtab_idx = self.add_section(Section(".strtab", C.SHT_STRTAB, data=strtab))
            self.add_section(Section(".symtab", C.SHT_SYMTAB, data=symtab,
                                     link=strtab_idx, info=first_global,
                                     align=word, entsize=entsize))

        shstr = bytearray(b"\0")
        shstrtab = Section(".shstrtab", C.SHT_STRTAB)
        self.sections.append(shstrtab)
        for s in self.sections[1:]:
            s.name_offset = len(shstr)
            shstr += s.name.encode("utf-8", "replace") + b"\0"
        shstrtab.data = bytes(shstr)
        shstrtab.size = len(shstr)
        shstrndx = len(self.sections) - 1

        ehsize = 64 if self.is64 else 52
        shentsize = 64 if self.is64 else 40

        body = bytearray()
        offset = ehsize
        for s in self.sections[1:]:
            if s.type == C.SHT_NOBITS:
                s.offset = offset
                continue
            align = max(s.align, 1)
            pad = (-offset) % align
            body += b"\0" * pad
            offset += pad
            s.offset = offset
            body += s.data
            offset += len(s.data)
        pad = (-offset) % word
        body += b"\0" * pad
        offset += pad
        shoff = offset

        ident = b"\x7fELF" + bytes([2 if self.is64 else 1,
                                    2 if self.big_endian else 1,
                                    1, 0, 0]) + b"\0" * 7
        if self.is64:
            hdr = ident + struct.pack(self.end + "HHIQQQIHHHHHH",
                                      C.ET_EXEC, self.machine, 1, self.entry, 0,
                                      shoff, self.flags, ehsize, 0, 0,
                                      shentsize, len(self.sections), shstrndx)
        else:
            hdr = ident + struct.pack(self.end + "HHIIIIIHHHHHH",
                                      C.ET_EXEC, self.machine, 1, self.entry, 0,
                                      shoff, self.flags, ehsize, 0, 0,
                                      shentsize, len(self.sections), shstrndx)
        assert len(hdr) == ehsize

        shdrs = bytearray()
        for s in self.sections:
            if s.type == C.SHT_NULL:
                shdrs += b"\0" * shentsize
                continue
            if self.is64:
                shdrs += struct.pack(self.end + "IIQQQQIIQQ", s.name_offset, s.type,
                                     s.flags, s.addr, s.offset, s.size, s.link,
                                     s.info, s.align, s.entsize)
            else:
                shdrs += struct.pack(self.end + "IIIIIIIIII", s.name_offset, s.type,
                                     s.flags, s.addr, s.offset, s.size, s.link,
                                     s.info, s.align, s.entsize)
        return hdr + bytes(body) + bytes(shdrs)
