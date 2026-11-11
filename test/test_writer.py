#!/usr/bin/env python3
"""Unit tests for the Ghidra-independent DWARF/ELF writer.

Run:  python3 test/test_writer.py   (from the repo root)

Validates the output with llvm-dwarfdump --verify, readelf, and gdb-multiarch
(if they are installed).
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "ghidra_scripts"))

from dwarfexport import consts as C  # noqa: E402
from dwarfexport.dwarf import DwarfBuilder, uleb, sleb, CommonInformation, FrameDescription  # noqa: E402
from dwarfexport.elf import ElfWriter, Section  # noqa: E402


def have(tool):
    return shutil.which(tool) is not None


def build_sample(addr_size=4, big_endian=True):
    dw = DwarfBuilder(addr_size, big_endian)
    cu = dw.cu
    dw.name(cu, "sample.c")
    cu.add(C.DW_AT_comp_dir, C.DW_FORM_strp, "/tmp")
    cu.add(C.DW_AT_language, C.DW_FORM_data2, C.DW_LANG_C99)
    cu.add(C.DW_AT_low_pc, C.DW_FORM_addr, 0)
    cu.add(C.DW_AT_ranges, C.DW_FORM_sec_offset, dw.add_ranges([(0x1000, 0x1010)]))
    cu.add(C.DW_AT_stmt_list, C.DW_FORM_sec_offset, 0)
    dw.add_file("sample.c")

    int_t = cu.child(C.DW_TAG_base_type)
    dw.name(int_t, "int")
    int_t.add(C.DW_AT_byte_size, C.DW_FORM_udata, 4)
    int_t.add(C.DW_AT_encoding, C.DW_FORM_data1, C.DW_ATE_signed)

    st = cu.child(C.DW_TAG_structure_type)
    dw.name(st, "node")
    st.add(C.DW_AT_byte_size, C.DW_FORM_udata, 8)
    ptr = cu.child(C.DW_TAG_pointer_type)
    ptr.add(C.DW_AT_byte_size, C.DW_FORM_udata, addr_size)
    ptr.add(C.DW_AT_type, C.DW_FORM_ref4, st)  # self-referential struct
    m = st.child(C.DW_TAG_member)
    dw.name(m, "value")
    m.add(C.DW_AT_type, C.DW_FORM_ref4, int_t)
    m.add(C.DW_AT_data_member_location, C.DW_FORM_udata, 0)
    m = st.child(C.DW_TAG_member)
    dw.name(m, "next")
    m.add(C.DW_AT_type, C.DW_FORM_ref4, ptr)
    m.add(C.DW_AT_data_member_location, C.DW_FORM_udata, 4)

    fn = cu.child(C.DW_TAG_subprogram)
    dw.name(fn, "main")
    fn.add(C.DW_AT_external, C.DW_FORM_flag_present)
    fn.add(C.DW_AT_prototyped, C.DW_FORM_flag_present)
    fn.add(C.DW_AT_type, C.DW_FORM_ref4, int_t)
    fn.add(C.DW_AT_low_pc, C.DW_FORM_addr, 0x1000)
    fn.add(C.DW_AT_high_pc, C.DW_FORM_data4, 0x10)
    fn.add(C.DW_AT_frame_base, C.DW_FORM_exprloc, dw.expr().call_frame_cfa().bytes())
    fn.add(C.DW_AT_decl_file, C.DW_FORM_udata, 1)
    fn.add(C.DW_AT_decl_line, C.DW_FORM_udata, 1)
    p = fn.child(C.DW_TAG_formal_parameter)
    dw.name(p, "argc")
    p.add(C.DW_AT_type, C.DW_FORM_ref4, int_t)
    p.add(C.DW_AT_location, C.DW_FORM_sec_offset,
          dw.add_loclist([(0x1000, 0x1008, dw.expr().reg(3).bytes()),
                          (0x1008, 0x1010, dw.expr().fbreg(-8).bytes())]))
    v = fn.child(C.DW_TAG_variable)
    dw.name(v, "head")
    v.add(C.DW_AT_type, C.DW_FORM_ref4, ptr)
    v.add(C.DW_AT_location, C.DW_FORM_exprloc, dw.expr().fbreg(-16).bytes())

    g = cu.child(C.DW_TAG_variable)
    dw.name(g, "g_list")
    g.add(C.DW_AT_type, C.DW_FORM_ref4, ptr)
    g.add(C.DW_AT_external, C.DW_FORM_flag_present)
    g.add(C.DW_AT_location, C.DW_FORM_exprloc, dw.expr().addr(0x2000).bytes())

    dw.add_sequence([(0x1000, 1), (0x1004, 3), (0x1008, 2), (0x100c, 400)], 0x1010)
    dw.aranges.append((0x1000, 0x1010))

    dw.cie = CommonInformation(4, -4, 65, bytes([C.DW_CFA_def_cfa]) + uleb(1) + uleb(0))
    dw.fdes.append(FrameDescription(0x1000, 0x1010, [
        (0x1004, bytes([C.DW_CFA_def_cfa_offset]) + uleb(32)),
    ]))
    return dw


def write_elf(dw, path, is64=False, big_endian=True, machine=20):
    elf = ElfWriter(is64, big_endian, machine, entry=0x1000)
    elf.add_section(Section(".text", C.SHT_NOBITS, C.SHF_ALLOC | C.SHF_EXECINSTR,
                            addr=0x1000, size=0x1000, align=4))
    elf.add_section(Section(".data", C.SHT_NOBITS, C.SHF_ALLOC | C.SHF_WRITE,
                            addr=0x2000, size=0x100, align=4))
    for name, data in dw.build():
        elf.add_section(Section(name, C.SHT_PROGBITS, data=data))
    elf.add_symbol("main", 0x1000, 0x10, C.STT_FUNC, shndx=elf.section_index_for(0x1000))
    elf.add_symbol("g_list", 0x2000, addr_size_of(is64), C.STT_OBJECT,
                   shndx=elf.section_index_for(0x2000))
    elf.write(path)


def addr_size_of(is64):
    return 8 if is64 else 4


class LebTest(unittest.TestCase):
    def test_uleb(self):
        self.assertEqual(uleb(0), b"\x00")
        self.assertEqual(uleb(127), b"\x7f")
        self.assertEqual(uleb(128), b"\x80\x01")
        self.assertEqual(uleb(624485), b"\xe5\x8e\x26")

    def test_sleb(self):
        self.assertEqual(sleb(0), b"\x00")
        self.assertEqual(sleb(-1), b"\x7f")
        self.assertEqual(sleb(63), b"\x3f")
        self.assertEqual(sleb(64), b"\xc0\x00")
        self.assertEqual(sleb(-64), b"\x40")
        self.assertEqual(sleb(-65), b"\xbf\x7f")
        self.assertEqual(sleb(-123456), b"\xc0\xbb\x78")


class WriterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _variants(self):
        # (is64, big_endian, machine, gdb arch)
        return [(False, True, 20, "powerpc:common"),
                (False, False, 40, "arm"),
                (True, False, 62, "i386:x86-64"),
                (True, True, 21, "powerpc:common64")]

    @unittest.skipUnless(have("llvm-dwarfdump"), "llvm-dwarfdump not installed")
    def test_dwarfdump_verify(self):
        for is64, be, machine, _ in self._variants():
            with self.subTest(is64=is64, be=be):
                path = os.path.join(self.tmp, "out.elf")
                write_elf(build_sample(8 if is64 else 4, be), path, is64, be, machine)
                r = subprocess.run(["llvm-dwarfdump", "--verify", path],
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                r = subprocess.run(["llvm-dwarfdump", "--debug-line", "--debug-info",
                                    "--debug-frame", path], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn('DW_AT_name\t("head")', r.stdout)
                self.assertIn("0x0000000000001008      2", r.stdout)
                self.assertIn("0x000000000000100c    400", r.stdout)

    @unittest.skipUnless(have("llvm-dwarfdump"), "llvm-dwarfdump not installed")
    def test_top_of_address_space(self):
        """A function ending at 0xffffffff (code at the top of a 32-bit
        space, e.g. a reset vector at 0xfffffffc): exclusive end 2**32."""
        dw = DwarfBuilder(4, True)
        cu = dw.cu
        dw.name(cu, "top.c")
        cu.add(C.DW_AT_low_pc, C.DW_FORM_addr, 0)
        cu.add(C.DW_AT_ranges, C.DW_FORM_sec_offset, dw.add_ranges([(0xfffffff0, 1 << 32)]))
        cu.add(C.DW_AT_stmt_list, C.DW_FORM_sec_offset, 0)
        dw.add_file("top.c")
        int_t = cu.child(C.DW_TAG_base_type)
        dw.name(int_t, "int")
        int_t.add(C.DW_AT_byte_size, C.DW_FORM_udata, 4)
        int_t.add(C.DW_AT_encoding, C.DW_FORM_data1, C.DW_ATE_signed)
        fn = cu.child(C.DW_TAG_subprogram)
        dw.name(fn, "last_fn")
        fn.add(C.DW_AT_ranges, C.DW_FORM_sec_offset, dw.add_ranges([(0xfffffff0, 1 << 32)]))
        p = fn.child(C.DW_TAG_formal_parameter)
        dw.name(p, "v")
        p.add(C.DW_AT_type, C.DW_FORM_ref4, int_t)
        p.add(C.DW_AT_location, C.DW_FORM_sec_offset,
              dw.add_loclist([(0xfffffff0, 1 << 32, dw.expr().reg(3).bytes())]))
        dw.add_sequence([(0xfffffff0, 1), (0xfffffffc, 2)], 1 << 32)
        dw.aranges.append((0xfffffff0, 1 << 32))
        dw.cie = CommonInformation(4, -4, 65, bytes([C.DW_CFA_def_cfa]) + uleb(1) + uleb(0))
        dw.fdes.append(FrameDescription(0xfffffff0, 1 << 32, []))
        elf = ElfWriter(False, True, 20, entry=0xfffffffc)
        elf.add_section(Section(".text", C.SHT_NOBITS, C.SHF_ALLOC | C.SHF_EXECINSTR,
                                addr=0xffff0000, size=0x10000, align=4))
        for name, data in dw.build():
            elf.add_section(Section(name, C.SHT_PROGBITS, data=data))
        elf.add_symbol("last_fn", 0xfffffff0, 0x10, C.STT_FUNC, shndx=elf.section_index_for(0xfffffff0))
        path = os.path.join(self.tmp, "top.elf")
        elf.write(path)
        r = subprocess.run(["llvm-dwarfdump", "--verify", path], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_section_limit(self):
        """More sections than ELF section indexes allow: a clear error, not
        indexes colliding with SHN_ABS/SHN_COMMON."""
        elf = ElfWriter(False, True, 20, entry=0)
        for i in range(0xff00):
            elf.add_section(Section(".s%d" % i, C.SHT_NOBITS, C.SHF_ALLOC, addr=i * 4, size=4))
        with self.assertRaises(ValueError):
            elf.to_bytes()

    @unittest.skipUnless(have("readelf"), "readelf not installed")
    def test_readelf(self):
        path = os.path.join(self.tmp, "out.elf")
        write_elf(build_sample(), path)
        r = subprocess.run(["readelf", "-W", "-S", "-s", path], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Warning", r.stdout + r.stderr)
        self.assertIn("main", r.stdout)
        self.assertIn(".debug_info", r.stdout)

    @unittest.skipUnless(have("gdb-multiarch"), "gdb-multiarch not installed")
    def test_gdb_reads_it(self):
        for is64, be, machine, arch in self._variants():
            with self.subTest(is64=is64, be=be):
                path = os.path.join(self.tmp, "out.elf")
                write_elf(build_sample(8 if is64 else 4, be), path, is64, be, machine)
                r = subprocess.run(["gdb-multiarch", "-q", "-nx", "-batch",
                                    "-ex", "file " + path,
                                    "-ex", "ptype struct node",
                                    "-ex", "info address main",
                                    "-ex", "info line *0x1008",
                                    "-ex", "info scope main",
                                    "-ex", "ptype g_list"],
                                   capture_output=True, text=True)
                out = r.stdout + r.stderr
                self.assertIn("struct node *next;", out)
                self.assertIn("Line 2 of \"sample.c\"", out)
                self.assertIn("Symbol argc is multi-location", out)
                self.assertIn("type = struct node {", out)
                self.assertNotIn("Dwarf Error", out)


if __name__ == "__main__":
    unittest.main()
