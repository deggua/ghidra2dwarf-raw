# ghidra2dwarf-raw

Source-level debugging of **reverse-engineered, non-ELF programs** (raw
firmware / memory dumps, ROMs, ...) in GDB, using what you've annotated in
Ghidra.

A PyGhidra script exports a Ghidra program as:

| File | Contents |
|------|----------|
| `<name>.c`   | pseudo-C: the decompiler output of every function (optionally preceded by the program's data types as C) |
| `<name>.elf` | an ELF *symbol file*: sections mirroring the program's memory map, a symbol table, and DWARF 4 debug info whose line table points into `<name>.c` |

Load the ELF into GDB while attached to the real target or an emulator (QEMU),
and `break`, `list`, `next`, `step`, `finish`, `bt`, `up`, `info locals`,
`p var`, `p *ptr`, `ptype` all work on the decompiled code.

It combines the ideas of
[ghidra2dwarf](https://github.com/cesena/ghidra2dwarf) (decompiled source +
line info + variables, but only for programs that *are* ELF files, since it
patches the original binary) and
[ghidra-ExportDwarfELFSymbols](https://github.com/aldelaro5/ghidra-ExportDwarfELFSymbols)
(builds an ELF from scratch for any format, but only function ranges). It has
no native dependencies: the DWARF and ELF writers are pure Python.

## Requirements

* Ghidra 12.x with PyGhidra (bundled). Developed and tested against
  Ghidra 12.2.
* `gdb-multiarch` (or a GDB for your target) to use the output. GDB >= 13 is
  recommended (it honors the `prologue_end` markers).

## Install

1. Ghidra's Script Manager -> *Manage Script Directories* -> add
   `ghidra2dwarf-raw/ghidra_scripts`.
2. Start Ghidra with **`support/pyghidraRun`** so Python 3 scripts can run (the
   first launch offers to install PyGhidra into Ghidra's own virtualenv from
   the bundled wheels).

## Export

**GUI:** run `ExportDwarfELF.py` (category *DWARF*) and pick an output
directory.

**Headless:**

```sh
$GHIDRA/support/pyghidraRun -H <project dir> <project name> -process <program> -noanalysis \
    -postScript ghidra2dwarf-raw/ghidra_scripts/ExportDwarfELF.py <out dir> [key=value ...]
```

Options (`key=value` script arguments in headless mode; defaults in
`dwarfexport/ghidra_export.py:Options` for the GUI):

| Option | Default | Meaning |
|--------|---------|---------|
| `address_offset` | `0` | Added to every address. Use it if the Ghidra image base differs from where the code runs. |
| `embed_bytes` | `false` | Store the initialized memory blocks' bytes in the ELF (PROGBITS), for offline `objdump`/`gdb disassemble`. Otherwise they're NOBITS placeholders. |
| `cfi` | `true` | Generate `.debug_frame` (call frame info) from p-code. |
| `types_header` | `true` | Put the program's data types (as C) at the top of the `.c` file. |
| `all_types` | `true` | Emit DWARF for every struct/union/enum/typedef, not only the ones in use (so `ptype`/casts work for all of them). |
| `decompile_timeout` | `60` | Per-function decompiler timeout, in seconds. |
| `basename` | program name | Output file base name. |

Re-export (and `symbol-file` again in GDB) whenever you change annotations.
Don't edit the `.c` file: the line table points at its exact line numbers.

## Debug

```
$ qemu-system-ppc -M <machine> -bios fw.bin -S -gdb tcp::1234 ...
$ gdb-multiarch
(gdb) symbol-file out/fw.bin.elf
(gdb) target remote :1234
(gdb) break sensor_update
(gdb) continue
Breakpoint 1, sensor_update (s=0x100008 <g_sensors>, sample=257) at fw.bin.c:235
235       if (s->filter != (filter_fn)0x0) {
(gdb) p *s
$1 = {name = "temp\000\000\000", id = 257, flags = 17 '\021', enabled = 1 '\001', channel = 2 '\002',
  mode = MODE_RUN, pos = {x = 10, y = 20}, history = {0, 0, 0, 0}, samples = 0,
  next = 0x10003c <g_sensors+52>, filter = 0xfff00150 <filter_double>}
(gdb) bt
#0  sensor_update (s=0x100008 <g_sensors>, sample=257) at fw.bin.c:235
#1  0xfff003f4 in process_all (list=0x100008 <g_sensors>, round=<optimized out>) at fw.bin.c:264
#2  0xfff00500 in fw_main () at fw.bin.c:293
#3  0xfff00610 in _cstart () at fw.bin.c:332
#4  0xfff00124 in _reset () at fw.bin.c:89
```

GDB finds the `.c` file through the absolute output directory recorded in the
DWARF (`DW_AT_comp_dir`). If you move the files, use
`set substitute-path <old dir> <new dir>` or `directory <new dir>`.

## What is exported

* **Memory map**: one allocated section per loaded memory block in the default
  address space (overlays and other spaces are skipped), with the block's
  R/W/X permissions.
* **Symbols** (`.symtab`): functions (`STT_FUNC`, with size), defined data
  (`STT_OBJECT`), and other non-code labels. Code labels inside functions are
  left out so GDB keeps showing `<func+off>`.
* **Types**: base types, pointers, typedefs, structs (including bitfields),
  unions, enums, arrays, function types. Every struct/union/enum/typedef is
  exported, even unused ones.
* **Global variables**: every defined data item with a name, with its type.
* **Functions**: name, address range(s) (non-contiguous bodies use
  `DW_AT_ranges`), return type, and the decompiler's parameters and locals
  under the names used in the `.c` file.
* **Line table**: each decompiled line is mapped to the instructions behind its
  tokens. The frame setup maps to the signature line, and the first body
  instruction carries `prologue_end`, so `break func` stops before any argument
  register is overwritten.
* **Variable locations**: location lists, see below.
* **Call frame information** (`.debug_frame`): see below.

### How variable locations and unwinding work

The decompiler copy-propagates away register moves and spills. For example,
in a parameter that the compiled code copies into a callee-saved register
before a call, the decompiler's SSA form still says "parameter in r3" after
the call has clobbered r3. Using the decompiler's storage would print wrong
values, so the exporter combines two analyses:

1. **Which value** a variable holds at each PC: the reaching definition of the
   decompiler's SSA instances over its basic blocks. A variable is shown until
   it is reassigned, not just while the decompiler still needs it.
2. **Where that value physically is** at each PC: a small abstract
   interpretation over the raw p-code of every instruction (`flow.py`). It
   tracks the stack pointer as *entry SP + delta*, register entry values,
   per-instruction definitions, phi merges at joins, and stack slots, through
   copies, spills/reloads and calls (call-clobbered registers are invalidated).

At each PC the exporter picks the best physical location for the current
value. Call-preserved registers and stack slots are preferred because they
stay valid when the frame is a caller frame. If the value no longer exists
anywhere, the variable shows as `<optimized out>`, as with optimized
compiler-generated debug info.

The same analysis yields the CFI: the CFA rule (SP + offset, or a frame
pointer register) and the save slots of the return address and callee-saved
registers at every instruction, including shrink-wrapped functions (the
return address saved on only some paths) and epilogue restores. Call-clobbered
registers are marked `DW_CFA_undefined`, so caller frames show them as not
saved instead of showing the callee's values. Program entry points get an
undefined return address, so backtraces end cleanly.

## Limitations

* Tested end-to-end on 32-bit big-endian PowerPC (GCC -O0/-O1/-O2). The code is
  architecture-agnostic: it uses Ghidra's DWARF register mappings, compiler
  spec, and p-code. PowerPC gets an override table because Ghidra's
  `ppc.dwarf` numbers LR/CTR differently from GCC/GDB. Other architectures
  should work but may need similar register-number fixes (`build_register_map`)
  or a link register entry (`flow._LINK_REGISTERS`).
* Only the default address space. Overlays and bank-switched memory are not
  represented.
* The CFI analysis understands SP-relative frames and frame pointers copied
  from SP. Stack realignment (`and sp, -16`) or `alloca`-style dynamic SP
  changes end CFA tracking for the rest of the function, and GDB falls back to
  its prologue analyzer there.
* Values that only exist as an expression of other registers (e.g. `i` when
  only `i+1` is kept) are reported as `<optimized out>`. There's no
  `DW_OP_stack_value` synthesis.
* Delay-slot architectures (MIPS, SPARC) have not been tested.

## Layout

```
ghidra_scripts/ExportDwarfELF.py        the Ghidra script (entry point, options)
ghidra_scripts/dwarfexport/
    ghidra_export.py   Ghidra -> DWARF: types, functions, line table, variables, globals, ELF
    flow.py            p-code data flow: CFI + physical value locations
    dwarf.py           pure-Python DWARF 4 producer
    elf.py             pure-Python ELF writer
    consts.py          DWARF/ELF constants
test/
    run_all.sh         full test suite
    test_writer.py     unit tests for dwarf.py/elf.py (llvm-dwarfdump, readelf, gdb)
    firmware/          PPC32 BE bare-metal test firmware (raw image at 0xfff00000)
    ghidra_setup.py    simulates RE annotations on the raw import (names, prototypes, types)
    export_fw.sh       headless import + annotate + export
    run_gdb_test.py    boots the firmware in QEMU (mac99) and runs gdb_checks.py
    gdb_checks.py      GDB-Python assertions (backtraces, args, locals, stepping, finish, globals)
```

## Tests

Needs `qemu-system-ppc`, `gdb-multiarch`, `gcc-powerpc-linux-gnu`, `llvm`
(for `llvm-dwarfdump`), and Ghidra at `../ghidra_12.2_PUBLIC` (or set
`GHIDRA_INSTALL_DIR`).

```sh
test/run_all.sh            # ~25 s
```

The test firmware is built from C, stripped to a raw binary, and imported into
Ghidra as a raw binary at 0xfff00000. `ghidra_setup.py` recreates what an
analyst would have done: function names and prototypes (parsed from
`firmware/fw.h` with Ghidra's C parser), typed globals, and a RAM block. The
firmware then runs under `qemu-system-ppc -M mac99 -bios fw.bin`, and GDB,
using only the exported files, checks argument and local values in
inner and outer frames, 64-bit register-pair and stack-passed arguments,
recursion, indirect calls, stepping, `finish` return values, struct/bitfield/enum
printing, and final global state. The checks adapt to code shapes that differ
legitimately between `-O` levels (tail calls, recursion turned into a loop).
