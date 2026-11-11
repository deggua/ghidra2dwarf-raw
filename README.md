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
`info frame`, `p var`, `p *ptr`, `ptype`, `call func(...)`, `return`,
`watch`, `advance`, `until` and `jump` all work on the decompiled code.
Backtraces continue through interrupt and exception handlers into the
interrupted code.

Supported and tested (see [Tests](#tests)): **PowerPC** (32-bit BE, including
603e/MPC8xxx exception handlers; 64-bit BE ELFv1 and ELFv2, LE), **MIPS**
(o32, n32 and n64, BE and LE), **ARM** (LE, BE8, Thumb-2; hard-float and
softfp), **AArch64** (LE and BE), and **x86** (i386, including `-mregparm`,
and x86-64).

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
  recommended (it honors the `prologue_end` markers). Developed with GDB 16.

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
| `sanitize_names` | `false` | Rewrite every name into a plain C identifier (`Get?Value` → `Get_Value`, `Foo::init` → `Foo__init`, a variable named `switch` → `switch_`), consistently in the DWARF, the ELF symbols and the `.c` file. See [Names](#names). |
| `skip_decompile` | | Comma-separated function names (or entry addresses) not to decompile, e.g. ones that hang the decompiler. They still get symbols, address ranges, CFI and a one-line prototype. |
| `elf_flags` | `-1` (auto) | ELF header `e_flags`. By default derived from the language and compiler spec (ARM EABI5, BE8 and float ABI; MIPS o32/n32/o64/EABI/n64 and ISA; PPC64 ELFv1/ELFv2). GDB uses it to pick the ABI. |
| `irq_signal_frame` | `true` | Mark interrupt/exception handler frames as signal frames, see [Interrupt and exception handlers](#interrupt-and-exception-handlers). |

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

## Names

Ghidra allows names that aren't C identifiers (`Get?Value`, `field?1`,
`Foo::init`, `operator<<`, names with spaces, non-ASCII). By default they are
exported verbatim, so the DWARF, the `.c` file and the Ghidra database all
agree. GDB handles them as follows:

* Breakpoint locations need no quoting: `break Get?Value`, `break Foo::init`.
* In expressions, put the name in single quotes. This works for variables,
  struct fields, types, casts and `sizeof`:

  ```
  (gdb) p 'p?arg'
  (gdb) p 'g?thing'.'field?1'
  (gdb) p *('Thing?Info' *)0x100094
  (gdb) ptype struct 'Thing?Info'
  (gdb) p &'Foo::counter'
  ```
* Names that are valid identifiers, or contain only `$` and `<>`, also work
  unquoted.
* A name containing `'` can't be quoted at all, so `'` (and control characters)
  are always replaced with `_` (`it's` → `it_s`).
* `info address` does not accept quoted names; use `p &'name'` instead.

If you'd rather never quote, export with `sanitize_names=true`.

Namespaced functions and globals are exported with their qualified name
(`Foo::init`), as the decompiler prints them, so same-named functions in
different namespaces stay distinct.

## Architecture notes

GDB needs a few ABI facts that a raw dump doesn't carry. The exporter derives
them from the Ghidra language and compiler spec:

| Architecture | What the exporter adds |
|--------------|------------------------|
| PowerPC | GCC/GDB DWARF register numbers (Ghidra's `ppc.dwarf` numbers LR/CTR differently). |
| PPC64 | `e_flags` ELFv2 when functions start with a TOC setup (`addis r2,r12,..` or `lis r2,..` followed by `addi r2,r2,..`), and local entry points in the symbols' `st_other`. Local calls enter 8 bytes in, so breakpoints go there. Otherwise ELFv1: see below. |
| MIPS | `e_flags` ABI and ISA: o32/EABI from the compiler spec; with 64-bit registers, n64, or n32 (`0x20`) when pointers are 32 bits (`MIPS:*:64:64-32addr` languages). Delay slots: Ghidra folds a slot into its branch's p-code, and a PC inside a slot (a caller frame's return address) gets the state *after* the slot executed. n32 code does its stack-pointer arithmetic in the low 32 bits of the 64-bit `sp`; the CFI analysis follows it. |
| ARM | `e_flags` (EABI5, BE8 for `ARM:LEBE` languages, float ABI) and a `.ARM.attributes` section (GDB reads the float ABI from `Tag_ABI_VFP_args`). Thumb functions (from Ghidra's `TMode` context) get symbols with bit 0 set and `$t`/`$a`/`$d` mapping symbols. |
| AArch64, x86 | Nothing special. 32-bit writes to 64-bit registers (AArch64 `w0`/`x0`, x86-64 `eax`/`rax`) are tracked as the low part of the wider register. |

**PPC64 ELFv1 function descriptors.** ELFv1 function pointers point at
3-doubleword descriptors (entry, TOC, environment) in `.opd`, and GDB resolves
`call ptr(...)`, `break *ptr` and function-pointer values through the `.opd`
section. A raw image has no sections, so the exporter finds descriptor arrays:
aligned doublewords pointing at a function entry, followed by the program's
common TOC value and 0. They're emitted as an `.opd` section with a symbol per
descriptor. GDB's inferior calls load r2 from the descriptor; for the code to
run correctly the TOC (r2) must be set up as on the real target.

Things to check in your Ghidra project, all found while testing:

* **Calling convention variants.** The DWARF follows Ghidra's prototypes. Where
  Ghidra's compiler spec models a different ABI variant than your compiler,
  arguments are wrong in both the decompiled code and GDB until you fix the
  prototype (e.g. with custom storage). Known cases:
  * PPC32: Ghidra's `ppc_32.cspec` returns structs of 8 bytes or less in r3:r4
    (SVR4/EABI, GCC `-msvr4-struct-return`). Linux GCC
    (`powerpc-linux-gnu`) returns them in memory via a hidden pointer in r3.
    So does PPC64 ELFv1. Fix: return a pointer and add the pointer as the
    first parameter.
  * PPC64: both Ghidra PPC64 compiler specs put stack arguments at SP+112
    (ELFv1). ELFv2, which is always the case for little-endian, puts them at
    SP+96.
  * ARM: `ARM.cspec`'s default convention passes floating point arguments in
    VFP registers (hard-float). For softfp code (`-mfloat-abi=softfp`: VFP
    instructions, but float arguments in core registers) set the functions'
    calling convention to `__stdcall_softfp`; the exporter then also marks
    the ELF as soft-float, which GDB uses for `finish` and `call`.
  * MIPS n32: use a `MIPS:*:64:64-32addr` language with the `n32` compiler
    spec. That spec allocates FP and integer argument registers
    independently, but n32 (like n64) gives every argument a slot: in
    `double f(float a, double b, int c)`, `c` is in `a2`, not `a0`. Fix
    mixed float/integer prototypes with custom storage.
  * i386 `-mregparm=3` (Linux kernel style): Ghidra's `__regparm3` gives
    float/double arguments registers and never passes an `int64` in
    registers. GCC does the opposite: floats and structs always go on the
    stack, an `int64` takes a register pair (EAX:EDX) if two are left, and an
    argument that doesn't fit ends register passing. Use custom storage.
  * Callee-pops conventions (`stdcall`, `-mrtd`): the CFI analysis takes the
    popped bytes from the callee's prototype (`extrapop`) and accounts for
    them after the call. This path is untested, since the GCC x86 compiler
    spec has no callee-pops convention.
  * `char` signedness follows the compiler spec, which for most processors is
    signed (GCC uses unsigned on ARM, AArch64 and PowerPC).
* **Language variant.** Pick one that decodes all your instructions; e.g. POWER8+
  code needs `PowerPC:*:64:A2ALT`, since the `default` PPC64 languages lack VSX
  (`mtfprd`).
* **Thumb-only images** (Cortex-M): select a Cortex/v8-m language or set `TMode`
  to 1 *before* auto-analysis, otherwise the code is disassembled as ARM.
* **PPC64 ELFv2 raw images**: auto-analysis creates functions at the local entry
  points (`func+8`, the target of local calls), splitting each function after
  its 2-instruction TOC setup. Merge them back into one function starting at
  the global entry.

## Interrupt and exception handlers

Handlers entered by the hardware get their own CFI (a separate CIE): the
return address is the interrupt return register (PPC `SRR0`, `CSRR0` for
critical and `MCSRR0` for machine-check interrupts, MIPS `EPC`/`ErrorEPC`,
AArch64 `ELR_ELn`), and every register is recovered from where the handler
saved it. Unwinding from a C function called by the handler goes through the
handler into the interrupted function at the interrupted instruction, with
that function's registers and arguments restored from the exception frame.

A function is treated as a handler when:

* it returns with an interrupt-return instruction (`rfi`, `rfid`, `rfci`,
  `rfmci`, `eret`, `iret`, ...);
* it has the Ghidra function tag `INTERRUPT` (for handlers whose return
  isn't in the function, e.g. ones that branch to a common exit path);
* it is an entry point (Ghidra *external entry point*) at a classic PowerPC
  exception vector, 0x200-0x2f00 above 0 or 0xfff00000 (system reset at
  0x100 has nothing to return to); or
* one of the above jumps (not calls) to it. This covers vector stubs like
  `nop; nop; b handler`.

With `irq_signal_frame=true` (default) the handler CIE has augmentation `S`,
and GDB shows the handler as `<signal handler called>` and looks up the
interrupted frame's line and CFI at the exact interrupted PC. With `false`,
GDB treats the handler like a normal caller and uses PC-1 for the interrupted
frame's line and CFI. That is off by one instruction when the interrupt hit
the first instruction after a branch or at a function start.

Limitation: the return address is only recoverable once the handler has
stored `SRR0` (or `EPC`, ...) in memory. GDB can read `$srr0` by name but
can't map DWARF register numbers to special-purpose registers, so before the
save (in the vector stub, and the first few instructions of the handler) the
backtrace ends at the handler instead of continuing into the interrupted
code.

## What is exported

* **Memory map**: allocated sections for the loaded memory blocks in the
  default address space (overlays and other spaces are skipped), with the
  blocks' R/W/X permissions. Executable blocks are split into code runs
  (function bodies) and data runs, since GDB decides whether a symbol is a
  function or data from its section, and raw dumps are often one RWX block.
  The main code run is named `.text`: GDB files DWARF function symbols under
  `.text`, and without it `list func` / `info line func` fail.
* **Symbols** (`.symtab`): functions (`STT_FUNC`, with size), defined data
  (`STT_OBJECT`), and other non-code labels. A label on memory with no data
  type is a symbol only: GDB says it "has unknown type", so cast it
  (`p *(int *)&'name'`). Code labels inside functions are
  left out so GDB keeps showing `<func+off>`.
* **Types**: base types, pointers, typedefs, structs (including bitfields,
  packed layouts, anonymous members, flexible array members), unions, enums
  (including 8-byte and > `INT_MAX` values), multi-dimensional arrays, and
  function types (including varargs). Every struct/union/enum/typedef is
  exported, even unused ones. Ghidra-only types are mapped as follows:

  | Ghidra | DWARF |
  |--------|-------|
  | `undefined`, `undefined1..8` | unsigned base types with those names |
  | strings and unicode strings | an array of `char` / `char16_t` / `char32_t` of the data's actual length, so GDB prints them as strings (`"..."`, `u"..."`, `U"..."`) |
  | other dynamic-size data | a byte array of the data's actual length |
  | fixed-size types with no C equivalent | a typedef with the Ghidra name, to a byte array of the same size |
  | pointer typedefs with an offset, shift, mask, relative/image-base type, or another address space (e.g. `int *32 __((offset(-0x4)))`) | a typedef with the Ghidra name, to an unsigned integer, so GDB shows the raw value instead of dereferencing the wrong address |
  | "not yet defined" placeholder structs | a declaration (GDB shows `<incomplete type>`) |
  | the decompiler's `code *` (function pointer of unknown type) | a pointer to typedef `code` = `void (...)` |
  | same-named types in different categories | separate types; each variable refers to the right one |

  `char` signedness follows Ghidra's compiler spec (e.g. signed for PowerPC,
  even though GCC treats it as unsigned there), so values print the way the
  decompiled code reads them.
* **Global variables**: every defined data item with a name, with its type.
* **Functions**: name, address range(s) (non-contiguous bodies use
  `DW_AT_ranges`), return type, varargs, and the decompiler's parameters and
  locals under the names used in the `.c` file. Custom-storage parameters
  (e.g. a struct or bitfield value in a register, split over two registers,
  or in stack slots) are exported with that storage. If a function fails to
  decompile, the `.c` file gets its prototype and the error, and the function
  still has symbols, ranges, CFI and a line-table entry.
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
   copies, spills/reloads, zero/sign extensions and sub-register views, and
   calls (call-clobbered registers are invalidated). Decompiler temporaries
   (HASH storage) are followed through the register their defining
   instruction wrote. A parameter the decompiled code never reads is shown
   wherever its entry value still exists.

At each PC the exporter picks the best physical location for the current
value. Call-preserved registers and stack slots are preferred because they
stay valid when the frame is a caller frame. If the value no longer exists
anywhere, the variable shows as `<optimized out>`, as with optimized
compiler-generated debug info.

The same analysis yields the CFI: the CFA rule (SP + offset, or a frame
pointer register) and the save slots of the return address and callee-saved
registers at every instruction, including shrink-wrapped functions (the
return address saved on only some paths), epilogue restores, and reloads in
delay slots. The rules are derived from the state at each PC (which register
or stack slot still holds each entry value), not from save/restore events. Call-clobbered
registers are marked `DW_CFA_undefined`, so caller frames show them as not
saved instead of showing the callee's values. Program entry points get an
undefined return address, so backtraces end cleanly.

## Limitations

* The code is architecture-agnostic (Ghidra's DWARF register mappings,
  compiler spec, and p-code), but only the architectures above are tested.
  Others may need a register-number override (`build_register_map`) or a link
  register entry (`flow._LINK_REGISTERS`).
* The DWARF reflects the Ghidra annotations, including their mistakes (see
  [Architecture notes](#architecture-notes)).
* MIPS16/microMIPS mode switches are not represented in the symbols (Thumb
  is).
* C only. The pseudo-C and DWARF are C (namespaced names are kept as
  qualified names); C++ (classes with member functions, `this`, references,
  templates, `DW_TAG_namespace`) is future work.
* `call func(...)` in GDB marshals arguments by the architecture's standard
  calling convention. GDB doesn't use the DWARF parameter locations for that,
  and DWARF can't describe a custom convention, so calling functions that
  use custom storage or a non-standard convention (i386 regparm, softfp
  without the soft-float ELF flag) passes the arguments in the wrong places.
  Breakpoints, argument display, `finish` and backtraces aren't affected.
* `return` in GDB pops the frame using the CFI and puts the value where the
  standard convention returns it.
* Interrupt handlers before the return-address save: see
  [Interrupt and exception handlers](#interrupt-and-exception-handlers).
* Some GDB + QEMU combinations can't read floating point / vector registers
  at all, even with GCC's own debug info: x86-64 under QEMU user mode
  (GDB misnumbers the xmm registers), MIPS o32 doubles in FPR pairs, and
  AArch64 big-endian vector registers. Values located there show wrong
  (the tests detect this and check the locations instead).
* `ptype struct X` can't find a declaration-only (placeholder) struct by
  name; it shows as `<incomplete type>` through pointers to it.
* Only the default address space. Overlays and bank-switched memory are not
  represented.
* The CFI analysis understands SP-relative frames and frame pointers copied
  from SP. Stack realignment (`and sp, -16`) or `alloca`-style dynamic SP
  changes end CFA tracking for the rest of the function, and GDB falls back to
  its prologue analyzer there.
* Values that only exist as an expression of other registers (e.g. `i` when
  only `i+1` is kept) are reported as `<optimized out>`. There's no
  `DW_OP_stack_value` synthesis.

## Performance

Exporting the stripped PPC32 glibc (`libc.so.6`, 2.3 MB, 3,687 functions,
9,687 globals) took about 4 minutes on a 16-core VM. Roughly 40% is Ghidra's
decompiler and the rest is the flow/location analysis. The 3.3 MB ELF loads
in GDB in about 0.1 s and passes `llvm-dwarfdump --verify`.

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
    run_all.py         full test suite (parallel; targets x -O levels)
    targets.py         the 20 targets: toolchain, flags, Ghidra language, QEMU
    build_fw.py        builds the test firmware for a target
    test_writer.py     unit tests for dwarf.py/elf.py (llvm-dwarfdump, readelf, gdb)
    firmware/          test firmware: portable C + per-ISA crt0.S / edge_asm.S
    ghidra_setup.py    simulates RE annotations on the raw import (names, prototypes, types)
    export_fw.py       headless import (raw binary) + annotate + export
    run_gdb_test.py    runs the firmware under QEMU and the GDB check scripts
    gdb_checks.py      GDB-Python assertions (backtraces, args, locals, stepping, finish, globals)
    gdb_edge_checks.py edge cases (see below)
    gdb_feature_checks.py  call, return, watch (global and scoped local), advance, until, jump, info frame
    gdb_irq_checks.py  backtraces through PPC exception handlers (ppc32)
    gdb_helpers.py     shared GDB-side helpers
    ghidra_setup_edge.py  Ghidra-only annotations for the edge cases
    ghidra_setup_irq.py   INTERRUPT tag / entry points for the exception vectors
    roundtrip.py       re-imports the exported ELF into Ghidra (DWARF only) and diffs it
    ghidra_dump.py, ghidra_dwarf_only.py  helpers for the round trip
```

## Tests

Needs `gdb-multiarch`, `llvm` (for `llvm-dwarfdump`), Ghidra at
`../ghidra_12.2_PUBLIC` (or set `GHIDRA_INSTALL_DIR`), and for each target its
cross GCC and QEMU: `qemu-system-ppc` (ppc32), `qemu-user` (the rest),
`gcc-powerpc-linux-gnu`, `gcc-powerpc64-linux-gnu`, `gcc-powerpc64le-linux-gnu`,
`gcc-mips-linux-gnu`, `gcc-mipsel-linux-gnu`, `gcc-mips64-linux-gnuabi64`,
`gcc-mips64el-linux-gnuabi64`, `gcc-arm-linux-gnueabi`, `gcc-aarch64-linux-gnu`,
and the host GCC (`-m32`/`-m64`).

```sh
test/run_all.py                         # 20 targets x -O0/-O1/-O2 + sanitized names
test/run_all.py -t armle-thumb,mips32be -O O1
```

| Target | Ghidra language | Runs under |
|--------|-----------------|------------|
| ppc32 | `PowerPC:BE:32:default`, 603e, SVR4 struct returns, exception handlers | `qemu-system-ppc -M mac99 -cpu 603e` (boot ROM at 0xfff00000) |
| ppc32-linux | same, Linux ABI (structs returned in memory) | `qemu-system-ppc -M mac99` |
| ppc64be / ppc64le | `PowerPC:{BE,LE}:64:A2ALT` (ELFv2) | `qemu-ppc64` / `qemu-ppc64le` |
| ppc64be-elfv1 | `PowerPC:BE:64:A2ALT` (ELFv1, `.opd` descriptors) | `qemu-ppc64` |
| mips32be / mips32le | `MIPS:{BE,LE}:32:default` (o32) | `qemu-mips` / `qemu-mipsel` |
| mips64be / mips64le | `MIPS:{BE,LE}:64:default` (n64) | `qemu-mips64` / `qemu-mips64el` |
| mips64n32be / mips64n32le | `MIPS:{BE,LE}:64:64-32addr`, `n32` compiler spec | `qemu-mipsn32` / `qemu-mipsn32el` |
| armle / armbe | `ARM:LE:32:v7` / `ARM:LEBE:32:v7LEInstruction` (BE8), hard-float | `qemu-arm` / `qemu-armeb` |
| armle-thumb | `ARM:LE:32:v7`, Thumb-2 | `qemu-arm` |
| armle-softfp | `ARM:LE:32:v7`, `__stdcall_softfp` | `qemu-arm` |
| aarch64le / aarch64be | `AARCH64:{LE,BE}:64:v8A` | `qemu-aarch64` / `qemu-aarch64_be` |
| i386 / x86_64 | `x86:LE:{32,64}:default`, `gcc` compiler spec | `qemu-i386` / `qemu-x86_64` |
| i386-regparm | same, `-mregparm=3` (`__regparm3` + custom storage) | `qemu-i386` |

The test firmware is built from C, converted to a raw binary
(`objcopy -O binary`), and imported into Ghidra as a raw binary at its link
address without auto-analysis. `ghidra_setup.py` then does what an analyst
would: marks the known function entries (setting Thumb mode where needed),
runs the analysis, and applies names, prototypes (parsed from `firmware/fw.h`
with Ghidra's C parser) and typed globals. Except for ppc32, which boots as a
real ROM, the firmware runs as a static binary under QEMU user mode; GDB is
forced to use only the exported files (QEMU user mode would otherwise hand GDB
the reference binary with GCC's debug info).

GDB then checks argument and local values in inner and outer frames, 64-bit
register-pair and stack-passed arguments, recursion, indirect calls, stepping,
`finish` return values, struct/bitfield/enum printing, and final global state.
A second session per run exercises GDB features that depend on the debug info:
inferior calls (register, stack, int64 and function-pointer calls), `return`
with a forced value (the program then has to carry on with it), `info frame`,
hardware/software watchpoints on a global and on a stack local (which GDB must
delete when its frame returns), `advance`, `until`, and `jump`. On ppc32 a
third session checks backtraces through the exception handlers (system call,
program check via a tagged stub, decrementer via a vector stub), `finish` out
of a C handler, and stepping over `rfi`.

Every export is also re-imported into a fresh Ghidra project with only the
DWARF analyzer and compared with the annotated original: function names,
prototypes (parameter names and types), globals and their types, and
struct/union/enum layouts must survive the round trip.
The checks adapt to code shapes that differ legitimately between targets and
`-O` levels (tail calls, recursion turned into a loop, arguments passed only in
registers). Before checking floating point values, the harness probes whether
GDB can read them in that GDB+QEMU combination using GCC's own debug info, and
where it can't, checks the exported locations instead.

The edge-case module (`firmware/edge.c`, `edge_asm.S`, `ghidra_setup_edge.py`,
`gdb_edge_checks.py`) covers:
* names with `?`, `'`, `::`, a C keyword and non-ASCII characters (functions,
  parameters, locals, globals, struct tags, fields), in both naming modes;
* namespaced duplicate functions and globals;
* unions, anonymous unions, packed structs, flexible array members, 2-D
  arrays, bitfields crossing bytes and signed bitfields, `> INT_MAX` and
  8-byte enums, bool, int64, function-pointer arrays;
* string and unicode data, `undefined4`, labels with no data, placeholder
  structs, shifted pointer typedefs, duplicate type names, the decompiler's
  `code *`;
* varargs, float/double arguments and returns, struct returns, stack-array
  locals, renamed locals;
* custom storage: a bitfield struct passed by value in a register (checked
  field by field against GCC's own decode), a struct split over two
  registers or two stack slots, and a struct return type;
* a non-contiguous function (stepping into its detached tail and backtracing
  from there), and a function whose decompilation fails or is skipped.

All of it runs on all 20 targets at three `-O` levels, and with
`sanitize_names=true`: 80 export-and-debug runs.

Where GDB or QEMU gets something wrong even with GCC's own debug info, the
checks detect it and skip: floating point registers in some GDB+QEMU
combinations, `info frame` under `qemu-mipsn32`, and inferior calls with
stack arguments on big-endian AArch64.
