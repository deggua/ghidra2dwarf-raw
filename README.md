# ghidra2dwarf-raw

Source-level debugging of **reverse-engineered, non-ELF programs** (raw
firmware / memory dumps, ROMs, ...) in GDB, using what you've annotated in
Ghidra.

A Ghidra script, `ExportDwarfELF.java`, exports a program as:

| File | Contents |
|------|----------|
| `<name>.src/<name>.0.c`, `.1.c`, ... | pseudo-C: the decompiler output of every function, split into files of at most 100 KB / 100,000 lines |
| `<name>.src/<name>.types.h` | the program's data types as C (included by the `.c` files) |
| `<name>.elf` | an ELF *symbol file*: sections mirroring the program's memory map, a symbol table, and DWARF 4 debug info whose line table points into the `.c` files |

Load the ELF into GDB while attached to the real target or an emulator (QEMU),
and debug the decompiled code as if it were the source.

It combines the ideas of
[ghidra2dwarf](https://github.com/cesena/ghidra2dwarf) (decompiled source,
line info and variables, but only for programs that *are* ELF files) and
[ghidra-ExportDwarfELFSymbols](https://github.com/aldelaro5/ghidra-ExportDwarfELFSymbols)
(an ELF built from scratch for any format, but only function ranges).

## Features

* `break`, `list`, `next`, `step`, `finish`, `bt`, `up`, `info locals`,
  `info frame`, `p var`, `p *ptr`, `ptype`, `call func(...)`, `return`,
  `watch`, `advance`, `until` and `jump` work on the decompiled code.
* Functions, parameters and locals under the decompiler's names, with
  location lists that follow values through registers, spills and calls
  (`<optimized out>` where a value no longer exists).
* Call frame information computed from the machine code, so backtraces and
  `finish` work at every instruction, including through interrupt and
  exception handlers into the interrupted code.
* All data types (structs, unions, enums, bitfields, typedefs, function
  pointers, ...), typed globals, labels (`break func:label`), equates, and the
  decompiler's comments.
* Names Ghidra allows but C doesn't (`Get?Value`, `Foo::init`) are kept, or
  rewritten into C identifiers with `sanitize_names=true`.
* No dependencies beyond Ghidra.

What exactly is exported and how: [docs/details.md](docs/details.md).

**Supported and tested:** PowerPC (32-bit BE, including 603e/MPC8xxx
exception handlers; 64-bit BE ELFv1 and ELFv2, LE), MIPS (o32, n32 and n64,
BE and LE), ARM (LE, BE8, Thumb-2; hard-float and softfp), AArch64 (LE and
BE), and x86 (i386, including `-mregparm`, and x86-64). The analysis is
architecture-independent (Ghidra p-code), so other processors may work too.

## Requirements

* Ghidra 12.x (developed and tested with 12.2).
* `gdb-multiarch` or a GDB for your target. GDB 13 or later is recommended
  (it honors the `prologue_end` markers).

## Setup

In Ghidra's Script Manager, *Manage Script Directories* → add
`ghidra2dwarf-raw/java_scripts`. The script (category *DWARF*) is compiled
the first time it runs. See also [Recommended settings](#recommended-settings).

## Usage

**GUI:** run `ExportDwarfELF.java`. A dialog asks for the output directory
and the options below, prefilled with the defaults.

**Headless:**

```sh
$GHIDRA/support/analyzeHeadless <project dir> <project name> -process <program> -noanalysis \
    -scriptPath ghidra2dwarf-raw/java_scripts -postScript ExportDwarfELF.java <out dir> [key=value ...]
```

Options (`key=value` arguments headless, the dialog in the GUI):

| Option | Default | Meaning |
|--------|---------|---------|
| `address_offset` | `0` | Added to every address, if the Ghidra image base differs from where the code runs. |
| `embed_bytes` | `false` | Store the initialized memory in the ELF (for offline `objdump` / `disassemble`); otherwise it's NOBITS placeholders. |
| `cfi` | `true` | Generate call frame information (`.debug_frame`). |
| `types_header` | `true` | Write the data types to `<name>.types.h`. |
| `all_types` | `true` | Emit every struct/union/enum/typedef, not only the ones in use. |
| `c_max_bytes` | `100000` | Start a new `.c` file when the next function would make the current one larger than this (0 = no limit). |
| `c_max_lines` | `100000` | The same limit in lines. |
| `decompile_timeout` | `60` | Per-function decompiler timeout, in seconds. |
| `decompile_threads` | `-1` | Worker threads, each with its own decompiler process; `-1` = min(16, CPUs - 1), `1` = serial. |
| `skip_decompile` | | Comma-separated function names or entry addresses not to decompile (e.g. ones that hang the decompiler). They still get symbols, ranges and CFI. |
| `sanitize_names` | `false` | Rewrite every name into a plain C identifier (`Get?Value` → `Get_Value`, `Foo::init` → `Foo__init`), consistently everywhere. |
| `basename` | program name | Output file base name. |
| `elf_flags` | `-1` (auto) | ELF `e_flags`; by default derived from the language and compiler spec (ARM float ABI, MIPS ABI, PPC64 ELFv1/v2). |
| `irq_signal_frame` | `true` | Mark interrupt/exception handler frames as signal frames (GDB shows `<signal handler called>`). |

In the GUI, the `.c` files follow the CodeBrowser's decompiler display options
(line width, comments, brace style, ...); headless runs use Ghidra's
defaults. Re-export (and `symbol-file` again) after changing annotations, and
don't edit the `.c` files: the line table points at their exact lines.

## Debugging

```
$ qemu-system-ppc -M <machine> -bios fw.bin -S -gdb tcp::1234 ...
$ gdb-multiarch
(gdb) symbol-file out/fw.bin.elf
(gdb) target remote :1234
(gdb) break sensor_update
(gdb) continue
Breakpoint 1, sensor_update (s=0x100008 <g_sensors>, sample=257) at fw.bin.c:235
235       if (s->filter != (filter_fn)0x0) {
(gdb) bt
#0  sensor_update (s=0x100008 <g_sensors>, sample=257) at fw.bin.c:235
#1  0xfff003f4 in process_all (list=0x100008 <g_sensors>, round=<optimized out>) at fw.bin.c:264
#2  0xfff00500 in fw_main () at fw.bin.c:293
```

GDB finds the `.c` files through the output directory recorded in the
DWARF. If you move them, use `set substitute-path <old dir> <new dir>`.
Names that aren't C identifiers need single quotes in expressions
(`p 'g?thing'.'field?1'`), not in breakpoint locations; see
[Names](docs/details.md#names).

## Recommended settings

**Memory and JVM threads.** The export decompiles and analyzes functions in
parallel, as far ahead as memory allows (code in flight up to 1/4096 of the
maximum heap), so a larger heap is faster. Exporting glibc for PPC32
(3,687 functions) on 16 cores takes 20 s with the headless defaults, 17 s
with an 8 GB heap, and 16 s with an 8 GB heap and more GC/JIT threads.
Recommended, if the machine has the memory:

* GUI (`ghidraRun`): set `MAXMEM_DEFAULT=8G` in `ghidraRun`, or export
  `GHIDRA_GUI_MAXMEM=8G` (the JVM default is 1/4 of the physical memory).
* Headless (`support/analyzeHeadless`, default 2 GB, and the GC and JIT
  compiler pinned to 2 threads each): set `MAXMEM_DEFAULT=8G` there, or
  `GHIDRA_HEADLESS_MAXMEM=8G`, and
  `GHIDRA_HEADLESS_JAVA_OPTIONS="-XX:ParallelGCThreads=8 -XX:CICompilerCount=4"`.

**Decompiler limits.** In the GUI the export uses the CodeBrowser's
decompiler limits (*Edit → Tool Options → Decompiler*: *Max Instructions per
Function*, *Decompiler Max-Payload (MBytes)*, *Max Entries per Jumptable*). A
function over them isn't decompiled (or its switch isn't recovered), so raise
them for very large functions. Other Ghidra options (such as the decompiler's
cache size) don't affect the export.

**The Ghidra project.** The DWARF follows Ghidra's annotations, mistakes
included. Worth checking before debugging:

* prototypes where Ghidra's compiler spec models a different ABI variant
  than your compiler (PPC32 struct returns, ARM softfp, MIPS n32, i386
  regparm, ...);
* switch tables the decompiler couldn't recover ("Could not recover
  jumptable"): their case code gets no lines, CFI or variables;
* the language variant (all instructions decoded) and Thumb mode;
* interrupt handlers that aren't found automatically: tag them `INTERRUPT`.

Details and fixes: [Architecture notes](docs/details.md#architecture-notes),
[Interrupt and exception handlers](docs/details.md#interrupt-and-exception-handlers).

## Limitations

* Only the architectures above are tested.
* C only: C++ classes, `this`, references and namespaces as DWARF scopes are
  not represented (qualified names are kept).
* Only the default address space: no overlays or bank-switched memory.
* `call func(...)` in GDB passes arguments by the standard calling
  convention, so calling a function with custom storage or a non-standard
  convention passes them in the wrong places.
* A value that only exists as an expression of others (e.g. `i` when only
  `i+1` is kept) shows as `<optimized out>`, as does a value kept in a
  call-clobbered register across a call (GCC `-fipa-ra`).
* After a stack realignment or `alloca`, GDB falls back to its own prologue
  analysis, which can get the caller wrong (i386 -O2).
* Before an interrupt handler has saved the return address, the backtrace
  ends at the handler.
* Some GDB + QEMU combinations can't read floating point / vector registers
  even with GCC's own debug info.

The full list: [docs/details.md](docs/details.md#limitations).

## Tests

```sh
test/run_all.py                         # 20 targets x -O0/-O1/-O2, plus sanitized names
test/run_all.py -t armle-thumb,mips32be -O O1
```

Each run builds a test firmware with a cross GCC, imports it into Ghidra as a
raw binary, annotates it, exports it, and debugs it under QEMU with GDB using
only the exported files. Requirements, targets and what is checked:
[test/README.md](test/README.md).

## Python version

The exporter was first written in Python (PyGhidra). That version is in
`ghidra_scripts/` (run `ExportDwarfELF.py` from Ghidra started with
`support/pyghidraRun`). It produces the same output but is about 7 times
slower on large programs. `DWARFEXPORT_IMPL=python test/run_all.py` tests it.
