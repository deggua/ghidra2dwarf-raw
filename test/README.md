# Tests

The test suite builds a test firmware for 20 targets, imports it into Ghidra as
a raw binary, annotates it like an analyst would, exports it, and debugs it
under QEMU with GDB using only the exported files.

Needs `gdb-multiarch`, `llvm` (for `llvm-dwarfdump`), Ghidra at
`../ghidra_12.2_PUBLIC` (or set `GHIDRA_INSTALL_DIR`) with PyGhidra (the
harness's Ghidra scripts are Python), and for each target its
cross GCC and QEMU: `qemu-system-ppc` (ppc32), `qemu-user` (the rest),
`gcc-powerpc-linux-gnu`, `gcc-powerpc64-linux-gnu`, `gcc-powerpc64le-linux-gnu`,
`gcc-mips-linux-gnu`, `gcc-mipsel-linux-gnu`, `gcc-mips64-linux-gnuabi64`,
`gcc-mips64el-linux-gnuabi64`, `gcc-arm-linux-gnueabi`, `gcc-aarch64-linux-gnu`,
and the host GCC (`-m32`/`-m64`).

```sh
test/run_all.py                         # 20 targets x -O0/-O1/-O2 + sanitized names
test/run_all.py -t armle-thumb,mips32be -O O1
DWARFEXPORT_IMPL=python test/run_all.py   # the same tests on the Python version
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
  from there), and a function whose decompilation fails or is skipped;
* code shapes found by an adversarial review (`firmware/shapes.c`): a
  conditional return before the frame setup, conditional moves, a 40 KB
  frame, arguments copied into a stack object a callee modifies, a store as
  the first instruction, a realigned stack, a thunk; from a second review an
  early return through a non-contiguous decompiler block, indirect calls
  (delay slots), a computed-goto dispatcher with 65 cases and an indirect
  tail call whose table is in RAM, and pointer parameters in prototypes the
  exporter writes itself; from a third review 64-bit and float call results
  kept across a later call, an early return in a loop whose epilogue the
  decompiler duplicates (stepped instruction by instruction: the early
  `return` line must never show on the normal path), and a jump-table
  `switch` (stepping each case must show only that case's lines, and no
  `case` label); on ppc32 also
  out-of-line `_savegpr`/`_restgpr` helpers (including a backtrace from
  inside `_restgpr_29_x`), a return address parked in r30,
  and an exception handler that leaves through a shared `rfi` exit;
* a memory map without the X flag (ppc32-linux);
* alias labels on a function and on data items;
* a comment with Ghidra annotations (by address and by name, namespaced,
  data, unknown, URLs wrapped over several comment lines);
* a named label on a `goto` target and default `LAB_` labels
  (`break func:label`), and equates (in code, unused, literal-named, named
  like a global).

The GUI check (`CheckExportDialog.java`) also runs the script down its GUI
path with a stand-in tool whose decompiler options set a 50-character line
width, C++ comments and end-of-line comments, and checks the C files follow
them.

**Differential unwinding test** (`test/difftrace.py`): the firmware is
single-stepped twice from the same point (5,000 instructions from
`shapes_main`, 3,000 from `edge_main`), once with GCC's own debug info and
once with the export, and the unwound PC and SP of every frame must be
identical at every instruction (wherever GCC has CFI, i.e. outside
hand-written assembly). The same trace checks the line table: once an
invocation of a function has shown its closing `}` (the epilogue), it must
not show any other of its lines before it returns.

All of it runs on all 20 targets at three `-O` levels, and with
`sanitize_names=true`: 80 export-and-debug runs. The sanitized runs also
split the pseudo-C into many small files (300 lines / 20 KB each), so every
GDB check runs against a multi-file export too, and every -O1 export is
repeated with `decompile_threads=1` and must be identical. The GUI options
dialog is checked headless with `askValues` stubbed. (The ppc32 ROM must stay
under 16 KB: QEMU's mac99 machine overwrites larger `-bios` images from
0xfff04000 on; the build checks this.)

Where GDB or QEMU gets something wrong even with GCC's own debug info, the
checks detect it and skip: floating point registers in some GDB+QEMU
combinations, `info frame` under `qemu-mipsn32`, and inferior calls with
stack arguments on big-endian AArch64.

## Files

```
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
difftrace.py, gdb_trace.py  unwinding at every instruction vs GCC's own CFI
check_gui_options.py  the GUI options dialog of the Python version, headless (askValues stubbed)
port/flow_dump.py  development check: the Python flow states (vs PortFlowDump.java)
ghidra_dump.py, ghidra_dwarf_only.py  helpers for the round trip
```

