# Export the program's RE annotations (functions, decompiled code, data types,
# globals, labels) as an ELF file with DWARF debug info plus a pseudo-C source
# file, for source-level debugging in GDB of targets that are NOT ELF files
# (raw firmware / memory dumps, ROMs, ...).
#
# Output: <dir>/<program>.elf and <dir>/<program>.c
# In GDB (attached to the target or QEMU):  symbol-file <dir>/<program>.elf
#
# GUI: asks for the output directory.
# Headless (pyghidraRun -H ... -postScript ExportDwarfELF.py <outdir> [key=value ...])
#   options: address_offset=0x..       embed_bytes=true|false   cfi=true|false
#            types_header=true|false   all_types=true|false     decompile_timeout=60
#            sanitize_names=true|false skip_decompile=f1,f2     basename=name
#            irq_signal_frame=true|false  elf_flags=-1
#
# @category DWARF
# @runtime PyGhidra

import importlib
import os
import sys

_script_dir = os.path.dirname(str(getSourceFile().getAbsolutePath()))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

# Reload so edits to the package are picked up without restarting Ghidra.
import dwarfexport.consts
import dwarfexport.dwarf
import dwarfexport.elf
import dwarfexport.flow
import dwarfexport.ghidra_export
for _m in (dwarfexport.consts, dwarfexport.dwarf, dwarfexport.elf, dwarfexport.flow, dwarfexport.ghidra_export):
    importlib.reload(_m)

from dwarfexport.ghidra_export import Exporter, Options


def _default_dir():
    exe = currentProgram.getExecutablePath()
    if exe:
        d = os.path.dirname(str(exe))
        if os.path.isdir(d):
            return d
    return os.getcwd()


def main():
    opts = Options()
    args = [str(a) for a in getScriptArgs()]
    out_dir = None
    for a in args:
        if "=" in a:
            k, v = a.split("=", 1)
            opts.set(k.strip(), v.strip())
        elif out_dir is None:
            out_dir = a
        else:
            raise ValueError("unexpected argument %r" % a)
    if out_dir is None:
        if isRunningHeadless():
            out_dir = _default_dir()
        else:
            out_dir = str(askDirectory("Output directory for the .elf/.c files", "Export").getAbsolutePath())
    Exporter(currentProgram, monitor, out_dir, opts).run()


main()
