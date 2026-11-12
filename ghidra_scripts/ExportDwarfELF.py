# Export the program's RE annotations (functions, decompiled code, data types,
# globals, labels) as an ELF file with DWARF debug info plus a pseudo-C source
# file, for source-level debugging in GDB of targets that are NOT ELF files
# (raw firmware / memory dumps, ROMs, ...).
#
# Output: <dir>/<program>.elf, and <dir>/<program>.src/ with the pseudo-C
# (<program>.0.c, <program>.1.c, ... split by size) and <program>.types.h
# In GDB (attached to the target or QEMU):  symbol-file <dir>/<program>.elf
#
# GUI: a dialog asks for the output directory and every option (prefilled
# with the defaults).
# Headless (pyghidraRun -H ... -postScript ExportDwarfELF.py <outdir> [key=value ...])
#   options: address_offset=0x..       embed_bytes=true|false   cfi=true|false
#            types_header=true|false   all_types=true|false     decompile_timeout=60
#            sanitize_names=true|false skip_decompile=f1,f2     basename=name
#            irq_signal_frame=true|false  elf_flags=-1  decompile_threads=-1
#            c_max_bytes=100000        c_max_lines=100000
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


# Options shown in the GUI dialog (internal ones are left out).
_INTERNAL = ("split_sections", "frameless_rows")
_OUT_DIR = "Output directory"


def _gui_options(opts):
    """Ask for the output directory and every option, prefilled with the
    defaults. Returns the output directory (raises CancelledException)."""
    from java.io import File
    from jpype import JImplements, JOverride
    from ghidra.features.base.values import GhidraValuesMap

    keys = [k for k in vars(opts) if k not in _INTERNAL]
    values = GhidraValuesMap()
    values.defineDirectory(_OUT_DIR, File(_default_dir()))
    for k in keys:
        v = getattr(opts, k)
        if isinstance(v, bool):
            values.defineBoolean(k, v)
        elif isinstance(v, int):
            values.defineString(k, ("0x%x" % v if v >= 0 else str(v)) if k == "address_offset" else str(v))
        else:
            values.defineString(k, "" if v is None else str(v))

    def apply(vmap, target):
        for k in keys:
            try:
                if isinstance(getattr(Options(), k), bool):
                    target.set(k, "true" if vmap.getBoolean(k) else "false")
                else:
                    text = str(vmap.getString(k) or "").strip()
                    if k == "basename" and not text:
                        continue          # default: the program name
                    target.set(k, text)
            except Exception as e:  # noqa: BLE001
                raise ValueError("%s: %s" % (k, e))

    def out_dir_of(vmap):
        f = vmap.getFile(_OUT_DIR)
        if f is None or not str(f.getPath()).strip():
            raise ValueError("choose an output directory")
        d = os.path.expanduser(str(f.getPath()).strip())
        # (relative to the program's directory, not Ghidra's working directory)
        d = d if os.path.isabs(d) else os.path.join(_default_dir(), d)
        if os.path.exists(d) and not os.path.isdir(d):
            raise ValueError("output directory: %s is a file" % d)
        return d

    @JImplements("docking.widgets.values.ValuesMapValidator")
    class Validator(object):
        @JOverride
        def validate(self, vmap, status):
            try:
                out_dir_of(vmap)
                apply(vmap, Options())
                return True
            except Exception as e:  # noqa: BLE001
                status.setStatusText("Invalid value for %s" % e)
                return False

    values.setValidator(Validator())
    values = askValues("Export DWARF/ELF for GDB",
                       "Output directory and options (defaults prefilled; see the README):", values)
    apply(values, opts)
    return os.path.abspath(out_dir_of(values))


def main():
    opts = Options()
    args = [str(a) for a in getScriptArgs()]
    out_dir = None
    for a in args:
        k = a.split("=", 1)[0].strip()
        if "=" in a and hasattr(opts, k):
            opts.set(k, a.split("=", 1)[1].strip())
        elif out_dir is None:
            out_dir = a
        else:
            raise ValueError("unexpected argument %r" % a)
    if out_dir is None:
        if isRunningHeadless():
            out_dir = _default_dir()
        else:
            from ghidra.util.exception import CancelledException
            try:
                out_dir = _gui_options(opts)
            except CancelledException:
                print("Export cancelled.")
                return
    # (in the GUI, the CodeBrowser's decompiler display options shape the C)
    tool = None if isRunningHeadless() else getState().getTool()
    Exporter(currentProgram, monitor, out_dir, opts, tool=tool).run()


main()
