# Test helper (pre-script): restrict auto-analysis to the DWARF importer so
# the round-trip program contains only what the exported ELF/DWARF carries.
#
# Usage (headless): -preScript ghidra_dwarf_only.py
# @runtime PyGhidra

from ghidra.program.model.listing import Program

opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
for name in opts.getOptionNames():
    if "." in name:
        continue          # sub-options
    try:
        if isinstance(opts.getObject(name, None), bool) or str(opts.getType(name)) == "BOOLEAN_TYPE":
            opts.setBoolean(name, name == "DWARF")
    except Exception:
        pass
print("analyzers enabled: %s" % [n for n in opts.getOptionNames()
                                 if "." not in n and str(opts.getType(n)) == "BOOLEAN_TYPE"
                                 and opts.getBoolean(n, False)])
