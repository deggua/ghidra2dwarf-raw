# Test helper: exercise ExportDwarfELF.py's GUI options dialog headless --
# askValues is replaced by a stub that inspects the prefilled form, checks
# the validator and edits some values, like a user would.
#
# Usage (headless): -postScript check_gui_options.py <scratch dir>
# @runtime PyGhidra

import os
import sys

from java.io import File
from jpype import JImplements, JOverride

scratch = str(getScriptArgs()[0])
here = os.path.dirname(str(getSourceFile().getAbsolutePath()))
repo = os.path.dirname(here)
sys.path.insert(0, os.path.join(repo, "ghidra_scripts"))
script = os.path.join(repo, "ghidra_scripts", "ExportDwarfELF.py")
with open(script) as f:
    source = f.read()
assert source.rstrip().endswith("main()")
ns = dict(globals())
# (PyGhidra's script functions aren't plain module globals)
ns.update(getSourceFile=getSourceFile, isRunningHeadless=isRunningHeadless, getScriptArgs=getScriptArgs,
          currentProgram=currentProgram, monitor=monitor)
exec(compile(source.rstrip()[:-len("main()")], script, "exec"), ns)

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("GUI PASS %s" % name) if cond else ("GUI FAIL %s: %s" % (name, detail)))


@JImplements("ghidra.util.StatusListener")
class Status(object):
    def __init__(self):
        self.text = None

    @JOverride
    def setStatusText(self, *args):
        self.text = str(args[0])

    @JOverride
    def clearStatusText(self):
        self.text = None


def fake_ask(title, message, values):
    defaults = ns["Options"]()
    for k in vars(defaults):
        if k in ns["_INTERNAL"]:
            check("internal option %s not shown" % k, k not in [str(v.getName()) for v in values.getValues()])
            continue
        v = getattr(defaults, k)
        if isinstance(v, bool):
            check("default %s" % k, values.getBoolean(k) == v, values.getBoolean(k))
        elif isinstance(v, int):
            check("default %s" % k, int(str(values.getString(k)), 0) == v, values.getString(k))
        else:
            check("default %s" % k, str(values.getString(k) or "") == ("" if v is None else str(v)),
                  values.getString(k))
    check("output directory prefilled", values.getFile(ns["_OUT_DIR"]) is not None)
    status = Status()
    values.setString("decompile_timeout", "soon")
    check("invalid number rejected", not values.isValid(status) and status.text, status.text)
    check("error names the field", "decompile_timeout" in (status.text or ""), status.text)
    values.setString("decompile_timeout", "30")
    values.setString("basename", "../elsewhere/fw")
    check("basename with directories rejected", not values.isValid(status) and "basename" in (status.text or ""),
          status.text)
    values.setString("basename", "")
    values.setString("address_offset", "0x1000")
    values.setString("c_max_lines", "5000")
    values.setBoolean("embed_bytes", True)
    values.setFile(ns["_OUT_DIR"], File(scratch))
    check("edited values accepted", values.isValid(status), status.text)
    return values


ns["askValues"] = fake_ask
opts = ns["Options"]()
out = ns["_gui_options"](opts)
check("output directory returned", os.path.abspath(out) == os.path.abspath(scratch), out)
check("edits applied", (opts.decompile_timeout, opts.address_offset, opts.c_max_lines, opts.embed_bytes)
      == (30, 0x1000, 5000, True), vars(opts))
check("empty basename keeps the default", opts.basename is None, opts.basename)
print("GUI SUMMARY %d passed, %d failed" % (results.count(True), results.count(False)))
