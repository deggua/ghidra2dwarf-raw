# Test helper: dump what the DWARF round trip should preserve (function
# names/prototypes, typed globals, composite and enum types) as JSON.
#
# Usage (headless): -postScript ghidra_dump.py <out.json>
# @runtime PyGhidra

import json

from ghidra.program.model.data import (Array, BitFieldDataType, Enum, FunctionDefinition, Pointer, StringDataInstance,
                                       Structure, TypeDef, Union)
from ghidra.program.model.symbol import SourceType

out_path = str(getScriptArgs()[0])
prog = currentProgram


def tname(dt, depth=0):
    """Structural type name, independent of category paths."""
    if dt is None:
        return "void"
    if isinstance(dt, Pointer):
        return tname(dt.getDataType(), depth + 1) + " *"
    if isinstance(dt, Array):
        return "%s[%d]" % (tname(dt.getDataType(), depth + 1), dt.getNumElements())
    if isinstance(dt, FunctionDefinition):
        return "<function>"       # (names of function types aren't preserved)
    if isinstance(dt, BitFieldDataType):
        return "%s:%d" % (tname(dt.getBaseDataType(), depth + 1), dt.getBitSize())
    return str(dt.getName())


def composite(dt):
    fields = []
    for c in dt.getDefinedComponents():
        fields.append([int(c.getOffset()), str(c.getFieldName() or ""), tname(c.getDataType()),
                       int(c.getLength())])
    return {"kind": "union" if isinstance(dt, Union) else "struct", "size": int(dt.getLength()),
            "fields": fields}


funcs = {}
for f in prog.getFunctionManager().getFunctions(True):
    if f.getSymbol().getSource() == SourceType.DEFAULT:
        continue
    params = [[str(p.getName()), tname(p.getDataType())] for p in f.getParameters()]
    funcs["%x" % f.getEntryPoint().getOffset()] = {
        "name": str(f.getName(True)), "ret": tname(f.getReturnType()), "params": params,
        "varargs": bool(f.hasVarArgs()), "sig_source": str(f.getSignatureSource())}

globs = {}
listing = prog.getListing()
for d in listing.getDefinedData(True):
    s = d.getPrimarySymbol()
    if s is None or s.getSource() == SourceType.DEFAULT:
        continue
    t = tname(d.getDataType())
    dt = d.getDataType()
    if dt is not None and dt.getLength() <= 0 and "Pascal" not in dt.getClass().getSimpleName():
        sdi = StringDataInstance.getStringDataInstance(d)
        if sdi is not None and sdi != StringDataInstance.NULL_INSTANCE:
            n = str(sdi.getCharsetName()).upper()
            cs = 4 if "32" in n else 2 if "16" in n else 1
            t = "%s[%d]" % ({1: "char", 2: "wchar16", 4: "wchar32"}[cs], d.getLength() // cs)
    globs["%x" % d.getAddress().getOffset()] = {"name": str(s.getName(True)), "type": t,
                                                "size": int(d.getLength())}

types = {}   # name -> [definitions] (same-named types in different categories)
for dt in prog.getDataTypeManager().getAllDataTypes():
    if isinstance(dt, (Structure, Union)) and not dt.isNotYetDefined():
        d = composite(dt)
    elif isinstance(dt, Enum):
        d = {"kind": "enum", "size": int(dt.getLength()),
             "values": sorted([str(n), int(dt.getValue(n))] for n in dt.getNames())}
    elif isinstance(dt, TypeDef):
        d = {"kind": "typedef", "to": tname(dt.getDataType())}
    else:
        continue
    types.setdefault(str(dt.getName()), []).append(d)

with open(out_path, "w") as f:
    json.dump({"functions": funcs, "globals": globs, "types": types}, f, indent=1, sort_keys=True)
print("dumped %d functions, %d globals, %d types" % (len(funcs), len(globs), len(types)))
