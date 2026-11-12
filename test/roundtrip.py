#!/usr/bin/env python3
"""DWARF round trip: import the exported ELF into a fresh Ghidra project with
only the DWARF analyzer, dump functions/globals/types, and compare with the
dump of the annotated original program (written by export_fw.py).

    test/roundtrip.py <export work dir> [--sanitized]

Prints one line per difference; exit status 1 if there are any.
"""

import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def ghidra_dump(work):
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", os.path.join(os.path.dirname(REPO), "ghidra_12.2_PUBLIC"))
    proj = os.path.join(work, "rt-project")
    shutil.rmtree(proj, ignore_errors=True)
    os.makedirs(proj)
    out = os.path.join(work, "roundtrip.json")
    if os.path.exists(out):
        os.remove(out)
    cmd = [os.path.join(ghidra, "support", "pyghidraRun"), "-H", proj, "rt",
           "-import", os.path.join(work, "out", "fw.bin.elf"), "-overwrite",
           "-preScript", os.path.join(HERE, "ghidra_dwarf_only.py"),
           "-postScript", os.path.join(HERE, "ghidra_dump.py"), out]
    log_path = os.path.join(work, "roundtrip.log")
    with open(log_path, "w") as log:
        subprocess.run(cmd, input="y\n", stdout=log, stderr=subprocess.STDOUT, text=True)
    if not os.path.exists(out):
        return None
    with open(out) as f:
        return json.load(f)


def _exporter_word_sets():
    """_C_KEYWORDS / _C_TYPE_WORDS from the exporter (which only imports
    inside Ghidra), so the expected sanitized names follow its rules."""
    import ast
    path = os.path.join(REPO, "ghidra_scripts", "dwarfexport", "ghidra_export.py")
    with open(path) as f:
        tree = ast.parse(f.read())
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) in ("_C_KEYWORDS", "_C_TYPE_WORDS"):
            out[node.targets[0].id] = eval(compile(ast.Expression(node.value), path, "eval"),
                                           {"frozenset": frozenset})
    return out["_C_KEYWORDS"], out["_C_TYPE_WORDS"]


C_KEYWORDS, C_TYPE_WORDS = _exporter_word_sets()


def sanitize(name):
    """The exporter's sanitize_names rule for identifiers."""
    out = re.sub(r"[^A-Za-z0-9_]", "_", name) or "_"
    if out[0].isdigit():
        out = "_" + out
    if out in C_KEYWORDS:
        out += "_"
    return out


def sanitize_type(t):
    """Sanitize the base name of a dumped type ("base *", "base[4]")."""
    m = re.match(r"^(.*?)((?: \*|\[\d+\]|:\d+)*)$", t)
    base, suffix = m.group(1), m.group(2)
    if base.startswith("<") or base.split() and all(w in C_TYPE_WORDS for w in base.split()):
        return t
    return sanitize(base) + suffix


# Type names that legitimately differ after a round trip: Ghidra's
# "undefinedN" become same-size integers / byte arrays, DWARF base types are
# imported under their C names, and function pointer typedefs are re-created
# as "_func_..." function definitions.
def norm_type(t, types=None):
    t = re.sub(r"\.conflict\d*", "", t)    # duplicate type names, renamed on import
    t = t.replace("char16_t", "wchar16").replace("char32_t", "wchar32")
    t = re.sub(r"\bundefined(\d)\b", lambda m: "u%s" % m.group(1), t)
    t = re.sub(r"\bundefined\b", "u1", t)
    for a, b in (("uint", "u4"), ("int", "s4"), ("ulonglong", "u8"), ("longlong", "s8"),
                 ("ushort", "u2"), ("short", "s2"), ("uchar", "u1"), ("char", "c1"),
                 ("bool", "b1"), ("byte", "u1"), ("word", "u2"), ("dword", "u4"),
                 ("qword", "u8"), ("sbyte", "s1"), ("unsigned int", "u4"),
                 ("unsigned char", "u1"), ("unsigned short", "u2"), ("long long", "s8"),
                 ("unsigned long long", "u8"), ("signed char", "s1")):
        t = re.sub(r"(?<![\w ])%s(?![\w])" % re.escape(a), b, t)
    return t.replace(" ", "")


def compare(orig, rt, sanitized):
    diffs = []
    ty = sanitize_type if sanitized else (lambda t: t)
    # the exporter's name filter: quotes/control characters always become
    # '_' (they can't be typed in GDB); sanitize_names maps C-invalid ones
    fix = sanitize if sanitized else (lambda n: re.sub(r"['\x00-\x1f\x7f]", "_", n))
    for addr, f in sorted(orig["functions"].items()):
        g = rt["functions"].get(addr)
        if g is None:
            diffs.append("function %s @%s missing" % (f["name"], addr))
            continue
        if g["name"] != fix(f["name"]):
            diffs.append("function @%s name %s -> %s" % (addr, f["name"], g["name"]))
        if f.get("sig_source") == "DEFAULT":
            # no committed signature: the exporter emits the decompiler's
            # inferred prototype (Ghidra's database has none to compare)
            continue
        if norm_type(g["ret"]) == norm_type(ty(f["ret"])) + "*":
            # DWARF has no return-value location: a struct returned in
            # registers via custom storage is re-imported with the compiler
            # spec's hidden-pointer return
            params = g["params"]
            if params and params[0][0] == "__return_storage_ptr__":
                params = params[1:]
            g = dict(g, ret=f["ret"], params=params)
        if norm_type(g["ret"]) != norm_type(ty(f["ret"])):
            diffs.append("function %s return %s -> %s" % (f["name"], f["ret"], g["ret"]))
        if g["varargs"] != f["varargs"]:
            diffs.append("function %s varargs %s -> %s" % (f["name"], f["varargs"], g["varargs"]))
        if len(g["params"]) != len(f["params"]):
            diffs.append("function %s params %s -> %s" % (f["name"], f["params"], g["params"]))
            continue
        for (pn, pt), (qn, qt) in zip(f["params"], g["params"]):
            if qn != fix(pn) or norm_type(qt) != norm_type(ty(pt)):
                diffs.append("function %s param %s %s -> %s %s" % (f["name"], pt, pn, qt, qn))
    for addr, v in sorted(orig["globals"].items()):
        w = rt["globals"].get(addr)
        if w is None:
            diffs.append("global %s @%s missing" % (v["name"], addr))
            continue
        if w["name"] != fix(v["name"]):
            diffs.append("global @%s name %s -> %s" % (addr, v["name"], w["name"]))
        if norm_type(w["type"]) != norm_type(ty(v["type"])):
            diffs.append("global %s type %s -> %s" % (v["name"], v["type"], w["type"]))
    # Same-named types come back as "name", "name.conflict", ... in any order:
    # each original definition must match one of them.
    rt_types = {}
    for name, defs in rt["types"].items():
        rt_types.setdefault(re.sub(r"\.conflict\d*$", "", name), []).extend(defs)
    for name, defs in sorted(orig["types"].items()):
        for t in defs:
            if t["kind"] not in ("struct", "union", "enum"):
                continue
            cands = rt_types.get(fix(name), [])
            if not cands:
                diffs.append("type %s missing" % name)
                continue
            problems = [_type_diff(name, t, u, fix, ty) for u in cands]
            if all(problems):
                diffs.append(min(problems, key=len))
    return diffs


def _type_diff(name, t, u, fix, ty):
    """None if u (round trip) matches t (original), else a description."""
    if u["kind"] != t["kind"] or u["size"] != t["size"]:
        return "type %s: %s/%d -> %s/%d" % (name, t["kind"], t["size"], u["kind"], u["size"])
    if t["kind"] == "enum":
        if sorted([fix(n), v] for n, v in t["values"]) != sorted([n, v] for n, v in u["values"]):
            return "enum %s values %s -> %s" % (name, t["values"], u["values"])
        return None
    a = [(o, fix(n) if n else n, norm_type(ty(ft)), ln) for o, n, ft, ln in t["fields"]]
    # anonymous members come back with Ghidra's default field names
    b = [(o, "" if re.match(r"field\d+_0x[0-9a-f]+$", n) else n, norm_type(ty), ln)
         for o, n, ty, ln in u["fields"]]
    if a != b:
        return "%s %s fields %s -> %s" % (t["kind"], name, t["fields"], u["fields"])
    return None


def roundtrip(work, sanitized=False):
    """Returns (ok, list of difference lines)."""
    with open(os.path.join(work, "original.json")) as f:
        orig = json.load(f)
    rt = ghidra_dump(work)
    if rt is None:
        return False, ["round-trip import failed (see %s/roundtrip.log)" % work]
    diffs = compare(orig, rt, sanitized)
    return not diffs, diffs


if __name__ == "__main__":
    ok, diffs = roundtrip(sys.argv[1], "--sanitized" in sys.argv)
    print("\n".join(diffs) or "round trip: no differences")
    sys.exit(0 if ok else 1)
