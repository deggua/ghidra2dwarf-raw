// Export the program's RE annotations (functions, decompiled code, data types,
// globals, labels) as an ELF file with DWARF debug info plus pseudo-C source
// files, for source-level debugging in GDB of targets that are NOT ELF files
// (raw firmware / memory dumps, ROMs, ...).
//
// Output: <dir>/<program>.elf, and <dir>/<program>.src/ with the pseudo-C
// (<program>.0.c, <program>.1.c, ... split by size) and <program>.types.h
// In GDB (attached to the target or QEMU):  symbol-file <dir>/<program>.elf
//
// GUI: a dialog asks for the output directory and every option (prefilled
// with the defaults).
// Headless (analyzeHeadless ... -postScript ExportDwarfELF.java <outdir> [key=value ...])
//   options: address_offset=0x..       embed_bytes=true|false   cfi=true|false
//            types_header=true|false   all_types=true|false     decompile_timeout=60
//            sanitize_names=true|false skip_decompile=f1,f2     basename=name
//            irq_signal_frame=true|false  elf_flags=-1  decompile_threads=-1
//            c_max_bytes=100000        c_max_lines=100000
//
// @category DWARF
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import docking.widgets.values.GValuesMap;
import docking.widgets.values.ValuesMapValidator;
import dwarfexport.Exporter;
import dwarfexport.Options;
import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.util.StatusListener;
import ghidra.util.exception.CancelledException;

public class ExportDwarfELF extends GhidraScript {
    static final String OUT_DIR = "Output directory";

    String defaultDir() {
        String exe = currentProgram.getExecutablePath();
        if (exe != null && !exe.isEmpty()) {
            File d = new File(exe).getParentFile();
            if (d != null && d.isDirectory()) {
                return d.getPath();
            }
        }
        return System.getProperty("user.dir");
    }

    List<String> dialogKeys() {
        List<String> keys = new ArrayList<>();
        for (String k : Options.names()) {
            if (!Options.INTERNAL.contains(k)) {
                keys.add(k);
            }
        }
        return keys;
    }

    void apply(GValuesMap vmap, Options target) {
        for (String k : dialogKeys()) {
            try {
                if (target.type(k) == boolean.class) {
                    target.set(k, vmap.getBoolean(k) ? "true" : "false");
                }
                else {
                    String s = vmap.getString(k);
                    String text = s == null ? "" : s.strip();
                    if (k.equals("basename") && text.isEmpty()) {
                        continue; // default: the program name
                    }
                    target.set(k, text);
                }
            }
            catch (Exception e) {
                throw new IllegalArgumentException(k + ": " + e.getMessage());
            }
        }
    }

    String outDirOf(GValuesMap vmap) {
        File f = vmap.getFile(OUT_DIR);
        if (f == null || f.getPath().strip().isEmpty()) {
            throw new IllegalArgumentException("choose an output directory");
        }
        String d = f.getPath().strip();
        if (d.startsWith("~")) {
            d = System.getProperty("user.home") + d.substring(1);
        }
        Path p = Path.of(d);
        if (!p.isAbsolute()) {
            p = Path.of(defaultDir()).resolve(p);
        }
        if (p.toFile().exists() && !p.toFile().isDirectory()) {
            throw new IllegalArgumentException("output directory: " + p + " is a file");
        }
        return p.toString();
    }

    /** Asks for the output directory and every option; returns the directory. */
    String guiOptions(Options opts) throws CancelledException {
        GhidraValuesMap values = new GhidraValuesMap();
        values.defineDirectory(OUT_DIR, new File(defaultDir()));
        for (String k : dialogKeys()) {
            Object v = opts.get(k);
            if (v instanceof Boolean) {
                values.defineBoolean(k, (Boolean) v);
            }
            else if (v instanceof Long) {
                long n = (Long) v;
                values.defineString(k, k.equals("address_offset") && n >= 0 ? "0x" + Long.toHexString(n)
                        : Long.toString(n));
            }
            else {
                values.defineString(k, v == null ? "" : v.toString());
            }
        }
        values.setValidator(new ValuesMapValidator() {
            @Override
            public boolean validate(GValuesMap vmap, StatusListener status) {
                try {
                    outDirOf(vmap);
                    apply(vmap, new Options());
                    return true;
                }
                catch (Exception e) {
                    status.setStatusText("Invalid value for " + e.getMessage());
                    return false;
                }
            }
        });
        GValuesMap result = askValues("Export DWARF/ELF for GDB",
            "Output directory and options (defaults prefilled; see the README):", values);
        apply(result, opts);
        return Path.of(outDirOf(result)).toAbsolutePath().toString();
    }

    @Override
    protected void run() throws Exception {
        Options opts = new Options();
        String outDir = null;
        for (String a : getScriptArgs()) {
            int eq = a.indexOf('=');
            String k = eq >= 0 ? a.substring(0, eq).strip() : a.strip();
            if (eq >= 0 && opts.has(k)) {
                opts.set(k, a.substring(eq + 1).strip());
            }
            else if (outDir == null) {
                outDir = a;
            }
            else {
                throw new IllegalArgumentException("unexpected argument '" + a + "'");
            }
        }
        if (outDir == null) {
            if (isRunningHeadless()) {
                outDir = defaultDir();
            }
            else {
                try {
                    outDir = guiOptions(opts);
                }
                catch (CancelledException e) {
                    println("Export cancelled.");
                    return;
                }
            }
        }
        // headless: plain stdout lines (the log is parsed by tests and tools)
        Consumer<String> log = isRunningHeadless() ? s -> {
            System.out.println(s);
            System.out.flush();
        } : this::println;
        // (in the GUI, the CodeBrowser's decompiler display options shape the C)
        new Exporter(currentProgram, monitor, outDir, opts, isRunningHeadless() ? null : state.getTool(), log).run();
    }
}
