// Test of ExportDwarfELF's GUI path (run headless by test/run_all.py):
// askValues is replaced by a stand-in that inspects the prefilled dialog,
// checks the validator and edits some values like a user would; then the
// script's GUI path runs with stand-in tool options (line width, comment
// types and style) and the C files must follow them.
// Args: <scratch directory>
// @category DWARF.Test
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;

import docking.widgets.values.AbstractValue;
import dwarfexport.Options;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.util.StatusListener;

public class CheckExportDialog extends ExportDwarfELF {
    static final int WIDTH = 50;
    int passed, failed;
    String scratch;
    boolean firstAsk = true, mainRun;
    ToolOptions fields, dec;

    void check(String name, boolean cond, Object detail) {
        if (cond) {
            passed++;
            System.out.println("GUI PASS " + name);
        }
        else {
            failed++;
            System.out.println("GUI FAIL " + name + ": " + detail);
        }
    }

    static final class Status implements StatusListener {
        String text;

        @Override
        public void setStatusText(String text) {
            this.text = text;
        }

        @Override
        public void setStatusText(String text, ghidra.util.MessageType type) {
            this.text = text;
        }

        @Override
        public void setStatusText(String text, ghidra.util.MessageType type, boolean alert) {
            this.text = text;
        }

        @Override
        public void clearStatusText() {
            text = null;
        }
    }

    @Override
    public GhidraValuesMap askValues(String title, String message, GhidraValuesMap values) {
        if (firstAsk) {
            firstAsk = false;
            Options defaults = new Options();
            List<String> shown = new ArrayList<>();
            for (AbstractValue<?> v : values.getValues()) {
                shown.add(v.getName());
            }
            for (String k : Options.names()) {
                if (Options.INTERNAL.contains(k)) {
                    check("internal option " + k + " not shown", !shown.contains(k), shown);
                    continue;
                }
                Object v = defaults.get(k);
                if (v instanceof Boolean) {
                    check("default " + k, values.getBoolean(k) == (Boolean) v, values.getBoolean(k));
                }
                else if (v instanceof Long) {
                    String s = values.getString(k);
                    long got = s.startsWith("0x") ? Long.parseLong(s.substring(2), 16) : Long.parseLong(s);
                    check("default " + k, got == (Long) v, s);
                }
                else {
                    String s = values.getString(k);
                    check("default " + k, (s == null ? "" : s).equals(v == null ? "" : v.toString()), s);
                }
            }
            check("output directory prefilled", values.getFile(OUT_DIR) != null, null);
            Status status = new Status();
            values.setString("decompile_timeout", "soon");
            check("invalid number rejected", !values.isValid(status) && status.text != null, status.text);
            check("error names the field", status.text != null && status.text.contains("decompile_timeout"),
                status.text);
            values.setString("decompile_timeout", "30");
            values.setString("basename", "../elsewhere/fw");
            check("basename with directories rejected",
                !values.isValid(status) && status.text != null && status.text.contains("basename"), status.text);
            values.setString("basename", "");
            values.setString("address_offset", "0x1000");
            values.setString("c_max_lines", "5000");
            values.setBoolean("embed_bytes", true);
            values.setFile(OUT_DIR, new File(scratch));
            status.text = null;
            check("edited values accepted", values.isValid(status), status.text);
            return values;
        }
        values.setString("decompile_timeout", "30");
        values.setString("address_offset", "0x1000");
        values.setString("c_max_lines", "5000");
        values.setBoolean("embed_bytes", true);
        values.setFile(OUT_DIR, new File(scratch));
        return values;
    }

    @Override
    protected boolean headless() {
        return false;
    }

    @Override
    protected Function<String, ToolOptions> toolOptions() {
        return name -> name.equals("Listing Fields") ? fields : dec;
    }

    @Override
    public String[] getScriptArgs() {
        return mainRun ? new String[0] : super.getScriptArgs();
    }

    @Override
    protected void run() throws Exception {
        scratch = getScriptArgs()[0];
        // the dialog
        Options opts = new Options();
        String out = guiOptions(opts);
        check("output directory returned", Path.of(out).toAbsolutePath().equals(Path.of(scratch).toAbsolutePath()),
            out);
        check("edits applied", opts.decompile_timeout == 30 && opts.address_offset == 0x1000 &&
            opts.c_max_lines == 5000 && opts.embed_bytes, opts.decompile_timeout + " " + opts.address_offset);
        check("empty basename keeps the default", opts.basename == null, opts.basename);

        // the GUI path: the tool's decompiler display options shape the C files
        fields = new ToolOptions("Listing Fields");
        dec = new ToolOptions("Decompiler");
        new DecompileOptions().registerOptions(fields, dec, currentProgram);
        dec.setInt("Display.Maximum characters in a code line", WIDTH);
        dec.setBoolean("Display.Display EOL comments", true);
        dec.setEnum("Display.Comment style", DecompileOptions.CommentStyleEnum.CPPStyle);
        ghidra.program.model.listing.Function f = getGlobalFunctions("sensor_update").get(0);
        List<Instruction> ins = new ArrayList<>();
        currentProgram.getListing().getInstructions(f.getBody(), true).forEach(ins::add);
        int tx = currentProgram.startTransaction("comment");
        currentProgram.getListing().setComment(ins.get(ins.size() / 2).getAddress(), CommentType.EOL,
            "eol note on {@sym sensor_update} done");
        currentProgram.endTransaction(tx, true);
        mainRun = true;
        super.run();
        mainRun = false;

        List<Path> srcs = new ArrayList<>();
        try (var ds = Files.newDirectoryStream(Path.of(scratch), "*.src")) {
            for (Path d : ds) {
                try (var cs = Files.newDirectoryStream(d, "*.c")) {
                    cs.forEach(srcs::add);
                }
            }
        }
        check("GUI export wrote C files", !srcs.isEmpty(), scratch);
        StringBuilder sb = new StringBuilder();
        for (Path p : srcs) {
            sb.append(Files.readString(p)).append('\n');
        }
        String text = sb.toString();
        String[] lines = text.split("\n");
        // (the comment is wrapped at the line width: read its lines together)
        String comments = text;
        String prev;
        do {
            prev = comments;
            comments = comments.replaceAll("(//[^\n]*)\n\\s*// ", "$1 ");
        }
        while (!comments.equals(prev));
        check("tool option: EOL comments shown, annotation rendered",
            Pattern.compile("//.*eol note on sensor_update done").matcher(comments).find(), "");
        boolean cpp = false, cstyle = false;
        for (String l : lines) {
            cpp |= l.strip().startsWith("// WARNING");
            cstyle |= l.strip().startsWith("/* WARNING");
        }
        check("tool option: C++ comment style", cpp && !cstyle, "");
        int code = 0, longer = 0;
        for (String l : lines) {
            if (!l.strip().isEmpty() && !l.strip().startsWith("//") && !l.strip().startsWith("/* ----")) {
                code++;
                if (l.length() > WIDTH) {
                    longer++;
                }
            }
        }
        check("tool option: line width", longer <= code / 50, longer + " of " + code);
        System.out.println("GUI SUMMARY " + passed + " passed, " + failed + " failed");
    }
}
