package dwarfexport;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * A minimal DWARF 4 producer (a port of dwarf.py): one compile unit from a
 * tree of {@link Die}s, emitting .debug_info, .debug_abbrev, .debug_str,
 * .debug_line, .debug_loc, .debug_ranges, .debug_aranges and .debug_frame.
 */
public final class DwarfBuilder {

    // -- bytes -------------------------------------------------------------------

    /** A growable byte buffer. */
    public static final class Buf {
        byte[] a = new byte[64];
        int n;

        public Buf add(int b) {
            if (n == a.length) {
                a = Arrays.copyOf(a, a.length * 2);
            }
            a[n++] = (byte) b;
            return this;
        }

        public Buf add(byte[] b) {
            if (n + b.length > a.length) {
                a = Arrays.copyOf(a, Math.max(a.length * 2, n + b.length));
            }
            System.arraycopy(b, 0, a, n, b.length);
            n += b.length;
            return this;
        }

        public Buf add(Buf b) {
            return add(b.bytes());
        }

        public int length() {
            return n;
        }

        public byte[] bytes() {
            return Arrays.copyOf(a, n);
        }
    }

    public static byte[] uleb(long value) {
        if (value < 0) {
            throw new IllegalArgumentException("uleb128 of negative value " + value);
        }
        Buf out = new Buf();
        while (true) {
            int b = (int) (value & 0x7F);
            value >>>= 7;
            if (value != 0) {
                out.add(b | 0x80);
            }
            else {
                out.add(b);
                return out.bytes();
            }
        }
    }

    public static byte[] sleb(long value) {
        Buf out = new Buf();
        while (true) {
            int b = (int) (value & 0x7F);
            value >>= 7;
            boolean done = (value == 0 && (b & 0x40) == 0) || (value == -1 && (b & 0x40) != 0);
            if (done) {
                out.add(b);
                return out.bytes();
            }
            out.add(b | 0x80);
        }
    }

    static byte[] utf8z(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        byte[] r = Arrays.copyOf(b, b.length + 1);
        return r;
    }

    // -- location expressions ----------------------------------------------------

    /** Builder for DWARF location expressions. */
    public static final class Expr {
        final int addrSize;
        final boolean bigEndian;
        final Buf buf = new Buf();

        Expr(int addrSize, boolean bigEndian) {
            this.addrSize = addrSize;
            this.bigEndian = bigEndian;
        }

        public Expr op(int opcode) {
            buf.add(opcode);
            return this;
        }

        public Expr reg(int regno) {
            if (regno < 32) {
                buf.add(C.DW_OP_reg0 + regno);
            }
            else {
                buf.add(C.DW_OP_regx);
                buf.add(uleb(regno));
            }
            return this;
        }

        public Expr breg(int regno, long offset) {
            if (regno < 32) {
                buf.add(C.DW_OP_breg0 + regno);
            }
            else {
                buf.add(C.DW_OP_bregx);
                buf.add(uleb(regno));
            }
            buf.add(sleb(offset));
            return this;
        }

        public Expr fbreg(long offset) {
            buf.add(C.DW_OP_fbreg);
            buf.add(sleb(offset));
            return this;
        }

        public Expr addr(long address) {
            buf.add(C.DW_OP_addr);
            buf.add(pack(address, addrSize, bigEndian));
            return this;
        }

        public Expr piece(long size) {
            buf.add(C.DW_OP_piece);
            buf.add(uleb(size));
            return this;
        }

        public Expr bitPiece(long bits, long offset) {
            buf.add(C.DW_OP_bit_piece);
            buf.add(uleb(bits));
            buf.add(uleb(offset));
            return this;
        }

        public Expr callFrameCfa() {
            buf.add(C.DW_OP_call_frame_cfa);
            return this;
        }

        public byte[] bytes() {
            return buf.bytes();
        }
    }

    static byte[] pack(long v, int size, boolean bigEndian) {
        byte[] b = new byte[size];
        for (int i = 0; i < size; i++) {
            int shift = 8 * (bigEndian ? size - 1 - i : i);
            b[i] = (byte) (v >>> shift);
        }
        return b;
    }

    // -- DIEs --------------------------------------------------------------------

    /** An attribute: (attribute, form, value). */
    public static final class Attr {
        public final int at, form;
        public final Object value;

        Attr(int at, int form, Object value) {
            this.at = at;
            this.form = form;
            this.value = value;
        }
    }

    public static final class Die {
        public final int tag;
        public final List<Attr> attrs = new ArrayList<>();
        public final List<Die> children = new ArrayList<>();
        int offset = -1;
        int code;
        Object[] enc;

        public Die(int tag) {
            this.tag = tag;
        }

        public Die add(int at, int form, Object value) {
            attrs.add(new Attr(at, form, value));
            return this;
        }

        public Die add(int at, int form) {
            return add(at, form, null);
        }

        public Die child(int tag) {
            Die d = new Die(tag);
            children.add(d);
            return d;
        }

        @Override
        public String toString() {
            return String.format("<Die tag=0x%x attrs=%d children=%d>", tag, attrs.size(), children.size());
        }
    }

    static final class StringTable {
        final Buf buf = new Buf();
        final Map<String, Integer> index = new HashMap<>();

        int add(String s) {
            Integer off = index.get(s);
            if (off == null) {
                off = buf.length();
                index.put(s, off);
                buf.add(utf8z(s));
            }
            return off;
        }
    }

    // -- line table ----------------------------------------------------------------

    public static final int LINE_BASE = -5;
    public static final int LINE_RANGE = 14;
    public static final int OPCODE_BASE = 13;
    static final int[] STD_OPCODE_LENGTHS = {0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1};
    public static final int ROW_PROLOGUE_END = 1;

    /** A line table row: address, line, flags (ROW_PROLOGUE_END). */
    public static final class Row {
        public final long addr;
        public final long line;
        public final int flags;

        public Row(long addr, long line, int flags) {
            this.addr = addr;
            this.line = line;
            this.flags = flags;
        }
    }

    /** A contiguous run of code: rows sorted by address, ending at end. */
    public static final class LineSequence {
        final List<Row> rows;
        final long end;
        final int file;

        LineSequence(List<Row> rows, long end, int file) {
            this.rows = rows;
            this.end = end;
            this.file = file;
        }
    }

    // -- call frame information ----------------------------------------------------

    /** A CFI row: the address and its CFA ops. */
    public static final class CfiRow {
        public final long addr;
        public final byte[] ops;

        public CfiRow(long addr, byte[] ops) {
            this.addr = addr;
            this.ops = ops;
        }
    }

    /** An FDE; cie indexes the CIEs (0: the default one). */
    public static final class FrameDescription {
        public final long start, end;
        public final List<CfiRow> instructions;
        public final int cie;

        public FrameDescription(long start, long end, List<CfiRow> instructions, int cie) {
            this.start = start;
            this.end = end;
            this.instructions = instructions;
            this.cie = cie;
        }
    }

    /** A CIE. Augmentation "S" marks signal/interrupt frames. */
    public static final class CommonInformation {
        final long codeAlign, dataAlign, raReg;
        final byte[] initialInstructions;
        final String augmentation;

        public CommonInformation(long codeAlign, long dataAlign, long raReg, byte[] initialInstructions,
                String augmentation) {
            this.codeAlign = codeAlign;
            this.dataAlign = dataAlign;
            this.raReg = raReg;
            this.initialInstructions = initialInstructions;
            this.augmentation = augmentation;
        }
    }

    // -- the producer --------------------------------------------------------------

    public final int addrSize;
    public final boolean bigEndian;
    final StringTable strtab = new StringTable();
    public final Die cu = new Die(C.DW_TAG_compile_unit);
    final Buf loc = new Buf();
    final Buf ranges = new Buf();
    /** [(name, dir index)] */
    final List<Object[]> files = new ArrayList<>();
    final List<String> dirs = new ArrayList<>();
    final List<LineSequence> sequences = new ArrayList<>();
    public final List<long[]> aranges = new ArrayList<>();
    public CommonInformation cie;
    final List<CommonInformation> cies = new ArrayList<>();
    public final List<FrameDescription> fdes = new ArrayList<>();
    /** Optional filter applied to every DW_AT_name (see the exporter). */
    public UnaryOperator<String> nameFilter;

    public DwarfBuilder(int addrSize, boolean bigEndian) {
        if (addrSize != 4 && addrSize != 8) {
            throw new IllegalArgumentException("unsupported address size " + addrSize);
        }
        this.addrSize = addrSize;
        this.bigEndian = bigEndian;
    }

    /** Registers an additional CIE; returns its index for FrameDescription. */
    public int addCie(CommonInformation c) {
        cies.add(c);
        return cies.size();
    }

    byte[] u16(long v) {
        return pack(v, 2, bigEndian);
    }

    byte[] u32(long v) {
        return pack(v, 4, bigEndian);
    }

    byte[] u64(long v) {
        return pack(v, 8, bigEndian);
    }

    byte[] uaddr(long v) {
        // an exclusive end at the very top of the address space: one byte early
        if (addrSize == 4 && v == 1L << 32) {
            v -= 1;
        }
        return addrSize == 4 ? u32(v) : u64(v);
    }

    public Expr expr() {
        return new Expr(addrSize, bigEndian);
    }

    public void name(Die die, String s, boolean raw) {
        if (!raw && nameFilter != null) {
            s = nameFilter.apply(s);
        }
        die.add(C.DW_AT_name, C.DW_FORM_strp, s);
    }

    public void name(Die die, String s) {
        name(die, s, false);
    }

    public int addFile(String name, int dirIndex) {
        files.add(new Object[] {name, dirIndex});
        return files.size();
    }

    public int addDir(String path) {
        dirs.add(path);
        return dirs.size();
    }

    /** entries: [(start, end, expr bytes)]; returns the offset into .debug_loc. */
    public int addLoclist(List<Object[]> entries) {
        int off = loc.length();
        for (Object[] e : entries) {
            long start = (Long) e[0], end = (Long) e[1];
            byte[] ex = (byte[]) e[2];
            if (Long.compareUnsigned(end, start) <= 0) {
                continue;
            }
            loc.add(uaddr(start)).add(uaddr(end));
            loc.add(u16(ex.length)).add(ex);
        }
        loc.add(uaddr(0)).add(uaddr(0));
        return off;
    }

    public int addRanges(List<long[]> rs) {
        int off = ranges.length();
        for (long[] r : rs) {
            if (Long.compareUnsigned(r[1], r[0]) <= 0) {
                continue;
            }
            ranges.add(uaddr(r[0])).add(uaddr(r[1]));
        }
        ranges.add(uaddr(0)).add(uaddr(0));
        return off;
    }

    public void addSequence(List<Row> rows, long end, int file) {
        if (!rows.isEmpty()) {
            sequences.add(new LineSequence(rows, end, file));
        }
    }

    // -- attribute encoding ----------------------------------------------------------

    static long num(Object v) {
        if (v instanceof Boolean) {
            return ((Boolean) v) ? 1 : 0;
        }
        return ((Number) v).longValue();
    }

    /** Returns bytes, or an Integer size for forms that need a later fixup. */
    Object encodeAttr(int form, Object value) {
        if (form == C.DW_FORM_ref4) {
            return 4;
        }
        if (form == C.DW_FORM_strp) {
            return u32(strtab.add((String) value));
        }
        if (form == C.DW_FORM_string) {
            return utf8z((String) value);
        }
        if (form == C.DW_FORM_addr) {
            return uaddr(num(value));
        }
        if (form == C.DW_FORM_data1) {
            return new byte[] {(byte) num(value)};
        }
        if (form == C.DW_FORM_data2) {
            return u16(num(value) & 0xFFFF);
        }
        if (form == C.DW_FORM_data4 || form == C.DW_FORM_sec_offset) {
            return u32(num(value) & 0xFFFFFFFFL);
        }
        if (form == C.DW_FORM_data8) {
            return u64(num(value));
        }
        if (form == C.DW_FORM_udata) {
            return uleb(num(value));
        }
        if (form == C.DW_FORM_sdata) {
            return sleb(num(value));
        }
        if (form == C.DW_FORM_exprloc) {
            byte[] b = (byte[]) value;
            return new Buf().add(uleb(b.length)).add(b).bytes();
        }
        if (form == C.DW_FORM_flag_present) {
            return new byte[0];
        }
        if (form == C.DW_FORM_flag) {
            return new byte[] {(byte) (num(value) != 0 ? 1 : 0)};
        }
        throw new IllegalArgumentException(String.format("unsupported form 0x%x", form));
    }

    // -- .debug_info / .debug_abbrev -------------------------------------------------

    byte[][] buildInfo() {
        Map<String, Integer> abbrevs = new HashMap<>();
        Buf abbrevBuf = new Buf();
        List<Die> order = new ArrayList<>();
        ArrayDeque<Die> stack = new ArrayDeque<>();
        stack.push(cu);
        while (!stack.isEmpty()) {
            Die die = stack.pop();
            order.add(die);
            for (int i = die.children.size() - 1; i >= 0; i--) {
                stack.push(die.children.get(i));
            }
        }
        for (Die die : order) {
            StringBuilder kb = new StringBuilder();
            kb.append(die.tag).append(die.children.isEmpty() ? ":0" : ":1");
            for (Attr a : die.attrs) {
                kb.append(':').append(a.at).append('/').append(a.form);
            }
            String key = kb.toString();
            Integer code = abbrevs.get(key);
            if (code == null) {
                code = abbrevs.size() + 1;
                abbrevs.put(key, code);
                abbrevBuf.add(uleb(code)).add(uleb(die.tag));
                abbrevBuf.add(die.children.isEmpty() ? C.DW_CHILDREN_no : C.DW_CHILDREN_yes);
                for (Attr a : die.attrs) {
                    abbrevBuf.add(uleb(a.at)).add(uleb(a.form));
                }
                abbrevBuf.add(0).add(0);
            }
            die.code = code;
            die.enc = new Object[die.attrs.size()];
            for (int i = 0; i < die.attrs.size(); i++) {
                Attr a = die.attrs.get(i);
                die.enc[i] = encodeAttr(a.form, a.value);
            }
        }
        abbrevBuf.add(0);

        int headerSize = 11;
        int offset = headerSize;
        // offsets: DFS order, each children list closed by one 0 byte
        ArrayDeque<Object[]> st = new ArrayDeque<>();
        st.push(new Object[] {cu, false});
        while (!st.isEmpty()) {
            Object[] e = st.pop();
            Die die = (Die) e[0];
            if ((Boolean) e[1]) {
                offset += 1;
                continue;
            }
            die.offset = offset;
            offset += uleb(die.code).length;
            for (Object enc : die.enc) {
                offset += enc instanceof Integer ? (Integer) enc : ((byte[]) enc).length;
            }
            if (!die.children.isEmpty()) {
                st.push(new Object[] {die, true});
                for (int i = die.children.size() - 1; i >= 0; i--) {
                    st.push(new Object[] {die.children.get(i), false});
                }
            }
        }
        int total = offset;

        Buf body = new Buf();
        st.push(new Object[] {cu, false});
        while (!st.isEmpty()) {
            Object[] e = st.pop();
            Die die = (Die) e[0];
            if ((Boolean) e[1]) {
                body.add(0);
                continue;
            }
            if (die.offset != headerSize + body.length()) {
                throw new IllegalStateException("offset mismatch");
            }
            body.add(uleb(die.code));
            for (int i = 0; i < die.attrs.size(); i++) {
                Attr a = die.attrs.get(i);
                if (a.form == C.DW_FORM_ref4) {
                    Die ref = (Die) a.value;
                    if (ref.offset < 0) {
                        throw new IllegalStateException("reference to a DIE that is not in the tree: " + ref);
                    }
                    body.add(u32(ref.offset));
                }
                else {
                    body.add((byte[]) die.enc[i]);
                }
            }
            if (!die.children.isEmpty()) {
                st.push(new Object[] {die, true});
                for (int i = die.children.size() - 1; i >= 0; i--) {
                    st.push(new Object[] {die.children.get(i), false});
                }
            }
        }
        Buf info = new Buf();
        info.add(u32(total - 4)).add(u16(4)).add(u32(0)).add(addrSize).add(body);
        if (info.length() != total) {
            throw new IllegalStateException("info size mismatch");
        }
        return new byte[][] {info.bytes(), abbrevBuf.bytes()};
    }

    // -- .debug_line -------------------------------------------------------------------

    byte[] buildLine() {
        Buf hdr = new Buf();
        hdr.add(1).add(1).add(1).add(LINE_BASE).add(LINE_RANGE).add(OPCODE_BASE);
        for (int v : STD_OPCODE_LENGTHS) {
            hdr.add(v);
        }
        for (String d : dirs) {
            hdr.add(utf8z(d));
        }
        hdr.add(0);
        for (Object[] f : files) {
            hdr.add(utf8z((String) f[0]));
            hdr.add(uleb((Integer) f[1])).add(uleb(0)).add(uleb(0));
        }
        hdr.add(0);

        Buf prog = new Buf();
        List<LineSequence> seqs = new ArrayList<>(sequences);
        seqs.sort((x, y) -> Long.compareUnsigned(x.rows.get(0).addr, y.rows.get(0).addr));
        for (LineSequence seq : seqs) {
            Long addr = null;
            long line = 1;
            if (seq.file != 1) {
                prog.add(C.DW_LNS_set_file).add(uleb(seq.file));
            }
            for (Row row : seq.rows) {
                if ((row.flags & ROW_PROLOGUE_END) != 0) {
                    prog.add(C.DW_LNS_set_prologue_end);
                }
                if (addr == null) {
                    prog.add(0).add(uleb(1 + addrSize)).add(C.DW_LNE_set_address).add(uaddr(row.addr));
                    addr = row.addr;
                }
                long addrDelta = row.addr - addr;
                long lineDelta = row.line - line;
                if (addrDelta < 0) {
                    throw new IllegalStateException("line rows not sorted");
                }
                Integer special = null;
                if (LINE_BASE <= lineDelta && lineDelta < LINE_BASE + LINE_RANGE) {
                    long op = (lineDelta - LINE_BASE) + LINE_RANGE * addrDelta + OPCODE_BASE;
                    if (op <= 255) {
                        special = (int) op;
                    }
                }
                if (special != null) {
                    prog.add(special);
                }
                else {
                    if (lineDelta != 0) {
                        prog.add(C.DW_LNS_advance_line).add(sleb(lineDelta));
                    }
                    if (addrDelta != 0) {
                        prog.add(C.DW_LNS_advance_pc).add(uleb(addrDelta));
                    }
                    prog.add(C.DW_LNS_copy);
                }
                addr = row.addr;
                line = row.line;
            }
            if (Long.compareUnsigned(seq.end, addr) > 0) {
                prog.add(C.DW_LNS_advance_pc).add(uleb(seq.end - addr));
            }
            prog.add(0).add(uleb(1)).add(C.DW_LNE_end_sequence);
        }
        Buf out = new Buf();
        out.add(u16(4)).add(u32(hdr.length())).add(hdr).add(prog);
        return new Buf().add(u32(out.length())).add(out).bytes();
    }

    // -- .debug_aranges ----------------------------------------------------------------

    byte[] buildAranges() {
        Buf body = new Buf();
        body.add(u16(2)).add(u32(0)).add(addrSize).add(0);
        int hdrLen = 4 + body.length();
        int pad = Math.floorMod(-hdrLen, 2 * addrSize);
        for (int i = 0; i < pad; i++) {
            body.add(0);
        }
        List<long[]> sorted = new ArrayList<>(aranges);
        sorted.sort((x, y) -> {
            int c = Long.compareUnsigned(x[0], y[0]);
            return c != 0 ? c : Long.compareUnsigned(x[1], y[1]);
        });
        for (long[] r : sorted) {
            if (Long.compareUnsigned(r[1], r[0]) > 0) {
                body.add(uaddr(r[0])).add(uaddr(r[1] - r[0]));
            }
        }
        body.add(uaddr(0)).add(uaddr(0));
        return new Buf().add(u32(body.length())).add(body).bytes();
    }

    // -- .debug_frame ------------------------------------------------------------------

    private void padEntry(Buf entry) {
        while ((entry.length() + 4) % addrSize != 0) {
            entry.add(C.DW_CFA_nop);
        }
    }

    byte[] buildFrame() {
        if (cie == null) {
            return null;
        }
        Buf out = new Buf();
        List<CommonInformation> all = new ArrayList<>();
        all.add(cie);
        all.addAll(cies);
        List<Integer> cieOffsets = new ArrayList<>();
        for (CommonInformation c : all) {
            cieOffsets.add(out.length());
            Buf body = new Buf();
            body.add(u32(0xFFFFFFFFL)).add(4).add(utf8z(c.augmentation)).add(addrSize).add(0);
            body.add(uleb(c.codeAlign)).add(sleb(c.dataAlign)).add(uleb(c.raReg)).add(c.initialInstructions);
            padEntry(body);
            out.add(u32(body.length())).add(body);
        }
        for (FrameDescription fde : fdes) {
            CommonInformation c = all.get(fde.cie);
            Buf body = new Buf();
            body.add(u32(cieOffsets.get(fde.cie))).add(uaddr(fde.start)).add(uaddr(fde.end - fde.start));
            long locAddr = fde.start;
            for (CfiRow row : fde.instructions) {
                long delta = Math.floorDiv(row.addr - locAddr, c.codeAlign);
                if (delta < 0) {
                    throw new IllegalStateException("CFI rows not sorted");
                }
                if (delta != 0) {
                    if (delta < 0x40) {
                        body.add(C.DW_CFA_advance_loc | (int) delta);
                    }
                    else if (delta <= 0xFF) {
                        body.add(C.DW_CFA_advance_loc1).add((int) delta);
                    }
                    else if (delta <= 0xFFFF) {
                        body.add(C.DW_CFA_advance_loc2).add(u16(delta));
                    }
                    else {
                        body.add(C.DW_CFA_advance_loc4).add(u32(delta));
                    }
                    locAddr = row.addr;
                }
                body.add(row.ops);
            }
            padEntry(body);
            out.add(u32(body.length())).add(body);
        }
        return out.bytes();
    }

    /** The sections, in order: [(name, bytes)]. */
    public List<Object[]> build() {
        byte[][] ia = buildInfo();
        List<Object[]> s = new ArrayList<>();
        s.add(new Object[] {".debug_info", ia[0]});
        s.add(new Object[] {".debug_abbrev", ia[1]});
        s.add(new Object[] {".debug_line", buildLine()});
        s.add(new Object[] {".debug_str", strtab.buf.bytes()});
        if (!aranges.isEmpty()) {
            s.add(new Object[] {".debug_aranges", buildAranges()});
        }
        if (loc.length() > 0) {
            s.add(new Object[] {".debug_loc", loc.bytes()});
        }
        if (ranges.length() > 0) {
            s.add(new Object[] {".debug_ranges", ranges.bytes()});
        }
        byte[] frame = buildFrame();
        if (frame != null && frame.length > 0) {
            s.add(new Object[] {".debug_frame", frame});
        }
        return s;
    }
}
