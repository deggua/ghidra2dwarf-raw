package dwarfexport;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal ELF writer (a port of elf.py): an ET_EXEC with section headers only,
 * as a GDB symbol file for a target whose real image is not an ELF.
 * Allocated sections mirror the memory map: SHT_NOBITS by default, or the
 * actual bytes (SHT_PROGBITS).
 */
public final class ElfWriter {
    public static final class Section {
        public final String name;
        public final long type;
        public long flags, addr;
        public byte[] data;
        public long size;
        public long link, info, align, entsize;
        long offset, nameOffset;

        public Section(String name, long type, long flags, long addr, byte[] data, Long size, long link, long info,
                long align, long entsize) {
            this.name = name;
            this.type = type;
            this.flags = flags;
            this.addr = addr;
            this.data = data != null ? data : new byte[0];
            this.size = size != null ? size : this.data.length;
            this.link = link;
            this.info = info;
            this.align = align;
            this.entsize = entsize;
        }

        public Section(String name, long type) {
            this(name, type, 0, 0, null, null, 0, 0, 1, 0);
        }
    }

    static final class Symbol {
        final String name;
        final long value, size;
        final int type, bind, shndx, other;

        Symbol(String name, long value, long size, int type, int bind, int shndx, int other) {
            this.name = name;
            this.value = value;
            this.size = size;
            this.type = type;
            this.bind = bind;
            this.shndx = shndx;
            this.other = other;
        }
    }

    public final boolean is64, bigEndian;
    public final int machine;
    public final long flags, entry;
    public final List<Section> sections = new ArrayList<>();
    final List<Symbol> symbols = new ArrayList<>();
    public static final int MAX_SECTIONS = 0xff00 - 4;

    public ElfWriter(boolean is64, boolean bigEndian, int machine, long flags, long entry) {
        this.is64 = is64;
        this.bigEndian = bigEndian;
        this.machine = machine;
        this.flags = flags;
        this.entry = entry;
        sections.add(new Section("", C.SHT_NULL));
    }

    public int addSection(Section s) {
        sections.add(s);
        return sections.size() - 1;
    }

    public void addSymbol(String name, long value, long size, int type, int bind, int shndx, int other) {
        symbols.add(new Symbol(name, value, size, type, bind, shndx, other));
    }

    private long[][] index;
    private int indexN = -1;

    /** Index of the allocated section containing addr, else SHN_ABS. */
    public int sectionIndexFor(long addr) {
        int n = sections.size();
        if (indexN != n) {
            List<long[]> idx = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                Section s = sections.get(i);
                if ((s.flags & C.SHF_ALLOC) != 0) {
                    idx.add(new long[] {s.addr, s.addr + Math.max(s.size, 1), i});
                }
            }
            idx.sort((x, y) -> {
                for (int k = 0; k < 3; k++) {
                    int c = k < 2 ? Long.compareUnsigned(x[k], y[k]) : Long.compare(x[k], y[k]);
                    if (c != 0) {
                        return c;
                    }
                }
                return 0;
            });
            index = idx.toArray(new long[0][]);
            indexN = n;
        }
        // bisect_right on the starts
        int lo = 0, hi = index.length;
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (Long.compareUnsigned(addr, index[mid][0]) < 0) {
                hi = mid;
            }
            else {
                lo = mid + 1;
            }
        }
        int j = lo - 1;
        if (j >= 0 && Long.compareUnsigned(index[j][0], addr) <= 0 && Long.compareUnsigned(addr, index[j][1]) < 0) {
            return (int) index[j][2];
        }
        return C.SHN_ABS;
    }

    private byte[] pack(long v, int size) {
        return DwarfBuilder.pack(v, size, bigEndian);
    }

    private Object[] buildSymtab() {
        DwarfBuilder.Buf strtab = new DwarfBuilder.Buf().add(0);
        Map<String, Integer> names = new HashMap<>();
        java.util.function.Function<String, Integer> addStr = s -> {
            Integer off = names.get(s);
            if (off == null) {
                off = strtab.length();
                names.put(s, off);
                strtab.add(DwarfBuilder.utf8z(s));
            }
            return off;
        };
        List<Symbol> syms = new ArrayList<>(symbols);
        syms.sort((a, b) -> {
            int la = a.bind != C.STB_LOCAL ? 1 : 0, lb = b.bind != C.STB_LOCAL ? 1 : 0;
            return la != lb ? Integer.compare(la, lb) : Long.compareUnsigned(a.value, b.value);
        });
        int firstGlobal = 1;
        for (Symbol s : syms) {
            if (s.bind == C.STB_LOCAL) {
                firstGlobal++;
            }
        }
        DwarfBuilder.Buf out = new DwarfBuilder.Buf();
        int entsize;
        if (is64) {
            out.add(new byte[24]);
            for (Symbol s : syms) {
                out.add(pack(addStr.apply(s.name), 4)).add((s.bind << 4) | s.type).add(s.other)
                        .add(pack(s.shndx, 2)).add(pack(s.value, 8)).add(pack(s.size, 8));
            }
            entsize = 24;
        }
        else {
            out.add(new byte[16]);
            for (Symbol s : syms) {
                out.add(pack(addStr.apply(s.name), 4)).add(pack(s.value, 4)).add(pack(s.size, 4))
                        .add((s.bind << 4) | s.type).add(s.other).add(pack(s.shndx, 2));
            }
            entsize = 16;
        }
        return new Object[] {out.bytes(), strtab.bytes(), firstGlobal, entsize};
    }

    public void write(String path) throws IOException {
        try (FileOutputStream f = new FileOutputStream(path)) {
            f.write(toBytes());
        }
    }

    public byte[] toBytes() {
        int word = is64 ? 8 : 4;
        if (sections.size() + 3 > MAX_SECTIONS) {
            throw new IllegalStateException("too many ELF sections (" + sections.size() + ")");
        }
        if (!symbols.isEmpty()) {
            Object[] st = buildSymtab();
            int strtabIdx = addSection(new Section(".strtab", C.SHT_STRTAB, 0, 0, (byte[]) st[1], null, 0, 0, 1, 0));
            addSection(new Section(".symtab", C.SHT_SYMTAB, 0, 0, (byte[]) st[0], null, strtabIdx,
                (Integer) st[2], word, (Integer) st[3]));
        }
        DwarfBuilder.Buf shstr = new DwarfBuilder.Buf().add(0);
        Section shstrtab = new Section(".shstrtab", C.SHT_STRTAB);
        sections.add(shstrtab);
        for (Section s : sections.subList(1, sections.size())) {
            s.nameOffset = shstr.length();
            shstr.add(s.name.getBytes(StandardCharsets.UTF_8)).add(0);
        }
        shstrtab.data = shstr.bytes();
        shstrtab.size = shstrtab.data.length;
        int shstrndx = sections.size() - 1;

        int ehsize = is64 ? 64 : 52;
        int shentsize = is64 ? 64 : 40;
        DwarfBuilder.Buf body = new DwarfBuilder.Buf();
        long offset = ehsize;
        for (Section s : sections.subList(1, sections.size())) {
            if (s.type == C.SHT_NOBITS) {
                s.offset = offset;
                continue;
            }
            long align = Math.max(s.align, 1);
            long pad = Math.floorMod(-offset, align);
            body.add(new byte[(int) pad]);
            offset += pad;
            s.offset = offset;
            body.add(s.data);
            offset += s.data.length;
        }
        long pad = Math.floorMod(-offset, (long) word);
        body.add(new byte[(int) pad]);
        offset += pad;
        long shoff = offset;

        DwarfBuilder.Buf hdr = new DwarfBuilder.Buf();
        hdr.add(new byte[] {0x7f, 'E', 'L', 'F', (byte) (is64 ? 2 : 1), (byte) (bigEndian ? 2 : 1), 1, 0, 0});
        hdr.add(new byte[7]);
        hdr.add(pack(C.ET_EXEC, 2)).add(pack(machine, 2)).add(pack(1, 4));
        if (is64) {
            hdr.add(pack(entry, 8)).add(pack(0, 8)).add(pack(shoff, 8));
        }
        else {
            hdr.add(pack(entry, 4)).add(pack(0, 4)).add(pack(shoff, 4));
        }
        hdr.add(pack(flags, 4)).add(pack(ehsize, 2)).add(pack(0, 2)).add(pack(0, 2)).add(pack(shentsize, 2))
                .add(pack(sections.size(), 2)).add(pack(shstrndx, 2));
        if (hdr.length() != ehsize) {
            throw new IllegalStateException("ELF header size");
        }
        DwarfBuilder.Buf shdrs = new DwarfBuilder.Buf();
        for (Section s : sections) {
            if (s.type == C.SHT_NULL) {
                shdrs.add(new byte[shentsize]);
                continue;
            }
            if (is64) {
                shdrs.add(pack(s.nameOffset, 4)).add(pack(s.type, 4)).add(pack(s.flags, 8)).add(pack(s.addr, 8))
                        .add(pack(s.offset, 8)).add(pack(s.size, 8)).add(pack(s.link, 4)).add(pack(s.info, 4))
                        .add(pack(s.align, 8)).add(pack(s.entsize, 8));
            }
            else {
                shdrs.add(pack(s.nameOffset, 4)).add(pack(s.type, 4)).add(pack(s.flags, 4)).add(pack(s.addr, 4))
                        .add(pack(s.offset, 4)).add(pack(s.size, 4)).add(pack(s.link, 4)).add(pack(s.info, 4))
                        .add(pack(s.align, 4)).add(pack(s.entsize, 4));
            }
        }
        byte[] h = hdr.bytes(), b = body.bytes(), sh = shdrs.bytes();
        byte[] all = Arrays.copyOf(h, h.length + b.length + sh.length);
        System.arraycopy(b, 0, all, h.length, b.length);
        System.arraycopy(sh, 0, all, h.length + b.length, sh.length);
        return all;
    }
}
