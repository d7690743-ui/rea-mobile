package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.List;

/**
 * ALFA-1: parser ELF mínimo (32/64-bit little-endian) para bibliotecas
 * nativas de APKs. Extrae arquitectura, tipo, librerías NEEDED, símbolos
 * dinámicos importados/exportados y exportaciones JNI, trabajando sobre
 * ventanas cabeza+cola (los .so grandes no caben enteros en memoria).
 * Java puro. Nunca lanza: lo ausente queda en partial/error.
 *
 * <p>Límites honestos: sin desensamblado ni relocs; los símbolos estáticos
 * (.symtab) suelen estar eliminados en Android y no se buscan.</p>
 */
public final class AlfaElf {
    private AlfaElf() {
    }

    public static final int MAX_SYMS_SCAN = 20000;
    public static final int MAX_KEEP_SYMS = 50;
    public static final int MAX_JNI = 100;
    public static final int MAX_NEEDED = 20;
    public static final int MAX_PHDRS = 32;
    public static final int MAX_DYNAMIC = 100;
    public static final int MAX_DYNSTR = 8 * 1024 * 1024;
    public static final int MAX_SECTIONS = 100;

    /** Ficha de un .so parseado. Nunca lanza. */
    public static class ElfInfo {
        public String name = "?";
        public long fileSize;
        public boolean is64;
        public String arch = "?";
        public String elfType = "?";
        public List<String> needed = new ArrayList<>();
        public String soname = "";
        public int importCount;
        public int exportCount;
        public List<String> imports = new ArrayList<>();
        public List<String> exports = new ArrayList<>();
        public List<String> jniExports = new ArrayList<>();
        public boolean hasJniOnLoad;
        public int sectionCount;
        public boolean stripped;
        public boolean partial;
        public String error;
    }

    private static class View {
        final byte[] head;
        final byte[] tail;
        final long tailStart;

        View(byte[] head, byte[] tail, long tailStart) {
            this.head = head == null ? new byte[0] : head;
            this.tail = tail == null ? new byte[0] : tail;
            this.tailStart = tailStart;
        }

        /** Rebanada [off, off+len) o null si no está entera. Nunca lanza. */
        byte[] slice(long off, int len) {
            try {
                if (off < 0 || len < 0) return null;
                if (off + len <= head.length) {
                    byte[] o = new byte[len];
                    System.arraycopy(head, (int) off, o, 0, len);
                    return o;
                }
                long rel = off - tailStart;
                if (rel >= 0 && rel + len <= tail.length) {
                    byte[] o = new byte[len];
                    System.arraycopy(tail, (int) rel, o, 0, len);
                    return o;
                }
            } catch (Throwable ignored) {
            }
            return null;
        }
    }

    private static class Load {
        long vaddr;
        long offset;
        long filesz;
    }

    /**
     * Parsea un ELF desde ventanas head+tail (tailStart = offset absoluto
     * del primer byte de tail). Nunca null ni lanza.
     */
    public static ElfInfo parse(String name, byte[] head, byte[] tail, long tailStart,
            long fileSize) {
        ElfInfo r = new ElfInfo();
        try {
            if (name != null) r.name = name;
            r.fileSize = fileSize;
            View v = new View(head, tail, tailStart);
            byte[] ident = v.slice(0, 64);
            if (ident == null || ident.length < 64) {
                r.error = "cabecera fuera de ventana";
                r.partial = true;
                return r;
            }
            if (ident[0] != 0x7F || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') {
                r.error = "sin magia ELF";
                return r;
            }
            int eiClass = ident[4] & 0xFF;
            if (eiClass == 1) r.is64 = false;
            else if (eiClass == 2) r.is64 = true;
            else {
                r.error = "clase ELF inválida";
                return r;
            }
            if ((ident[5] & 0xFF) != 1) {
                r.error = "big-endian no soportado";
                return r;
            }
            r.elfType = elfTypeName(u16(ident, 16));
            r.arch = machineName(u16(ident, 18));
            List<Load> loads = new ArrayList<>();
            long dynOff = -1;
            long dynSize = 0;
            if (!readPhdrs(v, r.is64, loads)) {
                r.partial = true;
            } else {
                long[] dyn = findDynamic(v, r.is64, loads);
                if (dyn != null) {
                    dynOff = dyn[0];
                    dynSize = dyn[1];
                }
            }
            readSections(v, r);
            if (dynOff >= 0) {
                readDynamic(v, r, loads, dynOff, dynSize);
            } else {
                r.partial = true;
            }
        } catch (Throwable t) {
            r.error = "elf: " + t.getMessage();
            r.partial = true;
        }
        return r;
    }

    private static String elfTypeName(int t) {
        if (t == 1) return "REL";
        if (t == 2) return "EXEC";
        if (t == 3) return "DYN";
        return "tipo-" + t;
    }

    private static String machineName(int m) {
        if (m == 3) return "x86";
        if (m == 40) return "ARM32";
        if (m == 62) return "x86_64";
        if (m == 183) return "ARM64";
        if (m == 243) return "RISCV";
        return "mach-" + m;
    }

    /** Lee program headers; rellena segmentos LOAD. false si incompletos. */
    private static boolean readPhdrs(View v, boolean is64, List<Load> loads) {
        try {
            byte[] eh = v.slice(0, 64);
            if (eh == null) return false;
            long phoff;
            int phentsize;
            int phnum;
            if (is64) {
                phoff = u64(eh, 32);
                phentsize = u16(eh, 54);
                phnum = u16(eh, 56);
            } else {
                phoff = u32(eh, 28);
                phentsize = u16(eh, 42);
                phnum = u16(eh, 44);
            }
            if (phnum < 0 || phnum > MAX_PHDRS || phentsize <= 0 || phentsize > 256) return false;
            for (int i = 0; i < phnum; i++) {
                byte[] p = v.slice(phoff + (long) i * phentsize,
                        is64 ? 56 : 32);
                if (p == null) return false;
                if (u32(p, 0) != 1) continue;
                Load l = new Load();
                if (is64) {
                    l.offset = u64(p, 8);
                    l.vaddr = u64(p, 16);
                    l.filesz = u64(p, 32);
                } else {
                    l.offset = u32(p, 4);
                    l.vaddr = u32(p, 8);
                    l.filesz = u32(p, 16);
                }
                loads.add(l);
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Localiza PT_DYNAMIC (offset, tamaño) o null. Nunca lanza. */
    private static long[] findDynamic(View v, boolean is64, List<Load> loads) {
        try {
            byte[] eh = v.slice(0, 64);
            if (eh == null) return null;
            long phoff;
            int phentsize;
            int phnum;
            if (is64) {
                phoff = u64(eh, 32);
                phentsize = u16(eh, 54);
                phnum = u16(eh, 56);
            } else {
                phoff = u32(eh, 28);
                phentsize = u16(eh, 42);
                phnum = u16(eh, 44);
            }
            if (phnum < 0 || phnum > MAX_PHDRS || phentsize <= 0 || phentsize > 256) return null;
            for (int i = 0; i < phnum; i++) {
                byte[] p = v.slice(phoff + (long) i * phentsize,
                        is64 ? 56 : 32);
                if (p == null || u32(p, 0) != 2) continue;
                if (is64) return new long[]{u64(p, 8), u64(p, 32)};
                return new long[]{u32(p, 4), u32(p, 16)};
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static void readSections(View v, ElfInfo r) {
        try {
            byte[] eh = v.slice(0, 64);
            if (eh == null) {
                r.partial = true;
                return;
            }
            long shoff = r.is64 ? u64(eh, 40) : u32(eh, 32);
            int shnum = r.is64 ? u16(eh, 60) : u16(eh, 48);
            if (shoff == 0 || shnum <= 0) {
                r.stripped = true;
                return;
            }
            if (shnum > MAX_SECTIONS) {
                r.sectionCount = shnum;
                r.partial = true;
                return;
            }
            r.sectionCount = shnum;
        } catch (Throwable ignored) {
            r.partial = true;
        }
    }

    private static void readDynamic(View v, ElfInfo r, List<Load> loads, long dynOff, long dynSize) {
        try {
            int step = r.is64 ? 16 : 8;
            long n = dynSize <= 0 ? MAX_DYNAMIC : Math.min(dynSize / step, MAX_DYNAMIC);
            long strtab = -1;
            long strsz = 0;
            long symtab = -1;
            long syment = r.is64 ? 24 : 16;
            long hash = -1;
            List<Long> neededOffs = new ArrayList<>();
            long sonameOff = -1;
            for (long i = 0; i < n; i++) {
                byte[] e = v.slice(dynOff + i * step, step);
                if (e == null) {
                    r.partial = true;
                    break;
                }
                long tag;
                long val;
                if (r.is64) {
                    tag = (long) s64(e, 0);
                    val = u64(e, 8);
                } else {
                    tag = s32(e, 0);
                    val = u32(e, 4);
                }
                if (tag == 0) break;
                if (tag == 1 && neededOffs.size() < MAX_NEEDED) neededOffs.add(val);
                else if (tag == 4) hash = val;
                else if (tag == 5) strtab = val;
                else if (tag == 6) symtab = val;
                else if (tag == 10) strsz = val;
                else if (tag == 11 && val == 16 || tag == 11 && val == 24) syment = val;
                else if (tag == 14) sonameOff = val;
            }
            byte[] dynstr = null;
            if (strtab >= 0 && strsz > 0 && strsz <= MAX_DYNSTR) {
                long off = mapFile(loads, strtab);
                if (off >= 0) dynstr = v.slice(off, (int) strsz);
                else r.partial = true;
            } else if (strtab >= 0) {
                r.partial = true;
            }
            if (dynstr != null) {
                for (long o : neededOffs) {
                    String s = cstr(dynstr, o);
                    if (s != null && !s.isEmpty()) r.needed.add(s);
                }
                if (sonameOff >= 0) {
                    String s = cstr(dynstr, sonameOff);
                    if (s != null) r.soname = s;
                }
            }
            long symCount = -1;
            if (hash >= 0) {
                long off = mapFile(loads, hash);
                byte[] h = off >= 0 ? v.slice(off, 8) : null;
                if (h != null) symCount = u32(h, 4);
                else r.partial = true;
            } else {
                r.partial = true;
            }
            if (symtab < 0 || dynstr == null || symCount <= 0) return;
            long symOff = mapFile(loads, symtab);
            if (symOff < 0) {
                r.partial = true;
                return;
            }
            long total = Math.min(symCount, MAX_SYMS_SCAN);
            for (long i = 0; i < total; i++) {
                byte[] s = v.slice(symOff + i * syment, (int) syment);
                if (s == null) {
                    r.partial = true;
                    break;
                }
                int name;
                int info;
                int shndx;
                if (r.is64) {
                    name = (int) u32(s, 0);
                    info = s[4] & 0xFF;
                    shndx = u16(s, 6);
                } else {
                    name = (int) u32(s, 0);
                    info = s[12] & 0xFF;
                    shndx = u16(s, 14);
                }
                String nm = cstr(dynstr, name);
                if (nm == null || nm.isEmpty()) continue;
                int bind = (info >> 4) & 0xF;
                if (shndx == 0) {
                    r.importCount++;
                    if (r.imports.size() < MAX_KEEP_SYMS) r.imports.add(nm);
                } else if (bind != 0) {
                    r.exportCount++;
                    if (r.exports.size() < MAX_KEEP_SYMS) r.exports.add(nm);
                    if (nm.startsWith("Java_") && r.jniExports.size() < MAX_JNI) {
                        r.jniExports.add(nm);
                    }
                    if ("JNI_OnLoad".equals(nm)) r.hasJniOnLoad = true;
                }
            }
        } catch (Throwable ignored) {
            r.partial = true;
        }
    }

    /** vaddr → offset de fichero por PT_LOAD, o -1. Nunca lanza. */
    private static long mapFile(List<Load> loads, long vaddr) {
        try {
            if (loads == null) return -1;
            for (Load l : loads) {
                if (l != null && vaddr >= l.vaddr && vaddr < l.vaddr + l.filesz) {
                    return l.offset + (vaddr - l.vaddr);
                }
            }
        } catch (Throwable ignored) {
        }
        return -1;
    }

    /** Cadena C en bytes (offset relativo) o null. Nunca lanza. */
    private static String cstr(byte[] buf, long off) {
        try {
            if (buf == null || off < 0 || off >= buf.length) return null;
            int end = (int) off;
            while (end < buf.length && buf[end] != 0) end++;
            if (end - off > 4096) return null;
            return new String(buf, (int) off, end - (int) off, "UTF-8");
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static int u16(byte[] b, int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8);
    }

    private static long u32(byte[] b, int p) {
        return (b[p] & 0xFFL) | ((b[p + 1] & 0xFFL) << 8)
                | ((b[p + 2] & 0xFFL) << 16) | ((b[p + 3] & 0xFFL) << 24);
    }

    private static int s32(byte[] b, int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8)
                | ((b[p + 2] & 0xFF) << 16) | (b[p + 3] << 24);
    }

    private static long u64(byte[] b, int p) {
        return (b[p] & 0xFFL) | ((b[p + 1] & 0xFFL) << 8)
                | ((b[p + 2] & 0xFFL) << 16) | ((b[p + 3] & 0xFFL) << 24)
                | ((b[p + 4] & 0xFFL) << 32) | ((b[p + 5] & 0xFFL) << 40)
                | ((b[p + 6] & 0xFFL) << 48) | ((b[p + 7] & 0xFFL) << 56);
    }

    private static long s64(byte[] b, int p) {
        long v = u64(b, p);
        return v;
    }
}
