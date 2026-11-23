package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Grafo de llamadas lite: aristas clasePropia→métodoInvocado recorriendo los
 * code_item del DEX. Reutiliza la tabla de opcodes de SmaliDumper.
 * Java puro. Nunca lanza.
 */
public final class DexCalls {
    private DexCalls() {
    }

    public static final int MAX_METHODS_SCAN = 20000;
    public static final int MAX_UNITS = 6000;
    public static final int MAX_EDGES = 20000;
    public static final int MAX_STRINGREFS = 20000;

    public static class Edge {
        public String caller = "?";
        public String callee = "?";
        public String dex = "?";
        public int pos = -1;
    }

    /** Quién carga un literal (const-string) y dónde. Nunca lanza. */
    public static class StringRef {
        public String user = "?";
        public String value = "?";
        public String dex = "?";
        public int pos = -1;
    }

    public static class Result {
        public List<Edge> edges = new ArrayList<>();
        public List<StringRef> strings = new ArrayList<>();
        public Map<String, String> supers = new LinkedHashMap<>();
        public boolean truncated;
        public boolean stringsTruncated;
    }

    /**
     * Recolecta invoke-* de las clases bajo pkgSlash ("com/x/" o null=todas).
     * Nunca lanza: ante cualquier anomalía devuelve lo acumulado.
     */
    public static Result collect(byte[] dex, String pkgSlash) {
        return collect(dex, pkgSlash, "?");
    }

    /**
     * Variante que etiqueta cada arista con su DEX de origen (p. ej.
     * "classes2.dex"). Usada por ReaEngine para el RefGraph. Nunca lanza.
     */
    public static Result collect(byte[] dex, String pkgSlash, String dexName) {
        Result r = new Result();
        String tag = dexName == null ? "?" : dexName;
        try {
            if (dex == null || dex.length < 0x70) return r;
            if (dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x' || dex[3] != '\n') return r;
            int stringN = u32(dex, 56);
            int stringOff = u32(dex, 60);
            int typeN = u32(dex, 64);
            int typeOff = u32(dex, 68);
            int methodN = u32(dex, 88);
            int methodOff = u32(dex, 92);
            int classN = u32(dex, 96);
            int classOff = u32(dex, 100);
            if (stringN < 0 || stringN > 2000000 || typeN < 0 || typeN > 1000000
                    || methodN < 0 || methodN > 1000000 || classN < 0 || classN > 500000) return r;

            String[] strings = new String[stringN];
            for (int i = 0; i < stringN; i++) {
                int idPos = stringOff + i * 4;
                if (idPos + 4 > dex.length) break;
                try {
                    int[] rr = AxmlDecoder.readUleb128(dex, u32(dex, idPos));
                    strings[i] = DexParser.decodeMutf8(dex, rr[1]);
                } catch (RuntimeException e) {
                    strings[i] = "";
                }
            }
            String[] types = new String[typeN];
            for (int i = 0; i < typeN; i++) {
                int idPos = typeOff + i * 4;
                if (idPos + 4 > dex.length) break;
                types[i] = get(strings, u32(dex, idPos));
            }
            int[] mClass = new int[methodN];
            int[] mName = new int[methodN];
            for (int i = 0; i < methodN; i++) {
                int q = methodOff + i * 8;
                if (q + 8 > dex.length) break;
                mClass[i] = u16(dex, q);
                mName[i] = u32(dex, q + 4);
            }

            int scanned = 0;
            for (int i = 0; i < classN; i++) {
                int p = classOff + i * 32;
                if (p + 32 > dex.length) break;
                String cls = typeAt(types, u32(dex, p));
                String sup = typeAt(types, u32(dex, p + 8));
                if (!"?".equals(cls) && !"?".equals(sup) && !cls.equals(sup)
                        && !"Ljava/lang/Object;".equals(sup)) r.supers.put(cls, sup);
                int dataOff = u32(dex, p + 24);
                if (pkgSlash != null && !cls.startsWith("L" + pkgSlash)) continue;
                if (dataOff == 0) continue;
                try {
                    int q = dataOff;
                    int[] a = AxmlDecoder.readUleb128(dex, q);
                    q = a[1];
                    a = AxmlDecoder.readUleb128(dex, q);
                    q = a[1];
                    a = AxmlDecoder.readUleb128(dex, q);
                    int directN = a[0];
                    q = a[1];
                    a = AxmlDecoder.readUleb128(dex, q);
                    int virtualN = a[0];
                    q = a[1];
                    if (directN < 0 || directN > 100000 || virtualN < 0 || virtualN > 100000) continue;
                    // Salta fields: cada uno son 2 uleb (idxDiff, access).
                    q = skipFields(dex, q, dataOff);
                    int mIdx = 0;
                    for (int k = 0; k < directN; k++) {
                        int[] rr = readMethod(dex, q);
                        mIdx += rr[0];
                        q = rr[3];
                        scanned += scanMethod(dex, r, cls, mIdx, rr[2], types, strings, mClass, mName, tag);
                        if (stop(r, scanned)) return r;
                    }
                    mIdx = 0;
                    for (int k = 0; k < virtualN; k++) {
                        int[] rr = readMethod(dex, q);
                        mIdx += rr[0];
                        q = rr[3];
                        scanned += scanMethod(dex, r, cls, mIdx, rr[2], types, strings, mClass, mName, tag);
                        if (stop(r, scanned)) return r;
                    }
                } catch (RuntimeException e) {
                    // clase anómala: sigue con la siguiente
                }
            }
        } catch (Throwable t) {
            r.truncated = true;
        }
        return r;
    }

    // Relee los conteos de fields desde el inicio de class_data y avanza q
    // tras ellos (q ya apunta después de los 4 conteos).
    private static int skipFields(byte[] dex, int q, int dataOff) {
        int p = dataOff;
        int[] a = AxmlDecoder.readUleb128(dex, p);
        int staticN = a[0];
        p = a[1];
        a = AxmlDecoder.readUleb128(dex, p);
        int instanceN = a[0];
        p = a[1];
        // q ya apunta tras los 4 conteos; salta static+instance fields.
        for (int i = 0; i < staticN + instanceN; i++) {
            a = AxmlDecoder.readUleb128(dex, q);
            q = a[1];
            a = AxmlDecoder.readUleb128(dex, q);
            q = a[1];
        }
        return q;
    }

    private static boolean stop(Result r, int scanned) {
        if (r.edges.size() >= MAX_EDGES || scanned >= MAX_METHODS_SCAN) {
            r.truncated = true;
            return true;
        }
        return false;
    }

    /** Escanea un método; devuelve 1 (método contado) y añade aristas. */
    private static int scanMethod(byte[] dex, Result r, String cls, int mIdx, int codeOff,
                                  String[] types, String[] strings, int[] mClass, int[] mName,
                                  String dexName) {
        if (codeOff == 0) return 1;
        check(dex, codeOff, 16);
        int insnsSize = u32(dex, codeOff + 12);
        if (insnsSize < 0 || insnsSize > 1000000) return 1;
        int n = Math.min(insnsSize, MAX_UNITS);
        check(dex, codeOff + 16, n * 2);
        String caller = cls + "->" + methodName(types, strings, mClass, mName, mIdx);
        int p = 0;
        while (p < n) {
            int u0 = u16(dex, codeOff + 16 + p * 2);
            int op = u0 & 0xFF;
            int fmt = SmaliDumper.FORMATS[op] & 0xFF;
            int size = sizeOf(fmt, dex, codeOff + 16, p, n);
            if (size <= 0 || p + size > n) break;
            if (SmaliDumper.REFS[op] == SmaliDumper.R_METHOD) {
                int idx = u16(dex, codeOff + 16 + (p + 1) * 2);
                if (idx >= 0 && idx < mClass.length && r.edges.size() < MAX_EDGES) {
                    Edge e = new Edge();
                    e.caller = caller;
                    e.callee = typeAt(types, mClass[idx]) + "->" + get(strings, mName[idx]);
                    e.dex = dexName;
                    e.pos = p;
                    r.edges.add(e);
                }
            } else if (SmaliDumper.REFS[op] == SmaliDumper.R_STR) {
                // const-string/jumbo: el índice es u16 (21c) o u32 (31c).
                int idx = op == 0x1b
                        ? u32(dex, codeOff + 16 + (p + 1) * 2)
                        : u16(dex, codeOff + 16 + (p + 1) * 2);
                if (idx >= 0 && idx < strings.length) {
                    String v = get(strings, idx);
                    if (v != null && !v.isEmpty() && !"?".equals(v)) {
                        if (r.strings.size() < MAX_STRINGREFS) {
                            StringRef s = new StringRef();
                            s.user = caller;
                            s.value = v;
                            s.dex = dexName;
                            s.pos = p;
                            r.strings.add(s);
                        } else {
                            r.stringsTruncated = true;
                            r.truncated = true;
                        }
                    }
                }
            }
            p += size;
        }
        return 1;
    }

    private static int sizeOf(int fmt, byte[] dex, int base, int p, int n) {
        // Tamaños fijos por formato; payloads (nop 0x00) como 1 unidad.
        switch (fmt) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
                return 1;
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            case 16:
                return 2;
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
            case 22:
            case 26:
                return 3;
            case 23:
            case 24:
                return 4;
            case 25:
                return 5;
            default:
                return 1;
        }
    }

    private static int[] readMethod(byte[] dex, int p) {
        int[] a = AxmlDecoder.readUleb128(dex, p);
        int diff = a[0];
        p = a[1];
        a = AxmlDecoder.readUleb128(dex, p);
        p = a[1];
        a = AxmlDecoder.readUleb128(dex, p);
        return new int[]{diff, a[0], a[0], a[1]};
    }

    private static String methodName(String[] types, String[] strings, int[] mClass, int[] mName, int idx) {
        if (idx < 0 || idx >= mName.length) return "?";
        return get(strings, mName[idx]);
    }

    private static String get(String[] arr, int idx) {
        if (idx < 0 || idx >= arr.length || arr[idx] == null) return "?";
        return arr[idx];
    }

    private static String typeAt(String[] types, int idx) {
        if (idx < 0 || idx >= types.length || types[idx] == null) return "?";
        return types[idx];
    }

    private static int u16(byte[] b, int p) {
        AxmlDecoder.check(b, p, 2);
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8);
    }

    private static int u32(byte[] b, int p) {
        AxmlDecoder.check(b, p, 4);
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8) | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }

    private static void check(byte[] b, int p, int len) {
        AxmlDecoder.check(b, p, len);
    }
}
