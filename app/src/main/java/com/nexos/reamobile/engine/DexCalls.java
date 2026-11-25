package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Grafo de llamadas lite: aristas clasePropia→métodoInvocado recorriendo los
 * code_item del DEX. Reutiliza la tabla de opcodes de SmaliDumper y las
 * tablas perezosas DexStrings/DexTypes (sin arrays completos).
 * Java puro. Nunca lanza.
 */
public final class DexCalls {
    private DexCalls() {
    }

    public static final int MAX_METHODS_SCAN = 20000;
    public static final int MAX_UNITS = 6000;
    public static final int MAX_EDGES = 20000;
    public static final int MAX_STRINGREFS = 20000;
    public static final int MAX_CODEOFFS = 4000;
    /** M-01: tope de entradas clase→super por DEX (con flag de truncado). */
    public static final int MAX_SUPERS = 100000;

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
        /** Aristas de clases ajenas (solo pase fusionado). */
        public List<Edge> libEdges = new ArrayList<>();
        public List<StringRef> strings = new ArrayList<>();
        /** Strings de clases ajenas (se fusionan tras las propias). */
        public List<StringRef> libStrings = new ArrayList<>();
        public Map<String, String> supers = new LinkedHashMap<>();
        /** Métodos propios con código ("Lcls;->m" → codeOff), para FlowScan. */
        public Map<String, Integer> codeOffs = new LinkedHashMap<>();
        /** Tabla de strings usada (se comparte con FlowScan). */
        public DexStrings table;
        public boolean truncated;
        public boolean libTruncated;
        public boolean stringsTruncated;
        public boolean libStringsTruncated;
        public boolean supersTruncated;
    }

    /**
     * Recolecta invoke-* de las clases bajo pkgSlash ("com/x/" o null=todas).
     * Nunca lanza: ante cualquier anomalía devuelve lo acumulado.
     */
    public static Result collect(byte[] dex, String pkgSlash) {
        return collect(dex, pkgSlash, "?", false);
    }

    /**
     * Variante que etiqueta cada arista con su DEX de origen (p. ej.
     * "classes2.dex"). Usada por ReaEngine para el RefGraph. Nunca lanza.
     */
    public static Result collect(byte[] dex, String pkgSlash, String dexName) {
        return collect(dex, pkgSlash, dexName, false);
    }

    /**
     * Variante fusionada: un solo recorrido del DEX. Si includeLib es true,
     * las clases fuera de pkgSlash también aportan aristas (a libEdges) y
     * strings; si es false se omiten como antes. Los presupuestos de
     * propias y ajenas son independientes: la cobertura propia es idéntica
     * a la del pase clásico. Nunca lanza.
     */
    public static Result collect(byte[] dex, String pkgSlash, String dexName, boolean includeLib) {
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

            DexStrings strings = DexStrings.of(dex, stringOff, stringN);
            DexTypes types = DexTypes.of(dex, typeOff, typeN, strings);
            r.table = strings;
            // M-03: method_ids perezoso vía midClass/midName (antes 2xint[<=1M]).

            int ownScanned = 0;
            int libScanned = 0;
            boolean ownDone = false;
            boolean libDone = !includeLib;
            for (int i = 0; i < classN; i++) {
                if (ownDone && libDone) break;
                int p = classOff + i * 32;
                if (p + 32 > dex.length) break;
                String cls = types.get(u32(dex, p));
                String sup = types.get(u32(dex, p + 8));
                if (!"?".equals(cls) && !"?".equals(sup) && !cls.equals(sup)
                        && !"Ljava/lang/Object;".equals(sup)) {
                    if (r.supers.size() < MAX_SUPERS) r.supers.put(cls, sup);
                    else r.supersTruncated = true;
                }
                int dataOff = u32(dex, p + 24);
                boolean own = pkgSlash == null || cls.startsWith("L" + pkgSlash);
                if (own && ownDone) continue;
                if (!own && (libDone || !includeLib)) continue;
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
                        if (own) {
                            if (ownScanned >= MAX_METHODS_SCAN) {
                                r.truncated = true;
                                ownDone = true;
                                break;
                            }
                            scanMethod(dex, r, cls, mIdx, rr[2], types, strings, methodOff, methodN,
                                    tag, true);
                            ownScanned++;
                        } else {
                            if (libScanned >= MAX_METHODS_SCAN) {
                                r.libTruncated = true;
                                libDone = true;
                                break;
                            }
                            scanMethod(dex, r, cls, mIdx, rr[2], types, strings, methodOff, methodN,
                                    tag, false);
                            libScanned++;
                        }
                        if (r.edges.size() >= MAX_EDGES) {
                            r.truncated = true;
                            ownDone = true;
                        }
                        if (r.libEdges.size() >= MAX_EDGES) {
                            r.libTruncated = true;
                            libDone = true;
                        }
                        if (ownDone && libDone) break;
                    }
                    if (ownDone && libDone) break;
                    mIdx = 0;
                    for (int k = 0; k < virtualN; k++) {
                        int[] rr = readMethod(dex, q);
                        mIdx += rr[0];
                        q = rr[3];
                        if (own) {
                            if (ownScanned >= MAX_METHODS_SCAN) {
                                r.truncated = true;
                                ownDone = true;
                                break;
                            }
                            scanMethod(dex, r, cls, mIdx, rr[2], types, strings, methodOff, methodN,
                                    tag, true);
                            ownScanned++;
                        } else {
                            if (libScanned >= MAX_METHODS_SCAN) {
                                r.libTruncated = true;
                                libDone = true;
                                break;
                            }
                            scanMethod(dex, r, cls, mIdx, rr[2], types, strings, methodOff, methodN,
                                    tag, false);
                            libScanned++;
                        }
                        if (r.edges.size() >= MAX_EDGES) {
                            r.truncated = true;
                            ownDone = true;
                        }
                        if (r.libEdges.size() >= MAX_EDGES) {
                            r.libTruncated = true;
                            libDone = true;
                        }
                        if (ownDone && libDone) break;
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

    /** Escanea un método; añade aristas (own→edges, ajenas→libEdges). */
    private static void scanMethod(byte[] dex, Result r, String cls, int mIdx, int codeOff,
                                   DexTypes types, DexStrings strings, int methodOff, int methodN,
                                   String dexName, boolean own) {
        if (codeOff == 0) return;
        check(dex, codeOff, 16);
        int insnsSize = u32(dex, codeOff + 12);
        if (insnsSize < 0 || insnsSize > 1000000) return;
        int n = Math.min(insnsSize, MAX_UNITS);
        check(dex, codeOff + 16, n * 2);
        String caller = cls + "->" + methodName(strings, dex, methodOff, methodN, mIdx);
        if (own && r.codeOffs.size() < MAX_CODEOFFS && !r.codeOffs.containsKey(caller)) {
            r.codeOffs.put(caller, codeOff);
        }
        List<Edge> dst = own ? r.edges : r.libEdges;
        int p = 0;
        while (p < n) {
            int u0 = u16(dex, codeOff + 16 + p * 2);
            int op = u0 & 0xFF;
            int fmt = SmaliDumper.FORMATS[op] & 0xFF;
            int size = sizeOf(fmt, dex, codeOff + 16, p, n);
            if (size <= 0 || p + size > n) break;
            if (SmaliDumper.REFS[op] == SmaliDumper.R_METHOD) {
                int idx = u16(dex, codeOff + 16 + (p + 1) * 2);
                if (idx >= 0 && idx < methodN && dst.size() < MAX_EDGES) {
                    Edge e = new Edge();
                    e.caller = caller;
                    e.callee = types.get(midClass(dex, methodOff, methodN, idx))
                            + "->" + strings.get(midName(dex, methodOff, methodN, idx));
                    e.dex = dexName;
                    e.pos = p;
                    dst.add(e);
                }
            } else if (SmaliDumper.REFS[op] == SmaliDumper.R_STR) {
                // const-string/jumbo: el índice es u16 (21c) o u32 (31c).
                int idx = op == 0x1b
                        ? u32(dex, codeOff + 16 + (p + 1) * 2)
                        : u16(dex, codeOff + 16 + (p + 1) * 2);
                if (idx >= 0 && idx < strings.size()) {
                    String v = strings.get(idx);
                    if (v != null && !v.isEmpty() && !"?".equals(v)) {
                        List<StringRef> sdst = own ? r.strings : r.libStrings;
                        if (sdst.size() < MAX_STRINGREFS) {
                            StringRef s = new StringRef();
                            s.user = caller;
                            s.value = v;
                            s.dex = dexName;
                            s.pos = p;
                            sdst.add(s);
                        } else if (own) {
                            r.stringsTruncated = true;
                            r.truncated = true;
                        } else {
                            r.libStringsTruncated = true;
                            r.libTruncated = true;
                        }
                    }
                }
            }
            p += size;
        }
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

    private static String methodName(DexStrings strings, byte[] dex, int methodOff, int methodN,
                                     int idx) {
        if (idx < 0 || idx >= methodN) return "?";
        return strings.get(midName(dex, methodOff, methodN, idx));
    }

    /** method_ids perezoso (8B: u16 clase, u16 proto, u32 nombre). 0 si ilegible. Nunca lanza. */
    private static int midClass(byte[] dex, int methodOff, int methodN, int idx) {
        return midCell(dex, methodOff, methodN, idx, 0);
    }

    private static int midName(byte[] dex, int methodOff, int methodN, int idx) {
        return midCell(dex, methodOff, methodN, idx, 4);
    }

    private static int midCell(byte[] dex, int off, int n, int idx, int add) {
        try {
            if (dex == null || idx < 0 || idx >= n || off < 0) return 0;
            long q = (long) off + (long) idx * 8 + add;
            int need = add == 4 ? 4 : 2;
            if (q > (long) dex.length - need) return 0;
            int p = (int) q;
            return add == 4 ? u32(dex, p) : u16(dex, p);
        } catch (Throwable ignored) {
            return 0;
        }
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
