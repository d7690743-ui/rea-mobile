package com.nexos.reamobile.engine;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * OMEGA Fase E0: recolector acotado de IR por método para el análisis de
 * flujo. Recorre el class_data del DEX (igual que DexCalls, sin tocarlo) y
 * construye IrBuilder.MethodIr solo de métodos propios pequeños, más el
 * pool de const-string que referencian (para resolver valores en
 * ReachConsts.CallConst). Java puro. Nunca lanza.
 *
 * <p>Claves de método con el formato de DexCalls: {@code Lcom/x/A;->foo}.</p>
 */
public final class FlowScan {
    private FlowScan() {
    }

    public static final int MAX_FLOW_METHODS = 400;
    public static final int MAX_METHOD_UNITS = 4000;
    public static final int MAX_POOL_STRINGS = 5000;
    public static final int MAX_STRING_LEN = 500;

    /** Resultado de escanear un DEX. Nunca lanza. */
    public static class FlowResult {
        /** "Lcls;->name" → IR (el primero gana entre dexes). */
        public Map<String, IrBuilder.MethodIr> irs = new LinkedHashMap<>();
        /** método → dex de origen. */
        public Map<String, String> flowDex = new LinkedHashMap<>();
        /** dex+"\0"+refIdx → literal (solo const-string referenciadas). */
        public Map<String, String> strings = new LinkedHashMap<>();
        public int skipped;
        public boolean truncated;
    }

    /**
     * Construye IRs desde los codeOff que DexCalls ya recolectó, resolviendo
     * el pool con su misma tabla (sin re-recorrer ni re-decodificar).
     * codeOffs/table nulos → vacío. Nunca null ni lanza.
     */
    public static FlowResult buildFrom(byte[] dex, Map<String, Integer> codeOffs,
            DexStrings table, String dexName, int budget) {
        FlowResult r = new FlowResult();
        String tag = dexName == null ? "?" : dexName;
        try {
            if (dex == null || codeOffs == null || codeOffs.isEmpty() || budget <= 0) return r;
            Set<Integer> wantStr = new LinkedHashSet<>();
            for (Map.Entry<String, Integer> en : codeOffs.entrySet()) {
                if (r.irs.size() >= budget) {
                    r.truncated = true;
                    break;
                }
                if (en.getKey() == null || en.getValue() == null) continue;
                int codeOff = en.getValue();
                if (codeOff <= 0 || codeOff + 16 > dex.length) {
                    r.skipped++;
                    continue;
                }
                int insnsSize = (dex[codeOff + 12] & 0xFF) | ((dex[codeOff + 13] & 0xFF) << 8)
                        | ((dex[codeOff + 14] & 0xFF) << 16) | ((dex[codeOff + 15] & 0xFF) << 24);
                if (insnsSize < 0 || insnsSize > MAX_METHOD_UNITS) {
                    r.skipped++;
                    continue;
                }
                IrBuilder.MethodIr ir = IrBuilder.buildMethod(dex, codeOff);
                if (ir == null || ir.error != null) {
                    r.skipped++;
                    continue;
                }
                r.irs.put(en.getKey(), ir);
                r.flowDex.put(en.getKey(), tag);
                for (IrBuilder.Insn in : ir.insns) {
                    if (in == null) continue;
                    int op = in.op & 0xFF;
                    if ((op == 0x1A || op == 0x1B) && wantStr.size() < MAX_POOL_STRINGS) {
                        wantStr.add(in.refIdx);
                    }
                }
            }
            if (table != null) {
                for (int idx : wantStr) {
                    if (r.strings.size() >= MAX_POOL_STRINGS) {
                        r.truncated = true;
                        break;
                    }
                    String v = table.get(idx);
                    if (v != null && !v.isEmpty() && !"?".equals(v)) {
                        if (v.length() > MAX_STRING_LEN) v = v.substring(0, MAX_STRING_LEN);
                        r.strings.put(tag + "\u0000" + idx, v);
                    }
                }
            }
        } catch (Throwable t) {
            r.truncated = true;
        }
        return r;
    }

    /**
     * Recolecta IRs de métodos propios (pkgSlash null = todos), hasta
     * budget métodos. budget &lt;= 0 → vacío. Nunca null ni lanza.
     */
    public static FlowResult collect(byte[] dex, String pkgSlash, String dexName, int budget) {
        FlowResult r = new FlowResult();
        String tag = dexName == null ? "?" : dexName;
        try {
            if (dex == null || budget <= 0) return r;
            if (dex.length < 0x70) return r;
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
            String[] types = new String[typeN];
            int[] mName = new int[methodN];
            for (int i = 0; i < methodN; i++) {
                int q = methodOff + i * 8;
                if (q + 8 > dex.length) break;
                mName[i] = u32(dex, q + 4);
            }
            // Nombres de tipo y método (mismo orden que DexCalls).
            String[] strings = readStrings(dex, stringOff, stringN);
            for (int i = 0; i < typeN; i++) {
                int idPos = typeOff + i * 4;
                if (idPos + 4 > dex.length) break;
                types[i] = get(strings, u32(dex, idPos));
            }
            Set<Integer> wantStr = new LinkedHashSet<>();
            for (int i = 0; i < classN; i++) {
                int p = classOff + i * 32;
                if (p + 32 > dex.length) break;
                String cls = typeAt(types, u32(dex, p));
                int dataOff = u32(dex, p + 24);
                if (pkgSlash != null && !cls.startsWith("L" + pkgSlash)) continue;
                if (dataOff == 0) continue;
                try {
                    scanClass(dex, r, tag, cls, dataOff, strings, mName, budget, wantStr);
                } catch (RuntimeException e) {
                    // clase anómala: sigue con la siguiente
                }
                if (r.irs.size() >= budget) {
                    r.truncated = true;
                    break;
                }
            }
            for (int idx : wantStr) {
                if (r.strings.size() >= MAX_POOL_STRINGS) {
                    r.truncated = true;
                    break;
                }
                String v = get(strings, idx);
                if (v != null && !v.isEmpty() && !"?".equals(v)) {
                    if (v.length() > MAX_STRING_LEN) v = v.substring(0, MAX_STRING_LEN);
                    r.strings.put(tag + "\u0000" + idx, v);
                }
            }
        } catch (Throwable t) {
            r.truncated = true;
        }
        return r;
    }

    private static void scanClass(byte[] dex, FlowResult r, String tag, String cls,
            int dataOff, String[] strings, int[] mName, int budget, Set<Integer> wantStr) {
        int q = dataOff;
        int[] a = AxmlDecoder.readUleb128(dex, q);
        int staticN = a[0];
        q = a[1];
        a = AxmlDecoder.readUleb128(dex, q);
        int instanceN = a[0];
        q = a[1];
        a = AxmlDecoder.readUleb128(dex, q);
        int directN = a[0];
        q = a[1];
        a = AxmlDecoder.readUleb128(dex, q);
        int virtualN = a[0];
        q = a[1];
        if (directN < 0 || directN > 100000 || virtualN < 0 || virtualN > 100000) return;
        if (staticN < 0 || staticN > 100000 || instanceN < 0 || instanceN > 100000) return;
        for (int i = 0; i < staticN + instanceN; i++) {
            a = AxmlDecoder.readUleb128(dex, q);
            q = a[1];
            a = AxmlDecoder.readUleb128(dex, q);
            q = a[1];
        }
        int mIdx = 0;
        for (int k = 0; k < directN; k++) {
            int[] rr = readMethod(dex, q);
            mIdx += rr[0];
            q = rr[3];
            scanMethod(dex, r, tag, cls, mIdx, rr[2], strings, mName, budget, wantStr);
            if (r.irs.size() >= budget) return;
        }
        mIdx = 0;
        for (int k = 0; k < virtualN; k++) {
            int[] rr = readMethod(dex, q);
            mIdx += rr[0];
            q = rr[3];
            scanMethod(dex, r, tag, cls, mIdx, rr[2], strings, mName, budget, wantStr);
            if (r.irs.size() >= budget) return;
        }
    }

    private static void scanMethod(byte[] dex, FlowResult r, String tag, String cls,
            int mIdx, int codeOff, String[] strings, int[] mName, int budget,
            Set<Integer> wantStr) {
        if (codeOff == 0 || r.irs.size() >= budget) return;
        AxmlDecoder.check(dex, codeOff, 16);
        int insnsSize = u32(dex, codeOff + 12);
        if (insnsSize < 0 || insnsSize > MAX_METHOD_UNITS) {
            r.skipped++;
            return;
        }
        String key = cls + "->" + get(strings, mIdx >= 0 && mIdx < mName.length ? mName[mIdx] : -1);
        if (r.irs.containsKey(key)) return;
        IrBuilder.MethodIr ir = IrBuilder.buildMethod(dex, codeOff);
        if (ir == null || ir.error != null) {
            r.skipped++;
            return;
        }
        r.irs.put(key, ir);
        r.flowDex.put(key, tag);
        for (IrBuilder.Insn in : ir.insns) {
            if (in == null) continue;
            int op = in.op & 0xFF;
            if ((op == 0x1A || op == 0x1B) && wantStr.size() < MAX_POOL_STRINGS) {
                wantStr.add(in.refIdx);
            }
        }
    }

    private static String[] readStrings(byte[] dex, int stringOff, int stringN) {
        String[] strings = new String[stringN];
        for (int i = 0; i < stringN; i++) {
            int idPos = stringOff + i * 4;
            if (idPos + 4 > dex.length) break;
            try {
                int[] rr = AxmlDecoder.readUleb128(dex, u32(dex, idPos));
                strings[i] = DexParser.decodeMutf8(dex, rr[1], rr[0]);
            } catch (RuntimeException e) {
                strings[i] = "";
            }
        }
        return strings;
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

    private static String get(String[] arr, int idx) {
        if (idx < 0 || idx >= arr.length || arr[idx] == null) return "?";
        return arr[idx];
    }

    private static String typeAt(String[] types, int idx) {
        if (idx < 0 || idx >= types.length || types[idx] == null) return "?";
        return types[idx];
    }

    private static int u32(byte[] b, int p) {
        AxmlDecoder.check(b, p, 4);
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8) | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }
}
