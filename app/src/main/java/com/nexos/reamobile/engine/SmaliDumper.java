package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Desensamblador Dalvik a smali (best-effort): interfaces, valores estáticos,
 * anotaciones, try/catch y código. Java puro. Omite debug_info; los payloads
 * de switch/array se emiten como comentarios con datos crudos (no
 * reensamblables). Pensado para análisis y recuperación, no para reensamblar
 * a ciegas: lo dudoso queda marcado con '#'.
 */
public final class SmaliDumper {
    private SmaliDumper() {
    }

    public static final int MAX_CLASSES = 1500;
    public static final int MAX_UNITS_PER_METHOD = 6000;
    public static final long MAX_TOTAL_BYTES = 40L * 1024 * 1024;
    /** Tope de fallos retenidos (failTotal cuenta todos). Solo FullDump. */
    public static final int MAX_FAILURES = 5000;
    /** T2: cotas de emisión por clase y por método (se comprueban durante). */
    public static final int MAX_CHARS_PER_CLASS = 2 * 1024 * 1024;
    public static final int MAX_CHARS_PER_METHOD = 256 * 1024;

    // Visibles en el paquete para IrBuilder (Fase 3). Sin cambio de conducta.
    static final int F10x = 0, F12x = 1, F11n = 2, F11x = 3, F10t = 4, F20t = 5,
            F22x = 6, F21t = 7, F22t = 8, F21s = 9, F21h = 10, F21lh = 11, F21c = 12,
            F22s = 13, F22b = 14, F23x = 15, F22c = 16, F32x = 17, F31i = 18, F31t = 19,
            F31c = 20, F35c = 21, F3rc = 22, F45cc = 23, F4rcc = 24, F51l = 25, F30t = 26, F00 = 27;
    static final int R_NONE = 0, R_STR = 1, R_TYPE = 2, R_FIELD = 3, R_METHOD = 4, R_RAW = 5;

    static final String[] NAMES = new String[256];
    static final byte[] FORMATS = new byte[256];
    static final byte[] REFS = new byte[256];

    private static final String TABLE =
            "00=nop:00,01=move:12x,02=move/from16:22x,03=move/16:32x,04=move-wide:12x,"
                    + "05=move-wide/from16:22x,06=move-wide/16:32x,07=move-object:12x,08=move-object/from16:22x,"
                    + "09=move-object/16:32x,0a=move-result:11x,0b=move-result-wide:11x,0c=move-result-object:11x,"
                    + "0d=move-exception:11x,0e=return-void:10x,0f=return:11x,10=return-wide:11x,11=return-object:11x,"
                    + "12=const/4:11n,13=const/16:21s,14=const:31i,15=const/high16:21h,16=const-wide/16:21s,"
                    + "17=const-wide/32:31i,18=const-wide:51l,19=const-wide/high16:21lh,1a=const-string:21c:s,"
                    + "1b=const-string/jumbo:31c:s,1c=const-class:21c:t,1d=monitor-enter:11x,1e=monitor-exit:11x,"
                    + "1f=check-cast:21c:t,20=instance-of:22c:t,21=array-length:12x,22=new-instance:21c:t,"
                    + "23=new-array:22c:t,24=filled-new-array:35c:t,25=filled-new-array/range:3rc:t,26=fill-array-data:31t,"
                    + "27=throw:11x,28=goto:10t,29=goto/16:20t,2a=goto/32:30t,2b=packed-switch:31t,2c=sparse-switch:31t,"
                    + "2d=cmpl-float:23x,2e=cmpg-float:23x,2f=cmpl-double:23x,30=cmpg-double:23x,31=cmp-long:23x,"
                    + "32=if-eq:22t,33=if-ne:22t,34=if-lt:22t,35=if-ge:22t,36=if-gt:22t,37=if-le:22t,38=if-eqz:21t,"
                    + "39=if-nez:21t,3a=if-ltz:21t,3b=if-gez:21t,3c=if-gtz:21t,3d=if-lez:21t,"
                    + "44=aget:23x,45=aget-wide:23x,46=aget-object:23x,47=aget-boolean:23x,48=aget-byte:23x,"
                    + "49=aget-char:23x,4a=aget-short:23x,4b=aput:23x,4c=aput-wide:23x,4d=aput-object:23x,"
                    + "4e=aput-boolean:23x,4f=aput-byte:23x,50=aput-char:23x,51=aput-short:23x,"
                    + "52=iget:22c:f,53=iget-wide:22c:f,54=iget-object:22c:f,55=iget-boolean:22c:f,56=iget-byte:22c:f,"
                    + "57=iget-char:22c:f,58=iget-short:22c:f,59=iput:22c:f,5a=iput-wide:22c:f,5b=iput-object:22c:f,"
                    + "5c=iput-boolean:22c:f,5d=iput-byte:22c:f,5e=iput-char:22c:f,5f=iput-short:22c:f,"
                    + "60=sget:21c:f,61=sget-wide:21c:f,62=sget-object:21c:f,63=sget-boolean:21c:f,64=sget-byte:21c:f,"
                    + "65=sget-char:21c:f,66=sget-short:21c:f,67=sput:21c:f,68=sput-wide:21c:f,69=sput-object:21c:f,"
                    + "6a=sput-boolean:21c:f,6b=sput-byte:21c:f,6c=sput-char:21c:f,6d=sput-short:21c:f,"
                    + "6e=invoke-virtual:35c:m,6f=invoke-super:35c:m,70=invoke-direct:35c:m,71=invoke-static:35c:m,"
                    + "72=invoke-interface:35c:m,74=invoke-virtual/range:3rc:m,75=invoke-super/range:3rc:m,"
                    + "76=invoke-direct/range:3rc:m,77=invoke-static/range:3rc:m,78=invoke-interface/range:3rc:m,"
                    + "7b=neg-int:12x,7c=not-int:12x,7d=neg-long:12x,7e=not-long:12x,7f=neg-float:12x,80=neg-double:12x,"
                    + "81=int-to-long:12x,82=int-to-float:12x,83=int-to-double:12x,84=long-to-int:12x,"
                    + "85=long-to-float:12x,86=long-to-double:12x,87=float-to-int:12x,88=float-to-long:12x,"
                    + "89=float-to-double:12x,8a=double-to-int:12x,8b=double-to-long:12x,8c=double-to-float:12x,"
                    + "8d=int-to-byte:12x,8e=int-to-char:12x,8f=int-to-short:12x,"
                    + "90=add-int:23x,91=sub-int:23x,92=mul-int:23x,93=div-int:23x,94=rem-int:23x,95=and-int:23x,"
                    + "96=or-int:23x,97=xor-int:23x,98=shl-int:23x,99=shr-int:23x,9a=ushr-int:23x,9b=add-long:23x,"
                    + "9c=sub-long:23x,9d=mul-long:23x,9e=div-long:23x,9f=rem-long:23x,a0=and-long:23x,a1=or-long:23x,"
                    + "a2=xor-long:23x,a3=shl-long:23x,a4=shr-long:23x,a5=ushr-long:23x,a6=add-float:23x,"
                    + "a7=sub-float:23x,a8=mul-float:23x,a9=div-float:23x,aa=rem-float:23x,ab=add-double:23x,"
                    + "ac=sub-double:23x,ad=mul-double:23x,ae=div-double:23x,af=rem-double:23x,"
                    + "b0=add-int/2addr:12x,b1=sub-int/2addr:12x,b2=mul-int/2addr:12x,b3=div-int/2addr:12x,"
                    + "b4=rem-int/2addr:12x,b5=and-int/2addr:12x,b6=or-int/2addr:12x,b7=xor-int/2addr:12x,"
                    + "b8=shl-int/2addr:12x,b9=shr-int/2addr:12x,ba=ushr-int/2addr:12x,bb=add-long/2addr:12x,"
                    + "bc=sub-long/2addr:12x,bd=mul-long/2addr:12x,be=div-long/2addr:12x,bf=rem-long/2addr:12x,"
                    + "c0=and-long/2addr:12x,c1=or-long/2addr:12x,c2=xor-long/2addr:12x,c3=shl-long/2addr:12x,"
                    + "c4=shr-long/2addr:12x,c5=ushr-long/2addr:12x,c6=add-float/2addr:12x,c7=sub-float/2addr:12x,"
                    + "c8=mul-float/2addr:12x,c9=div-float/2addr:12x,ca=rem-float/2addr:12x,cb=add-double/2addr:12x,"
                    + "cc=sub-double/2addr:12x,cd=mul-double/2addr:12x,ce=div-double/2addr:12x,cf=rem-double/2addr:12x,"
                    + "d0=add-int/lit16:22s,d1=rsub-int:22s,d2=mul-int/lit16:22s,d3=div-int/lit16:22s,"
                    + "d4=rem-int/lit16:22s,d5=and-int/lit16:22s,d6=or-int/lit16:22s,d7=xor-int/lit16:22s,"
                    + "d8=add-int/lit8:22b,d9=rsub-int/lit8:22b,da=mul-int/lit8:22b,db=div-int/lit8:22b,"
                    + "dc=rem-int/lit8:22b,dd=and-int/lit8:22b,de=or-int/lit8:22b,df=xor-int/lit8:22b,"
                    + "e0=shl-int/lit8:22b,e1=shr-int/lit8:22b,e2=ushr-int/lit8:22b,"
                    + "f2=invoke-polymorphic:45cc:m,f3=invoke-polymorphic/range:4rcc:m,f4=invoke-custom:35c:r,"
                    + "f5=invoke-custom/range:3rc:r,f6=const-method-handle:21c:r,f7=const-method-type:21c:r";

    static {
        for (int i = 0; i < 256; i++) {
            NAMES[i] = "unused-" + Integer.toHexString(i);
            FORMATS[i] = F10x;
            REFS[i] = R_NONE;
        }
        for (String e : TABLE.split(",")) {
            if (e.isEmpty()) continue;
            String[] p = e.split(":");
            int op = Integer.parseInt(p[0].substring(0, 2), 16);
            NAMES[op] = p[0].substring(3);
            FORMATS[op] = (byte) fmtCode(p[1]);
            if (p.length > 2) REFS[op] = (byte) refCode(p[2]);
        }
    }

    private static int fmtCode(String s) {
        if (s.equals("10x")) return F10x;
        if (s.equals("12x")) return F12x;
        if (s.equals("11n")) return F11n;
        if (s.equals("11x")) return F11x;
        if (s.equals("10t")) return F10t;
        if (s.equals("20t")) return F20t;
        if (s.equals("22x")) return F22x;
        if (s.equals("21t")) return F21t;
        if (s.equals("22t")) return F22t;
        if (s.equals("21s")) return F21s;
        if (s.equals("21h")) return F21h;
        if (s.equals("21lh")) return F21lh;
        if (s.equals("21c")) return F21c;
        if (s.equals("22s")) return F22s;
        if (s.equals("22b")) return F22b;
        if (s.equals("23x")) return F23x;
        if (s.equals("22c")) return F22c;
        if (s.equals("32x")) return F32x;
        if (s.equals("31i")) return F31i;
        if (s.equals("31t")) return F31t;
        if (s.equals("31c")) return F31c;
        if (s.equals("35c")) return F35c;
        if (s.equals("3rc")) return F3rc;
        if (s.equals("45cc")) return F45cc;
        if (s.equals("4rcc")) return F4rcc;
        if (s.equals("51l")) return F51l;
        if (s.equals("30t")) return F30t;
        return F00;
    }

    private static int refCode(String s) {
        if (s.equals("s")) return R_STR;
        if (s.equals("t")) return R_TYPE;
        if (s.equals("f")) return R_FIELD;
        if (s.equals("m")) return R_METHOD;
        return R_RAW;
    }

    static class Tables {
        byte[] buf;
        DexStrings strings;
        DexTypes types;
        int methodN, methodOff, fieldN, fieldOff;
        int protoOff, protoSize;
    }

    public static class SmaliClass {
        public String path = "";
        public String text = "";
    }

    public static class DumpResult {
        public List<SmaliClass> classes = new ArrayList<>();
        public List<String> classSummaries = new ArrayList<>();
        public List<String> appPrefixes = new ArrayList<>();
        public List<String> notes = new ArrayList<>();
        public long bytes;
        public boolean truncated;
        /** Cobertura (ambos modos): clases vistas / volcadas / propias. */
        public int scanned;
        public int dumped;
        public int ownMatched;
        /** Fallos por clase "dexDir|clase|motivo" (tope MAX_FAILURES). */
        public List<String> failures = new ArrayList<>();
        /** Fallos totales (aunque failures esté recortado). */
        public int failTotal;
        /** Cobertura por dex en modo FullDump (orden de volcado). */
        public List<DexStat> dexStats = new ArrayList<>();
    }

    /** Cobertura de un dex en el volcado total. Nunca lanza. */
    public static class DexStat {
        public String dex = "?";
        public int scanned;
        public int dumped;
        public int failed;
        public long bytes;
    }

    /** Destino de clases volcadas (p. ej. escribir directo al ZIP). */
    public interface ClassSink {
        void accept(String path, String text);
    }

    /** El sink la lanza para detener el volcado (tope); FullDump la absorbe. */
    public static class Stop extends RuntimeException {
        public Stop(String m) {
            super(m);
        }
    }

    /**
     * Volcado incremental dex por dex: el llamador aporta cada dex y libera
     * sus bytes tras volcarlo, sin retenerlos todos. Misma semántica por dex
     * que dumpAll; el reintento con prefijo alternativo lo decide el llamador
     * con altPrefix(). Nunca lanza (los dex malos quedan en notas).
     */
    public static class StreamDump {
        public final DumpResult r = new DumpResult();
        private final Map<String, Integer> prefixCount = new LinkedHashMap<>();
        private final String filterSlash;

        public StreamDump(String filterSlash) {
            this.filterSlash = filterSlash == null ? "" : filterSlash;
        }

        /** Vuelca un dex (null-seguro). Nunca lanza. */
        public void addDex(byte[] dex) {
            try {
                if (dex == null) return;
                dumpOne(dex, filterSlash, r, prefixCount);
            } catch (RuntimeException e) {
                r.notes.add("dex omitido: " + e.getMessage());
            } catch (OutOfMemoryError e) {
                r.truncated = true;
                r.notes.add("dex omitido (memoria)");
            }
        }

        /**
         * Prefijo alternativo si no hubo clases bajo el filtro (o null).
         * Rellena r.appPrefixes como dumpAll. Nunca null-riesgoso ni lanza.
         */
        public String altPrefix() {
            try {
                List<String> prefs = new ArrayList<>();
                for (Map.Entry<String, Integer> e : prefixCount.entrySet()) {
                    if (prefs.size() >= 10) break;
                    if (!isFrameworkPrefix(e.getKey())) prefs.add(e.getKey());
                }
                r.appPrefixes.clear();
                r.appPrefixes.addAll(prefs);
                if (r.classes.isEmpty() && !prefs.isEmpty()
                        && !prefs.get(0).equals(filterSlash)) {
                    return prefs.get(0);
                }
            } catch (Throwable ignored) {
            }
            return null;
        }
    }

    /**
     * Volcado TOTAL dex por dex: todas las clases (propias y librerías) van
     * al sink en streaming, sin retenerlas (sin topes 1500/40MB de memoria).
     * Los resúmenes solo cubren el paquete propio. Sigue el tope por método
     * (6000 units, marcado en el smali). Nunca lanza.
     */
    public static class FullDump {
        public final DumpResult r = new DumpResult();
        private final String ownSlash;
        private final ClassSink sink;

        public FullDump(String ownSlash, ClassSink sink) {
            this.ownSlash = ownSlash == null ? "" : ownSlash;
            this.sink = sink;
        }

        /** Vuelca un dex completo al sink (null-seguro). Nunca lanza. */
        public void addDex(byte[] dex) {
            addDex(dex, "classes.dex");
        }

        /**
         * Variante con nombre de dex: las rutas salen como
         * "smali/&lt;dex&gt;/…" y la cobertura queda en dexStats.
         * Null-seguro. Nunca lanza.
         */
        public void addDex(byte[] dex, String dexName) {
            String dir = dexDir(dexName);
            int s0 = r.scanned;
            int d0 = r.dumped;
            int f0 = r.failTotal;
            long b0 = r.bytes;
            try {
                if (dex == null) return;
                dumpFull(dex, ownSlash, sink, r, dir);
            } catch (Stop s) {
                r.truncated = true;
                r.notes.add("smali: detenido (" + s.getMessage() + ")");
            } catch (RuntimeException e) {
                r.notes.add("dex omitido: " + e.getMessage());
                recordFailure(r, dir, "?", "dex omitido: " + e.getMessage());
            } catch (OutOfMemoryError e) {
                r.truncated = true;
                r.notes.add("dex omitido (memoria)");
                recordFailure(r, dir, "?", "dex omitido (memoria)");
            } finally {
                DexStat st = new DexStat();
                st.dex = dexName == null ? "?" : dexName;
                st.scanned = r.scanned - s0;
                st.dumped = r.dumped - d0;
                st.failed = r.failTotal - f0;
                st.bytes = r.bytes - b0;
                r.dexStats.add(st);
            }
        }
    }

    /**
     * "classes2.dex" → "classes2" (saneado a [A-Za-z0-9._-], tope 32).
     * Nunca lanza; nunca vacío.
     */
    public static String dexDir(String dexName) {
        try {
            String n = dexName == null ? "" : dexName;
            int slash = n.lastIndexOf('/');
            if (slash >= 0) n = n.substring(slash + 1);
            if (n.toLowerCase().endsWith(".dex")) {
                n = n.substring(0, n.length() - 4);
            }
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < n.length() && b.length() < 32; i++) {
                char c = n.charAt(i);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
                b.append(ok ? c : '_');
            }
            return b.length() == 0 ? "classes" : b.toString();
        } catch (Throwable ignored) {
            return "classes";
        }
    }

    /**
     * Registra un fallo con motivo (lista + contador total + nota
     * resumida). Nunca lanza.
     */
    private static void recordFailure(DumpResult r, String dexDir,
                                     String cls, String why) {
        try {
            if (r == null) return;
            r.failTotal++;
            String w = why == null || why.isEmpty() ? "motivo desconocido" : why;
            if (w.length() > 160) w = w.substring(0, 160);
            String c = cls == null ? "?" : cls;
            if (r.failures.size() < MAX_FAILURES) {
                r.failures.add(dexDir + "|" + c + "|" + w);
            }
            if (r.notes.size() < 200) r.notes.add(c + ": omitida (" + w + ")");
        } catch (Throwable ignored) {
        }
    }

    /** Desensambla las clases bajo pkgSlash (p.ej. "com/nexos/app/") de todos los dex. */
    public static DumpResult dumpAll(List<byte[]> dexes, String pkgSlash) {
        StreamDump sd = new StreamDump(pkgSlash);
        if (dexes != null) {
            for (byte[] dex : dexes) {
                sd.addDex(dex);
                if (sd.r.truncated) break;
            }
        }
        String alt = sd.altPrefix();
        if (alt != null) {
            sd.r.notes.add("sin clases bajo " + pkgSlash + "; reintento con " + alt);
            StreamDump sd2 = new StreamDump(alt);
            if (dexes != null) {
                for (byte[] dex : dexes) {
                    sd2.addDex(dex);
                    if (sd2.r.truncated) break;
                }
            }
            sd.r.classes = sd2.r.classes;
            sd.r.classSummaries = sd2.r.classSummaries;
            sd.r.bytes = sd2.r.bytes;
            sd.r.truncated = sd2.r.truncated;
            sd.r.notes.addAll(sd2.r.notes);
        }
        return sd.r;
    }

    /**
     * Cuenta prefijos de clases de un dex (sin desensamblar) para elegir el
     * paquete propio antes del volcado total. Nunca lanza.
     */
    public static void countPrefixes(byte[] dex, Map<String, Integer> out) {
        try {
            if (dex == null || out == null || dex.length < 0x70) return;
            if (dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') return;
            int stringN = u32(dex, 56);
            int stringOff = u32(dex, 60);
            int typeN = u32(dex, 64);
            int typeOff = u32(dex, 68);
            int classN = u32(dex, 96);
            int classOff = u32(dex, 100);
            if (stringN < 0 || stringN > 2000000 || typeN < 0 || typeN > 1000000
                    || classN < 0 || classN > 500000) return;
            DexStrings strings = DexStrings.of(dex, stringOff, stringN);
            DexTypes types = DexTypes.of(dex, typeOff, typeN, strings);
            for (int i = 0; i < classN; i++) {
                int p = classOff + i * 32;
                if (p + 32 > dex.length) break;
                String cls;
                try {
                    cls = types.get(u32(dex, p));
                } catch (Throwable ignored) {
                    continue;
                }
                countPrefix(out, cls);
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Elige el prefijo propio: pkgSlash si aparece, si no el no-framework
     * más numeroso, si no "". Nunca null ni lanza.
     */
    public static String pickOwnPrefix(Map<String, Integer> counts, String pkgSlash) {
        try {
            if (counts == null) return "";
            if (pkgSlash != null && !pkgSlash.isEmpty()) {
                for (String k : counts.keySet()) {
                    if (k != null && k.startsWith(pkgSlash)) return pkgSlash;
                }
            }
            String best = "";
            int bestN = 0;
            for (Map.Entry<String, Integer> e : counts.entrySet()) {
                if (e.getKey() == null || e.getValue() == null) continue;
                if (isFrameworkPrefix(e.getKey())) continue;
                if (e.getValue() > bestN) {
                    bestN = e.getValue();
                    best = e.getKey();
                }
            }
            return best;
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** Desensambla una sola clase (descriptor estilo "Lcom/x/A;") o null. */
    public static String dumpSingleClass(List<byte[]> dexes, String classDesc) {
        if (dexes == null || classDesc == null) return null;
        for (byte[] dex : dexes) {
            try {
                if (dex == null || dex.length < 0x70) continue;
                Tables t = buildTables(dex);
                int classN = u32(dex, 96);
                int classOff = u32(dex, 100);
                if (classN < 0 || classN > 500000) continue;
                for (int i = 0; i < classN; i++) {
                    int p = classOff + i * 32;
                    if (p + 32 > dex.length) break;
                    String cls = typeAt(t, u32(dex, p));
                    if (!classDesc.equals(cls)) continue;
                    DumpResult tmp = new DumpResult();
                    return dumpClass(dex, t, tmp, cls, u32(dex, p + 4), u32(dex, p + 8),
                            u32(dex, p + 16), u32(dex, p + 24), u32(dex, p + 12),
                            u32(dex, p + 20), u32(dex, p + 28));
                }
            } catch (RuntimeException e) {
                // prueba con el siguiente dex
            } catch (OutOfMemoryError e) {
                // igual: la clase gigante no tumba la extracción
            }
        }
        return null;
    }

    private static void dumpOne(byte[] dex, String filterSlash, DumpResult r,
                                Map<String, Integer> prefixCount) {
        if (dex == null || dex.length < 0x70 || dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') {
            throw new IllegalArgumentException("dex inválido");
        }
        Tables t = buildTables(dex);
        int classN = u32(dex, 96);
        int classOff = u32(dex, 100);
        if (classN < 0 || classN > 500000) throw new IllegalArgumentException("class_defs inválido");
        for (int i = 0; i < classN; i++) {
            if (r.classes.size() >= MAX_CLASSES || r.bytes >= MAX_TOTAL_BYTES) {
                r.truncated = true;
                return;
            }
            int p = classOff + i * 32;
            if (p + 32 > dex.length) break;
            int classIdx = u32(dex, p);
            int access = u32(dex, p + 4);
            int superIdx = u32(dex, p + 8);
            int srcIdx = u32(dex, p + 16);
            int dataOff = u32(dex, p + 24);
            String cls = typeAt(t, classIdx);
            countPrefix(prefixCount, cls);
            r.scanned++;
            if (!cls.startsWith("L" + filterSlash)) continue;
            r.ownMatched++;
            try {
                String text = dumpClass(dex, t, r, cls, access, superIdx, srcIdx, dataOff,
                        u32(dex, p + 12), u32(dex, p + 20), u32(dex, p + 28));
                if (r.bytes + text.length() > MAX_TOTAL_BYTES) {
                    r.truncated = true;
                    return;
                }
                SmaliClass sc = new SmaliClass();
                sc.path = "smali/" + cls.substring(1, cls.length() - 1) + ".smali";
                sc.text = text;
                r.classes.add(sc);
                r.bytes += text.length();
                r.dumped++;
            } catch (RuntimeException e) {
                r.notes.add(cls + ": omitida (" + e.getMessage() + ")");
            } catch (OutOfMemoryError e) {
                r.notes.add(cls + ": omitida (memoria)");
            }
        }
    }

    /**
     * Núcleo del volcado total: todas las clases al sink como
     * "smali/&lt;dexDir&gt;/…", resúmenes solo propias. Sin topes de memoria;
     * cada clase fallida queda en failures con motivo y no tumba el resto.
     */
    private static void dumpFull(byte[] dex, String ownSlash, ClassSink sink,
                                 DumpResult r, String dexDir) {
        if (dex == null || dex.length < 0x70 || dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x') {
            throw new IllegalArgumentException("dex inválido");
        }
        Tables t = buildTables(dex);
        int classN = u32(dex, 96);
        int classOff = u32(dex, 100);
        if (classN < 0 || classN > 500000) throw new IllegalArgumentException("class_defs inválido");
        for (int i = 0; i < classN; i++) {
            int p = classOff + i * 32;
            if (p + 32 > dex.length) break;
            int classIdx = u32(dex, p);
            String cls = typeAt(t, classIdx);
            if ("?".equals(cls)) {
                r.scanned++;
                recordFailure(r, dexDir, "?idx" + classIdx,
                        "descriptor ilegible (type_idx=" + classIdx + ")");
                continue;
            }
            r.scanned++;
            boolean own = !ownSlash.isEmpty() && cls.startsWith("L" + ownSlash);
            if (own) r.ownMatched++;
            try {
                int access = u32(dex, p + 4);
                int superIdx = u32(dex, p + 8);
                int srcIdx = u32(dex, p + 16);
                int dataOff = u32(dex, p + 24);
                // Resúmenes solo propias: volcado temporal y descarte si ajena.
                int sum0 = r.classSummaries.size();
                String text = dumpClass(dex, t, r, cls, access, superIdx, srcIdx, dataOff,
                        u32(dex, p + 12), u32(dex, p + 20), u32(dex, p + 28));
                if (!own && r.classSummaries.size() > sum0) {
                    r.classSummaries.remove(r.classSummaries.size() - 1);
                }
                if (sink != null) {
                    sink.accept("smali/" + dexDir + "/"
                            + cls.substring(1, cls.length() - 1) + ".smali", text);
                }
                r.bytes += text.length();
                r.dumped++;
            } catch (Stop s) {
                throw s;
            } catch (RuntimeException e) {
                recordFailure(r, dexDir, cls, e.getMessage());
            } catch (OutOfMemoryError e) {
                recordFailure(r, dexDir, cls, "memoria");
            }
        }
    }

    /** Celda method_ids/field_ids perezosa (8B: u16,u16,u32). 0 si ilegible. Nunca lanza. */
    private static int idCell(Tables t, int off, int n, int idx, int sub) {
        try {
            if (t == null || t.buf == null || idx < 0 || idx >= n || off < 0) return 0;
            long q = (long) off + (long) idx * 8 + (sub == 2 ? 4 : sub == 1 ? 2 : 0);
            int need = sub == 2 ? 4 : 2;
            if (q > (long) t.buf.length - need) return 0;
            int p = (int) q;
            return sub == 2 ? u32(t.buf, p) : u16(t.buf, p);
        } catch (Throwable ignored) {
            return 0;
        }
    }

    private static int mClassAt(Tables t, int idx) {
        return idCell(t, t.methodOff, t.methodN, idx, 0);
    }

    private static int mProtoAt(Tables t, int idx) {
        return idCell(t, t.methodOff, t.methodN, idx, 1);
    }

    private static int mNameAt(Tables t, int idx) {
        return idCell(t, t.methodOff, t.methodN, idx, 2);
    }

    private static int fClassAt(Tables t, int idx) {
        return idCell(t, t.fieldOff, t.fieldN, idx, 0);
    }

    private static int fTypeAt(Tables t, int idx) {
        return idCell(t, t.fieldOff, t.fieldN, idx, 1);
    }

    private static int fNameAt(Tables t, int idx) {
        return idCell(t, t.fieldOff, t.fieldN, idx, 2);
    }

    private static Tables buildTables(byte[] buf) {
        Tables t = new Tables();
        t.buf = buf;
        int stringN = u32(buf, 56), stringOff = u32(buf, 60);
        int typeN = u32(buf, 64), typeOff = u32(buf, 68);
        t.protoSize = u32(buf, 72);
        t.protoOff = u32(buf, 76);
        int fieldN = u32(buf, 80), fieldOff = u32(buf, 84);
        int methodN = u32(buf, 88), methodOff = u32(buf, 92);
        if (stringN < 0 || stringN > 2000000 || typeN < 0 || typeN > 1000000
                || methodN < 0 || methodN > 1000000 || fieldN < 0 || fieldN > 1000000) {
            throw new IllegalArgumentException("cabecera dex inválida");
        }
        t.strings = DexStrings.of(buf, stringOff, stringN);
        t.types = DexTypes.of(buf, typeOff, typeN, t.strings);
        if ((methodN > 0 && (methodOff < 0 || methodOff > buf.length))
                || (fieldN > 0 && (fieldOff < 0 || fieldOff > buf.length))) {
            throw new IllegalArgumentException("method/field_ids fuera del fichero");
        }
        // M-03: métodos/campos perezosos (antes 6xint[<=1M] ~24MB por DEX).
        t.methodN = methodN;
        t.methodOff = methodOff;
        t.fieldN = fieldN;
        t.fieldOff = fieldOff;
        return t;
    }

    private static String dumpClass(byte[] dex, Tables t, DumpResult r, String cls, int access,
                                    int superIdx, int srcIdx, int dataOff, int ifacesOff,
                                    int annotOff, int staticOff) {
        StringBuilder sb = new StringBuilder();
        sb.append(".class ").append(accessStr(access, 0)).append(cls).append('\n');
        String sup = (superIdx == 0xFFFFFFFF || superIdx < 0) ? "Ljava/lang/Object;" : typeAt(t, superIdx);
        sb.append(".super ").append(sup).append('\n');
        String src = (srcIdx == 0xFFFFFFFF) ? "" : t.strings.get(srcIdx);
        if (!src.isEmpty() && !src.equals("?")) sb.append(".source \"").append(escape(src)).append("\"\n");
        try {
            for (String iface : interfacesAt(dex, t, ifacesOff)) {
                sb.append(".implements ").append(iface).append('\n');
            }
        } catch (RuntimeException e) {
            sb.append("# interfaces omitidas\n");
        }
        AnnotDir annots = new AnnotDir();
        try {
            annots = parseAnnotDir(dex, annotOff);
            String clsAnn = renderAnnotSet(dex, t, annots.classSet, "");
            if (!clsAnn.isEmpty()) sb.append("\n# annotations\n").append(clsAnn);
        } catch (RuntimeException e) {
            sb.append("\n# anotaciones de clase omitidas\n");
        }
        List<String> staticVals = new ArrayList<>();
        try {
            staticVals = staticValuesAt(dex, t, staticOff);
        } catch (RuntimeException e) {
            sb.append("# valores estáticos omitidos\n");
        }
        sb.append('\n');
        int methods = 0;
        int insns = 0;
        if (dataOff != 0) {
            int p = dataOff;
            int[] a = AxmlDecoder.readUleb128(dex, p);
            int staticN = a[0];
            p = a[1];
            a = AxmlDecoder.readUleb128(dex, p);
            int instanceN = a[0];
            p = a[1];
            a = AxmlDecoder.readUleb128(dex, p);
            int directN = a[0];
            p = a[1];
            a = AxmlDecoder.readUleb128(dex, p);
            int virtualN = a[0];
            p = a[1];
            if (staticN < 0 || staticN > 100000 || instanceN < 0 || instanceN > 100000
                    || directN < 0 || directN > 100000 || virtualN < 0 || virtualN > 100000) {
                throw new IllegalArgumentException("class_data inválido");
            }
            if (staticN > 0) sb.append("# static fields\n");
            int fIdx = 0;
            for (int i = 0; i < staticN; i++) {
                a = AxmlDecoder.readUleb128(dex, p);
                fIdx += a[0];
                p = a[1];
                a = AxmlDecoder.readUleb128(dex, p);
                int fAcc = a[0];
                p = a[1];
                sb.append(".field ").append(accessStr(fAcc, 2)).append(fieldName(t, fIdx));
                if (i < staticVals.size() && staticVals.get(i) != null) {
                    sb.append(" = ").append(staticVals.get(i));
                }
                sb.append('\n');
                appendFieldAnnot(dex, t, sb, annots, fIdx);
            }
            if (instanceN > 0) sb.append("# instance fields\n");
            fIdx = 0;
            for (int i = 0; i < instanceN; i++) {
                a = AxmlDecoder.readUleb128(dex, p);
                fIdx += a[0];
                p = a[1];
                a = AxmlDecoder.readUleb128(dex, p);
                int fAcc = a[0];
                p = a[1];
                sb.append(".field ").append(accessStr(fAcc, 2)).append(fieldName(t, fIdx)).append('\n');
                appendFieldAnnot(dex, t, sb, annots, fIdx);
            }
            if (directN > 0) sb.append("\n# direct methods\n");
            int mIdx = 0;
            int[] counts = new int[1];
            boolean cut = false;
            for (int i = 0; i < directN && methods < 2000 && !cut; i++) {
                if (sb.length() > MAX_CHARS_PER_CLASS) {
                    cut = true;
                    break;
                }
                int[] rr = readMethod(dex, p);
                mIdx += rr[0];
                p = rr[3];
                methods += renderMethodCapped(dex, t, sb, mIdx, rr[1], rr[2], counts, annots);
            }
            if (virtualN > 0) sb.append("\n# virtual methods\n");
            mIdx = 0;
            for (int i = 0; i < virtualN && methods < 2000 && !cut; i++) {
                if (sb.length() > MAX_CHARS_PER_CLASS) {
                    cut = true;
                    break;
                }
                int[] rr = readMethod(dex, p);
                mIdx += rr[0];
                p = rr[3];
                methods += renderMethodCapped(dex, t, sb, mIdx, rr[1], rr[2], counts, annots);
            }
            if (cut) {
                sb.append("# clase recortada (tope 2M caracteres)\n");
                if (r.notes.size() < 200) r.notes.add(cls + ": recortada (tope 2M)");
            } else if (directN + virtualN > methods) {
                sb.append("# métodos recortados (tope 2000)\n");
            }
            insns = counts[0];
        }
        r.classSummaries.add(cls + " | super=" + sup + " | metodos=" + methods + " | insns~" + insns);
        return sb.toString();
    }

    /** Añade las anotaciones de un campo tras su .field. Nunca lanza. */
    private static void appendFieldAnnot(byte[] dex, Tables t, StringBuilder sb,
                                         AnnotDir annots, int fIdx) {
        try {
            if (annots == null || !annots.fields.containsKey(fIdx)) return;
            String block = renderAnnotSet(dex, t, annots.fields.get(fIdx), "");
            if (!block.isEmpty()) sb.append("# annotations\n").append(block);
        } catch (RuntimeException e) {
            sb.append("# anotaciones de campo omitidas\n");
        }
    }

    /** Lee sleb128. Devuelve {valor, nextPos}. Nunca null. */
    private static int[] readSleb128(byte[] b, int p) {
        int result = 0;
        int shift = 0;
        for (int i = 0; i < 5; i++) {
            check(b, p, 1);
            int cur = b[p++] & 0xFF;
            result |= (cur & 0x7F) << shift;
            shift += 7;
            if ((cur & 0x80) == 0) {
                if (shift < 32 && (cur & 0x40) != 0) result |= -(1 << shift);
                return new int[]{result, p};
            }
        }
        throw new IllegalArgumentException("sleb128 largo");
    }

    /** Lee n bytes LE (con o sin signo). */
    private static long readLe(byte[] dex, int p, int n) {
        check(dex, p, n);
        long v = 0;
        for (int i = 0; i < n; i++) v |= ((long) (dex[p + i] & 0xFF)) << (8 * i);
        return v;
    }

    private static long signExtend(long v, int n) {
        if (n < 8 && (v & (1L << (8 * n - 1))) != 0) v |= -(1L << (8 * n));
        return v;
    }

    /** Valor codificado leído: texto smali + siguiente posición. */
    private static class EncVal {
        String text = "?";
        int next;
    }

    /**
     * Parsea un encoded_value DEX a literal smali. Profundidad acotada.
     * Lanza RuntimeException si está corrupto (el llamador lo marca).
     */
    private static EncVal readEncVal(byte[] dex, Tables t, int p, int depth, String pad) {
        EncVal r = new EncVal();
        if (depth > 8) throw new IllegalArgumentException("valor profundo");
        check(dex, p, 1);
        int b0 = dex[p++] & 0xFF;
        int arg = (b0 >> 5) & 0x7;
        int type = b0 & 0x1F;
        int n = arg + 1;
        switch (type) {
            case 0x00: { // byte
                long v = readLe(dex, p, 1);
                r.text = "0x" + hex(v & 0xFF, 2) + "t";
                r.next = p + 1;
                return r;
            }
            case 0x02: { // short
                if (n > 2) throw new IllegalArgumentException("short largo");
                long v = signExtend(readLe(dex, p, n), n);
                r.text = "0x" + hex(v & 0xFFFF, 4) + "s";
                r.next = p + n;
                return r;
            }
            case 0x03: { // char
                if (n > 2) throw new IllegalArgumentException("char largo");
                long v = readLe(dex, p, n);
                r.text = "0x" + hex(v & 0xFFFF, 4) + "c";
                r.next = p + n;
                return r;
            }
            case 0x04: { // int
                if (n > 4) throw new IllegalArgumentException("int largo");
                long v = signExtend(readLe(dex, p, n), n);
                r.text = "0x" + hex(v & 0xFFFFFFFFL, 8);
                r.next = p + n;
                return r;
            }
            case 0x06: { // long
                if (n > 8) throw new IllegalArgumentException("long largo");
                long v = signExtend(readLe(dex, p, n), n);
                r.text = "0x" + Long.toHexString(v) + "L";
                r.next = p + n;
                return r;
            }
            case 0x10: { // float (extensión con ceros a la derecha)
                if (n > 4) throw new IllegalArgumentException("float largo");
                int bits = (int) readLe(dex, p, n);
                r.text = Float.toString(Float.intBitsToFloat(bits)) + "f";
                r.next = p + n;
                return r;
            }
            case 0x11: { // double
                if (n > 8) throw new IllegalArgumentException("double largo");
                long bits = readLe(dex, p, n);
                r.text = Double.toString(Double.longBitsToDouble(bits));
                r.next = p + n;
                return r;
            }
            case 0x17: { // string
                int idx = (int) readLe(dex, p, n);
                String s;
                try {
                    s = t.strings.get(idx);
                } catch (Throwable ignored) {
                    s = "?";
                }
                r.text = "\"" + escape(s == null ? "?" : s) + "\"";
                r.next = p + n;
                return r;
            }
            case 0x18: { // type
                int idx = (int) readLe(dex, p, n);
                r.text = typeAt(t, idx);
                r.next = p + n;
                return r;
            }
            case 0x19: // field
            case 0x1b: { // enum
                int idx = (int) readLe(dex, p, n);
                r.text = fieldRef(t, idx);
                r.next = p + n;
                return r;
            }
            case 0x1a: { // method
                int idx = (int) readLe(dex, p, n);
                r.text = methodRef(t, idx);
                r.next = p + n;
                return r;
            }
            case 0x1c: { // array
                int[] a = AxmlDecoder.readUleb128(dex, p);
                int size = a[0];
                p = a[1];
                if (size < 0 || size > 10000) throw new IllegalArgumentException("array largo");
                StringBuilder sb = new StringBuilder("{ ");
                for (int i = 0; i < size; i++) {
                    if (i > 0) sb.append(", ");
                    EncVal e = readEncVal(dex, t, p, depth + 1, pad);
                    sb.append(e.text);
                    p = e.next;
                }
                sb.append(size == 0 ? "}" : " }");
                r.text = sb.toString();
                r.next = p;
                return r;
            }
            case 0x1d: { // annotation anidada
                r.text = readSubAnnotation(dex, t, p, depth, pad);
                r.next = subNext;
                return r;
            }
            case 0x1e: // null
                r.text = "null";
                r.next = p;
                return r;
            case 0x1f: // boolean
                r.text = arg == 0 ? "false" : "true";
                r.next = p;
                return r;
            default:
                throw new IllegalArgumentException("valor tipo 0x" + Integer.toHexString(type));
        }
    }

    /** Siguiente posición tras readSubAnnotation (hilo único, best-effort). */
    private static int subNext;

    /** Parsea una encoded_annotation anidada a bloque .subannotation. */
    private static String readSubAnnotation(byte[] dex, Tables t, int p, int depth, String pad) {
        int[] a = AxmlDecoder.readUleb128(dex, p);
        String type = typeAt(t, a[0]);
        p = a[1];
        int[] b = AxmlDecoder.readUleb128(dex, p);
        int size = b[0];
        p = b[1];
        if (size < 0 || size > 1000) throw new IllegalArgumentException("anotación larga");
        StringBuilder sb = new StringBuilder(".subannotation ").append(type).append(";\n");
        for (int i = 0; i < size; i++) {
            int[] c = AxmlDecoder.readUleb128(dex, p);
            String name;
            try {
                name = t.strings.get(c[0]);
            } catch (Throwable ignored) {
                name = "?";
            }
            p = c[1];
            EncVal e = readEncVal(dex, t, p, depth + 1, pad + "    ");
            p = e.next;
            sb.append(pad).append("    ").append(name).append(" = ").append(e.text).append('\n');
        }
        sb.append(pad).append(".end subannotation");
        subNext = p;
        return sb.toString();
    }

    /** Referencia completa de campo "Lclase;->nombre:Tipo". Nunca lanza. */
    private static String fieldRef(Tables t, int idx) {
        try {
            if (idx < 0 || idx >= t.fieldN) return "campo#0x" + Integer.toHexString(idx);
            return typeAt(t, fClassAt(t, idx)) + "->" + fieldName(t, idx);
        } catch (Throwable ignored) {
            return "campo#0x" + Integer.toHexString(idx);
        }
    }

    /** Referencia completa de método. Nunca lanza. */
    private static String methodRef(Tables t, int idx) {
        try {
            if (idx < 0 || idx >= t.methodN) return "metodo#0x" + Integer.toHexString(idx);
            String name;
            try {
                name = t.strings.get(mNameAt(t, idx));
            } catch (Throwable ignored) {
                name = "?";
            }
            return typeAt(t, mClassAt(t, idx)) + "->" + name + protoString(t, mProtoAt(t, idx));
        } catch (Throwable ignored) {
            return "metodo#0x" + Integer.toHexString(idx);
        }
    }

    /** Lista de interfaces (type_list). Vacía si off==0. Puede lanzar. */
    private static List<String> interfacesAt(byte[] dex, Tables t, int off) {
        List<String> out = new ArrayList<>();
        if (off == 0) return out;
        check(dex, off, 4);
        int size = u32(dex, off);
        if (size < 0 || size > 10000) throw new IllegalArgumentException("type_list inválido");
        check(dex, off + 4, size * 2);
        for (int i = 0; i < size; i++) out.add(typeAt(t, u16(dex, off + 4 + i * 2)));
        return out;
    }

    /** Valores estáticos (encoded_array). Vacía si off==0. Puede lanzar. */
    private static List<String> staticValuesAt(byte[] dex, Tables t, int off) {
        List<String> out = new ArrayList<>();
        if (off == 0) return out;
        int[] a = AxmlDecoder.readUleb128(dex, off);
        int size = a[0];
        int p = a[1];
        if (size < 0 || size > 100000) throw new IllegalArgumentException("static_values largo");
        for (int i = 0; i < size; i++) {
            EncVal e = readEncVal(dex, t, p, 0, "");
            out.add(e.text);
            p = e.next;
        }
        return out;
    }

    /** Directorio de anotaciones de una clase. */
    private static class AnnotDir {
        int classSet;
        Map<Integer, Integer> fields = new LinkedHashMap<>();
        Map<Integer, Integer> methods = new LinkedHashMap<>();
        Map<Integer, Integer> params = new LinkedHashMap<>();
    }

    /** Parsea annotation_directory_item. Vacío si off==0. Puede lanzar. */
    private static AnnotDir parseAnnotDir(byte[] dex, int off) {
        AnnotDir d = new AnnotDir();
        if (off == 0) return d;
        check(dex, off, 16);
        d.classSet = u32(dex, off);
        int fn = u32(dex, off + 4);
        int mn = u32(dex, off + 8);
        int pn = u32(dex, off + 12);
        if (fn < 0 || fn > 100000 || mn < 0 || mn > 100000 || pn < 0 || pn > 10000) {
            throw new IllegalArgumentException("annot_dir inválido");
        }
        int p = off + 16;
        check(dex, p, (fn + mn + pn) * 8);
        for (int i = 0; i < fn; i++) {
            d.fields.put(u32(dex, p), u32(dex, p + 4));
            p += 8;
        }
        for (int i = 0; i < mn; i++) {
            d.methods.put(u32(dex, p), u32(dex, p + 4));
            p += 8;
        }
        for (int i = 0; i < pn; i++) {
            d.params.put(u32(dex, p), u32(dex, p + 4));
            p += 8;
        }
        return d;
    }

    private static String visibilityName(int v) {
        if (v == 0) return "build";
        if (v == 2) return "system";
        return "runtime";
    }

    /**
     * Renderiza un annotation_set_item a bloques smali con indentación pad.
     * "" si off==0 o vacío. Puede lanzar si está corrupto.
     */
    private static String renderAnnotSet(byte[] dex, Tables t, int off, String pad) {
        if (off == 0) return "";
        check(dex, off, 4);
        int size = u32(dex, off);
        if (size < 0 || size > 1000) throw new IllegalArgumentException("annot_set largo");
        check(dex, off + 4, size * 4);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < size; i++) {
            int item = u32(dex, off + 4 + i * 4);
            check(dex, item, 2);
            int vis = dex[item] & 0xFF;
            int p = item + 1;
            int[] a = AxmlDecoder.readUleb128(dex, p);
            String type = typeAt(t, a[0]);
            p = a[1];
            int[] b = AxmlDecoder.readUleb128(dex, p);
            int n = b[0];
            p = b[1];
            if (n < 0 || n > 1000) throw new IllegalArgumentException("anotación larga");
            sb.append(pad).append(".annotation ").append(visibilityName(vis)).append(' ')
                    .append(type).append(";\n");
            for (int k = 0; k < n; k++) {
                int[] c = AxmlDecoder.readUleb128(dex, p);
                String name;
                try {
                    name = t.strings.get(c[0]);
                } catch (Throwable ignored) {
                    name = "?";
                }
                p = c[1];
                EncVal e = readEncVal(dex, t, p, 0, pad + "    ");
                p = e.next;
                sb.append(pad).append("    ").append(name).append(" = ").append(e.text)
                        .append('\n');
            }
            sb.append(pad).append(".end annotation\n");
        }
        return sb.toString();
    }

    /**
     * Renderiza annotation_set_ref_list (anotaciones de parámetros).
     * Devuelve por índice de parámetro su bloque (indent pad). Puede lanzar.
     */
    private static List<String> renderParamAnnots(byte[] dex, Tables t, int off, String pad) {
        List<String> out = new ArrayList<>();
        if (off == 0) return out;
        check(dex, off, 4);
        int size = u32(dex, off);
        if (size < 0 || size > 1000) throw new IllegalArgumentException("param_list largo");
        check(dex, off + 4, size * 4);
        for (int i = 0; i < size; i++) {
            int set = u32(dex, off + 4 + i * 4);
            if (set == 0 || set == 0xFFFFFFFF) out.add("");
            else out.add(renderAnnotSet(dex, t, set, pad));
        }
        return out;
    }

    /** Un try: {inicio, fin, offset de handler relativo a la lista}. */
    private static class TryItem {
        int start;
        int end;
        int handlerOff;
    }

    /**
     * Parsea tries + base de handlers de un code_item. Nunca lanza:
     * corrupto → lista vacía.
     */
    private static List<TryItem> parseTries(byte[] dex, int codeOff, int insnsSize,
                                            int[] handlersBase) {
        List<TryItem> out = new ArrayList<>();
        try {
            check(dex, codeOff, 16);
            int triesSize = u16(dex, codeOff + 6);
            if (triesSize <= 0 || triesSize > 10000) return out;
            long to = (long) codeOff + 16 + (long) insnsSize * 2;
            to = (to + 3) & ~3L;
            if (to > Integer.MAX_VALUE - 8) return out;
            int triesOff = (int) to;
            check(dex, triesOff, triesSize * 8);
            for (int i = 0; i < triesSize; i++) {
                TryItem ti = new TryItem();
                ti.start = u32(dex, triesOff + i * 8);
                int count = u16(dex, triesOff + i * 8 + 4);
                ti.end = ti.start + count;
                ti.handlerOff = u16(dex, triesOff + i * 8 + 6);
                out.add(ti);
            }
            handlersBase[0] = triesOff + triesSize * 8;
        } catch (RuntimeException ignored) {
            out.clear();
        }
        return out;
    }

    /** Un handler: pares (type_idx, addr) + catch-all (-1 si no hay). */
    private static class Handler {
        List<int[]> pairs = new ArrayList<>();
        int catchAll = -1;
    }

    /** Parsea un encoded_catch_handler. Puede lanzar si está corrupto. */
    private static Handler parseHandler(byte[] dex, int p) {
        Handler h = new Handler();
        int[] s = readSleb128(dex, p);
        int size = s[0];
        p = s[1];
        int count = size < 0 ? -size : size;
        if (count < 0 || count > 10000) throw new IllegalArgumentException("handlers inválido");
        for (int i = 0; i < count; i++) {
            int[] a = AxmlDecoder.readUleb128(dex, p);
            int type = a[0];
            p = a[1];
            int[] b = AxmlDecoder.readUleb128(dex, p);
            int addr = b[0];
            p = b[1];
            h.pairs.add(new int[]{type, addr});
        }
        if (size <= 0) {
            int[] c = AxmlDecoder.readUleb128(dex, p);
            h.catchAll = c[0];
        }
        return h;
    }

    /** Lee un encoded_method. Devuelve {idxDiff, access, codeOff, nextPos}. */
    private static int[] readMethod(byte[] dex, int p) {
        int[] a = AxmlDecoder.readUleb128(dex, p);
        int diff = a[0];
        p = a[1];
        a = AxmlDecoder.readUleb128(dex, p);
        int acc = a[0];
        p = a[1];
        a = AxmlDecoder.readUleb128(dex, p);
        return new int[]{diff, acc, a[0], a[1]};
    }

    /** Emite un método. Devuelve 1 y acumula instrucciones en counts[0]. */
    /** renderMethod con tope por método (T2): recorta y re-cierra el bloque. Nunca lanza. */
    private static int renderMethodCapped(byte[] dex, Tables t, StringBuilder sb, int mIdx, int acc,
                                          int codeOff, int[] counts, AnnotDir annots) {
        int start = sb.length();
        int m = renderMethod(dex, t, sb, mIdx, acc, codeOff, counts, annots);
        if (sb.length() - start > MAX_CHARS_PER_METHOD) {
            sb.setLength(start + MAX_CHARS_PER_METHOD);
            sb.append("\n    # [...método recortado: tope 256K caracteres...]\n.end method\n\n");
        }
        return m;
    }

    private static int renderMethod(byte[] dex, Tables t, StringBuilder sb, int mIdx, int acc, int codeOff,
                                    int[] counts, AnnotDir annots) {
        String cls = "?";
        String name = "?";
        String proto = "()?";
        if (mIdx >= 0 && mIdx < t.methodN) {
            cls = typeAt(t, mClassAt(t, mIdx));
            name = t.strings.get(mNameAt(t, mIdx));
            proto = protoString(t, mProtoAt(t, mIdx));
        }
        sb.append(".method ").append(accessStr(acc, 1)).append(name).append(proto).append('\n');
        String methodAnn = "";
        List<String> paramAnns = new ArrayList<>();
        try {
            if (annots != null && annots.methods.containsKey(mIdx)) {
                methodAnn = renderAnnotSet(dex, t, annots.methods.get(mIdx), "    ");
            }
            if (annots != null && annots.params.containsKey(mIdx)) {
                paramAnns = renderParamAnnots(dex, t, annots.params.get(mIdx), "        ");
            }
        } catch (RuntimeException e) {
            sb.append("    # anotaciones de método omitidas\n");
        }
        if (codeOff != 0) {
            try {
                counts[0] += renderCode(dex, t, sb, codeOff, methodAnn, paramAnns);
            } catch (RuntimeException e) {
                sb.append("    # código omitido\n");
            }
        } else if (!methodAnn.isEmpty()) {
            sb.append(methodAnn);
        }
        sb.append(".end method\n\n");
        return 1;
    }

    private static int renderCode(byte[] dex, Tables t, StringBuilder sb, int codeOff,
                                  String methodAnn, List<String> paramAnns) {
        check(dex, codeOff, 16);
        int regs = u16(dex, codeOff);
        int ins = u16(dex, codeOff + 2);
        int firstParam = regs - ins;
        int insnsSize = u32(dex, codeOff + 12);
        if (insnsSize < 0 || insnsSize > 1000000) throw new IllegalArgumentException("code_item inválido");
        int n = Math.min(insnsSize, MAX_UNITS_PER_METHOD);
        check(dex, codeOff + 16, n * 2);
        int[] units = new int[n];
        for (int i = 0; i < n; i++) units[i] = u16(dex, codeOff + 16 + i * 2);
        sb.append("    .registers ").append(regs).append('\n');
        if (methodAnn != null && !methodAnn.isEmpty()) sb.append(methodAnn);
        if (paramAnns != null) {
            for (int i = 0; i < paramAnns.size(); i++) {
                String block = paramAnns.get(i);
                if (block == null || block.isEmpty()) continue;
                sb.append("    .param p").append(i).append('\n');
                sb.append(block);
                sb.append("    .end param\n");
            }
        }
        // Tries: rangos y handlers; las direcciones se vuelven etiquetas.
        int[] hb = new int[1];
        List<TryItem> tries = parseTries(dex, codeOff, insnsSize, hb);
        List<Handler> tryHandlers = new ArrayList<>();
        List<String> catchLines = new ArrayList<>();
        for (TryItem ti : tries) {
            Handler h = null;
            if (ti == null || ti.start < 0 || ti.end <= ti.start || ti.end > insnsSize) {
                catchLines.add("    # try inválido omitido");
            } else if (ti.end > n) {
                catchLines.add("    # try@0x" + Integer.toHexString(ti.start)
                        + " recortado (tope)");
            } else {
                try {
                    h = parseHandler(dex, hb[0] + ti.handlerOff);
                } catch (RuntimeException e) {
                    catchLines.add("    # try@0x" + Integer.toHexString(ti.start)
                            + ": handlers omitidos");
                    h = null;
                }
                if (h != null) {
                    boolean ok = h.catchAll >= -1 && h.catchAll < n;
                    for (int[] pr : h.pairs) {
                        if (pr[1] < 0 || pr[1] >= n) {
                            ok = false;
                            break;
                        }
                    }
                    if (!ok) {
                        catchLines.add("    # try@0x" + Integer.toHexString(ti.start)
                                + ": handler fuera de rango");
                        h = null;
                    }
                }
                if (h != null) {
                    for (int[] pr : h.pairs) {
                        catchLines.add("    .catch " + typeAt(t, pr[0]) + " { "
                                + lbl(ti.start) + " .. " + lbl(ti.end) + " } " + lbl(pr[1]));
                    }
                    if (h.catchAll >= 0) {
                        catchLines.add("    .catchall { " + lbl(ti.start) + " .. " + lbl(ti.end)
                                + " } " + lbl(h.catchAll));
                    }
                }
            }
            tryHandlers.add(h);
        }
        // Pasada 1: tamaños y destinos de salto.
        List<Integer> addrs = new ArrayList<>();
        List<Integer> sizes = new ArrayList<>();
        Map<Integer, Boolean> targets = new LinkedHashMap<>();
        for (int i = 0; i < tries.size(); i++) {
            TryItem ti = tries.get(i);
            Handler h = tryHandlers.get(i);
            if (ti == null || h == null) continue;
            if (ti.start >= 0 && ti.start < n) targets.put(ti.start, Boolean.TRUE);
            if (ti.end >= 0 && ti.end < n) targets.put(ti.end, Boolean.TRUE);
            for (int[] pr : h.pairs) targets.put(pr[1], Boolean.TRUE);
            if (h.catchAll >= 0) targets.put(h.catchAll, Boolean.TRUE);
        }
        int p = 0;
        while (p < n) {
            int op = units[p] & 0xFF;
            int fmt = FORMATS[op];
            int size = insnSize(fmt, units, p, n);
            if (size <= 0 || p + size > n) break;
            addrs.add(p);
            sizes.add(size);
            int tgt = branchTarget(fmt, units, p, op);
            if (tgt >= 0 && tgt < n) targets.put(tgt, Boolean.TRUE);
            p += size;
        }
        // Pasada 2: emisión con etiquetas.
        int count = 0;
        for (int i = 0; i < addrs.size(); i++) {
            int addr = addrs.get(i);
            if (targets.containsKey(addr)) sb.append(lbl(addr)).append('\n');
            int op = units[addr] & 0xFF;
            int fmt = FORMATS[op];
            if (fmt == F00) {
                renderPayload(sb, units, addr, sizes.get(i));
            } else {
                sb.append("    ").append(NAMES[op]);
                String args = renderArgs(fmt, op, units, addr, t, targets, firstParam);
                if (!args.isEmpty()) sb.append(' ').append(args);
                sb.append('\n');
            }
            count++;
        }
        // Etiquetas al final del código (fin de try == n).
        for (TryItem ti : tries) {
            if (ti != null && ti.end == n && ti.end > 0) sb.append(lbl(ti.end)).append('\n');
        }
        for (String cl : catchLines) sb.append(cl).append('\n');
        if (insnsSize > n) sb.append("    # ...recortado (tope)\n");
        return count;
    }

    static int insnSize(int fmt, int[] units, int p, int n) {
        switch (fmt) {
            case F10x:
            case F12x:
            case F11n:
            case F11x:
            case F10t:
                return 1;
            case F20t:
            case F22x:
            case F21t:
            case F22t:
            case F21s:
            case F21h:
            case F21lh:
            case F21c:
            case F22s:
            case F22b:
            case F23x:
            case F22c:
                return 2;
            case F32x:
            case F31i:
            case F31t:
            case F31c:
            case F35c:
            case F3rc:
            case F30t:
                return 3;
            case F45cc:
            case F4rcc:
                return 4;
            case F51l:
                return 5;
            default:
                return payloadSize(units, p, n);
        }
    }

    /**
     * Tamaño de payload switch/array o 1 si es nop.
     * Layout verificado contra baksmali: el ident va PRIMERO
     * (0x0100 packed, 0x0200 sparse, 0x0300 array). Un switch de tamaño 0
     * no existe en dex real: se trata como nop para evitar falsos positivos.
     */
    static int payloadSize(int[] units, int p, int n) {
        if (p >= n) return 1;
        int u0 = units[p];
        try {
            if (u0 == 0x0100) { // packed-switch
                if (p + 4 > n) return 1;
                int size = units[p + 1];
                if (size <= 0 || size > 100000) return 1;
                int total = 4 + size * 2;
                return (p + total <= n) ? total : 1;
            } else if (u0 == 0x0200) { // sparse-switch
                if (p + 2 > n) return 1;
                int size = units[p + 1];
                if (size <= 0 || size > 100000) return 1;
                int total = 2 + size * 4;
                return (p + total <= n) ? total : 1;
            } else if (u0 == 0x0300) { // fill-array-data
                if (p + 4 > n) return 1;
                int width = units[p + 1];
                long size = ((long) units[p + 2]) | ((long) units[p + 3] << 16);
                if (width <= 0 || width > 8 || size < 0 || size > 1000000) return 1;
                int total = 4 + (int) ((size * width + 1) / 2);
                return (p + total <= n) ? total : 1;
            }
        } catch (RuntimeException e) {
            return 1;
        }
        return 1;
    }

    static int branchTarget(int fmt, int[] units, int p, int op) {
        try {
            switch (fmt) {
                case F10t:
                    return p + (byte) (units[p] >> 8);
                case F20t:
                case F21t:
                case F22t:
                    return p + (short) units[p + 1];
                case F30t:
                case F31t:
                    return p + (units[p + 1] | (units[p + 2] << 16));
                default:
                    return -1;
            }
        } catch (RuntimeException e) {
            return -1;
        }
    }

    private static String renderArgs(int fmt, int op, int[] units, int p, Tables t,
                                     Map<Integer, Boolean> targets, int firstParam) {
        int u0 = units[p];
        int refKind = REFS[op];
        switch (fmt) {
            case F10x:
                return "";
            case F12x:
                return v((u0 >> 8) & 15, firstParam) + ", " + v((u0 >> 12) & 15, firstParam);
            case F11n:
                return v((u0 >> 8) & 15, firstParam) + ", 0x" + Integer.toHexString((u0 >> 12) & 15);
            case F11x:
                return v((u0 >> 8) & 15, firstParam);
            case F10t:
                return labelOrRaw(targets, p + (byte) (u0 >> 8), 1);
            case F20t:
                return labelOrRaw(targets, p + (short) units[p + 1], 2);
            case F30t:
                return labelOrRaw(targets, p + (units[p + 1] | (units[p + 2] << 16)), 3);
            case F22x:
                return v((u0 >> 8) & 255, firstParam) + ", " + v(units[p + 1], firstParam);
            case F21t:
                return v((u0 >> 8) & 255, firstParam) + ", " + labelOrRaw(targets, p + (short) units[p + 1], 2);
            case F22t:
                return v((u0 >> 8) & 15, firstParam) + ", " + v((u0 >> 12) & 15, firstParam) + ", "
                        + labelOrRaw(targets, p + (short) units[p + 1], 2);
            case F21s:
                return v((u0 >> 8) & 255, firstParam) + ", 0x" + hex(units[p + 1] & 0xFFFF, 4);
            case F21h:
                return v((u0 >> 8) & 255, firstParam) + ", 0x" + hex((long) units[p + 1] << 16, 8);
            case F21lh:
                return v((u0 >> 8) & 255, firstParam) + ", 0x" + hex((long) units[p + 1] << 48, 16);
            case F21c:
                return v((u0 >> 8) & 255, firstParam) + ", " + ref(t, refKind, units[p + 1]);
            case F22s:
                return v((u0 >> 8) & 15, firstParam) + ", " + v((u0 >> 12) & 15, firstParam) + ", 0x" + hex(units[p + 1] & 0xFFFF, 4);
            case F22b:
                return v((u0 >> 8) & 15, firstParam) + ", " + v((u0 >> 12) & 15, firstParam) + ", 0x" + hex(units[p + 1] & 0xFF, 2);
            case F23x: {
                int u1 = units[p + 1];
                return v((u0 >> 8) & 255, firstParam) + ", " + v(u1 & 255, firstParam) + ", " + v((u1 >> 8) & 255, firstParam);
            }
            case F22c:
                return v((u0 >> 8) & 15, firstParam) + ", " + v((u0 >> 12) & 15, firstParam) + ", " + ref(t, refKind, units[p + 1]);
            case F32x:
                return v(units[p + 1], firstParam) + ", " + v(units[p + 2], firstParam);
            case F31i:
                return v((u0 >> 8) & 255, firstParam) + ", 0x" + hex(((long) units[p + 1]) | ((long) units[p + 2] << 16), 8);
            case F31t:
                return v((u0 >> 8) & 255, firstParam) + ", "
                        + labelOrRaw(targets, p + (units[p + 1] | (units[p + 2] << 16)), 3);
            case F31c:
                return v((u0 >> 8) & 255, firstParam) + ", "
                        + ref(t, refKind, units[p + 1] | (units[p + 2] << 16));
            case F35c:
                return regs35c(u0, units[p + 2], firstParam) + ", " + ref(t, refKind, units[p + 1]);
            case F3rc:
                return regs3rc((u0 >> 8) & 255, units[p + 2], firstParam) + ", " + ref(t, refKind, units[p + 1]);
            case F45cc:
                return regs35c(u0, units[p + 2], firstParam) + ", " + ref(t, refKind, units[p + 1])
                        + ", proto#0x" + hex(units[p + 3], 4);
            case F4rcc:
                return regs3rc((u0 >> 8) & 255, units[p + 2], firstParam) + ", " + ref(t, refKind, units[p + 1])
                        + ", proto#0x" + hex(units[p + 3], 4);
            case F51l: {
                long lit = ((long) units[p + 1]) | ((long) units[p + 2] << 16)
                        | ((long) units[p + 3] << 32) | ((long) units[p + 4] << 48);
                return v((u0 >> 8) & 255, firstParam) + ", 0x" + hex(lit, 16);
            }
            default:
                return "";
        }
    }

    private static String labelOrRaw(Map<Integer, Boolean> targets, int target, int size) {
        if (targets.containsKey(target)) return lbl(target);
        return "+0x" + Integer.toHexString(size);
    }

    private static String regs35c(int u0, int u2, int firstParam) {
        // 35c es A|G|op: A (conteo) en bits 12-15, G (5º registro) en bits 8-11.
        int a = (u0 >> 12) & 15;
        int[] regs = {u2 & 15, (u2 >> 4) & 15, (u2 >> 8) & 15, (u2 >> 12) & 15, (u0 >> 8) & 15};
        if (a <= 0) return "{}";
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < a && i < 5; i++) {
            if (i > 0) sb.append(", ");
            sb.append(v(regs[i], firstParam));
        }
        return sb.append('}').toString();
    }

    private static String regs3rc(int a, int first, int firstParam) {
        if (a <= 0) return "{}";
        if (a == 1) return "{" + v(first, firstParam) + "}";
        int n = Math.min(a, 256);
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(", ");
            sb.append(v(first + i, firstParam));
        }
        if (a > n) sb.append(", ...");
        return sb.append('}').toString();
    }

    private static void renderPayload(StringBuilder sb, int[] units, int p, int size) {
        if (size <= 1 || p >= units.length) {
            sb.append("    nop\n");
            return;
        }
        int u0 = units[p];
        if (u0 == 0x0100 && size >= 4) {
            int n = units[p + 1];
            int firstKey = units[p + 2] | (units[p + 3] << 16);
            sb.append("    # packed-switch: size=").append(n).append(" first_key=0x")
                    .append(Integer.toHexString(firstKey)).append('\n');
            for (int i = 0; i < n && 4 + i * 2 + 1 < size; i++) {
                int tgt = units[p + 4 + i * 2] | (units[p + 5 + i * 2] << 16);
                sb.append("    #   0x").append(Integer.toHexString(firstKey + i)).append(" -> +0x")
                        .append(Integer.toHexString(tgt)).append(" (raw)\n");
            }
        } else if (u0 == 0x0200 && size >= 2) {
            int n = units[p + 1];
            sb.append("    # sparse-switch: size=").append(n).append('\n');
            for (int i = 0; i < n && 2 + i * 2 + 1 < size; i++) {
                int key = units[p + 2 + i * 2] | (units[p + 3 + i * 2] << 16);
                int tp = p + 2 + n * 2 + i * 2;
                int tgt = (tp + 1 < p + size) ? (units[tp] | (units[tp + 1] << 16)) : 0;
                sb.append("    #   0x").append(Integer.toHexString(key)).append(" -> +0x")
                        .append(Integer.toHexString(tgt)).append(" (raw)\n");
            }
        } else if (u0 == 0x0300 && size >= 4) {
            int width = units[p + 1];
            long n = ((long) units[p + 2]) | ((long) units[p + 3] << 16);
            sb.append("    # fill-array-data: width=").append(width).append(" size=").append(n).append('\n');
            int dataUnits = size - 4;
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < dataUnits && i < 64; i++) {
                hex.append(hex(units[p + 4 + i], 4));
            }
            if (dataUnits > 64) hex.append("...");
            sb.append("    #   datos=").append(hex).append('\n');
        } else {
            sb.append("    nop\n");
        }
    }

    private static String ref(Tables t, int kind, int idx) {
        switch (kind) {
            case R_STR: {
                String s = t.strings.get(idx);
                return s.equals("?") ? "#str@0x" + Integer.toHexString(idx) : "\"" + escape(s) + "\"";
            }
            case R_TYPE: {
                String s = typeAt(t, idx);
                return s.equals("?") ? "#tipo@0x" + Integer.toHexString(idx) : s;
            }
            case R_FIELD:
                return methodFieldRef(t, idx, true);
            case R_METHOD:
                return methodFieldRef(t, idx, false);
            default:
                return "#0x" + Integer.toHexString(idx);
        }
    }

    private static String methodFieldRef(Tables t, int idx, boolean field) {
        try {
            if (field) {
                if (idx < 0 || idx >= t.fieldN) return "#campo@0x" + Integer.toHexString(idx);
                return typeAt(t, fClassAt(t, idx)) + "->" + t.strings.get(fNameAt(t, idx))
                        + ":" + typeAt(t, fTypeAt(t, idx));
            }
            if (idx < 0 || idx >= t.methodN) return "#metodo@0x" + Integer.toHexString(idx);
            return typeAt(t, mClassAt(t, idx)) + "->" + t.strings.get(mNameAt(t, idx))
                    + protoString(t, mProtoAt(t, idx));
        } catch (RuntimeException e) {
            return "#ref@0x" + Integer.toHexString(idx);
        }
    }

    private static String fieldName(Tables t, int idx) {
        try {
            if (idx < 0 || idx >= t.fieldN) return "campo#0x" + Integer.toHexString(idx);
            return t.strings.get(fNameAt(t, idx)) + ":" + typeAt(t, fTypeAt(t, idx));
        } catch (RuntimeException e) {
            return "campo#0x" + Integer.toHexString(idx);
        }
    }

    private static String protoString(Tables t, int idx) {
        try {
            if (idx < 0 || idx >= t.protoSize) return "(?)";
            int p = t.protoOff + idx * 12;
            if (p + 12 > t.buf.length) return "(?)";
            int ret = u32(t.buf, p + 4);
            int paramsOff = u32(t.buf, p + 8);
            StringBuilder sb = new StringBuilder("(");
            if (paramsOff != 0) {
                if (paramsOff + 4 > t.buf.length) return "(?)";
                int n = u32(t.buf, paramsOff);
                if (n < 0 || n > 500) return "(?)";
                for (int i = 0; i < n; i++) {
                    int tp = paramsOff + 4 + i * 2;
                    if (tp + 2 > t.buf.length) break;
                    sb.append(typeAt(t, u16(t.buf, tp)));
                }
            }
            return sb.append(')').append(typeAt(t, ret)).toString();
        } catch (RuntimeException e) {
            return "(?)";
        }
    }

    private static String accessStr(int flags, int kind) {
        StringBuilder sb = new StringBuilder();
        if ((flags & 0x1) != 0) sb.append("public ");
        if ((flags & 0x2) != 0) sb.append("private ");
        if ((flags & 0x4) != 0) sb.append("protected ");
        if ((flags & 0x8) != 0) sb.append("static ");
        if ((flags & 0x10) != 0) sb.append("final ");
        if (kind != 2 && (flags & 0x400) != 0) sb.append("abstract ");
        if ((flags & 0x1000) != 0) sb.append("synthetic ");
        if (kind == 0) {
            if ((flags & 0x200) != 0) sb.append("interface ");
            if ((flags & 0x2000) != 0) sb.append("annotation ");
            if ((flags & 0x4000) != 0) sb.append("enum ");
        } else if (kind == 1) {
            if ((flags & 0x20) != 0) sb.append("synchronized ");
            if ((flags & 0x40) != 0) sb.append("bridge ");
            if ((flags & 0x80) != 0) sb.append("varargs ");
            if ((flags & 0x100) != 0) sb.append("native ");
            if ((flags & 0x800) != 0) sb.append("strictfp ");
            if ((flags & 0x10000) != 0) sb.append("constructor ");
            if ((flags & 0x20000) != 0) sb.append("declared-synchronized ");
        } else {
            if ((flags & 0x40) != 0) sb.append("volatile ");
            if ((flags & 0x80) != 0) sb.append("transient ");
            if ((flags & 0x4000) != 0) sb.append("enum ");
        }
        return sb.toString();
    }

    private static void countPrefix(Map<String, Integer> m, String cls) {
        if (cls == null || !cls.startsWith("L")) return;
        String body = cls.substring(1);
        int segs = 0;
        int end = body.length();
        for (int i = 0; i < body.length(); i++) {
            if (body.charAt(i) == '/') {
                segs++;
                if (segs == 3) {
                    end = i + 1;
                    break;
                }
            }
        }
        String prefix = body.substring(0, end);
        m.put(prefix, m.containsKey(prefix) ? m.get(prefix) + 1 : 1);
    }

    private static boolean isFrameworkPrefix(String p) {
        String[] fw = {"android/", "java/", "javax/", "kotlin/", "kotlinx/", "dalvik/", "androidx/",
                "com/google/", "com/android/", "org/apache/", "org/json/", "org/w3c/", "org/xml/",
                "junit/", "org/junit/", "org/hamcrest/", "okhttp3/", "okio/", "retrofit2/",
                "com/squareup/", "io/reactivex/", "com/fasterxml/", "org/greenrobot/"};
        for (String f : fw) if (p.startsWith(f)) return true;
        return false;
    }

    private static String v(int n, int firstParam) {
        if (firstParam >= 0 && n >= firstParam) return "p" + (n - firstParam);
        return "v" + n;
    }

    private static String lbl(int addr) {
        return ":L" + hex(addr, 4);
    }

    private static String hex(long v, int width) {
        String s = Long.toHexString(v);
        while (s.length() < width) s = "0" + s;
        if (s.length() > width) s = s.substring(s.length() - width);
        return s;
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String typeAt(Tables t, int idx) {
        try {
            if (t == null || t.types == null) return "?";
            return t.types.get(idx);
        } catch (Throwable ignored) {
            return "?";
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
