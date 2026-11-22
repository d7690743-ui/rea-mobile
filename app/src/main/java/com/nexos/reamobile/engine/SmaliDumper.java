package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Desensamblador Dalvik a smali (best-effort) para las clases del paquete propio.
 * Java puro. Omite debug_info y try/catch; los payloads de switch/array se emiten
 * como comentarios con datos crudos (no reensamblables). Pensado para análisis.
 */
public final class SmaliDumper {
    private SmaliDumper() {
    }

    public static final int MAX_CLASSES = 1500;
    public static final int MAX_UNITS_PER_METHOD = 6000;
    public static final long MAX_TOTAL_BYTES = 40L * 1024 * 1024;

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
        String[] strings;
        String[] types;
        int[] mClass, mProto, mName;
        int[] fClass, fType, fName;
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
    }

    /** Desensambla las clases bajo pkgSlash (p.ej. "com/nexos/app/") de todos los dex. */
    public static DumpResult dumpAll(List<byte[]> dexes, String pkgSlash) {
        DumpResult r = new DumpResult();
        Map<String, Integer> prefixCount = new LinkedHashMap<>();
        for (byte[] dex : dexes) {
            try {
                dumpOne(dex, pkgSlash, r, prefixCount);
            } catch (RuntimeException e) {
                r.notes.add("dex omitido: " + e.getMessage());
            }
            if (r.truncated) break;
        }
        for (Map.Entry<String, Integer> e : prefixCount.entrySet()) {
            if (r.appPrefixes.size() >= 10) break;
            if (!isFrameworkPrefix(e.getKey())) r.appPrefixes.add(e.getKey());
        }
        if (r.classes.isEmpty() && !r.appPrefixes.isEmpty() && !r.appPrefixes.get(0).equals(pkgSlash)) {
            String alt = r.appPrefixes.get(0);
            r.notes.add("sin clases bajo " + pkgSlash + "; reintento con " + alt);
            DumpResult r2 = new DumpResult();
            for (byte[] dex : dexes) {
                try {
                    dumpOne(dex, alt, r2, new LinkedHashMap<String, Integer>());
                } catch (RuntimeException e) {
                    r2.notes.add("dex omitido: " + e.getMessage());
                }
                if (r2.truncated) break;
            }
            r.classes = r2.classes;
            r.classSummaries = r2.classSummaries;
            r.bytes = r2.bytes;
            r.truncated = r2.truncated;
            r.notes.addAll(r2.notes);
        }
        return r;
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
                            u32(dex, p + 16), u32(dex, p + 24));
                }
            } catch (RuntimeException e) {
                // prueba con el siguiente dex
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
            if (!cls.startsWith("L" + filterSlash)) continue;
            try {
                String text = dumpClass(dex, t, r, cls, access, superIdx, srcIdx, dataOff);
                if (r.bytes + text.length() > MAX_TOTAL_BYTES) {
                    r.truncated = true;
                    return;
                }
                SmaliClass sc = new SmaliClass();
                sc.path = "smali/" + cls.substring(1, cls.length() - 1) + ".smali";
                sc.text = text;
                r.classes.add(sc);
                r.bytes += text.length();
            } catch (RuntimeException e) {
                r.notes.add(cls + ": omitida (" + e.getMessage() + ")");
            }
        }
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
        t.strings = new String[stringN];
        for (int i = 0; i < stringN; i++) {
            int idPos = stringOff + i * 4;
            if (idPos + 4 > buf.length) break;
            try {
                int[] rr = AxmlDecoder.readUleb128(buf, u32(buf, idPos));
                t.strings[i] = DexParser.decodeMutf8(buf, rr[1]);
            } catch (RuntimeException e) {
                t.strings[i] = "";
            }
        }
        t.types = new String[typeN];
        for (int i = 0; i < typeN; i++) {
            int idPos = typeOff + i * 4;
            if (idPos + 4 > buf.length) break;
            t.types[i] = get(t.strings, u32(buf, idPos));
        }
        t.mClass = new int[methodN];
        t.mProto = new int[methodN];
        t.mName = new int[methodN];
        for (int i = 0; i < methodN; i++) {
            int q = methodOff + i * 8;
            if (q + 8 > buf.length) break;
            t.mClass[i] = u16(buf, q);
            t.mProto[i] = u16(buf, q + 2);
            t.mName[i] = u32(buf, q + 4);
        }
        t.fClass = new int[fieldN];
        t.fType = new int[fieldN];
        t.fName = new int[fieldN];
        for (int i = 0; i < fieldN; i++) {
            int q = fieldOff + i * 8;
            if (q + 8 > buf.length) break;
            t.fClass[i] = u16(buf, q);
            t.fType[i] = u16(buf, q + 2);
            t.fName[i] = u32(buf, q + 4);
        }
        return t;
    }

    private static String dumpClass(byte[] dex, Tables t, DumpResult r, String cls, int access,
                                    int superIdx, int srcIdx, int dataOff) {
        StringBuilder sb = new StringBuilder();
        sb.append(".class ").append(accessStr(access, 0)).append(cls).append('\n');
        String sup = (superIdx == 0xFFFFFFFF || superIdx < 0) ? "Ljava/lang/Object;" : typeAt(t, superIdx);
        sb.append(".super ").append(sup).append('\n');
        String src = (srcIdx == 0xFFFFFFFF) ? "" : get(t.strings, srcIdx);
        if (!src.isEmpty() && !src.equals("?")) sb.append(".source \"").append(escape(src)).append("\"\n");
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
                sb.append(".field ").append(accessStr(fAcc, 2)).append(fieldName(t, fIdx)).append('\n');
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
            }
            if (directN > 0) sb.append("\n# direct methods\n");
            int mIdx = 0;
            int[] counts = new int[1];
            for (int i = 0; i < directN && methods < 2000; i++) {
                int[] rr = readMethod(dex, p);
                mIdx += rr[0];
                p = rr[3];
                methods += renderMethod(dex, t, sb, mIdx, rr[1], rr[2], counts);
            }
            if (virtualN > 0) sb.append("\n# virtual methods\n");
            mIdx = 0;
            for (int i = 0; i < virtualN && methods < 2000; i++) {
                int[] rr = readMethod(dex, p);
                mIdx += rr[0];
                p = rr[3];
                methods += renderMethod(dex, t, sb, mIdx, rr[1], rr[2], counts);
            }
            insns = counts[0];
        }
        r.classSummaries.add(cls + " | super=" + sup + " | metodos=" + methods + " | insns~" + insns);
        return sb.toString();
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
    private static int renderMethod(byte[] dex, Tables t, StringBuilder sb, int mIdx, int acc, int codeOff,
                                    int[] counts) {
        String cls = "?";
        String name = "?";
        String proto = "()?";
        if (mIdx >= 0 && mIdx < t.mClass.length) {
            cls = typeAt(t, t.mClass[mIdx]);
            name = get(t.strings, t.mName[mIdx]);
            proto = protoString(t, t.mProto[mIdx]);
        }
        sb.append(".method ").append(accessStr(acc, 1)).append(name).append(proto).append('\n');
        if (codeOff != 0) {
            try {
                counts[0] += renderCode(dex, t, sb, codeOff);
            } catch (RuntimeException e) {
                sb.append("    # código omitido\n");
            }
        }
        sb.append(".end method\n\n");
        return 1;
    }

    private static int renderCode(byte[] dex, Tables t, StringBuilder sb, int codeOff) {
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
        // Pasada 1: tamaños y destinos de salto.
        List<Integer> addrs = new ArrayList<>();
        List<Integer> sizes = new ArrayList<>();
        Map<Integer, Boolean> targets = new LinkedHashMap<>();
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
                String s = get(t.strings, idx);
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
                if (idx < 0 || idx >= t.fClass.length) return "#campo@0x" + Integer.toHexString(idx);
                return typeAt(t, t.fClass[idx]) + "->" + get(t.strings, t.fName[idx])
                        + ":" + typeAt(t, t.fType[idx]);
            }
            if (idx < 0 || idx >= t.mClass.length) return "#metodo@0x" + Integer.toHexString(idx);
            return typeAt(t, t.mClass[idx]) + "->" + get(t.strings, t.mName[idx])
                    + protoString(t, t.mProto[idx]);
        } catch (RuntimeException e) {
            return "#ref@0x" + Integer.toHexString(idx);
        }
    }

    private static String fieldName(Tables t, int idx) {
        try {
            if (idx < 0 || idx >= t.fClass.length) return "campo#0x" + Integer.toHexString(idx);
            return get(t.strings, t.fName[idx]) + ":" + typeAt(t, t.fType[idx]);
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

    private static String get(String[] arr, int idx) {
        if (idx < 0 || idx >= arr.length || arr[idx] == null) return "?";
        return arr[idx];
    }

    private static String typeAt(Tables t, int idx) {
        if (idx < 0 || idx >= t.types.length || t.types[idx] == null) return "?";
        return t.types[idx];
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
