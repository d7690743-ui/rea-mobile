package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser mínimo de DEX: cabecera, strings (MUTF-8), tipos, clases y métodos.
 * Java puro, sin dependencias. No desensambla bytecode.
 */
public final class DexParser {
    private DexParser() {
    }

    public static final int MAX_STRINGS = 20000;
    public static final int MAX_CLASSES = 10000;
    public static final int MAX_METHODS_SAMPLE = 2000;
    public static final int MAX_SUSPICIOUS = 200;

    public static class ClassInfo {
        public String name = "?";
        public String superName = "?";
        public String sourceFile = "?";
    }

    public static class DexInfo {
        public String fileName = "?";
        public String version = "?";
        public int fileSize;
        public int stringCount;
        public List<String> strings = new ArrayList<>();
        public boolean stringsTruncated;
        public int typeCount;
        public int methodCount;
        public int classCount;
        public List<String> methodSample = new ArrayList<>();
        public List<ClassInfo> classes = new ArrayList<>();
        public boolean classesTruncated;
        public Map<String, Integer> apiStats = new LinkedHashMap<>();
        public List<String> suspicious = new ArrayList<>();
        public boolean hasKotlin;
        public boolean hasAndroidx;
        public boolean hasGms;
        public boolean hasUnity;
        public double obfuscatedRatio;
        public String error;
    }

    /** Patrones de API sensible: {prefijoDeClase, contieneEnFirma}. */
    private static final String[][] SUSPICIOUS_PATTERNS = {
            {"Ldalvik/system/DexClassLoader;", null},
            {"Ldalvik/system/PathClassLoader;", null},
            {"Ldalvik/system/InMemoryDexClassLoader;", null},
            {"Ljava/lang/Runtime;", "exec"},
            {"Ljava/lang/ProcessBuilder;", null},
            {"Ljava/lang/reflect/", null},
            {"Ljavax/crypto/", null},
            {"Ljava/security/", null},
            {"Landroid/telephony/", null},
            {"Landroid/location/", null},
            {"Ljava/net/URL;", null},
            {"Ljava/net/HttpURLConnection;", null},
            {"Lokhttp3/", null},
            {"Lorg/apache/http/", null},
            {"Landroid/webkit/WebView;", "addJavascriptInterface"},
            {"Ljava/lang/System;", "loadLibrary"},
            {"Ljava/lang/System;", "load("},
            {"Landroid/app/admin/DevicePolicyManager;", null},
            {"Landroid/accessibilityservice/", null},
            {"Landroid/provider/ContactsContract;", null},
            {"Landroid/hardware/fingerprint/", null},
            {"Landroid/hardware/biometrics/", null},
    };

    public static DexInfo parse(byte[] buf, String fileName) {
        DexInfo info = new DexInfo();
        info.fileName = fileName;
        try {
            if (buf == null || buf.length < 0x70) {
                info.error = "dex demasiado corto";
                return info;
            }
            if (buf[0] != 'd' || buf[1] != 'e' || buf[2] != 'x' || buf[3] != '\n') {
                info.error = "sin magia dex";
                return info;
            }
            info.version = new String(new byte[]{buf[4], buf[5], buf[6]});
            info.fileSize = buf.length;
            if (u32(buf, 40) != 0x12345678) {
                info.error = "endian no soportado";
                return info;
            }
            int stringIdsSize = u32(buf, 56);
            int stringIdsOff = u32(buf, 60);
            int typeIdsSize = u32(buf, 64);
            int typeIdsOff = u32(buf, 68);
            int protoIdsSize = u32(buf, 72);
            int protoIdsOff = u32(buf, 76);
            int methodIdsSize = u32(buf, 88);
            int methodIdsOff = u32(buf, 92);
            int classDefsSize = u32(buf, 96);
            int classDefsOff = u32(buf, 100);
            if (stringIdsSize < 0 || stringIdsSize > 2000000
                    || typeIdsSize < 0 || typeIdsSize > 1000000
                    || methodIdsSize < 0 || methodIdsSize > 1000000
                    || classDefsSize < 0 || classDefsSize > 500000) {
                info.error = "cabecera dex inválida";
                return info;
            }
            info.stringCount = stringIdsSize;
            info.typeCount = typeIdsSize;
            info.methodCount = methodIdsSize;
            info.classCount = classDefsSize;

            // 1) Strings.
            String[] strings = new String[stringIdsSize];
            int keepStrings = Math.min(stringIdsSize, MAX_STRINGS);
            for (int i = 0; i < stringIdsSize; i++) {
                int idPos = stringIdsOff + i * 4;
                if (idPos + 4 > buf.length) break;
                int dataOff = u32(buf, idPos);
                String s = "";
                try {
                    s = readDexString(buf, dataOff);
                } catch (RuntimeException e) {
                    s = "";
                }
                strings[i] = s;
                if (i < keepStrings) info.strings.add(s);
            }
            info.stringsTruncated = stringIdsSize > MAX_STRINGS;

            // 2) Tipos.
            String[] types = new String[typeIdsSize];
            for (int i = 0; i < typeIdsSize; i++) {
                int idPos = typeIdsOff + i * 4;
                if (idPos + 4 > buf.length) break;
                int descIdx = u32(buf, idPos);
                types[i] = get(strings, descIdx);
            }

            // 3) Métodos: firmas, stats y sospechosos.
            initStats(info.apiStats);
            int keepMethods = Math.min(methodIdsSize, MAX_METHODS_SAMPLE);
            for (int i = 0; i < methodIdsSize; i++) {
                int p = methodIdsOff + i * 8;
                if (p + 8 > buf.length) break;
                int classIdx = u16(buf, p);
                int protoIdx = u16(buf, p + 2);
                int nameIdx = u32(buf, p + 4);
                String cls = classIdx < types.length ? types[classIdx] : "?";
                String name = get(strings, nameIdx);
                String proto = readProto(buf, protoIdsOff, protoIdsSize, types, strings, protoIdx);
                if (i < keepMethods) info.methodSample.add(cls + "->" + name + proto);
                bucketize(info, cls);
                matchSuspicious(info, cls, name);
            }

            // 4) Clases definidas.
            int shortNames = 0;
            int keepClasses = Math.min(classDefsSize, MAX_CLASSES);
            for (int i = 0; i < classDefsSize; i++) {
                int p = classDefsOff + i * 32;
                if (p + 32 > buf.length) break;
                int classIdx = u32(buf, p);
                int superIdx = u32(buf, p + 8);
                int srcIdx = u32(buf, p + 16);
                String cls = (classIdx >= 0 && classIdx < types.length) ? types[classIdx] : "?";
                if (isShortName(cls)) shortNames++;
                if (i < keepClasses) {
                    ClassInfo ci = new ClassInfo();
                    ci.name = cls;
                    ci.superName = (superIdx == 0xFFFFFFFF || superIdx < 0 || superIdx >= types.length)
                            ? "-" : types[superIdx];
                    ci.sourceFile = (srcIdx == 0xFFFFFFFF) ? "-" : get(strings, srcIdx);
                    info.classes.add(ci);
                }
            }
            info.classesTruncated = classDefsSize > MAX_CLASSES;
            if (classDefsSize > 0) info.obfuscatedRatio = (double) shortNames / classDefsSize;
        } catch (RuntimeException e) {
            info.error = "error decodificando dex: " + e.getMessage();
        }
        return info;
    }

    private static String readProto(byte[] buf, int protoOff, int protoSize, String[] types,
                                    String[] strings, int protoIdx) {
        try {
            if (protoIdx < 0 || protoIdx >= protoSize) return "(?)";
            int p = protoOff + protoIdx * 12;
            if (p + 12 > buf.length) return "(?)";
            int retIdx = u32(buf, p + 4);
            int paramsOff = u32(buf, p + 8);
            StringBuilder sb = new StringBuilder("(");
            if (paramsOff != 0) {
                if (paramsOff + 4 > buf.length) return "(?)";
                int n = u32(buf, paramsOff);
                if (n < 0 || n > 500) return "(?)";
                for (int i = 0; i < n; i++) {
                    int tp = paramsOff + 4 + i * 2;
                    if (tp + 2 > buf.length) break;
                    int tIdx = u16(buf, tp);
                    sb.append(tIdx >= 0 && tIdx < types.length ? types[tIdx] : "?");
                }
            }
            sb.append(')');
            sb.append(retIdx >= 0 && retIdx < types.length ? types[retIdx] : "?");
            return sb.toString();
        } catch (RuntimeException e) {
            return "(?)";
        }
    }

    private static String readDexString(byte[] buf, int off) {
        int[] r = AxmlDecoder.readUleb128(buf, off);
        return decodeMutf8(buf, r[1]);
    }

    /** Decodifica MUTF-8 (incluye pares subrogados CESU-8) hasta 0x00. */
    static String decodeMutf8(byte[] buf, int start) {
        StringBuilder sb = new StringBuilder();
        int p = start;
        int guard = 0;
        while (p < buf.length && guard < 100000) {
            guard++;
            int a = buf[p++] & 0xFF;
            if (a == 0) break;
            if (a < 0x80) {
                sb.append((char) a);
            } else if ((a & 0xE0) == 0xC0) {
                if (p >= buf.length) break;
                int b = buf[p++] & 0xFF;
                sb.append((char) (((a & 0x1F) << 6) | (b & 0x3F)));
            } else if ((a & 0xF0) == 0xE0) {
                if (p + 1 >= buf.length) break;
                int b = buf[p++] & 0xFF;
                int c = buf[p++] & 0xFF;
                sb.append((char) (((a & 0x0F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F)));
            } else {
                sb.append('?');
            }
        }
        return sb.toString();
    }

    private static void initStats(Map<String, Integer> m) {
        m.put("Android framework", 0);
        m.put("Java/Javax", 0);
        m.put("Kotlin", 0);
        m.put("AndroidX/Jetpack", 0);
        m.put("Google/GMS", 0);
        m.put("Dalvik", 0);
        m.put("Red HTTP", 0);
        m.put("App/Otros", 0);
    }

    private static void bump(Map<String, Integer> m, String k) {
        m.put(k, m.get(k) + 1);
    }

    private static void bucketize(DexInfo info, String cls) {
        if (cls.startsWith("Landroid/")) bump(info.apiStats, "Android framework");
        else if (cls.startsWith("Ljava/") || cls.startsWith("Ljavax/")) bump(info.apiStats, "Java/Javax");
        else if (cls.startsWith("Lkotlin/") || cls.startsWith("Lkotlinx/")) {
            bump(info.apiStats, "Kotlin");
            info.hasKotlin = true;
        } else if (cls.startsWith("Landroidx/")) {
            bump(info.apiStats, "AndroidX/Jetpack");
            info.hasAndroidx = true;
        } else if (cls.startsWith("Lcom/google/android/gms/")
                || cls.startsWith("Lcom/google/firebase/")
                || cls.startsWith("Lcom/android/vending/")) {
            bump(info.apiStats, "Google/GMS");
            info.hasGms = true;
        } else if (cls.startsWith("Ldalvik/")) bump(info.apiStats, "Dalvik");
        else if (cls.startsWith("Lokhttp3/") || cls.startsWith("Lorg/apache/http/")
                || cls.startsWith("Lretrofit2/")) bump(info.apiStats, "Red HTTP");
        else {
            bump(info.apiStats, "App/Otros");
            if (cls.startsWith("Lcom/unity3d/")) info.hasUnity = true;
        }
    }

    private static void matchSuspicious(DexInfo info, String cls, String name) {
        if (info.suspicious.size() >= MAX_SUSPICIOUS) return;
        for (String[] pat : SUSPICIOUS_PATTERNS) {
            if (cls.startsWith(pat[0]) && (pat[1] == null || name.contains(pat[1]))) {
                info.suspicious.add(cls + "->" + name);
                return;
            }
        }
    }

    private static boolean isShortName(String cls) {
        if (cls == null || cls.length() < 3) return false;
        if (cls.startsWith("Landroid/") || cls.startsWith("Ljava/")
                || cls.startsWith("Ljavax/") || cls.startsWith("Lkotlin/")
                || cls.startsWith("Ldalvik/")) return false;
        int slash = cls.lastIndexOf('/');
        String simple = slash >= 0 ? cls.substring(slash + 1) : cls;
        if (simple.endsWith(";")) simple = simple.substring(0, simple.length() - 1);
        int dollar = simple.indexOf('$');
        if (dollar > 0) simple = simple.substring(0, dollar);
        return simple.length() <= 2;
    }

    private static String get(String[] arr, int idx) {
        if (idx < 0 || idx >= arr.length || arr[idx] == null) return "?";
        return arr[idx];
    }

    private static int u16(byte[] b, int p) {
        AxmlDecoder.check(b, p, 2);
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8);
    }

    private static int u32(byte[] b, int p) {
        AxmlDecoder.check(b, p, 4);
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8) | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }
}
