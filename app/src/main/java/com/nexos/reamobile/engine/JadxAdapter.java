package com.nexos.reamobile.engine;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.plugins.input.dex.DexInputPlugin;

/**
 * Adaptador fino sobre jadx-core (Apache 2.0): DEX/APK a Java por clase.
 * Un APK/ZIP se procesa dex por dex (secuencial, liberando entre dexes)
 * para no OOMear el heap móvil; un .dex suelto va directo. Extrae por
 * lotes con filtro de paquete, topes y cancelación cooperativa.
 * Llamar fuera del hilo principal. Nunca lanza.
 */
public final class JadxAdapter {
    private JadxAdapter() {
    }

    /** Se llama por cada clase extraída; devolver false detiene (trunca). */
    public interface Progress {
        boolean onClass(int done, int matched);

        /** Fase actual ("dex 2/6", "extrayendo"…). Opcional. */
        default void onPhase(String name) {
        }
    }

    /** Política de memoria: true = poca memoria, abortar con parcial. Inyectable en tests. */
    public interface MemoryPolicy {
        boolean lowMemory();
    }

    /** Tope de texto Java acumulado (~30 MB como UTF-16) para no OOMear la caché. */
    public static final long MAX_SOURCE_CHARS = 15_000_000L;
    /** Reserva mínima de heap antes/durante JADX (48 MB). */
    public static final long MIN_HEADROOM = 48L * 1024 * 1024;
    /** Tope por dex extraído del APK (100 MB); lo mayor se omite. */
    public static final long MAX_DEX_PART = 100L * 1024 * 1024;

    /** Política real: mide holgura del heap contra la reserva. */
    public static MemoryPolicy defaultPolicy() {
        return new MemoryPolicy() {
            @Override
            public boolean lowMemory() {
                Runtime rt = Runtime.getRuntime();
                long headroom = rt.maxMemory() - rt.totalMemory() + rt.freeMemory();
                return headroom < MIN_HEADROOM;
            }
        };
    }

    public static class Result {
        public Map<String, String> sources = new LinkedHashMap<>();
        public int errors;
        public int classes;
        public boolean truncated;
        public boolean memoryAbort;
        public String error;
        public List<String> log = new ArrayList<>();
    }

    /** Coincidencias de un dex (escaneo previo sin JADX). */
    public static class DexHit {
        public String name = "?";
        public long size = -1;
        public int totalClasses;
        public boolean truncated;
        public int matched;
        public String error;
    }

    /** Tope de líneas de log por resultado. */
    public static final int MAX_LOG_LINES = 120;
    /** APK multidex bajo este total: carga completa directa, sin escaneo. */
    public static final long SMALL_APK_BYTES = 8_000_000L;
    /** Presupuesto de heap por clase para intentar la carga completa. */
    public static final long BYTES_PER_CLASS = 32768L;

    /** Plan de carga elegido por tamaño del APK y heap. */
    public static class DexPlan {
        public boolean preferPerDex;
        public int dexCount;
        public long totalBytes;
        public int totalClasses;
        public String reason = "";
        public List<DexHit> hits;
    }

    /** Hilos JADX recomendados según heap máximo. Nunca lanza. */
    public static int recommendedThreads(long maxMem) {
        try {
            return maxMem < 256L * 1024 * 1024 ? 1 : 2;
        } catch (Throwable t) {
            return 1;
        }
    }

    /** Tope de clases recomendado según heap máximo. Nunca lanza. */
    public static int recommendedCap(long maxMem) {
        try {
            if (maxMem < 256L * 1024 * 1024) return 150;
            if (maxMem < 512L * 1024 * 1024) return 300;
            return 600;
        } catch (Throwable t) {
            return 150;
        }
    }

    /** Elige carga completa o directa por dex. Nunca lanza. */
    public static DexPlan planDexLoad(File apk, long maxMem, List<String> pkgSlashes) {
        return planDexLoadFor(apk, maxMem, SMALL_APK_BYTES, BYTES_PER_CLASS, pkgSlashes);
    }

    /** Variante con umbrales inyectables (tests). Nunca lanza. */
    static DexPlan planDexLoadFor(File apk, long maxMem, long smallBytes, long bytesPerClass,
                                  List<String> pkgSlashes) {
        DexPlan p = new DexPlan();
        try {
            if (apk == null || !apk.isFile()) {
                p.reason = "sin apk";
                return p;
            }
            ZipFile zip = new ZipFile(apk);
            try {
                Enumeration<? extends ZipEntry> en = zip.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (!e.isDirectory() && e.getName().matches("classes\\d*\\.dex")) {
                        p.dexCount++;
                        long s = e.getSize();
                        if (s > 0) p.totalBytes += s;
                    }
                }
            } finally {
                try {
                    zip.close();
                } catch (Throwable ignored) {
                }
            }
            if (p.dexCount <= 1) {
                p.reason = "dex único";
                return p;
            }
            if (p.totalBytes <= smallBytes) {
                p.reason = "apk pequeño";
                return p;
            }
            long budget = bytesPerClass <= 0 ? Long.MAX_VALUE : maxMem / bytesPerClass;
            p.hits = scanDexes(apk, pkgSlashes);
            for (DexHit h : p.hits) p.totalClasses += h.totalClasses;
            if (p.totalClasses > budget) {
                p.preferPerDex = true;
                p.reason = "APK grande";
            } else {
                p.reason = "cabe en heap";
            }
        } catch (Throwable ignored) {
            p.preferPerDex = false;
            p.reason = "repliegue";
        }
        return p;
    }

    /** Descompila todo el dex/apk sin filtro. Nunca lanza. */
    public static Result decompile(File input, File workDir, int threads) {
        return decompileFiltered(input, workDir, threads, new ArrayList<String>(), 0, null);
    }

    /**
     * Claves candidatas en Result.sources para un descriptor smali.
     * Las claves son el nombre raw del dex (a.b.C$D): la exacta suele
     * acertar; las variantes con puntos cubren el repliegue a getFullName
     * si el raw no está disponible. Nunca lanza.
     */
    public static List<String> candidateKeys(String smaliDesc) {
        List<String> out = new ArrayList<>();
        try {
            if (smaliDesc == null) return out;
            String base = smaliDesc;
            if (base.startsWith("L") && base.endsWith(";") && base.length() > 2) {
                base = base.substring(1, base.length() - 1).replace('/', '.');
            }
            out.add(base);
            int last = base.lastIndexOf('$');
            if (last >= 0) {
                String one = base.substring(0, last) + '.' + base.substring(last + 1);
                if (!out.contains(one)) out.add(one);
                String all = base.replace('$', '.');
                if (!out.contains(all)) out.add(all);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Claves externas candidatas ("a.B$C$1" a ["a.B$C", "a.B"]).
     * Las inners suelen venir vacías (van incluidas en la externa).
     * Nunca lanza.
     */
    public static List<String> outerKeys(String dottedKey) {
        List<String> out = new ArrayList<>();
        try {
            if (dottedKey == null) return out;
            String k = dottedKey;
            while (true) {
                int d = k.lastIndexOf('$');
                if (d <= 0) break;
                k = k.substring(0, d);
                out.add(k);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * true si el descriptor smali muestra Java en sources: directa o
     * replegando a externas, ignorando valores nulos o vacíos.
     * Misma búsqueda del visor. Nunca lanza.
     */
    public static boolean hasJava(String smaliDesc, Map<String, String> sources) {
        if (smaliDesc == null || sources == null) return false;
        try {
            for (String c : candidateKeys(smaliDesc)) {
                if (!isBlank(sources.get(c))) return true;
                for (String o : outerKeys(c)) {
                    if (!isBlank(sources.get(o))) return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    /** Primer descriptor con Java o null. Nunca lanza. */
    public static String firstWithJava(List<String> descs, Map<String, String> sources) {
        try {
            if (descs == null) return null;
            for (String d : descs) {
                if (hasJava(d, sources)) return d;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /**
     * Descompila con filtro de paquetes (prefijos estilo "com/x/"), tope de
     * clases (0 = sin tope) y progreso cancelable. Nunca lanza, ni siquiera
     * ante OutOfMemoryError: devuelve parcial con error legible.
     */
    public static Result decompileFiltered(File input, File workDir, int threads,
                                           List<String> pkgSlashes, int maxClasses, Progress progress) {
        return decompileFiltered(input, workDir, threads, pkgSlashes, maxClasses,
                progress, defaultPolicy());
    }

    /** Variante con política de memoria inyectable (tests). Nunca lanza. */
    public static Result decompileFiltered(File input, File workDir, int threads,
                                           List<String> pkgSlashes, int maxClasses, Progress progress,
                                           MemoryPolicy mem) {
        Result r = new Result();
        if (input == null || !input.isFile()) {
            r.error = "entrada no válida";
            return r;
        }
        if (workDir == null) {
            r.error = "sin directorio de trabajo";
            return r;
        }
        try {
            if (isZip(input)) {
                return decompileZip(input, workDir, threads, pkgSlashes,
                        maxClasses, progress, mem);
            }
            return decompileSingle(input, workDir, threads, pkgSlashes,
                    maxClasses, progress, mem, input.getName());
        } catch (Throwable t) {
            r.error = "jadx: " + fullMsg(t);
            return r;
        }
    }

    /** Un .dex suelto: carga directa. Nunca lanza. */
    private static Result decompileSingle(File input, File workDir, int threads,
                                          List<String> pkgSlashes, int maxClasses, Progress progress,
                                          MemoryPolicy mem, String tag) {
        Result r = new Result();
        JadxDecompiler jadx = null;
        try {
            if (lowMem(mem)) {
                r.memoryAbort = true;
                r.error = "memoria baja: no se pudo cargar JADX";
                log(r, "[" + tag + "] MEMORIA: sin cargar");
                return r;
            }
            int cap = maxClasses <= 0 ? Integer.MAX_VALUE : maxClasses;
            File outDir = new File(workDir, "jadx-out");
            File srcDir = new File(outDir, "src");
            File resDir = new File(outDir, "res");
            srcDir.mkdirs();
            resDir.mkdirs();
            JadxArgs args = new JadxArgs();
            args.setInputFile(input);
            args.setOutDir(outDir);
            args.setOutDirSrc(srcDir);
            args.setOutDirRes(resDir);
            args.setSkipResources(true);
            args.setThreadsCount(Math.max(1, threads));
            jadx = new JadxDecompiler(args);
            jadx.registerPlugin(new DexInputPlugin());
            jadx.load();
            List<JavaClass> classes = jadx.getClassesWithInners();
            r.classes = classes.size();
            int matched = 0;
            int checked = 0;
            long chars = 0;
            for (JavaClass cls : classes) {
                String key = clsKey(cls);
                if (key == null) continue;
                String slash = key.replace('.', '/');
                boolean ok = pkgSlashes == null || pkgSlashes.isEmpty();
                if (!ok) {
                    for (String p : pkgSlashes) {
                        if (p != null && slash.startsWith(p)) {
                            ok = true;
                            break;
                        }
                    }
                }
                if (!ok) continue;
                matched++;
                if (r.sources.size() >= cap) {
                    r.truncated = true;
                    break;
                }
                if ((checked++ % 10 == 0) && lowMem(mem)) {
                    r.truncated = true;
                    r.memoryAbort = true;
                    r.error = "memoria baja: parcial (" + r.sources.size() + " clases)";
                    log(r, "[" + tag + "] MEMORIA: parcial " + r.sources.size());
                    break;
                }
                String code;
                try {
                    code = cls.getCode();
                } catch (OutOfMemoryError oom) {
                    r.truncated = true;
                    r.memoryAbort = true;
                    r.error = "memoria insuficiente (parcial: "
                            + r.sources.size() + " clases)";
                    log(r, "[" + tag + "] OOM en " + clsName(cls));
                    break;
                } catch (Throwable t) {
                    r.errors++;
                    log(r, "[" + tag + "] ERR " + clsName(cls) + ": " + shortMsg(t));
                    continue;
                }
                if (code != null) {
                    chars += code.length();
                    if (chars > MAX_SOURCE_CHARS) {
                        r.truncated = true;
                        break;
                    }
                    try {
                        String storeKey = clsKey(cls);
                        if (storeKey == null) r.errors++;
                        else r.sources.put(storeKey, code);
                    } catch (Throwable t) {
                        r.errors++;
                    }
                }
                if (progress != null) {
                    try {
                        if (!progress.onClass(r.sources.size(), matched)) {
                            r.truncated = true;
                            break;
                        }
                    } catch (Throwable t) {
                        r.truncated = true;
                        break;
                    }
                }
            }
            try {
                r.errors += jadx.getErrorsCount();
            } catch (Throwable ignored) {
            }
        } catch (OutOfMemoryError oom) {
            r.truncated = true;
            r.memoryAbort = true;
            r.error = "memoria insuficiente para JADX";
            log(r, "[" + tag + "] OOM general");
        } catch (Throwable t) {
            r.error = "jadx: " + fullMsg(t);
            log(r, "[" + tag + "] LOAD: " + r.error);
        } finally {
            if (jadx != null) {
                try {
                    jadx.close();
                } catch (Throwable ignored) {
                }
            }
        }
        return r;
    }

    private static boolean lowMem(MemoryPolicy mem) {
        if (mem == null) return false;
        try {
            return mem.lowMemory();
        } catch (Throwable t) {
            return false;
        }
    }

    /** Cadena de causas + primer marco (el mensaje solo suele decir nada). */
    private static String fullMsg(Throwable t) {
        try {
            StringBuilder sb = new StringBuilder();
            int depth = 0;
            Throwable cur = t;
            Throwable deepest = t;
            while (cur != null && depth < 4) {
                if (depth > 0) sb.append(" <-causa- ");
                String m = String.valueOf(cur);
                if (m.length() > 300) m = m.substring(0, 300) + "…";
                sb.append(m);
                deepest = cur;
                cur = cur.getCause();
                depth++;
            }
            StackTraceElement[] st = deepest.getStackTrace();
            if (st != null && st.length > 0) {
                sb.append(" [en ").append(st[0].getClassName()).append('.')
                        .append(st[0].getMethodName()).append(':')
                        .append(st[0].getLineNumber()).append(']');
            }
            return sb.length() == 0 ? "?" : sb.toString();
        } catch (Throwable ignored) {
            return "?";
        }
    }

    private static void phase(Progress progress, String name) {
        if (progress == null) return;
        try {
            progress.onPhase(name);
        } catch (Throwable ignored) {
        }
    }

    private static void log(Result r, String s) {
        if (r.log.size() >= MAX_LOG_LINES) return;
        if (s.length() > 220) s = s.substring(0, 220) + "…";
        r.log.add(s);
    }

    private static String shortMsg(Throwable t) {
        try {
            String m = String.valueOf(t);
            return m.length() > 140 ? m.substring(0, 140) + "…" : m;
        } catch (Throwable ignored) {
            return "?";
        }
    }

    /**
     * Nombre original del dex (con $): inmune a renombres de JADX
     * (p.ej. A$1 → A.AnonymousClass1). Repliega a getFullName.
     * Null solo si la clase no da ningún nombre. Nunca lanza.
     */
    private static String clsKey(JavaClass cls) {
        try {
            String raw = cls.getRawName();
            if (raw != null && !raw.isEmpty()) return raw;
        } catch (Throwable ignored) {
        }
        try {
            return cls.getFullName();
        } catch (Throwable t) {
            return null;
        }
    }

    private static String clsName(JavaClass cls) {
        String k = clsKey(cls);
        return k != null ? k : "?";
    }

    /**
     * Escaneo previo: qué dex traen clases del filtro, sin cargar JADX.
     * Barato (DexParser) y nunca lanza.
     */
    public static List<DexHit> scanDexes(File apk, List<String> pkgSlashes) {
        List<DexHit> out = new ArrayList<>();
        try {
            if (apk == null || !apk.isFile()) return out;
            ZipFile zip = new ZipFile(apk);
            try {
                List<String> names = new ArrayList<>();
                Enumeration<? extends ZipEntry> en = zip.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (!e.isDirectory() && e.getName().matches("classes\\d*\\.dex")) {
                        names.add(e.getName());
                    }
                }
                Collections.sort(names);
                for (String dn : names) {
                    DexHit h = new DexHit();
                    h.name = dn;
                    try {
                        ZipEntry e = zip.getEntry(dn);
                        h.size = e == null ? -1 : e.getSize();
                        byte[] bytes = readBytes(zip, dn);
                        if (bytes == null) {
                            h.error = "no legible";
                        } else {
                            DexParser.DexInfo di = DexParser.parse(bytes, dn);
                            if (di.error != null) {
                                h.error = di.error;
                            } else {
                                h.totalClasses = di.classCount;
                                h.truncated = di.classesTruncated;
                                h.matched = countMatches(di.classes, pkgSlashes);
                            }
                        }
                    } catch (Throwable t) {
                        h.error = "scan: " + shortMsg(t);
                    }
                    out.add(h);
                }
            } finally {
                try {
                    zip.close();
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static int countMatches(List<DexParser.ClassInfo> classes, List<String> pkgSlashes) {
        if (pkgSlashes == null || pkgSlashes.isEmpty()) return classes.size();
        int n = 0;
        for (DexParser.ClassInfo ci : classes) {
            if (ci == null || ci.name == null) continue;
            for (String p : pkgSlashes) {
                if (p != null && ci.name.startsWith("L" + p)) {
                    n++;
                    break;
                }
            }
        }
        return n;
    }

    private static byte[] readBytes(ZipFile zip, String name) {
        try {
            ZipEntry e = zip.getEntry(name);
            if (e == null) return null;
            InputStream in = zip.getInputStream(e);
            try {
                java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                byte[] buf = new byte[32768];
                long total = 0;
                while (true) {
                    int n = in.read(buf);
                    if (n <= 0) break;
                    total += n;
                    if (total > MAX_DEX_PART) return null;
                    bos.write(buf, 0, n);
                }
                return bos.toByteArray();
            } finally {
                try {
                    in.close();
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable t) {
            return null;
        }
    }

    private static boolean isZip(File f) {
        FileInputStream in = null;
        try {
            in = new FileInputStream(f);
            byte[] magic = new byte[4];
            if (in.read(magic) != 4) return false;
            return magic[0] == 'P' && magic[1] == 'K' && magic[2] == 3 && magic[3] == 4;
        } catch (Throwable t) {
            return false;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    /**
     * APK/ZIP: si el plan lo pide, va directo por dex (reutilizando el
     * escaneo); si no, intenta carga completa (mejor calidad cross-dex) y,
     * solo si aborta por memoria o falla total, reintenta dex por dex.
     * Devuelve el mejor parcial. Nunca lanza.
     */
    private static Result decompileZip(File apk, File workDir, int threads,
                                       List<String> pkgSlashes, int maxClasses,
                                       Progress progress, MemoryPolicy mem) {
        long maxMem;
        try {
            maxMem = Runtime.getRuntime().maxMemory();
        } catch (Throwable t) {
            maxMem = 256L * 1024 * 1024;
        }
        DexPlan plan = planDexLoad(apk, maxMem, pkgSlashes);
        if (plan.preferPerDex) {
            phase(progress, "APK grande: directo por dex");
            return decompileZipPerDex(apk, workDir, threads, pkgSlashes,
                    maxClasses, progress, mem,
                    "APK grande: directo por dex (" + plan.totalClasses + " clases)",
                    plan.hits);
        }
        phase(progress, "cargando APK");
        Result full = decompileSingle(apk, workDir, threads, pkgSlashes,
                maxClasses, progress, mem, "APK");
        boolean totalFail = full.sources.isEmpty() && full.error != null;
        if (!full.memoryAbort && !totalFail) return full;
        phase(progress, "reintentando por dex");
        try {
            System.gc();
        } catch (Throwable ignored) {
        }
        Result per = decompileZipPerDex(apk, workDir, threads, pkgSlashes,
                maxClasses, progress, mem, null, null);
        if (per.sources.size() > full.sources.size() || full.sources.isEmpty()) return per;
        return full;
    }

    /**
     * APK/ZIP: extrae cada classesN.dex y lo descompila por separado,
     * liberando entre dexes. Pico de RAM ~= dex mayor, no el APK.
     * Nunca lanza.
     */
    private static Result decompileZipPerDex(File apk, File workDir, int threads,
                                             List<String> pkgSlashes, int maxClasses,
                                             Progress progress, MemoryPolicy mem,
                                             String prelude, List<DexHit> prescan) {
        Result acc = new Result();
        if (prelude != null && !prelude.isEmpty()) log(acc, prelude);
        int cap = maxClasses <= 0 ? Integer.MAX_VALUE : maxClasses;
        List<String> dexNames = new ArrayList<>();
        try {
            ZipFile zip = new ZipFile(apk);
            try {
                Enumeration<? extends ZipEntry> en = zip.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (!e.isDirectory() && e.getName().matches("classes\\d*\\.dex")) {
                        dexNames.add(e.getName());
                    }
                }
            } finally {
                try {
                    zip.close();
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable t) {
            acc.error = "apk no legible";
            return acc;
        }
        if (dexNames.isEmpty()) {
            acc.error = "apk sin dex";
            return acc;
        }
        Collections.sort(dexNames);
        // Búsqueda previa: solo se cargan dex con coincidencias.
        phase(progress, "localizando clases");
        Map<String, DexHit> hits = new LinkedHashMap<>();
        List<DexHit> scanned = prescan != null ? prescan : scanDexes(apk, pkgSlashes);
        for (DexHit h : scanned) hits.put(h.name, h);
        int withHits = 0;
        for (String dn : dexNames) {
            DexHit h = hits.get(dn);
            if (h == null || h.truncated || h.error != null || h.matched > 0) withHits++;
        }
        log(acc, "dex con coincidencias: " + withHits + " de " + dexNames.size());
        File parts = new File(workDir, "dexparts");
        parts.mkdirs();
        long chars = 0;
        int idx = 0;
        for (String dn : dexNames) {
            idx++;
            DexHit h = hits.get(dn);
            if (h != null && !h.truncated && h.error == null && h.matched == 0) {
                log(acc, "[" + dn + "] omitido: sin coincidencias (" + h.totalClasses + " clases)");
                continue;
            }
            if (lowMem(mem)) {
                acc.truncated = true;
                if (acc.error == null) {
                    acc.error = "memoria baja: parcial (" + acc.sources.size() + " clases)";
                }
                log(acc, "MEMORIA: parada en dex " + idx);
                break;
            }
            if (acc.sources.size() >= cap || chars > MAX_SOURCE_CHARS) {
                acc.truncated = true;
                log(acc, "tope alcanzado en dex " + idx);
                break;
            }
            phase(progress, "dex " + idx + "/" + dexNames.size());
            File part = new File(parts, "part" + idx + ".dex");
            if (!extractEntry(apk, dn, part)) {
                acc.truncated = true;
                log(acc, "[" + dn + "] omitido: no extraíble");
                continue;
            }
            Result one = decompileSingle(part, workDir, threads, pkgSlashes,
                    cap - acc.sources.size(), progress, mem, dn);
            try {
                part.delete();
            } catch (Throwable ignored) {
            }
            acc.classes += one.classes;
            acc.errors += one.errors;
            if (one.truncated) acc.truncated = true;
            if (one.memoryAbort) acc.memoryAbort = true;
            if (one.error != null && acc.error == null) acc.error = one.error;
            for (String l : one.log) log(acc, l);
            log(acc, "[" + dn + "] java=+" + one.sources.size() + " err=" + one.errors);
            phase(progress, "dex " + idx + "/" + dexNames.size() + ": " + one.sources.size()
                    + " java");
            for (Map.Entry<String, String> e : one.sources.entrySet()) {
                if (acc.sources.containsKey(e.getKey())) continue;
                String code = e.getValue();
                if (code != null) {
                    chars += code.length();
                    if (chars > MAX_SOURCE_CHARS) {
                        acc.truncated = true;
                        break;
                    }
                }
                acc.sources.put(e.getKey(), code);
            }
            System.gc();
        }
        if (acc.sources.isEmpty() && acc.error == null) acc.error = "sin clases extraídas";
        return acc;
    }

    /** Extrae una entrada a fichero con tope. false = omitido/fallo. */
    private static boolean extractEntry(File apk, String name, File dest) {
        ZipFile zip = null;
        try {
            zip = new ZipFile(apk);
            ZipEntry e = zip.getEntry(name);
            if (e == null) return false;
            InputStream in = zip.getInputStream(e);
            try {
                FileOutputStream out = new FileOutputStream(dest);
                try {
                    byte[] buf = new byte[32768];
                    long total = 0;
                    while (true) {
                        int n = in.read(buf);
                        if (n <= 0) break;
                        total += n;
                        if (total > MAX_DEX_PART) return false;
                        out.write(buf, 0, n);
                    }
                    return true;
                } finally {
                    try {
                        out.close();
                    } catch (Throwable ignored) {
                    }
                }
            } finally {
                try {
                    in.close();
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable t) {
            return false;
        } finally {
            if (zip != null) {
                try {
                    zip.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }
}
