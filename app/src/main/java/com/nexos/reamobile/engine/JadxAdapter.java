package com.nexos.reamobile.engine;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.plugins.input.dex.DexInputPlugin;

/**
 * Adaptador fino sobre jadx-core (Apache 2.0): DEX/APK a Java por clase.
 * Carga una vez y extrae por lotes con filtro de paquete, tope de clases
 * y cancelación cooperativa. Llamar fuera del hilo principal.
 */
public final class JadxAdapter {
    private JadxAdapter() {
    }

    /** Se llama por cada clase extraída; devolver false detiene (trunca). */
    public interface Progress {
        boolean onClass(int done, int matched);
    }

    public static class Result {
        public Map<String, String> sources = new LinkedHashMap<>();
        public int errors;
        public int classes;
        public boolean truncated;
        public String error;
    }

    /** Descompila todo el dex/apk sin filtro. Nunca lanza. */
    public static Result decompile(File input, File workDir, int threads) {
        return decompileFiltered(input, workDir, threads, new ArrayList<String>(), 0, null);
    }

    /**
     * Descompila con filtro de paquetes (prefijos estilo "com/x/"), tope de
     * clases (0 = sin tope) y progreso cancelable. Nunca lanza.
     */
    public static Result decompileFiltered(File input, File workDir, int threads,
                                           List<String> pkgSlashes, int maxClasses, Progress progress) {
        Result r = new Result();
        JadxDecompiler jadx = null;
        try {
            if (input == null || !input.isFile()) {
                r.error = "entrada no válida";
                return r;
            }
            if (workDir == null) {
                r.error = "sin directorio de trabajo";
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
            for (JavaClass cls : classes) {
                String slash;
                try {
                    slash = cls.getFullName().replace('.', '/');
                } catch (Exception e) {
                    continue;
                }
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
                try {
                    r.sources.put(cls.getFullName(), cls.getCode());
                } catch (Exception e) {
                    r.errors++;
                }
                if (progress != null) {
                    try {
                        if (!progress.onClass(r.sources.size(), matched)) {
                            r.truncated = true;
                            break;
                        }
                    } catch (Exception e) {
                        r.truncated = true;
                        break;
                    }
                }
            }
            r.errors += jadx.getErrorsCount();
        } catch (Exception e) {
            r.error = "jadx: " + e.getMessage();
        } finally {
            if (jadx != null) {
                try {
                    jadx.close();
                } catch (Exception ignored) {
                }
            }
        }
        return r;
    }
}
