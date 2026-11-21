package com.nexos.reamobile.engine;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.plugins.input.dex.DexInputPlugin;

/**
 * Adaptador fino sobre jadx-core (Apache 2.0): DEX/APK a Java por clase.
 * Spike v0.3: sin UI y sin cancelación (llegan con el visor).
 * Llamar fuera del hilo principal: puede tardar segundos o minutos.
 */
public final class JadxAdapter {
    private JadxAdapter() {
    }

    public static class Result {
        public Map<String, String> sources = new LinkedHashMap<>();
        public int errors;
        public int classes;
        public String error;
    }

    /** Descompila un dex o apk y devuelve el código por clase. Nunca lanza. */
    public static Result decompile(File input, File workDir, int threads) {
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
            for (JavaClass cls : classes) {
                try {
                    r.sources.put(cls.getFullName(), cls.getCode());
                } catch (Exception e) {
                    r.errors++;
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
