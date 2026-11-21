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

    /** Política de memoria: true = poca memoria, abortar con parcial. Inyectable en tests. */
    public interface MemoryPolicy {
        boolean lowMemory();
    }

    /** Tope de texto Java acumulado (~30 MB como UTF-16) para no OOMear la caché. */
    public static final long MAX_SOURCE_CHARS = 15_000_000L;
    /** Reserva mínima de heap antes/durante JADX (48 MB). */
    public static final long MIN_HEADROOM = 48L * 1024 * 1024;

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
        public String error;
    }

    /** Descompila todo el dex/apk sin filtro. Nunca lanza. */
    public static Result decompile(File input, File workDir, int threads) {
        return decompileFiltered(input, workDir, threads, new ArrayList<String>(), 0, null);
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
            if (lowMem(mem)) {
                r.error = "memoria baja: no se pudo cargar JADX";
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
                String slash;
                try {
                    slash = cls.getFullName().replace('.', '/');
                } catch (Throwable t) {
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
                if ((checked++ % 10 == 0) && lowMem(mem)) {
                    r.truncated = true;
                    r.error = "memoria baja: parcial (" + r.sources.size() + " clases)";
                    break;
                }
                String code;
                try {
                    code = cls.getCode();
                } catch (OutOfMemoryError oom) {
                    r.truncated = true;
                    r.error = "memoria insuficiente (parcial: "
                            + r.sources.size() + " clases)";
                    break;
                } catch (Throwable t) {
                    r.errors++;
                    continue;
                }
                if (code != null) {
                    chars += code.length();
                    if (chars > MAX_SOURCE_CHARS) {
                        r.truncated = true;
                        break;
                    }
                    try {
                        r.sources.put(cls.getFullName(), code);
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
            r.error = "memoria insuficiente para JADX";
        } catch (Throwable t) {
            String msg = t.getMessage();
            r.error = "jadx: " + (msg == null ? t.toString() : msg);
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
}
