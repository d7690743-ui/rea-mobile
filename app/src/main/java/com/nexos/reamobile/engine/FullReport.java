package com.nexos.reamobile.engine;

import java.util.List;
import java.util.Map;

/**
 * Informe completo en un solo TXT: árbol del APK + lista de clases + fuentes Java.
 * Lo genera el visor ("Informe") con lo ya analizado/descompilado, sin re-analizar.
 * Java puro con topes anti-OOM. Nunca lanza.
 */
public final class FullReport {
    private FullReport() {
    }

    public static final int MAX_TREE_LINES = 20000;
    public static final int MAX_CLASS_LINES = 20000;
    public static final int MAX_JAVA_FILES = 2000;
    public static final long MAX_JAVA_CHARS = 20L * 1024 * 1024;

    public static class Result {
        public String text = "";
        public int treeLines;
        public int treeTotal;
        public boolean treeTruncated;
        public int classLines;
        public int classTotal;
        public boolean classesTruncated;
        public int javaFiles;
        public int javaTotal;
        public boolean javaTruncated;
    }

    /** Construye el informe con los topes de producción. Nunca lanza. */
    public static Result build(String pkg, List<String> tree, List<String> classes,
                               Map<String, String> java) {
        return buildFor(pkg, tree, classes, java,
                MAX_TREE_LINES, MAX_CLASS_LINES, MAX_JAVA_FILES, MAX_JAVA_CHARS);
    }

    /** Variante con topes inyectables (tests). Nunca lanza. */
    static Result buildFor(String pkg, List<String> tree, List<String> classes,
                           Map<String, String> java,
                           int maxTree, int maxClasses, int maxFiles, long maxChars) {
        Result r = new Result();
        StringBuilder sb = new StringBuilder();
        try {
            String p = pkg == null || pkg.isEmpty() ? "?" : pkg;
            int treeTotal = tree == null ? 0 : tree.size();
            int classTotal = classes == null ? 0 : classes.size();
            int javaTotal = countWithCode(java);
            r.treeTotal = treeTotal;
            r.classTotal = classTotal;
            r.javaTotal = javaTotal;

            sb.append("REA Mobile v").append(ReaEngine.VERSION)
                    .append(" — informe completo (arbol + clases + Java)\n");
            sb.append("paquete=").append(p).append('\n');
            sb.append("arbol=").append(treeTotal)
                    .append(" clases=").append(classTotal)
                    .append(" java=").append(javaTotal).append('\n');

            sb.append("\n=== ARBOL DEL APK (").append(treeTotal).append(") ===\n");
            if (tree == null || tree.isEmpty()) {
                sb.append("(vacio)\n");
            } else {
                int cap = Math.max(0, maxTree);
                for (int i = 0; i < tree.size(); i++) {
                    if (i >= cap) {
                        r.treeTruncated = true;
                        break;
                    }
                    String line = tree.get(i);
                    sb.append(line == null ? "?" : line).append('\n');
                    r.treeLines++;
                }
                if (r.treeTruncated) {
                    sb.append("[...recortado: se muestran ").append(r.treeLines)
                            .append(" de ").append(treeTotal).append("...]\n");
                }
            }

            sb.append("\n=== CLASES PROPIAS (").append(classTotal).append(") ===\n");
            if (classes == null || classes.isEmpty()) {
                sb.append("(vacias)\n");
            } else {
                int cap = Math.max(0, maxClasses);
                for (int i = 0; i < classes.size(); i++) {
                    if (i >= cap) {
                        r.classesTruncated = true;
                        break;
                    }
                    String c = classes.get(i);
                    sb.append(c == null ? "?" : c).append('\n');
                    r.classLines++;
                }
                if (r.classesTruncated) {
                    sb.append("[...recortado: se muestran ").append(r.classLines)
                            .append(" de ").append(classTotal).append("...]\n");
                }
            }

            sb.append("\n=== JAVA (").append(javaTotal).append(" ficheros) ===\n");
            if (javaTotal == 0) {
                sb.append("(sin Java: usa Descompilar en el visor y regenera el informe)\n");
            } else {
                int capFiles = Math.max(0, maxFiles);
                long capChars = Math.max(0, maxChars);
                long chars = 0;
                for (Map.Entry<String, String> e : java.entrySet()) {
                    String code = e.getValue();
                    if (code == null || code.trim().isEmpty()) continue;
                    if (r.javaFiles >= capFiles || chars + code.length() > capChars) {
                        r.javaTruncated = true;
                        break;
                    }
                    String key = e.getKey() == null ? "?" : e.getKey();
                    sb.append("\n===== ").append(key).append(" =====\n");
                    sb.append(code);
                    if (!code.endsWith("\n")) sb.append('\n');
                    chars += code.length();
                    r.javaFiles++;
                }
                if (r.javaTruncated) {
                    sb.append("\n[...recortado: se incluyen ").append(r.javaFiles)
                            .append(" de ").append(javaTotal).append(" ficheros...]\n");
                }
            }
        } catch (Throwable ignored) {
            sb.append("\n[...informe parcial por error interno...]\n");
        }
        r.text = sb.toString();
        return r;
    }

    private static int countWithCode(Map<String, String> java) {
        try {
            if (java == null) return 0;
            int n = 0;
            for (Map.Entry<String, String> e : java.entrySet()) {
                String code = e.getValue();
                if (code != null && !code.trim().isEmpty()) n++;
            }
            return n;
        } catch (Throwable ignored) {
            return 0;
        }
    }
}
