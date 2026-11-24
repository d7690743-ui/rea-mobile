package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Informe completo en un solo TXT: informe estático (opcional) + árbol del APK + lista
 * de clases + fuentes Java (smali de respaldo para las clases sin Java).
 * Lo genera el visor ("Informe") con lo ya analizado/descompilado, sin re-analizar.
 * Clases y Java salen ordenados por clase externa y sin la ruta local del dex de trabajo.
 * Java puro con topes anti-OOM. Nunca lanza.
 */
public final class FullReport {
    private FullReport() {
    }

    public static final int MAX_TREE_LINES = 20000;
    public static final int MAX_CLASS_LINES = 20000;
    public static final int MAX_JAVA_FILES = 2000;
    public static final long MAX_JAVA_CHARS = 20L * 1024 * 1024;
    public static final int MAX_STATIC_CHARS = 512 * 1024;
    public static final int MAX_PACKAGE_CHARS = 512 * 1024;
    public static final int MAX_SMALI_CLASSES = 200;
    public static final long MAX_SMALI_CHARS = 4L * 1024 * 1024;

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
        public boolean staticIncluded;
        public boolean packageIncluded;
        public int smaliFiles;
        public int smaliTotal;
        public boolean smaliTruncated;
    }

    /** Origen del smali de una clase (descriptor "Lcom/x/A;"). Puede devolver null. */
    public interface SmaliProvider {
        String smali(String classDescriptor);
    }

    /** Datos opcionales que enriquecen el informe. Todo puede quedar vacío/null. */
    public static class Extras {
        /** Identificador del build de REA, p. ej. "0.4.0 · 1a2b3c4d". */
        public String build = "";
        /** Informe estático (ReaEngine.ApkReport.toText(): firma, manifest, hallazgos). */
        public String staticReport = "";
        /** Paquete máquina-legible (ApkReport.toJson(), PHANTOM incluido). */
        public String packageJson = "";
        /** Smali de respaldo para clases cuyo Java falta o salió vacío. */
        public SmaliProvider smali;
        public int maxSmaliClasses = MAX_SMALI_CLASSES;
        public long maxSmaliChars = MAX_SMALI_CHARS;
    }

    /** Construye el informe con los topes de producción. Nunca lanza. */
    public static Result build(String pkg, List<String> tree, List<String> classes,
                               Map<String, String> java) {
        return build(pkg, tree, classes, java, null);
    }

    /** Igual que {@link #build(String, List, List, Map)} con datos extra. Nunca lanza. */
    public static Result build(String pkg, List<String> tree, List<String> classes,
                               Map<String, String> java, Extras extras) {
        return buildFor(pkg, tree, classes, java,
                MAX_TREE_LINES, MAX_CLASS_LINES, MAX_JAVA_FILES, MAX_JAVA_CHARS, extras);
    }

    /** Variante con topes inyectables (tests). Nunca lanza. */
    static Result buildFor(String pkg, List<String> tree, List<String> classes,
                           Map<String, String> java,
                           int maxTree, int maxClasses, int maxFiles, long maxChars) {
        return buildFor(pkg, tree, classes, java, maxTree, maxClasses, maxFiles, maxChars, null);
    }

    static Result buildFor(String pkg, List<String> tree, List<String> classes,
                           Map<String, String> java,
                           int maxTree, int maxClasses, int maxFiles, long maxChars,
                           Extras extras) {
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

            sb.append("REA Mobile v").append(ReaEngine.VERSION);
            if (extras != null && extras.build != null && !extras.build.trim().isEmpty()) {
                sb.append(" (build ").append(extras.build.trim()).append(')');
            }
            sb.append(" — informe completo (arbol + clases + Java)\n");
            sb.append("paquete=").append(p).append('\n');
            sb.append("arbol=").append(treeTotal)
                    .append(" clases=").append(classTotal)
                    .append(" java=").append(javaTotal).append('\n');

            if (extras != null && extras.staticReport != null
                    && !extras.staticReport.trim().isEmpty()) {
                String st = extras.staticReport;
                sb.append("\n=== INFORME ESTATICO (firma, manifest, hallazgos) ===\n");
                if (st.length() > MAX_STATIC_CHARS) {
                    sb.append(st, 0, MAX_STATIC_CHARS).append("\n[...recortado...]\n");
                } else {
                    sb.append(st);
                    if (!st.endsWith("\n")) sb.append('\n');
                }
                r.staticIncluded = true;
            }

            if (extras != null && extras.packageJson != null
                    && !extras.packageJson.trim().isEmpty()) {
                String pj = extras.packageJson;
                sb.append("\n=== PAQUETE JSON (maquina-legible, PHANTOM incluido) ===\n");
                if (pj.length() > MAX_PACKAGE_CHARS) {
                    sb.append(pj, 0, MAX_PACKAGE_CHARS).append("\n[...recortado...]\n");
                } else {
                    sb.append(pj);
                    if (!pj.endsWith("\n")) sb.append('\n');
                }
                r.packageIncluded = true;
            }

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
            List<String> sortedClasses = sortClasses(classes);
            if (sortedClasses.isEmpty()) {
                sb.append("(vacias)\n");
            } else {
                int cap = Math.max(0, maxClasses);
                for (int i = 0; i < sortedClasses.size(); i++) {
                    if (i >= cap) {
                        r.classesTruncated = true;
                        break;
                    }
                    String c = sortedClasses.get(i);
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
                for (Map.Entry<String, String> e : sortedJava(java).entrySet()) {
                    String code = cleanJava(e.getValue());
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

            appendSmaliFallback(sb, r, sortedClasses, java, extras);
        } catch (Throwable ignored) {
            sb.append("\n[...informe parcial por error interno...]\n");
        }
        r.text = sb.toString();
        return r;
    }

    /** Clase externa de un descriptor: "Lcom/x/A$1;" -> "Lcom/x/A". */
    private static String outerOf(String desc) {
        String d = desc == null ? "" : desc;
        if (d.endsWith(";")) d = d.substring(0, d.length() - 1);
        int i = d.indexOf('$');
        return i > 0 ? d.substring(0, i) : d;
    }

    /** Copia ordenada por clase externa y luego por nombre completo. Nunca lanza. */
    static List<String> sortClasses(List<String> classes) {
        List<String> out = new ArrayList<>();
        try {
            if (classes == null) return out;
            out.addAll(classes);
            Collections.sort(out, new Comparator<String>() {
                @Override
                public int compare(String a, String b) {
                    int c = outerOf(a).compareTo(outerOf(b));
                    if (c != 0) return c;
                    // Misma clase externa: ella primero y luego sus internas ($ < ; en ASCII).
                    boolean ai = String.valueOf(a).indexOf('$') > 0;
                    boolean bi = String.valueOf(b).indexOf('$') > 0;
                    if (ai != bi) return ai ? 1 : -1;
                    return String.valueOf(a).compareTo(String.valueOf(b));
                }
            });
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Copia del mapa de Java ordenada por nombre de clase (claves nulas -> "?"). */
    private static Map<String, String> sortedJava(Map<String, String> java) {
        Map<String, String> out = new TreeMap<>();
        try {
            if (java == null) return out;
            for (Map.Entry<String, String> e : java.entrySet()) {
                out.put(e.getKey() == null ? "?" : e.getKey(), e.getValue());
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Quita la línea "/* loaded from: ... *&#47;" que JADX añade a cada clase: delata la ruta
     * local del dex de trabajo y no aporta nada al análisis.
     */
    static String cleanJava(String code) {
        if (code == null || code.indexOf("loaded from:") < 0) return code;
        try {
            StringBuilder sb = new StringBuilder(code.length());
            int i = 0;
            while (i < code.length()) {
                int nl = code.indexOf('\n', i);
                int end = nl < 0 ? code.length() : nl + 1;
                String line = code.substring(i, end);
                String t = line.trim();
                if (!(t.startsWith("/* loaded from:") && t.endsWith("*/"))) sb.append(line);
                i = end;
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return code;
        }
    }

    private static boolean hasJava(Map<String, String> java, String desc) {
        try {
            if (java == null) return false;
            String name = outerOf(desc);
            if (name.startsWith("L")) name = name.substring(1);
            name = name.replace('/', '.');
            String code = java.get(name);
            return code != null && !code.trim().isEmpty();
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Smali (vía proveedor) de las clases propias cuya clase externa no tiene Java. */
    private static void appendSmaliFallback(StringBuilder sb, Result r, List<String> classes,
                                            Map<String, String> java, Extras extras) {
        if (extras == null || extras.smali == null || classes == null || classes.isEmpty()) return;
        List<String> pend = new ArrayList<>();
        for (String c : classes) {
            if (c != null && !hasJava(java, c)) pend.add(c);
        }
        r.smaliTotal = pend.size();
        if (pend.isEmpty()) return;
        sb.append("\n=== SMALI DE RESPALDO (").append(pend.size())
                .append(" clases sin Java) ===\n");
        long chars = 0;
        for (String c : pend) {
            if (r.smaliFiles >= Math.max(0, extras.maxSmaliClasses)) {
                r.smaliTruncated = true;
                break;
            }
            String s = null;
            try {
                s = extras.smali.smali(c);
            } catch (Throwable ignored) {
            }
            if (s == null || s.trim().isEmpty()) continue;
            if (chars + s.length() > Math.max(0L, extras.maxSmaliChars)) {
                r.smaliTruncated = true;
                break;
            }
            sb.append("\n===== smali: ").append(c).append(" =====\n").append(s);
            if (!s.endsWith("\n")) sb.append('\n');
            chars += s.length();
            r.smaliFiles++;
        }
        if (r.smaliTruncated) {
            sb.append("\n[...recortado: se incluyen ").append(r.smaliFiles)
                    .append(" de ").append(pend.size()).append(" clases...]\n");
        }
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
