package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * PHANTOM atribución inversa (P3.1 datos + P3.2 almacén): los hallazgos
 * huérfanos (50 modelos, 8 helpers, SQL) se amarran a quien los usa vía
 * aristas inversas del grafo. Solo AÑADE evidencia ("referenciado por",
 * "llamado por"); el conteo de hallazgos no cambia y PhantomMetric
 * levanta estados con su cruce habitual. Nunca lanza.
 */
public final class PhantomAttrib {
    private PhantomAttrib() {
    }

    public static final int MAX_INDEX_CLASSES = 8000;
    public static final int MAX_CALLERS_PER_CLASS = 4;

    /**
     * Enriquece evidencias de datos/almacén con referenciadores del
     * grafo. Listas null o grafo null: no-op. Nunca lanza.
     */
    public static void enrich(List<PhantomData.DataHit> data,
                              List<PhantomStore.StoreHit> store,
                              RefGraph graph) {
        try {
            if (graph == null) return;
            Map<String, List<String>> idx = classCallers(graph);
            if (data != null) {
                for (PhantomData.DataHit h : data) {
                    if (h == null) continue;
                    if ("proto-model".equals(h.kind)) {
                        List<String> cs = idx.get(classOf(h.detail));
                        appendRef(h, cs);
                    } else if ("parcelable".equals(h.kind)) {
                        List<String> cs = new ArrayList<>();
                        for (String c : graph.callersOf(h.detail)) {
                            if (c != null && cs.size() < 2) cs.add(c);
                        }
                        if (cs.isEmpty()) cs = idx.get(classOf(h.detail));
                        appendRef(h, cs);
                    }
                }
            }
            if (store != null) {
                for (PhantomStore.StoreHit h : store) {
                    if (h == null) continue;
                    if ("sqlite-helper".equals(h.kind)
                            || "provider".equals(h.kind)) {
                        appendRef(h, idx.get(classOf(h.detail)));
                    } else if ("sql".equals(h.kind) || "db-file".equals(h.kind)) {
                        String u = PhantomMetric.evidenceUser(h.evidence);
                        if (u == null) continue;
                        List<String> cs = new ArrayList<>();
                        for (String c : graph.callersOf(u)) {
                            if (c == null || cs.size() >= 3) break;
                            if (isFramework(c)) continue;
                            cs.add(c);
                        }
                        if (!cs.isEmpty()) appendCalled(h, cs);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Índice clase-llamada → llamadores (una pasada al grafo, acotada).
     * Nunca null ni lanza.
     */
    static Map<String, List<String>> classCallers(RefGraph graph) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        try {
            if (graph == null) return out;
            for (RefGraph.RefEdge e : graph.edges()) {
                if (e == null || e.caller == null || e.callee == null) continue;
                String cls = classOf(e.callee);
                if (cls.isEmpty()) continue;
                List<String> l = out.get(cls);
                if (l == null) {
                    if (out.size() >= MAX_INDEX_CLASSES) continue;
                    l = new ArrayList<>();
                    out.put(cls, l);
                }
                if (l.size() < MAX_CALLERS_PER_CLASS
                        && !l.contains(e.caller)) l.add(e.caller);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static void appendRef(PhantomData.DataHit h, List<String> cs) {
        try {
            if (h == null || cs == null || cs.isEmpty()) return;
            if (h.evidence != null && h.evidence.contains("referenciado por")) return;
            String base = h.evidence == null ? "" : h.evidence;
            h.evidence = base + "; referenciado por " + join(cs, 2);
        } catch (Throwable ignored) {
        }
    }

    private static void appendRef(PhantomStore.StoreHit h, List<String> cs) {
        try {
            if (h == null || cs == null || cs.isEmpty()) return;
            if (h.evidence != null && h.evidence.contains("referenciado por")) return;
            String base = h.evidence == null ? "" : h.evidence;
            h.evidence = base + "; referenciado por " + join(cs, 2);
        } catch (Throwable ignored) {
        }
    }

    private static void appendCalled(PhantomStore.StoreHit h, List<String> cs) {
        try {
            if (h == null || cs == null || cs.isEmpty()) return;
            if (h.evidence != null && h.evidence.contains("llamado por")) return;
            String base = h.evidence == null ? "" : h.evidence;
            h.evidence = base + "; llamado por " + join(cs, 3);
        } catch (Throwable ignored) {
        }
    }

    private static String join(List<String> cs, int n) {
        try {
            StringBuilder sb = new StringBuilder();
            int k = 0;
            for (String c : cs) {
                if (c == null || k >= n) break;
                if (k > 0) sb.append(", ");
                sb.append(c);
                k++;
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** Clase de "Lcls;->m" o "Lcls;". "" si no hay. Nunca lanza. */
    static String classOf(String ref) {
        try {
            if (ref == null) return "";
            int a = ref.indexOf(";->");
            String cls = a < 0 ? ref : ref.substring(0, a + 1);
            return cls.startsWith("L") ? cls : "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static boolean isFramework(String m) {
        try {
            return m != null && (m.startsWith("Landroid/")
                    || m.startsWith("Ljava/") || m.startsWith("Ljavax/")
                    || m.startsWith("Ldalvik/"));
        } catch (Throwable ignored) {
            return false;
        }
    }
}
