package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OMEGA Fase B: índice en memoria de llamadas entre métodos. No analiza DEX:
 * solo indexa las aristas que le entrega {@link DexCalls} (toda relación está
 * respaldada por una instrucción invoke real; aquí no se infiere nada).
 * Con deduplicación, tope anti-OOM y detección de truncamiento.
 * Java puro. Nunca lanza.
 *
 * <p>Claves de método con el formato de DexCalls: {@code Lcom/x/A;->foo}.</p>
 */
public final class RefGraph {

    public static final int MAX_EDGES = 20000;

    /** Relación llamador→llamado con su sitio de llamada. Nunca lanza. */
    public static class RefEdge {
        public String caller = "?";
        public String callee = "?";
        public String callerClass = "?";
        public String callerMethod = "?";
        public String calleeClass = "?";
        public String calleeMethod = "?";
        public String dex = "?";
        public int pos = -1;
    }

    private final Map<String, RefEdge> edges = new LinkedHashMap<>();
    private final Map<String, Set<String>> forward = new LinkedHashMap<>();
    private final Map<String, Set<String>> backward = new LinkedHashMap<>();
    /** T8: llamador → sus aristas (evita el barrido O(E) de edgesFrom). */
    private final Map<String, List<RefEdge>> fromEdges = new LinkedHashMap<>();
    private final Set<String> nodes = new LinkedHashSet<>();
    private final int maxEdges;
    private int dropped;

    public RefGraph() {
        this(MAX_EDGES);
    }

    /** Variante con tope inyectable (tests). */
    RefGraph(int maxEdges) {
        this.maxEdges = maxEdges <= 0 ? MAX_EDGES : maxEdges;
    }

    /** Construye el índice desde aristas de DexCalls. Nunca lanza. */
    public static RefGraph from(List<DexCalls.Edge> in) {
        return from(in, MAX_EDGES);
    }

    /** Variante con tope inyectable (tests). Nunca lanza. */
    static RefGraph from(List<DexCalls.Edge> in, int maxEdges) {
        RefGraph g = new RefGraph(maxEdges);
        g.addAll(in);
        return g;
    }

    /** Añade una arista (deduplicada). false si se descartó. Nunca lanza. */
    public boolean add(DexCalls.Edge e) {
        try {
            if (e == null) {
                dropped++;
                return false;
            }
            String caller = e.caller == null ? "?" : e.caller;
            String callee = e.callee == null ? "?" : e.callee;
            if ("?".equals(caller) || "?".equals(callee)) {
                dropped++;
                return false;
            }
            String dex = e.dex == null ? "?" : e.dex;
            String key = caller + "\u0000" + callee + "\u0000" + dex + "\u0000" + e.pos;
            if (edges.containsKey(key)) return true;
            if (edges.size() >= maxEdges) {
                dropped++;
                return false;
            }
            RefEdge re = new RefEdge();
            re.caller = caller;
            re.callee = callee;
            String[] a = split(caller);
            re.callerClass = a[0];
            re.callerMethod = a[1];
            String[] b = split(callee);
            re.calleeClass = b[0];
            re.calleeMethod = b[1];
            re.dex = dex;
            re.pos = e.pos;
            edges.put(key, re);
            link(forward, caller, callee);
            link(backward, callee, caller);
            List<RefEdge> fl = fromEdges.get(caller);
            if (fl == null) {
                fl = new ArrayList<>();
                fromEdges.put(caller, fl);
            }
            fl.add(re);
            nodes.add(caller);
            nodes.add(callee);
            return true;
        } catch (Throwable ignored) {
            dropped++;
            return false;
        }
    }

    /** Añade una lista; devuelve cuántas se guardaron. Nunca lanza. */
    public int addAll(List<DexCalls.Edge> in) {
        int n = 0;
        try {
            if (in == null) return 0;
            for (DexCalls.Edge e : in) {
                if (add(e)) n++;
            }
        } catch (Throwable ignored) {
        }
        return n;
    }

    /** Llamadores distintos de un método, en orden de aparición. Nunca lanza. */
    public List<String> callersOf(String method) {
        return copySet(backward.get(method));
    }

    /** Llamados distintos desde un método, en orden de aparición. Nunca lanza. */
    public List<String> calleesOf(String method) {
        return copySet(forward.get(method));
    }

    /** Aristas de un llamador (índice; copia en orden de aparición). Nunca lanza. */
    public List<RefEdge> edgesFromKey(String caller) {
        try {
            if (caller == null) return new ArrayList<>();
            List<RefEdge> l = fromEdges.get(caller);
            if (l == null) return new ArrayList<>();
            return new ArrayList<>(l);
        } catch (Throwable ignored) {
            return new ArrayList<>();
        }
    }

    /** Sitios de llamada de una clase+método. Nunca lanza. */
    public List<RefEdge> edgesFrom(String cls, String method) {
        try {
            if (cls == null || method == null) return new ArrayList<>();
            return edgesFromKey(cls + "->" + method);
        } catch (Throwable ignored) {
            return new ArrayList<>();
        }
    }

    /** true si el método aparece como llamador o llamado. Nunca lanza. */
    public boolean containsMethod(String method) {
        try {
            return method != null && nodes.contains(method);
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Top llamadores por nº de llamados distintos (desempate alfabético).
     * Diagnóstico acotado para el informe. Nunca lanza.
     */
    public List<String> topCallers(int n) {
        try {
            int cap = n <= 0 ? 5 : Math.min(n, 50);
            List<String> keys = new ArrayList<>(forward.keySet());
            Collections.sort(keys, new Comparator<String>() {
                @Override
                public int compare(String a, String b) {
                    int sa = forward.containsKey(a) ? forward.get(a).size() : 0;
                    int sb = forward.containsKey(b) ? forward.get(b).size() : 0;
                    if (sa != sb) return sb - sa;
                    return a.compareTo(b);
                }
            });
            if (keys.size() > cap) keys = keys.subList(0, cap);
            return keys;
        } catch (Throwable ignored) {
            return new ArrayList<>();
        }
    }

    /** Todas las aristas (copia, orden de aparición). Nunca lanza. */
    public List<RefEdge> edges() {
        try {
            return new ArrayList<>(edges.values());
        } catch (Throwable ignored) {
            return new ArrayList<>();
        }
    }

    public int nodeCount() {
        return nodes.size();
    }

    public int edgeCount() {
        return edges.size();
    }

    public int dropped() {
        return dropped;
    }

    public boolean truncated() {
        return dropped > 0;
    }

    private static void link(Map<String, Set<String>> m, String k, String v) {
        Set<String> s = m.get(k);
        if (s == null) {
            s = new LinkedHashSet<>();
            m.put(k, s);
        }
        s.add(v);
    }

    private static List<String> copySet(Set<String> s) {
        try {
            if (s == null) return new ArrayList<>();
            return new ArrayList<>(s);
        } catch (Throwable ignored) {
            return new ArrayList<>();
        }
    }

    /**
     * Parte "Lcom/x/A;->foo" en ["Lcom/x/A;", "foo"], conservando el
     * descriptor completo como en el resto del motor. Robusto ante rarezas.
     */
    static String[] split(String ref) {
        try {
            if (ref == null) return new String[]{"?", "?"};
            int a = ref.indexOf(";->");
            if (a < 0) return new String[]{"?", ref};
            return new String[]{ref.substring(0, a + 1), ref.substring(a + 3)};
        } catch (Throwable ignored) {
            return new String[]{"?", "?"};
        }
    }
}
