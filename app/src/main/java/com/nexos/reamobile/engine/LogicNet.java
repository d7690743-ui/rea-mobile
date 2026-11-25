package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OMEGA red lógica: consultas de conectividad sobre {@link RefGraph}
 * (entradas, alcanzabilidad, cadenas entrada→API sensible, hubs).
 * No analiza DEX ni infiere llamadas: todo sale del grafo ya construido.
 * Java puro. Nunca lanza.
 */
public final class LogicNet {
    private LogicNet() {
    }

    public static final int DEFAULT_DEPTH = 8;
    public static final int DEFAULT_MAX_NODES = 2000;
    public static final int DEFAULT_MAX_CHAINS = 10;
    public static final int MAX_CHAIN_VISIT = 5000;

    /** Nombres de método tratados como puntos de entrada (heurística). */
    public static final String[] ENTRY_METHODS = {
            "onCreate", "onStart", "onResume", "onPause", "onStop", "onRestart", "onDestroy",
            "onBind", "onStartCommand", "onHandleIntent", "onReceive",
            "onClick", "onItemClick", "onCheckedChanged", "run",
    };

    /** Alcanzables desde una entrada + si hubo recorte. Nunca lanza. */
    public static class Reach {
        public List<String> nodes = new ArrayList<>();
        public boolean truncated;
    }

    /** Cadenas entrada→objetivo + si hubo recorte. Nunca lanza. */
    public static class Chains {
        public List<List<String>> chains = new ArrayList<>();
        public boolean truncated;
    }

    /** Nombre simple de "Lcom/x/A;->foo". Nunca lanza. */
    public static String simpleName(String methodKey) {
        try {
            if (methodKey == null) return "?";
            return RefGraph.split(methodKey)[1];
        } catch (Throwable ignored) {
            return "?";
        }
    }

    /** true si el nombre simple es punto de entrada conocido. Nunca lanza. */
    public static boolean isEntryName(String name) {
        try {
            if (name == null) return false;
            for (String e : ENTRY_METHODS) {
                if (e.equals(name)) return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /** Entradas del grafo (llamadores con nombre de entrada), en orden. Nunca lanza. */
    public static List<String> entryPoints(RefGraph g) {
        List<String> out = new ArrayList<>();
        try {
            if (g == null) return out;
            Set<String> seen = new HashSet<>();
            for (RefGraph.RefEdge e : g.edges()) {
                if (e == null || e.caller == null || !seen.add(e.caller)) continue;
                if (isEntryName(simpleName(e.caller))) out.add(e.caller);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Métodos alcanzables desde la entrada (sin incluirla), BFS con topes.
     * maxDepth<=0 usa DEFAULT_DEPTH; maxNodes<=0 usa DEFAULT_MAX_NODES.
     * Nunca lanza.
     */
    public static Reach reachableFrom(RefGraph g, String entry, int maxDepth, int maxNodes) {
        Reach r = new Reach();
        try {
            if (g == null || entry == null || entry.isEmpty()) return r;
            int depth = maxDepth <= 0 ? DEFAULT_DEPTH : maxDepth;
            int cap = maxNodes <= 0 ? DEFAULT_MAX_NODES : maxNodes;
            Set<String> seen = new HashSet<>();
            seen.add(entry);
            List<String> frontier = new ArrayList<>();
            frontier.add(entry);
            int d = 0;
            while (!frontier.isEmpty() && d < depth) {
                List<String> next = new ArrayList<>();
                for (String m : frontier) {
                    List<String> out;
                    try {
                        out = g.calleesOf(m);
                    } catch (Throwable ignored) {
                        continue;
                    }
                    if (out == null) continue;
                    for (String c : out) {
                        if (c == null || !seen.add(c)) continue;
                        if (r.nodes.size() >= cap) {
                            r.truncated = true;
                            return r;
                        }
                        r.nodes.add(c);
                        next.add(c);
                    }
                }
                frontier = next;
                d++;
            }
            // Profundidad agotada con frontera viva: puede haber más.
            if (d >= depth && !frontier.isEmpty()) {
                for (String m : frontier) {
                    List<String> out = null;
                    try {
                        out = g.calleesOf(m);
                    } catch (Throwable ignored) {
                    }
                    if (out == null) continue;
                    for (String c : out) {
                        if (c != null && !seen.contains(c)) {
                            r.truncated = true;
                            return r;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return r;
    }

    /**
     * Cadenas entrada→…→objetivo (DFS inverso desde el método `target`, clave
     * completa `Lcom/x/A;->foo`). Solo cadenas completas (raíz en entrada).
     * maxDepth = aristas máximas por cadena (<=0: DEFAULT_DEPTH);
     * maxChains<=0 usa DEFAULT_MAX_CHAINS. Nunca lanza.
     */
    public static Chains chainsTo(RefGraph g, String target, int maxDepth, int maxChains) {
        Chains r = new Chains();
        try {
            if (g == null || target == null || target.isEmpty()) return r;
            int depth = maxDepth <= 0 ? DEFAULT_DEPTH : maxDepth;
            int cap = maxChains <= 0 ? DEFAULT_MAX_CHAINS : maxChains;
            List<String> targets = new ArrayList<>();
            if (!g.callersOf(target).isEmpty()) {
                targets.add(target);
            } else if (g.containsMethod(target) && isEntryName(simpleName(target))) {
                targets.add(target); // solo-llamador que es entrada: cadena trivial.
            }
            Search st = new Search();
            st.cap = cap;
            st.depth = depth;
            for (String t : targets) {
                List<String> path = new ArrayList<>();
                path.add(t);
                Set<String> inPath = new HashSet<>();
                inPath.add(t);
                if (!dfs(g, path, inPath, r, st)) break;
            }
            r.truncated = st.cut;
        } catch (Throwable ignored) {
        }
        return r;
    }

    private static class Search {
        int cap;
        int depth;
        int visited;
        boolean cut;
    }

    /** DFS inverso; false = abortar todo (topes). Nunca lanza. */
    private static boolean dfs(RefGraph g, List<String> path, Set<String> inPath,
                               Chains r, Search st) {
        try {
            if (r.chains.size() >= st.cap) {
                st.cut = true;
                return false;
            }
            if (++st.visited > MAX_CHAIN_VISIT) {
                st.cut = true;
                return false;
            }
            String head = path.get(0);
            if (isEntryName(simpleName(head))) {
                r.chains.add(new ArrayList<>(path));
                return true;
            }
            int edges = path.size() - 1;
            List<String> callers;
            try {
                callers = g.callersOf(head);
            } catch (Throwable ignored) {
                return true;
            }
            if (callers == null || callers.isEmpty()) return true;
            if (edges >= st.depth) {
                st.cut = true;
                return true;
            }
            for (String c : callers) {
                if (c == null || inPath.contains(c)) continue;
                path.add(0, c);
                inPath.add(c);
                boolean ok = dfs(g, path, inPath, r, st);
                path.remove(0);
                inPath.remove(c);
                if (!ok) return false;
            }
            return true;
        } catch (Throwable ignored) {
            return true;
        }
    }

    /** Grupo de cadenas que comparten cola (todo menos la entrada). Nunca lanza. */
    public static class TrunkGroup {
        public List<String> first = new ArrayList<>();
        public List<String> entries = new ArrayList<>();
    }

    /**
     * Agrupa cadenas por cola común (orden de aparición). Nunca lanza.
     */
    public static List<TrunkGroup> groupByTrunk(List<List<String>> chains) {
        List<TrunkGroup> out = new ArrayList<>();
        try {
            if (chains == null) return out;
            Map<String, TrunkGroup> byKey = new LinkedHashMap<>();
            for (List<String> c : chains) {
                if (c == null || c.isEmpty()) continue;
                String key;
                if (c.size() > 1) {
                    StringBuilder k = new StringBuilder();
                    for (int i = 1; i < c.size(); i++) k.append('\0').append(c.get(i));
                    key = k.toString();
                } else {
                    key = c.get(0);
                }
                TrunkGroup g = byKey.get(key);
                if (g == null) {
                    g = new TrunkGroup();
                    g.first.addAll(c);
                    byKey.put(key, g);
                    out.add(g);
                }
                String e = c.get(0);
                if (e != null && !g.entries.contains(e)) g.entries.add(e);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Top llamados por nº de llamadores distintos (desempate alfabético).
     * Espejo de RefGraph.topCallers. Nunca lanza.
     */
    public static List<String> topCallees(RefGraph g, int n) {
        try {
            if (g == null) return new ArrayList<String>();
            int cap = n <= 0 ? 5 : Math.min(n, 50);
            Map<String, Set<String>> fan = new LinkedHashMap<String, Set<String>>();
            for (RefGraph.RefEdge e : g.edges()) {
                if (e == null || e.caller == null || e.callee == null) continue;
                Set<String> s = fan.get(e.callee);
                if (s == null) {
                    s = new LinkedHashSet<String>();
                    fan.put(e.callee, s);
                }
                s.add(e.caller);
            }
            List<String> keys = new ArrayList<String>(fan.keySet());
            final Map<String, Set<String>> f = fan;
            Collections.sort(keys, new Comparator<String>() {
                @Override
                public int compare(String a, String b) {
                    int sa = f.containsKey(a) ? f.get(a).size() : 0;
                    int sb = f.containsKey(b) ? f.get(b).size() : 0;
                    if (sa != sb) return sb - sa;
                    return a.compareTo(b);
                }
            });
            if (keys.size() > cap) keys = keys.subList(0, cap);
            return keys;
        } catch (Throwable ignored) {
            return new ArrayList<String>();
        }
    }
}
