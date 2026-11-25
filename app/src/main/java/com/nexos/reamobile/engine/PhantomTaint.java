package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * PHANTOM flujo extendido: taint multi-salto + reflexión. Parte del taint
 * OMEGA (1 salto) y encadena hasta 2 saltos extra por el grafo buscando
 * sumideros; además resuelve Class.forName/getMethod con consts de flujo
 * (best-effort, evidencia citada). Nunca lanza.
 */
public final class PhantomTaint {
    private PhantomTaint() {
    }

    public static final int MAX_EXTRA_HOPS = 2;
    public static final int MAX_EXTRA_FLOWS = 10;
    public static final int MAX_REFLECT = 20;
    public static final int MAX_IRS = 100;

    /** Flujo extendido multi-salto. Nunca lanza. */
    public static class XFlow {
        public String source = "?";
        public String sink = "?";
        public String method = "?";
        public List<String> chain = new ArrayList<>();
        public String evidence = "";
    }

    /** Reflexión resuelta por consts. Nunca lanza. */
    public static class ReflectHit {
        public String method = "?";
        public String call = "?";
        public String target = "?";
    }

    /** Resultado de flujo extendido. Nunca lanza. */
    public static class TaintXResult {
        public List<XFlow> extraFlows = new ArrayList<>();
        public List<ReflectHit> reflection = new ArrayList<>();
        public boolean truncated;
    }

    /**
     * Extiende el taint OMEGA (computa la base). Nunca null ni lanza.
     */
    public static TaintXResult extend(Map<String, IrBuilder.MethodIr> flowIrs,
                                      RefGraph graph, Map<String, String> supers,
                                      Map<String, String> flowDex,
                                      Map<String, String> flowStrings) {
        List<Taint.Flow> base = null;
        try {
            if (flowIrs != null && !flowIrs.isEmpty() && graph != null) {
                base = Taint.analyze(flowIrs, graph, supers).flows;
            }
        } catch (Throwable ignored) {
            base = null;
        }
        return extend(flowIrs, graph, supers, flowDex, flowStrings, base);
    }

    /**
     * Variante que reutiliza los flujos base ya computados (p. ej. del
     * FlowSummary memoizado): evita recalcular el taint. Nunca null ni lanza.
     */
    public static TaintXResult extend(Map<String, IrBuilder.MethodIr> flowIrs,
                                      RefGraph graph, Map<String, String> supers,
                                      Map<String, String> flowDex,
                                      Map<String, String> flowStrings,
                                      List<Taint.Flow> baseFlows) {
        return extend(flowIrs, graph, supers, flowDex, flowStrings, baseFlows,
                new IdentityHashMap<IrBuilder.MethodIr, ReachConsts.ConstResult>());
    }

    /** Variante con caché de constantes compartida (PHANTOM). Nunca null ni lanza. */
    public static TaintXResult extend(Map<String, IrBuilder.MethodIr> flowIrs,
                                      RefGraph graph, Map<String, String> supers,
                                      Map<String, String> flowDex,
                                      Map<String, String> flowStrings,
                                      List<Taint.Flow> baseFlows,
                                      Map<IrBuilder.MethodIr, ReachConsts.ConstResult> constCache) {
        TaintXResult r = new TaintXResult();
        try {
            if (flowIrs == null || flowIrs.isEmpty() || graph == null) return r;
            List<Taint.Flow> base = baseFlows;
            if (base == null) {
                try {
                    base = Taint.analyze(flowIrs, graph, supers).flows;
                } catch (Throwable ignored) {
                    base = new ArrayList<Taint.Flow>();
                }
            }
            for (Taint.Flow f : base) {
                if (f == null || r.extraFlows.size() >= MAX_EXTRA_FLOWS) {
                    if (f != null) r.truncated = true;
                    break;
                }
                chainFrom(f, graph, supers, r);
            }
            resolveReflection(flowIrs, graph, flowDex, flowStrings, r, constCache);
        } catch (Throwable ignored) {
        }
        return r;
    }

    private static void chainFrom(Taint.Flow f, RefGraph graph,
                                  Map<String, String> supers, TaintXResult r) {
        try {
            String start = (f.chain == null || f.chain.isEmpty()) ? f.method
                    : f.chain.get(f.chain.size() - 1);
            if (start == null) return;
            Set<String> seen = new LinkedHashSet<>();
            List<String> frontier = new ArrayList<>();
            frontier.add(start);
            seen.add(start);
            MapHop hops = new MapHop();
            hops.put(start, new ArrayList<String>());
            for (int d = 0; d < MAX_EXTRA_HOPS && r.extraFlows.size() < MAX_EXTRA_FLOWS; d++) {
                List<String> next = new ArrayList<>();
                for (String m : frontier) {
                    for (String c : graph.calleesOf(m)) {
                        if (c == null || !seen.add(c)) continue;
                        List<String> path = new ArrayList<>(hops.get(m));
                        path.add(c);
                        hops.put(c, path);
                        String[] parts = RefGraph.split(c);
                        if (Taint.isSink(parts[0], parts[1], supers)) {
                            XFlow x = new XFlow();
                            x.source = f.source == null ? "?" : f.source;
                            x.sink = c;
                            x.method = f.method == null ? "?" : f.method;
                            if (f.chain != null) x.chain.addAll(f.chain);
                            x.chain.addAll(path);
                            x.evidence = "cadena multi-salto (PHANTOM, best-effort)";
                            r.extraFlows.add(x);
                            if (r.extraFlows.size() >= MAX_EXTRA_FLOWS) return;
                        } else if (next.size() < 100) {
                            next.add(c);
                        }
                    }
                }
                frontier = next;
                if (frontier.isEmpty()) break;
            }
        } catch (Throwable ignored) {
        }
    }

    private static void resolveReflection(Map<String, IrBuilder.MethodIr> flowIrs,
                                          RefGraph graph, Map<String, String> flowDex,
                                          Map<String, String> flowStrings,
                                          TaintXResult r,
                                          Map<IrBuilder.MethodIr, ReachConsts.ConstResult> constCache) {
        try {
            int n = 0;
            for (Map.Entry<String, IrBuilder.MethodIr> en : flowIrs.entrySet()) {
                if (en.getKey() == null || en.getValue() == null) continue;
                if (n++ >= MAX_IRS || r.reflection.size() >= MAX_REFLECT) {
                    r.truncated = true;
                    break;
                }
                ReachConsts.ConstResult cr =
                        ReachConsts.analyzeCached(en.getValue(), constCache);
                if (cr == null || cr.callConsts == null) continue;
                for (ReachConsts.CallConst cc : cr.callConsts) {
                    if (cc == null || cc.kind != ReachConsts.Kind.STR) continue;
                    if (r.reflection.size() >= MAX_REFLECT) {
                        r.truncated = true;
                        return;
                    }
                    for (String callee : InterProc.calleesAt(graph, en.getKey(), cc.addr)) {
                        if (callee == null) continue;
                        String call = reflectCall(callee);
                        if (call == null) continue;
                        ReflectHit h = new ReflectHit();
                        h.method = en.getKey();
                        h.call = call;
                        h.target = resolveStr(flowDex, flowStrings, en.getKey(), cc.strRef);
                        r.reflection.add(h);
                        break;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static String reflectCall(String callee) {
        try {
            if (callee == null) return null;
            if (callee.equals("Ljava/lang/Class;->forName")) return "forName";
            if (callee.equals("Ljava/lang/Class;->getMethod")
                    || callee.equals("Ljava/lang/Class;->getDeclaredMethod")) return "getMethod";
            if (callee.equals("Ljava/lang/ClassLoader;->loadClass")) return "loadClass";
            return null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String resolveStr(Map<String, String> flowDex,
                                     Map<String, String> flowStrings,
                                     String caller, int strRef) {
        try {
            String dex = flowDex == null ? null : flowDex.get(caller);
            String v = (flowStrings == null || dex == null) ? null
                    : flowStrings.get(dex + "\u0000" + strRef);
            if (v == null) return "str#" + strRef;
            String t = v.replace('\n', ' ').trim();
            return t.length() > 80 ? t.substring(0, 80) + "…" : t;
        } catch (Throwable ignored) {
            return "?";
        }
    }

    /** Mapa pequeño método→camino (evita LinkedHashMap anidado). Nunca lanza. */
    private static class MapHop {
        private final List<String> keys = new ArrayList<>();
        private final List<List<String>> vals = new ArrayList<>();

        void put(String k, List<String> v) {
            keys.add(k);
            vals.add(v);
        }

        List<String> get(String k) {
            for (int i = 0; i < keys.size(); i++) {
                if (keys.get(i) != null && keys.get(i).equals(k)) return vals.get(i);
            }
            return new ArrayList<>();
        }
    }

    /** Líneas para el informe. Nunca lanza. */
    public static List<String> summarize(TaintXResult r) {
        List<String> out = new ArrayList<>();
        try {
            if (r == null) return out;
            for (XFlow x : r.extraFlows) {
                if (x == null) continue;
                out.add("multisalto: " + x.source + " →…→ " + x.sink
                        + " (" + x.chain.size() + " saltos, " + x.evidence + ")");
            }
            for (ReflectHit h : r.reflection) {
                if (h == null) continue;
                out.add("reflexion: " + h.call + "(\"" + h.target + "\") en " + h.method);
            }
            if (r.truncated) out.add("(flujo-X recortado por topes)");
        } catch (Throwable ignored) {
        }
        return out;
    }
}
