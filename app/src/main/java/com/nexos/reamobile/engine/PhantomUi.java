package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * PHANTOM UI: pantallas reales. ALFA parsea layouts; aquí se resuelve quién
 * los usa: llamadores de setContentView (con id de layout cuando la IR lo
 * demuestra), handlers onClick verificados en el grafo y detección de
 * Compose por aristas a androidx/compose. Sin mapa ARSC retenido el id no
 * se traduce a nombre (se declara). Nunca lanza.
 */
public final class PhantomUi {
    private PhantomUi() {
    }

    public static final int MAX_USERS = 60;
    public static final int MAX_HANDLERS = 60;
    public static final int MAX_COMPOSE_CALLERS = 10;

    /** Uso de setContentView con evidencia. Nunca lanza. */
    public static class ContentView {
        public String method = "?";
        public String className = "?";
        public boolean inManifest;
        public String layoutId = "";
        /** P2.5: id por rango R (no verificado en sitio) vs exacto. */
        public boolean layoutApprox;
        /** P2.5: clase que declara el setContentView llamado. */
        public String calleeClass = "?";
        public String dex = "?";
        /** P3.3: nombre ARSC ("layout/main_activity"), "" si no hay mapa. */
        public String layoutName = "";
        /** P3.3: id probado vía LayoutInflater.inflate→setContentView(View). */
        public boolean viaInflate;
        /** P3.3: usa vistas (inflate/findViewById/addView) sin id probado. */
        public boolean programmatic;
    }

    /** Handler onClick verificado en el grafo. Nunca lanza. */
    public static class HandlerUse {
        public String handler = "?";
        public String layout = "?";
        public List<String> methods = new ArrayList<>();
    }

    /** Resultado UI para una pantalla/informe. Nunca lanza. */
    public static class UiResult {
        public List<ContentView> contentViews = new ArrayList<>();
        public List<HandlerUse> handlers = new ArrayList<>();
        public int composeCalls;
        public List<String> composeCallers = new ArrayList<>();
        public boolean truncated;
    }

    /**
     * Resuelve UI sobre los índices OMEGA/ALFA (una pasada al grafo + IRs
     * de los candidatos). Nunca null ni lanza.
     */
    public static UiResult resolve(RefGraph graph, Set<String> manifestClasses,
                                   List<AlfaUi.Screen> screens,
                                   Map<String, IrBuilder.MethodIr> flowIrs) {
        return resolve(graph, manifestClasses, screens, flowIrs, null);
    }

    /**
     * Variante P3.3 con mapa ARSC id→nombre (puede ser null). Cadena de
     * resolución: const en sitio (exacto) → inflate (exacto) → rango R
     * (aprox). Nunca null ni lanza.
     */
    public static UiResult resolve(RefGraph graph, Set<String> manifestClasses,
                                   List<AlfaUi.Screen> screens,
                                   Map<String, IrBuilder.MethodIr> flowIrs,
                                   Map<String, String> arscIds) {
        UiResult r = new UiResult();
        try {
            if (graph == null) return r;
            List<RefGraph.RefEdge> edges = graph.edges();
            Map<String, RefGraph.RefEdge> svcCallers = new LinkedHashMap<>();
            Set<String> composeCallers = new LinkedHashSet<>();
            int composeCalls = 0;
            for (RefGraph.RefEdge e : edges) {
                if (e == null || e.caller == null || e.callee == null) continue;
                if (e.callee.endsWith("->setContentView")) {
                    if (!svcCallers.containsKey(e.caller)) svcCallers.put(e.caller, e);
                } else if (e.callee.startsWith("Landroidx/compose/")) {
                    composeCalls++;
                    if (composeCallers.size() < MAX_COMPOSE_CALLERS) {
                        composeCallers.add(e.caller);
                    }
                }
            }
            r.composeCalls = composeCalls;
            r.composeCallers.addAll(composeCallers);
            int n = 0;
            for (Map.Entry<String, RefGraph.RefEdge> en : svcCallers.entrySet()) {
                if (n >= MAX_USERS) {
                    r.truncated = true;
                    break;
                }
                ContentView cv = new ContentView();
                cv.method = en.getKey();
                String[] parts = RefGraph.split(en.getKey());
                cv.className = parts[0];
                cv.inManifest = manifestClasses != null && manifestClasses.contains(parts[0]);
                if (en.getValue() != null) {
                    if (en.getValue().dex != null) cv.dex = en.getValue().dex;
                    cv.calleeClass = RefGraph.split(en.getValue().callee)[0];
                }
                cv.layoutId = layoutArg(graph, en.getKey(), parts, flowIrs);
                if (cv.layoutId.isEmpty()) {
                    cv.layoutId = layoutViaInflate(graph, en.getKey(), flowIrs);
                    cv.viaInflate = !cv.layoutId.isEmpty();
                }
                if (cv.layoutId.isEmpty()) {
                    cv.layoutId = layoutApprox(flowIrs == null ? null
                            : flowIrs.get(en.getKey()));
                    cv.layoutApprox = !cv.layoutId.isEmpty();
                }
                if (!cv.layoutId.isEmpty()) {
                    cv.layoutName = arscName(arscIds, cv.layoutId);
                } else {
                    cv.programmatic = usesViews(graph, en.getKey());
                }
                r.contentViews.add(cv);
                n++;
            }
            if (screens != null) {
                for (AlfaUi.Screen s : screens) {
                    if (s == null || s.handlers == null) continue;
                    for (String h : s.handlers) {
                        if (h == null || r.handlers.size() >= MAX_HANDLERS) break;
                        List<String> cs = AlfaUi.handlerCallers(graph, h);
                        if (cs.isEmpty()) continue;
                        HandlerUse hu = new HandlerUse();
                        hu.handler = h;
                        hu.layout = s.layout == null ? "?" : s.layout;
                        for (String m : cs) {
                            if (hu.methods.size() >= 3) break;
                            hu.methods.add(m);
                        }
                        r.handlers.add(hu);
                    }
                    if (r.handlers.size() >= MAX_HANDLERS) {
                        r.truncated = true;
                        break;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return r;
    }

    /**
     * Id de layout pasado a setContentView (const int en el mismo sitio de
     * llamada, vía IR + grafo). "" si no se demuestra. Nunca lanza.
     */
    static String layoutArg(RefGraph graph, String caller, String[] parts,
                            Map<String, IrBuilder.MethodIr> flowIrs) {
        try {
            if (graph == null || caller == null || flowIrs == null) return "";
            IrBuilder.MethodIr ir = flowIrs.get(caller);
            if (ir == null) return "";
            ReachConsts.ConstResult cr = ReachConsts.analyze(ir);
            if (cr == null || cr.callConsts == null) return "";
            for (ReachConsts.CallConst cc : cr.callConsts) {
                if (cc == null || cc.kind != ReachConsts.Kind.LIT) continue;
                for (String callee : InterProc.calleesAt(graph, caller, cc.addr)) {
                    if (callee != null && callee.endsWith("->setContentView")) {
                        return String.format("0x%08x", cc.lit);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return "";
    }

    /**
     * Id de layout pasado a LayoutInflater.inflate en el mismo método que
     * llama a setContentView(View): patrón YTM probado (MusicActivity
     * infla 0x7f0e021c=layout/main_activity y entrega el View). Exacto
     * cuando el const alimenta el sitio inflate. "" si no hay. Nunca lanza.
     */
    static String layoutViaInflate(RefGraph graph, String caller,
                                   Map<String, IrBuilder.MethodIr> flowIrs) {
        try {
            if (graph == null || caller == null || flowIrs == null) return "";
            IrBuilder.MethodIr ir = flowIrs.get(caller);
            if (ir == null) return "";
            ReachConsts.ConstResult cr = ReachConsts.analyze(ir);
            if (cr == null || cr.callConsts == null) return "";
            for (ReachConsts.CallConst cc : cr.callConsts) {
                if (cc == null || cc.kind != ReachConsts.Kind.LIT) continue;
                if (cc.lit < 0x7f000000L || cc.lit > 0x7fffffffL) continue;
                for (String callee : InterProc.calleesAt(graph, caller, cc.addr)) {
                    if (isInflate(callee)) {
                        return String.format("0x%08x", cc.lit);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return "";
    }

    private static boolean isInflate(String callee) {
        try {
            return callee != null
                    && callee.startsWith("Landroid/view/LayoutInflater;")
                    && callee.endsWith("->inflate");
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Nombre ARSC de un id ("0x7f0e021c" → "layout/main_activity").
     * "" sin mapa o sin entrada. Nunca lanza.
     */
    static String arscName(Map<String, String> arscIds, String layoutId) {
        try {
            if (arscIds == null || arscIds.isEmpty() || layoutId == null) return "";
            String v = arscIds.get(layoutId.toLowerCase());
            return v == null ? "" : v;
        } catch (Throwable ignored) {
            return "";
        }
    }

    /**
     * true si el llamador toca vistas (inflate/findViewById/addView):
     * pantalla programática probable cuando no hay id. Nunca lanza.
     */
    static boolean usesViews(RefGraph graph, String caller) {
        try {
            if (graph == null || caller == null) return false;
            for (String c : graph.calleesOf(caller)) {
                if (c == null) continue;
                if (c.endsWith("->inflate") || c.endsWith("->findViewById")
                        || c.endsWith("->addView")) return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /**
     * Primer literal en rango R (0x7f000000-0x7fffffff) en la IR: candidato
     * LOW cuando el sitio exacto no se verifica. "" si no hay. Nunca lanza.
     */
    static String layoutApprox(IrBuilder.MethodIr ir) {
        try {
            if (ir == null) return "";
            ReachConsts.ConstResult cr = ReachConsts.analyze(ir);
            if (cr == null || cr.callConsts == null) return "";
            for (ReachConsts.CallConst cc : cr.callConsts) {
                if (cc == null || cc.kind != ReachConsts.Kind.LIT) continue;
                if (cc.lit >= 0x7f000000L && cc.lit <= 0x7fffffffL) {
                    return String.format("0x%08x", cc.lit);
                }
            }
        } catch (Throwable ignored) {
        }
        return "";
    }

    /** Líneas para el informe. Nunca lanza. */
    public static List<String> summarize(UiResult r) {
        List<String> out = new ArrayList<>();
        try {
            if (r == null) return out;
            for (ContentView cv : r.contentViews) {
                if (cv == null) continue;
                StringBuilder sb = new StringBuilder();
                sb.append(cv.className).append(" setContentView(");
                if (cv.layoutId.isEmpty()) {
                    sb.append(cv.programmatic ? "programática?" : '?');
                } else {
                    if (cv.layoutApprox) sb.append('~');
                    sb.append(cv.layoutId);
                    if (cv.layoutName != null && !cv.layoutName.isEmpty()) {
                        sb.append('=').append(cv.layoutName);
                    }
                    if (cv.viaInflate) sb.append(" [inflate]");
                }
                sb.append(')');
                if (cv.calleeClass != null && !"?".equals(cv.calleeClass)) {
                    sb.append(" via ").append(shortName(cv.calleeClass));
                }
                sb.append(cv.inManifest ? " [manifest]" : " [no-manifest]");
                sb.append(" <= ").append(cv.method);
                out.add(sb.toString());
            }
            for (HandlerUse h : r.handlers) {
                if (h == null || h.methods.isEmpty()) continue;
                out.add("handler " + h.handler + " en " + h.layout
                        + " => " + h.methods.get(0));
            }
            if (r.composeCalls > 0) {
                out.add("compose: " + r.composeCalls + " llamadas"
                        + (r.composeCallers.isEmpty() ? ""
                        : " p.ej. " + r.composeCallers.get(0)));
            }
            if (r.truncated) out.add("(ui recortada por topes)");
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static String shortName(String desc) {
        try {
            if (desc == null) return "?";
            int s = desc.lastIndexOf('/');
            int e = desc.endsWith(";") ? desc.length() - 1 : desc.length();
            String t = s < 0 ? desc.substring(0, e) : desc.substring(s + 1, e);
            return t.isEmpty() ? "?" : t;
        } catch (Throwable ignored) {
            return "?";
        }
    }
}
