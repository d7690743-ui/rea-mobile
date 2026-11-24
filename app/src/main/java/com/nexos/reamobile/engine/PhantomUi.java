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
        public String dex = "?";
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
                if (en.getValue() != null && en.getValue().dex != null) cv.dex = en.getValue().dex;
                cv.layoutId = layoutArg(graph, en.getKey(), parts, flowIrs);
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

    /** Líneas para el informe. Nunca lanza. */
    public static List<String> summarize(UiResult r) {
        List<String> out = new ArrayList<>();
        try {
            if (r == null) return out;
            for (ContentView cv : r.contentViews) {
                if (cv == null) continue;
                StringBuilder sb = new StringBuilder();
                sb.append(cv.className).append(" setContentView(");
                sb.append(cv.layoutId.isEmpty() ? "?" : cv.layoutId).append(')');
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
}
