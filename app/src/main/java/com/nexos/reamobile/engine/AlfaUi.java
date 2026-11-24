package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ALFA-2: estructura UI. Resume layouts (vistas, ids, handlers onClick,
 * vistas custom, includes) y verifica entradas reales: clases del manifest
 * con métodos presentes en el grafo. Utilidad estática sin estado.
 * Java puro. Nunca lanza.
 *
 * <p>Límites honestos: sin resolver setContentView (no se afirma qué
 * actividad muestra cada layout); los handlers se unen por nombre de
 * método, como las entradas de LogicNet.</p>
 */
public final class AlfaUi {
    private AlfaUi() {
    }

    public static final int MAX_IDS = 20;
    public static final int MAX_HANDLERS = 20;
    public static final int MAX_CUSTOM = 20;
    public static final int MAX_INCLUDES = 10;
    public static final int MAX_ENTRIES = 200;
    public static final int MAX_METHODS_PER_CLASS = 20;

    private static final Pattern TAG = Pattern.compile("<([A-Za-z][\\w.$]*)([^<>]*)/?>");
    private static final Pattern ID = Pattern.compile("android:id=\"@\\+?id/([\\w]+)\"");
    private static final Pattern ONCLICK = Pattern.compile("android:onClick=\"([\\w]+)\"");
    private static final Pattern INCLUDE = Pattern.compile("layout=\"@layout/([\\w]+)\"");

    /** Resumen de un layout. Nunca lanza. */
    public static class Screen {
        public String layout = "?";
        public int views;
        public List<String> ids = new ArrayList<>();
        public List<String> handlers = new ArrayList<>();
        public List<String> customViews = new ArrayList<>();
        public List<String> includes = new ArrayList<>();
    }

    /**
     * Resume un layout decodificado (XML texto). xml nulo/vacío → pantalla
     * vacía con el nombre. Nunca null ni lanza.
     */
    public static Screen parseLayout(String name, String xml) {
        Screen s = new Screen();
        try {
            if (name != null) s.layout = name;
            if (xml == null || xml.isEmpty()) return s;
            Matcher m = TAG.matcher(xml);
            while (m.find()) {
                String tag = m.group(1);
                String attrs = m.group(2) == null ? "" : m.group(2);
                if ("include".equals(tag)) {
                    Matcher mi = INCLUDE.matcher(attrs);
                    if (mi.find() && s.includes.size() < MAX_INCLUDES
                            && !s.includes.contains(mi.group(1))) {
                        s.includes.add(mi.group(1));
                    }
                    continue;
                }
                if ("merge".equals(tag) || "requestFocus".equals(tag)) continue;
                s.views++;
                Matcher mid = ID.matcher(attrs);
                if (mid.find() && s.ids.size() < MAX_IDS && !s.ids.contains(mid.group(1))) {
                    s.ids.add(mid.group(1));
                }
                Matcher mo = ONCLICK.matcher(attrs);
                if (mo.find() && s.handlers.size() < MAX_HANDLERS
                        && !s.handlers.contains(mo.group(1))) {
                    s.handlers.add(mo.group(1));
                }
                if (tag.contains(".") && s.customViews.size() < MAX_CUSTOM
                        && !s.customViews.contains(tag)) {
                    s.customViews.add(tag);
                }
            }
        } catch (Throwable ignored) {
        }
        return s;
    }

    /**
     * Entradas verificadas: métodos de clases del manifest presentes como
     * llamadores en el grafo (tienen código que llama). Orden: clases en
     * orden dado, métodos en orden de aparición. Tope MAX_ENTRIES.
     * Nunca null ni lanza.
     */
    public static List<String> verifiedEntries(RefGraph graph, Set<String> manifestClasses) {
        List<String> out = new ArrayList<>();
        try {
            if (graph == null || manifestClasses == null || manifestClasses.isEmpty()) return out;
            Set<String> callers = new LinkedHashSet<>();
            for (RefGraph.RefEdge e : graph.edges()) {
                if (e != null && e.caller != null) callers.add(e.caller);
            }
            for (String cls : manifestClasses) {
                if (cls == null || out.size() >= MAX_ENTRIES) break;
                String prefix = cls + "->";
                int perClass = 0;
                for (String c : callers) {
                    if (out.size() >= MAX_ENTRIES || perClass >= MAX_METHODS_PER_CLASS) break;
                    if (c.startsWith(prefix) && !out.contains(c)) {
                        out.add(c);
                        perClass++;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Llamadores cuyo método coincide en nombre (para handlers onClick).
     * Unión por nombre: documentado como aproximado. Tope 5.
     * Nunca null ni lanza.
     */
    public static List<String> handlerCallers(RefGraph graph, String method) {
        List<String> out = new ArrayList<>();
        try {
            if (graph == null || method == null || method.isEmpty()) return out;
            String suffix = "->" + method;
            for (RefGraph.RefEdge e : graph.edges()) {
                if (out.size() >= 5) break;
                if (e != null && e.caller != null && e.caller.endsWith(suffix)
                        && !out.contains(e.caller)) {
                    out.add(e.caller);
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Clases exportadas del manifest como descriptores ("activity:com.x.F"
     * → "Lcom/x/F;"). exported con formato "tipo:nombre". Nunca null.
     */
    public static Set<String> exportedDescriptors(List<String> exported, String pkg) {
        Set<String> out = new LinkedHashSet<>();
        try {
            if (exported == null) return out;
            for (String e : exported) {
                if (e == null) continue;
                int c = e.indexOf(':');
                String raw = c >= 0 ? e.substring(c + 1) : e;
                String d = ManifestChecks.resolveDescriptor(raw, pkg);
                if (d != null) out.add(d);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }
}
