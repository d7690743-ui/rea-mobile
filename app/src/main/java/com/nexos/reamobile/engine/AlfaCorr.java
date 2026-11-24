package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * ALFA-3 Correlador: une permiso → API → método → destino (URL) usando solo
 * estructuras ya construidas (StringRefs, RefGraph, PermApiTable, urls).
 * No re-parsea nada. Best-effort con topes. Nunca lanza.
 */
public final class AlfaCorr {
    private AlfaCorr() {
    }

    public static final int MAX_URLS = 30;
    public static final int MAX_USERS = 5;
    public static final int MAX_CHAINS = 50;

    /** Una cadena dato→destino con su amparo de permiso. */
    public static class Chain {
        public String destino = "?";
        public String host = "?";
        public String origen = "?";
        public String permiso = "?";
        public boolean permisoDeclarado;
        public boolean permisoRiesgo;
        public String api = "?";
        public List<String> metodos = new ArrayList<>();
    }

    /**
     * Correlaciona cada URL con los métodos que la usan y el permiso de la
     * primera API llamada por esos métodos: mapa exacto, un salto a
     * ayudantes, y amparo directo en el grafo. Tope 30 URLs / 50 cadenas.
     * Nunca null ni lanza.
     */
    public static List<Chain> correlate(List<String> urls, Map<String, String> urlOrigin,
            StringRefs refs, RefGraph graph, List<String> declaredPerms,
            Map<String, String> callerPerm) {
        List<Chain> out = new ArrayList<>();
        try {
            if (urls == null || refs == null || graph == null) return out;
            Set<String> declared = shortNames(declaredPerms);
            int seen = 0;
            for (String u : urls) {
                if (u == null || out.size() >= MAX_CHAINS || seen >= MAX_URLS) break;
                seen++;
                Chain c = new Chain();
                c.destino = u;
                c.host = hostOf(u);
                if (urlOrigin != null && urlOrigin.get(u) != null) {
                    c.origen = urlOrigin.get(u);
                }
                List<String> users;
                try {
                    users = refs.usersOf(u);
                    if (users == null) users = new ArrayList<>();
                    if (users.isEmpty()) {
                        users = refs.usersOfContaining(u);
                        if (users == null) users = new ArrayList<>();
                    }
                } catch (Throwable ignored) {
                    users = new ArrayList<>();
                }
                for (String m : users) {
                    if (c.metodos.size() >= MAX_USERS) break;
                    if (m != null && !c.metodos.contains(m)) c.metodos.add(m);
                }
                // Permiso en 3 pasos: (1) mapa exacto del método usuario,
                // (2) un salto: ayudantes llamados por el usuario en el mapa,
                // (3) amparo directo de los callees en el grafo.
                for (String m : c.metodos) {
                    if (applyMap(c, callerPerm, m)) break;
                }
                if ("?".equals(c.permiso)) {
                    int hops = 0;
                    boolean found = false;
                    for (String m : c.metodos) {
                        List<String> callees = safeCallees(graph, m);
                        for (String cal : callees) {
                            if (hops++ > 25) break;
                            if (applyMap(c, callerPerm, cal)) {
                                found = true;
                                break;
                            }
                        }
                        if (found || hops > 25) break;
                    }
                }
                if ("?".equals(c.permiso)) {
                    for (String m : c.metodos) {
                        boolean found = false;
                        for (String cal : safeCallees(graph, m)) {
                            String p = PermApiTable.permissionFor(cal);
                            if (p != null) {
                                c.permiso = p;
                                c.api = cal;
                                found = true;
                                break;
                            }
                        }
                        if (found) break;
                    }
                }
                c.permisoDeclarado = declared.contains(c.permiso);
                c.permisoRiesgo = PermApiTable.isRisky(c.permiso);
                out.add(c);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Aplica "permiso|api" del mapa a la cadena. Nunca lanza. */
    private static boolean applyMap(Chain c, Map<String, String> callerPerm, String m) {
        try {
            if (c == null || callerPerm == null || m == null) return false;
            String v = callerPerm.get(m);
            if (v == null) return false;
            int bar = v.indexOf('|');
            if (bar <= 0) return false;
            c.permiso = v.substring(0, bar);
            c.api = v.substring(bar + 1);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Callees sin nulls ni excepciones. Nunca null ni lanza. */
    private static List<String> safeCallees(RefGraph graph, String m) {
        try {
            if (graph == null || m == null) return new ArrayList<>();
            List<String> out = graph.calleesOf(m);
            return out == null ? new ArrayList<>() : out;
        } catch (Throwable ignored) {
            return new ArrayList<>();
        }
    }

    /** Nombre corto (tras el último punto) de cada permiso declarado. */
    static Set<String> shortNames(List<String> perms) {
        Set<String> out = new LinkedHashSet<>();
        try {
            if (perms == null) return out;
            for (String p : perms) {
                if (p == null) continue;
                int dot = p.lastIndexOf('.');
                out.add(dot >= 0 ? p.substring(dot + 1) : p);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Host best-effort de una URL, o "?". Nunca lanza. */
    public static String hostOf(String url) {
        try {
            if (url == null) return "?";
            int s = url.indexOf("://");
            if (s < 0) return "?";
            int e = url.indexOf('/', s + 3);
            String h = e < 0 ? url.substring(s + 3) : url.substring(s + 3, e);
            int port = h.indexOf(':');
            if (port >= 0) h = h.substring(0, port);
            return h.isEmpty() ? "?" : h;
        } catch (Throwable ignored) {
            return "?";
        }
    }

    /** Una línea de informe para una cadena. Nunca lanza. */
    public static String summarize(Chain c) {
        try {
            if (c == null) return "?";
            StringBuilder sb = new StringBuilder();
            sb.append("permiso=").append(c.permiso);
            if (c.permisoDeclarado) sb.append("[declarado]");
            if (c.permisoRiesgo) sb.append("[riesgo]");
            sb.append(" api=").append(c.api);
            sb.append(" metodo=").append(c.metodos.isEmpty() ? "?" : c.metodos.get(0));
            if (c.metodos.size() > 1) sb.append("(+").append(c.metodos.size() - 1).append(')');
            sb.append(" destino=").append(c.destino);
            sb.append(" (").append(c.origen).append(')');
            return sb.toString();
        } catch (Throwable ignored) {
            return "?";
        }
    }
}
