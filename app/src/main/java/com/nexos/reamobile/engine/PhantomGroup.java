package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * PHANTOM agrupador: entry→pantalla→subgrafo→red→permisos (FN-##). Convierte
 * el inventario suelto (URLs, aristas, consts) en funciones candidatas con
 * piezas enlazadas y estado por campo. Todo sobre índices OMEGA/ALFA, con
 * muestras retenidas (no subgrafos completos) para no crecer en memoria.
 * Nunca lanza.
 */
public final class PhantomGroup {
    private PhantomGroup() {
    }

    public static final int MAX_FUNCS = 60;
    public static final int MAX_DEPTH = 3;
    public static final int MAX_METHODS_SCAN = 150;
    public static final int MAX_METHODS_KEEP = 20;
    public static final int MAX_URLS = 10;
    public static final int MAX_PERMS = 8;
    public static final int MAX_SCREENS = 5;

    /** Estados de campo (estilo §0.1 RAG simplificado). */
    public static final int FALTA = 0;
    public static final int PARCIAL = 1;
    public static final int OK = 2;

    /** Los 8 campos mínimos de docs/RECONSTRUCCION.md, en orden. */
    public static final String[] FIELDS = {"entradas", "pantallas", "llamadas", "datos",
            "permisos", "red", "almacenamiento", "nativas"};

    /** Función candidata con piezas enlazadas. Nunca lanza. */
    public static class FuncGroup {
        public String id = "?";
        public String name = "?";
        public List<String> entries = new ArrayList<>();
        public List<String> methodSample = new ArrayList<>();
        public int methodTotal;
        public int callsOwn;
        public int callsFw;
        public List<String> urls = new ArrayList<>();
        public List<String> perms = new ArrayList<>();
        public List<String> screens = new ArrayList<>();
        public int[] states = new int[8];
    }

    private static final String[] LIFECYCLE = {"onCreate", "onStart", "onResume",
            "onPause", "onStop", "onDestroy", "onClick", "onReceive", "onBind",
            "onHandleIntent", "onCreateView", "onViewCreated", "attachBaseContext"};

    /**
     * Ordena entradas: ciclo de vida primero, sintéticos (lambdas, accessors)
     * al final. Estable y determinista. Nunca null ni lanza.
     */
    static List<String> orderEntries(List<String> entries) {
        List<String> ordered = new ArrayList<>();
        try {
            if (entries == null) return ordered;
            List<String> life = new ArrayList<>();
            List<String> plain = new ArrayList<>();
            List<String> synth = new ArrayList<>();
            for (String e : entries) {
                if (e == null) continue;
                String m = RefGraph.split(e)[1];
                if (isLifecycle(m)) life.add(e);
                else if (isSynthetic(m)) synth.add(e);
                else plain.add(e);
            }
            ordered.addAll(life);
            ordered.addAll(plain);
            ordered.addAll(synth);
        } catch (Throwable ignored) {
        }
        return ordered;
    }

    private static boolean isLifecycle(String m) {
        try {
            if (m == null) return false;
            for (String l : LIFECYCLE) {
                if (l.equals(m)) return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean isSynthetic(String m) {
        try {
            if (m == null) return false;
            return m.indexOf('$') >= 0 || m.indexOf("lambda$") >= 0
                    || m.startsWith("access$") || m.indexOf("-") >= 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Agrupa desde entradas verificadas ALFA. contentViews sirve para cruzar
     * pantallas (puede ser null). Nunca null ni lanza.
     */
    public static List<FuncGroup> group(RefGraph graph, Set<String> manifestClasses,
                                        List<String> urls, StringRefs stringRefs,
                                        Map<String, String> callerPerm,
                                        List<PhantomUi.ContentView> contentViews) {
        List<FuncGroup> out = new ArrayList<>();
        try {
            if (graph == null) return out;
            List<String> entries = orderEntries(
                    AlfaUi.verifiedEntries(graph, manifestClasses));
            Map<String, String> classToLayout = new LinkedHashMap<>();
            if (contentViews != null) {
                for (PhantomUi.ContentView cv : contentViews) {
                    if (cv == null || cv.className == null) continue;
                    String prev = classToLayout.get(cv.className);
                    if (prev == null) {
                        classToLayout.put(cv.className,
                                cv.layoutId == null ? "" : cv.layoutId);
                    } else if (prev.isEmpty() && cv.layoutId != null
                            && !cv.layoutId.isEmpty()) {
                        classToLayout.put(cv.className, cv.layoutId);
                    }
                }
            }
            int n = 0;
            for (String entry : entries) {
                if (entry == null || n >= MAX_FUNCS) break;
                FuncGroup g = new FuncGroup();
                g.id = String.format("FN-%02d", n + 1);
                g.entries.add(entry);
                g.name = shortName(RefGraph.split(entry)[0]);
                Set<String> seen = new LinkedHashSet<>();
                bfs(graph, entry, seen);
                g.methodTotal = seen.size();
                for (String m : seen) {
                    if (g.methodSample.size() >= MAX_METHODS_KEEP) break;
                    g.methodSample.add(m);
                }
                countCalls(graph, g, seen);
                attachUrls(g, urls, stringRefs, seen);
                attachPerms(g, callerPerm, graph, seen);
                attachScreens(g, classToLayout, seen);
                g.states[0] = OK;
                g.states[2] = g.methodTotal > 1 ? OK : (g.methodTotal == 1 ? PARCIAL : FALTA);
                g.states[4] = g.perms.isEmpty() ? FALTA : OK;
                g.states[5] = g.urls.isEmpty() ? FALTA : OK;
                out.add(g);
                n++;
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static void bfs(RefGraph graph, String root, Set<String> seen) {
        try {
            List<String> frontier = new ArrayList<>();
            frontier.add(root);
            seen.add(root);
            for (int d = 0; d < MAX_DEPTH && seen.size() < MAX_METHODS_SCAN; d++) {
                List<String> next = new ArrayList<>();
                for (String m : frontier) {
                    if (seen.size() >= MAX_METHODS_SCAN) break;
                    for (String c : graph.calleesOf(m)) {
                        if (c == null || !seen.add(c)) continue;
                        if (next.size() < MAX_METHODS_SCAN) next.add(c);
                        if (seen.size() >= MAX_METHODS_SCAN) break;
                    }
                }
                frontier = next;
                if (frontier.isEmpty()) break;
            }
        } catch (Throwable ignored) {
        }
    }

    private static void countCalls(RefGraph graph, FuncGroup g, Set<String> seen) {
        try {
            int own = 0;
            int fw = 0;
            int checked = 0;
            for (String m : seen) {
                if (checked++ >= MAX_METHODS_KEEP) break;
                for (String c : graph.calleesOf(m)) {
                    if (c == null) continue;
                    if (seen.contains(c)) own++;
                    else fw++;
                }
            }
            g.callsOwn = own;
            g.callsFw = fw;
        } catch (Throwable ignored) {
        }
    }

    private static void attachUrls(FuncGroup g, List<String> urls, StringRefs refs,
                                   Set<String> seen) {
        try {
            if (urls == null || refs == null) return;
            int checked = 0;
            for (String u : urls) {
                if (u == null || checked++ >= 50) break;
                if (g.urls.size() >= MAX_URLS) break;
                List<String> users = refs.usersOf(u);
                if (users.isEmpty()) users = refs.usersOfContaining(u, 25);
                for (String m : users) {
                    if (m != null && seen.contains(m)) {
                        g.urls.add(u);
                        break;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void attachPerms(FuncGroup g, Map<String, String> callerPerm,
                                    RefGraph graph, Set<String> seen) {
        try {
            Set<String> perms = new LinkedHashSet<>();
            int checked = 0;
            for (String m : seen) {
                if (checked++ >= MAX_METHODS_KEEP || perms.size() >= MAX_PERMS) break;
                if (callerPerm != null) {
                    String hit = callerPerm.get(m);
                    if (hit != null) {
                        int bar = hit.indexOf('|');
                        perms.add(bar < 0 ? hit : hit.substring(0, bar));
                        continue;
                    }
                }
                for (String c : graph.calleesOf(m)) {
                    String p = PermApiTable.permissionFor(c);
                    if (p != null) perms.add(p);
                    if (perms.size() >= MAX_PERMS) break;
                }
            }
            g.perms.addAll(perms);
        } catch (Throwable ignored) {
        }
    }

    private static void attachScreens(FuncGroup g, Map<String, String> classToLayout,
                                      Set<String> seen) {
        try {
            Set<String> out = new LinkedHashSet<>();
            boolean withId = false;
            for (String m : seen) {
                if (out.size() >= MAX_SCREENS) break;
                String cls = RefGraph.split(m)[0];
                if (!classToLayout.containsKey(cls)) continue;
                String lid = classToLayout.get(cls);
                if (lid != null && !lid.isEmpty()) {
                    out.add(cls + " " + lid);
                    withId = true;
                } else {
                    out.add(cls + " (layout?)");
                }
            }
            g.screens.addAll(out);
            g.states[1] = out.isEmpty() ? FALTA : (withId ? OK : PARCIAL);
        } catch (Throwable ignored) {
        }
    }

    private static String shortName(String desc) {
        try {
            if (desc == null) return "?";
            int s = desc.lastIndexOf('/');
            int e = desc.endsWith(";") ? desc.length() - 1 : desc.length();
            String tail = s < 0 ? desc.substring(0, e) : desc.substring(s + 1, e);
            if (tail.length() > 32) tail = tail.substring(0, 32);
            return tail.isEmpty() ? "?" : tail;
        } catch (Throwable ignored) {
            return "?";
        }
    }

    /** Líneas para el informe. Nunca lanza. */
    public static List<String> summarize(List<FuncGroup> groups) {
        List<String> out = new ArrayList<>();
        try {
            if (groups == null) return out;
            for (FuncGroup g : groups) {
                if (g == null) continue;
                StringBuilder sb = new StringBuilder();
                sb.append(g.id).append(' ').append(g.name);
                sb.append(" met=").append(g.methodTotal);
                sb.append(" llamadas=").append(g.callsOwn).append('+').append(g.callsFw);
                sb.append(" red=").append(g.urls.size());
                sb.append(" perm=").append(g.perms.size());
                sb.append(" pant=").append(g.screens.size());
                sb.append(" [").append(PhantomMetric.score(g)).append("/8]");
                out.add(sb.toString());
            }
        } catch (Throwable ignored) {
        }
        return out;
    }
}
