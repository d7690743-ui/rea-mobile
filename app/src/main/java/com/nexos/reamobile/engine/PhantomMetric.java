package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * PHANTOM métrica: completitud reconstructiva por función
 * (campos OK / 8) y distribución por APK. Cruza cada grupo con los
 * hallazgos de datos/almacenamiento/nativo (sobre muestras retenidas,
 * coste acotado). Nunca lanza.
 */
public final class PhantomMetric {
    private PhantomMetric() {
    }

    /** Nº de campos OK de un grupo (0-8). Nunca lanza. */
    public static int score(PhantomGroup.FuncGroup g) {
        try {
            if (g == null || g.states == null) return 0;
            int n = 0;
            for (int s : g.states) {
                if (s == PhantomGroup.OK) n++;
            }
            return n;
        } catch (Throwable ignored) {
            return 0;
        }
    }

    /**
     * Completa estados de datos (3), almacenamiento (6) y nativas (7)
     * cruzando con hallazgos PHANTOM/ALFA. Nunca lanza.
     */
    public static void completeStates(List<PhantomGroup.FuncGroup> groups,
                                      List<PhantomData.DataHit> data,
                                      List<PhantomStore.StoreHit> store,
                                      List<AlfaJni.JniLink> jniLinks,
                                      List<PhantomJni.DynLink> dynLinks) {
        completeStates(groups, data, store, jniLinks, dynLinks, null);
    }

    /**
     * Variante P2.1b con grafo: además del cruce por muestra (barato),
     * cierre exacto por grupo (subgrafo depth-3 + clases llamadas, solo
     * transitorio) para que los hallazgos fuera de la muestra también
     * levanten el campo. Nunca lanza.
     */
    public static void completeStates(List<PhantomGroup.FuncGroup> groups,
                                      List<PhantomData.DataHit> data,
                                      List<PhantomStore.StoreHit> store,
                                      List<AlfaJni.JniLink> jniLinks,
                                      List<PhantomJni.DynLink> dynLinks,
                                      RefGraph graph) {
        try {
            if (groups == null) return;
            for (PhantomGroup.FuncGroup g : groups) {
                if (g == null) continue;
                Closure c = graph == null ? null : closureFor(graph, g);
                g.states[3] = matchData(g, data, c);
                g.states[6] = matchStore(g, store, c);
                g.states[7] = matchNative(g, jniLinks, dynLinks, c);
            }
        } catch (Throwable ignored) {
        }
    }

    /** Cierre transitorio de un grupo (no se retiene). Nunca lanza. */
    static class Closure {
        final Set<String> methods = new LinkedHashSet<>();
        final Set<String> calleeClasses = new LinkedHashSet<>();
    }

    /**
     * Subgrafo depth-N desde las entradas + clases llamadas por él
     * (caza modelos/helpers usados aunque el framework los invoque).
     * Misma profundidad que el agrupador; topes 150/500.
     * Nunca null ni lanza.
     */
    static Closure closureFor(RefGraph graph, PhantomGroup.FuncGroup g) {
        Closure c = new Closure();
        try {
            if (graph == null || g == null || g.entries == null) return c;
            List<String> frontier = new ArrayList<>();
            for (String e : g.entries) {
                if (e != null && c.methods.add(e) && frontier.size() < 150) {
                    frontier.add(e);
                }
            }
            int depth = PhantomGroup.MAX_DEPTH;
            if (depth < 1 || depth > 8) depth = 5;
            for (int d = 0; d < depth && c.methods.size() < 150; d++) {
                List<String> next = new ArrayList<>();
                for (String m : frontier) {
                    if (c.methods.size() >= 150) break;
                    for (String cal : graph.calleesOf(m)) {
                        if (cal == null || !c.methods.add(cal)) continue;
                        if (next.size() < 150) next.add(cal);
                        if (c.methods.size() >= 150) break;
                    }
                }
                frontier = next;
                if (frontier.isEmpty()) break;
            }
            for (String m : c.methods) {
                if (c.calleeClasses.size() >= 500) break;
                for (String cal : graph.calleesOf(m)) {
                    if (cal == null) continue;
                    int a = cal.indexOf(";->");
                    if (a > 0 && c.calleeClasses.size() < 500) {
                        c.calleeClasses.add(cal.substring(0, a + 1));
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return c;
    }

    /** Método usuario citado en la evidencia ("…por Lcom/x;->m"), o null. */
    static String evidenceUser(String evidence) {
        try {
            if (evidence == null) return null;
            int p = evidence.indexOf("por ");
            if (p < 0) return null;
            String m = evidence.substring(p + 4).trim();
            int sp = m.indexOf(' ');
            if (sp > 0) m = m.substring(0, sp);
            return m.contains(";->") ? m : null;
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** Clase de un descriptor o de "Lcls;->m". "" si no hay. Nunca lanza. */
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

    private static int matchData(PhantomGroup.FuncGroup g, List<PhantomData.DataHit> data,
                                 Closure c) {
        try {
            if (data == null) return PhantomGroup.FALTA;
            boolean partial = false;
            for (PhantomData.DataHit h : data) {
                if (h == null) continue;
                if (mentions(h.detail, h.evidence, g)) {
                    if ("modelo?".equals(h.kind)) partial = true;
                    else return PhantomGroup.OK;
                }
                if (c != null && inClosure(h.detail, h.evidence, c)) {
                    if ("modelo?".equals(h.kind)) partial = true;
                    else return PhantomGroup.OK;
                }
            }
            return partial ? PhantomGroup.PARCIAL : PhantomGroup.FALTA;
        } catch (Throwable ignored) {
            return PhantomGroup.FALTA;
        }
    }

    private static int matchStore(PhantomGroup.FuncGroup g, List<PhantomStore.StoreHit> store,
                                  Closure c) {
        try {
            if (store == null) return PhantomGroup.FALTA;
            boolean partial = false;
            for (PhantomStore.StoreHit h : store) {
                if (h == null) continue;
                if (mentions(h.detail, h.evidence, g)) {
                    if ("prefs".equals(h.kind) && "?".equals(h.detail)) partial = true;
                    else return PhantomGroup.OK;
                }
                if (c != null && inClosure(h.detail, h.evidence, c)) {
                    if ("prefs".equals(h.kind) && "?".equals(h.detail)) partial = true;
                    else return PhantomGroup.OK;
                }
            }
            return partial ? PhantomGroup.PARCIAL : PhantomGroup.FALTA;
        } catch (Throwable ignored) {
            return PhantomGroup.FALTA;
        }
    }

    /**
     * true si el hallazgo pertenece al cierre: método en el subgrafo,
     * usuario en el subgrafo, o clase usada por el subgrafo. Nunca lanza.
     */
    static boolean inClosure(String detail, String evidence, Closure c) {
        try {
            if (c == null) return false;
            if (detail != null) {
                if (c.methods.contains(detail)) return true;
                String cls = classOf(detail);
                if (!cls.isEmpty() && c.calleeClasses.contains(cls)) return true;
            }
            String u = evidenceUser(evidence);
            if (u != null && c.methods.contains(u)) return true;
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static int matchNative(PhantomGroup.FuncGroup g, List<AlfaJni.JniLink> jniLinks,
                                   List<PhantomJni.DynLink> dynLinks, Closure c) {
        try {
            if (jniLinks != null) {
                for (AlfaJni.JniLink l : jniLinks) {
                    if (l == null || l.callers == null) continue;
                    for (String caller : l.callers) {
                        if (caller == null) continue;
                        if (g.methodSample.contains(caller)) return PhantomGroup.OK;
                        if (c != null && c.methods.contains(caller)) {
                            return PhantomGroup.OK;
                        }
                    }
                }
            }
            if (dynLinks != null) {
                for (PhantomJni.DynLink l : dynLinks) {
                    if (l == null || l.callers == null) continue;
                    for (String caller : l.callers) {
                        if (caller == null) continue;
                        if (g.methodSample.contains(caller)) return PhantomGroup.OK;
                        if (c != null && c.methods.contains(caller)) {
                            return PhantomGroup.OK;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return PhantomGroup.FALTA;
    }

    /** contains() con terminador: ";->foo" no casa con ";->foo2". Nunca lanza. */
    static boolean containsToken(String hay, String needle) {
        try {
            if (hay == null || needle == null || needle.isEmpty()) return false;
            int from = 0;
            while (true) {
                int i = hay.indexOf(needle, from);
                if (i < 0) return false;
                int end = i + needle.length();
                if (end >= hay.length() || !isIdentChar(hay.charAt(end))) return true;
                from = end;
            }
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean isIdentChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '_' || c == '$';
    }

    private static boolean mentions(String detail, String evidence,
                                    PhantomGroup.FuncGroup g) {
        try {
            if (g.methodSample != null) {
                for (String m : g.methodSample) {
                    if (m == null) continue;
                    if (containsToken(detail, m)) return true;
                    if (containsToken(evidence, m)) return true;
                }
            }
            if (g.classSample != null) {
                for (String cls : g.classSample) {
                    if (cls == null || "?".equals(cls)) continue;
                    if (detail != null && detail.contains(cls)) return true;
                    if (evidence != null && evidence.contains(cls)) return true;
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /** Distribución "12 funciones ≥6/8, 30 funciones ≤3/8". Nunca lanza. */
    public static String distribution(List<PhantomGroup.FuncGroup> groups) {
        try {
            if (groups == null || groups.isEmpty()) return "0 funciones";
            int hi = 0;
            int mid = 0;
            int lo = 0;
            for (PhantomGroup.FuncGroup g : groups) {
                int s = score(g);
                if (s >= 6) hi++;
                else if (s >= 4) mid++;
                else lo++;
            }
            return groups.size() + " funciones: " + hi + " ≥6/8, " + mid + " 4-5/8, "
                    + lo + " ≤3/8";
        } catch (Throwable ignored) {
            return "?";
        }
    }

    /** Líneas para el informe. Nunca lanza. */
    public static List<String> summarize(List<PhantomGroup.FuncGroup> groups) {
        List<String> out = new ArrayList<>();
        try {
            out.add("completitud: " + distribution(groups));
            if (groups != null) {
                for (PhantomGroup.FuncGroup g : groups) {
                    if (g == null) continue;
                    StringBuilder sb = new StringBuilder();
                    sb.append(g.id).append(" [").append(score(g)).append("/8]");
                    for (int i = 0; i < 8; i++) {
                        sb.append(' ').append(PhantomGroup.FIELDS[i]).append('=');
                        int st = g.states == null || i >= g.states.length ? 0 : g.states[i];
                        sb.append(st == PhantomGroup.OK ? "OK"
                                : st == PhantomGroup.PARCIAL ? "~" : "-");
                    }
                    out.add(sb.toString());
                    if (out.size() > 65) break;
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }
}
