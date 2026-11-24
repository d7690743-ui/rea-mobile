package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.List;

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
        try {
            if (groups == null) return;
            for (PhantomGroup.FuncGroup g : groups) {
                if (g == null) continue;
                g.states[3] = matchData(g, data);
                g.states[6] = matchStore(g, store);
                g.states[7] = matchNative(g, jniLinks, dynLinks);
            }
        } catch (Throwable ignored) {
        }
    }

    private static int matchData(PhantomGroup.FuncGroup g, List<PhantomData.DataHit> data) {
        try {
            if (data == null) return PhantomGroup.FALTA;
            boolean partial = false;
            for (PhantomData.DataHit h : data) {
                if (h == null) continue;
                if (mentions(h.detail, h.evidence, g)) {
                    if ("modelo?".equals(h.kind)) partial = true;
                    else return PhantomGroup.OK;
                }
            }
            return partial ? PhantomGroup.PARCIAL : PhantomGroup.FALTA;
        } catch (Throwable ignored) {
            return PhantomGroup.FALTA;
        }
    }

    private static int matchStore(PhantomGroup.FuncGroup g, List<PhantomStore.StoreHit> store) {
        try {
            if (store == null) return PhantomGroup.FALTA;
            boolean partial = false;
            for (PhantomStore.StoreHit h : store) {
                if (h == null) continue;
                if (mentions(h.detail, h.evidence, g)) {
                    if ("prefs".equals(h.kind) && "?".equals(h.detail)) partial = true;
                    else return PhantomGroup.OK;
                }
            }
            return partial ? PhantomGroup.PARCIAL : PhantomGroup.FALTA;
        } catch (Throwable ignored) {
            return PhantomGroup.FALTA;
        }
    }

    private static int matchNative(PhantomGroup.FuncGroup g, List<AlfaJni.JniLink> jniLinks,
                                   List<PhantomJni.DynLink> dynLinks) {
        try {
            if (jniLinks != null) {
                for (AlfaJni.JniLink l : jniLinks) {
                    if (l == null || l.callers == null) continue;
                    for (String c : l.callers) {
                        if (c != null && g.methodSample.contains(c)) return PhantomGroup.OK;
                    }
                }
            }
            if (dynLinks != null) {
                for (PhantomJni.DynLink l : dynLinks) {
                    if (l == null || l.callers == null) continue;
                    for (String c : l.callers) {
                        if (c != null && g.methodSample.contains(c)) return PhantomGroup.OK;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return PhantomGroup.FALTA;
    }

    private static boolean mentions(String detail, String evidence,
                                    PhantomGroup.FuncGroup g) {
        try {
            for (String m : g.methodSample) {
                if (m == null) continue;
                if (detail != null && detail.contains(m)) return true;
                if (evidence != null && evidence.contains(m)) return true;
                String cls = RefGraph.split(m)[0];
                if (!"?".equals(cls)) {
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
