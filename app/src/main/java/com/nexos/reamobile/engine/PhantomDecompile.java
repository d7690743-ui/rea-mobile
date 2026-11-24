package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * PHANTOM descompilación dirigida: lista de clases objetivo para JADX
 * (entradas + pantallas + JNI + top de grupos) en vez de muestreo genérico.
 * Mismo coste, empieza por lo reconstruible. Nunca lanza.
 */
public final class PhantomDecompile {
    private PhantomDecompile() {
    }

    public static final int MAX_PRIORITY = 150;

    /**
     * Descriptores objetivo ("Lcom/x/A;") por orden de interés. Nunca null
     * ni lanza.
     */
    public static List<String> priority(ReaEngine.ApkReport r, int cap) {
        List<String> out = new ArrayList<>();
        try {
            if (r == null) return out;
            int lim = cap <= 0 ? MAX_PRIORITY : Math.min(cap, 500);
            Set<String> seen = new LinkedHashSet<>();
            for (String en : ReaEngine.summarizeAlfaEntries(r)) {
                if (out.size() >= lim) break;
                addClass(seen, out, RefGraph.split(en)[0], lim);
            }
            Phantom.PhantomResult ph = null;
            try {
                ph = r.phantom();
            } catch (Throwable ignored) {
                ph = null;
            }
            if (ph != null) {
                if (ph.ui != null && ph.ui.contentViews != null) {
                    for (PhantomUi.ContentView cv : ph.ui.contentViews) {
                        if (out.size() >= lim) break;
                        if (cv != null) addClass(seen, out, cv.className, lim);
                    }
                }
                if (ph.groups != null) {
                    for (PhantomGroup.FuncGroup g : ph.groups) {
                        if (out.size() >= lim || g == null) break;
                        for (String m : g.methodSample) {
                            if (out.size() >= lim) break;
                            addClass(seen, out, RefGraph.split(m)[0], lim);
                        }
                    }
                }
            }
            if (r.graph != null && out.size() < lim) {
                for (String top : r.graph.topCallers(10)) {
                    if (out.size() >= lim) break;
                    addClass(seen, out, RefGraph.split(top)[0], lim);
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static void addClass(Set<String> seen, List<String> out, String desc, int lim) {
        try {
            if (desc == null || "?".equals(desc) || out.size() >= lim) return;
            if (!desc.startsWith("L") || !desc.endsWith(";")) return;
            if (seen.add(desc)) out.add(desc);
        } catch (Throwable ignored) {
        }
    }
}
