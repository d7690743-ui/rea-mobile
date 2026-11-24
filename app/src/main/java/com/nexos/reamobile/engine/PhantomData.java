package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * PHANTOM datos: modelos y serialización por evidencia. writeToParcel/CREATE
 * (sólido, via grafo); Gson/Moshi/kotlinx por aristas (sólido); modelos por
 * nombre (heurística LOW declarada); literales JSON por barrido. Nunca lanza.
 */
public final class PhantomData {
    private PhantomData() {
    }

    public static final int MAX_ITEMS = 50;

    /** Hallazgo de datos con evidencia. Nunca lanza. */
    public static class DataHit {
        public String kind = "?";
        public String detail = "?";
        public String evidence = "";
    }

    /** Resultado de datos. Nunca lanza. */
    public static class DataResult {
        public List<DataHit> hits = new ArrayList<>();
        public boolean truncated;
    }

    private static final String[] MODEL_SUFFIXES = {"Model;", "Entity;", "Dto;", "Bean;",
            "Item;", "State;", "Data;", "Record;", "Info;", "Result;"};
    private static final String[] JSON_NEEDLES = {"\":", "\":{"};

    /**
     * Analiza datos sobre índices existentes. Nunca null ni lanza.
     */
    public static DataResult analyze(RefGraph graph, StringRefs stringRefs,
                                     List<String> appClasses) {
        DataResult r = new DataResult();
        try {
            if (graph != null) {
                Set<String> seen = new LinkedHashSet<>();
                for (RefGraph.RefEdge e : graph.edges()) {
                    if (r.hits.size() >= MAX_ITEMS) {
                        r.truncated = true;
                        break;
                    }
                    if (e == null || e.caller == null || e.callee == null) continue;
                    if (e.caller.endsWith("->writeToParcel") && seen.add("P" + e.caller)) {
                        DataHit h = new DataHit();
                        h.kind = "parcelable";
                        h.detail = e.caller;
                        h.evidence = "implementa writeToParcel";
                        r.hits.add(h);
                    } else if (isJsonLib(e.callee) && seen.add("J" + e.caller + e.callee)) {
                        DataHit h = new DataHit();
                        h.kind = "json-lib";
                        h.detail = shortName(e.callee);
                        h.evidence = "usado por " + e.caller;
                        r.hits.add(h);
                    }
                }
            }
            if (appClasses != null && r.hits.size() < MAX_ITEMS) {
                int checked = 0;
                for (String cls : appClasses) {
                    if (cls == null || checked++ > 5000) break;
                    if (r.hits.size() >= MAX_ITEMS) {
                        r.truncated = true;
                        break;
                    }
                    if (looksModel(cls)) {
                        DataHit h = new DataHit();
                        h.kind = "modelo?";
                        h.detail = cls;
                        h.evidence = "heurística por nombre (LOW)";
                        r.hits.add(h);
                    }
                }
            }
            if (stringRefs != null && r.hits.size() < MAX_ITEMS) {
                for (StringRefs.LitHit lit : stringRefs.scanContains(JSON_NEEDLES, 20)) {
                    if (lit == null || r.hits.size() >= MAX_ITEMS) {
                        r.truncated = true;
                        break;
                    }
                    if (lit.value == null || lit.value.length() > 300) continue;
                    DataHit h = new DataHit();
                    h.kind = "json-lit";
                    h.detail = trim(lit.value);
                    h.evidence = lit.users.isEmpty() ? "literal sin usuario"
                            : "cargado por " + lit.users.get(0);
                    r.hits.add(h);
                }
            }
        } catch (Throwable ignored) {
        }
        return r;
    }

    private static boolean isJsonLib(String callee) {
        try {
            return callee != null && (callee.startsWith("Lcom/google/gson/")
                    || callee.startsWith("Lcom/squareup/moshi/")
                    || callee.startsWith("Lkotlinx/serialization/")
                    || callee.startsWith("Lcom/fasterxml/jackson/"));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean looksModel(String cls) {
        try {
            if (cls == null) return false;
            for (String s : MODEL_SUFFIXES) {
                if (cls.endsWith(s)) return true;
            }
            return false;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String shortName(String ref) {
        try {
            int a = ref.indexOf(";->");
            String cls = a < 0 ? ref : ref.substring(0, a + 1);
            int s = cls.lastIndexOf('/');
            String tail = s < 0 ? cls : cls.substring(s + 1);
            return tail + (a < 0 ? "" : "->" + ref.substring(a + 3));
        } catch (Throwable ignored) {
            return "?";
        }
    }

    private static String trim(String s) {
        try {
            if (s == null) return "";
            String t = s.replace('\n', ' ').trim();
            return t.length() > 120 ? t.substring(0, 120) + "…" : t;
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** Líneas para el informe. Nunca lanza. */
    public static List<String> summarize(DataResult r) {
        List<String> out = new ArrayList<>();
        try {
            if (r == null) return out;
            for (DataHit h : r.hits) {
                if (h == null) continue;
                out.add(h.kind + ": " + h.detail + " (" + h.evidence + ")");
            }
            if (r.truncated) out.add("(datos recortados por topes)");
        } catch (Throwable ignored) {
        }
        return out;
    }
}
