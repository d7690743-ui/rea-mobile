package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * PHANTOM almacenamiento: SQLite/prefs/ficheros por evidencia. SQLiteOpenHelper
 * por herencia (sólido, via superMap); SQL y rutas por literales (via
 * barrido); getSharedPreferences por aristas + literal del llamador
 * (best-effort). Room/Proto sin anotaciones: fuera de alcance declarado.
 * Nunca lanza.
 */
public final class PhantomStore {
    private PhantomStore() {
    }

    public static final int MAX_ITEMS = 50;

    /** Hallazgo de almacenamiento con evidencia. Nunca lanza. */
    public static class StoreHit {
        public String kind = "?";
        public String detail = "?";
        public String evidence = "";
    }

    /** Resultado de almacenamiento. Nunca lanza. */
    public static class StoreResult {
        public List<StoreHit> hits = new ArrayList<>();
        public boolean truncated;
    }

    private static final String[] SQL_NEEDLES = {"SELECT ", "INSERT INTO", "CREATE TABLE",
            "ALTER TABLE", "DELETE FROM", "UPDATE ", "DROP TABLE", ".db", ".sqlite", ".sqlite3"};

    /**
     * Analiza almacenamiento sobre índices existentes. Nunca null ni lanza.
     */
    public static StoreResult analyze(Map<String, String> superMap, StringRefs stringRefs,
                                      RefGraph graph) {
        StoreResult r = new StoreResult();
        try {
            if (superMap != null) {
                for (Map.Entry<String, String> e : superMap.entrySet()) {
                    if (r.hits.size() >= MAX_ITEMS) {
                        r.truncated = true;
                        break;
                    }
                    if (e == null || e.getKey() == null || e.getValue() == null) continue;
                    String sup = e.getValue();
                    if (sup.endsWith("SQLiteOpenHelper;")) {
                        StoreHit h = new StoreHit();
                        h.kind = "sqlite-helper";
                        h.detail = e.getKey();
                        h.evidence = "hereda " + shortName(sup);
                        r.hits.add(h);
                    } else if (sup.endsWith("ContentProvider;")) {
                        StoreHit h = new StoreHit();
                        h.kind = "provider";
                        h.detail = e.getKey();
                        h.evidence = "hereda ContentProvider";
                        r.hits.add(h);
                    }
                }
            }
            if (stringRefs != null && r.hits.size() < MAX_ITEMS) {
                for (StringRefs.LitHit lit : stringRefs.scanContains(SQL_NEEDLES, 30)) {
                    if (lit == null || r.hits.size() >= MAX_ITEMS) {
                        r.truncated = true;
                        break;
                    }
                    StoreHit h = new StoreHit();
                    h.kind = isDbFile(lit.value) ? "db-file" : "sql";
                    h.detail = trim(lit.value);
                    h.evidence = lit.users.isEmpty() ? "literal sin usuario"
                            : "cargado por " + lit.users.get(0);
                    r.hits.add(h);
                }
            }
            if (graph != null && r.hits.size() < MAX_ITEMS) {
                Set<String> seen = new LinkedHashSet<>();
                for (RefGraph.RefEdge e : graph.edges()) {
                    if (e == null || e.callee == null || e.caller == null) continue;
                    if (!e.callee.endsWith("->getSharedPreferences")) continue;
                    if (!seen.add(e.caller) || r.hits.size() >= MAX_ITEMS) {
                        r.truncated = true;
                        continue;
                    }
                    StoreHit h = new StoreHit();
                    h.kind = "prefs";
                    h.detail = prefName(stringRefs, e.caller);
                    h.evidence = "llamado por " + e.caller;
                    r.hits.add(h);
                }
            }
        } catch (Throwable ignored) {
        }
        return r;
    }

    private static boolean isDbFile(String s) {
        try {
            return s != null && (s.contains(".db") || s.contains(".sqlite"));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String prefName(StringRefs refs, String caller) {
        try {
            if (refs == null || caller == null) return "?";
            for (String lit : refs.literalsOf(caller, 20)) {
                if (lit == null) continue;
                String t = lit.trim();
                if (t.length() >= 2 && t.length() <= 64 && t.indexOf('\n') < 0
                        && t.indexOf('/') < 0 && !t.startsWith("L")) return t;
            }
        } catch (Throwable ignored) {
        }
        return "?";
    }

    private static String shortName(String desc) {
        try {
            int s = desc.lastIndexOf('/');
            int e = desc.endsWith(";") ? desc.length() - 1 : desc.length();
            return s < 0 ? desc : desc.substring(s + 1, e);
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
    public static List<String> summarize(StoreResult r) {
        List<String> out = new ArrayList<>();
        try {
            if (r == null) return out;
            for (StoreHit h : r.hits) {
                if (h == null) continue;
                out.add(h.kind + ": " + h.detail + " (" + h.evidence + ")");
            }
            if (r.truncated) out.add("(almacenamiento recortado por topes)");
        } catch (Throwable ignored) {
        }
        return out;
    }
}
