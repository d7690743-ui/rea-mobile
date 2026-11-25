package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OMEGA #2: índice en memoria cadena→métodos que la cargan. No analiza DEX:
 * solo indexa las referencias que le entrega {@link DexCalls} (toda relación
 * está respaldada por un const-string real; aquí no se infiere nada).
 * Con deduplicación, tope anti-OOM y detección de truncamiento.
 * Java puro. Nunca lanza.
 *
 * <p>Claves de método con el formato de DexCalls: {@code Lcom/x/A;->foo}.</p>
 */
public final class StringRefs {

    public static final int MAX_PAIRS = 20000;

    private final Map<String, Set<String>> users = new LinkedHashMap<>();
    /** T9: índice inverso método → literales (evita el barrido por llamada). */
    private final Map<String, Set<String>> byUser = new LinkedHashMap<>();
    private final int maxPairs;
    private int pairs;
    private int dropped;

    public StringRefs() {
        this(MAX_PAIRS);
    }

    /** Variante con tope inyectable (tests). */
    StringRefs(int maxPairs) {
        this.maxPairs = maxPairs <= 0 ? MAX_PAIRS : maxPairs;
    }

    /** Construye el índice desde referencias de DexCalls. Nunca lanza. */
    public static StringRefs from(List<DexCalls.StringRef> in) {
        return from(in, MAX_PAIRS);
    }

    /** Variante con tope inyectable (tests). Nunca lanza. */
    static StringRefs from(List<DexCalls.StringRef> in, int maxPairs) {
        StringRefs ix = new StringRefs(maxPairs);
        ix.addAll(in);
        return ix;
    }

    /** Añade una referencia (deduplicada). false si se descartó. Nunca lanza. */
    public boolean add(DexCalls.StringRef s) {
        try {
            if (s == null) {
                dropped++;
                return false;
            }
            String user = s.user == null ? "?" : s.user;
            String value = s.value == null ? "" : s.value;
            if ("?".equals(user) || value.isEmpty() || "?".equals(value)) {
                dropped++;
                return false;
            }
            Set<String> set = users.get(value);
            if (set != null && set.contains(user)) return true;
            if (pairs >= maxPairs) {
                dropped++;
                return false;
            }
            if (set == null) {
                set = new LinkedHashSet<>();
                users.put(value, set);
            }
            set.add(user);
            Set<String> inv = byUser.get(user);
            if (inv == null) {
                inv = new LinkedHashSet<>();
                byUser.put(user, inv);
            }
            inv.add(value);
            pairs++;
            return true;
        } catch (Throwable ignored) {
            dropped++;
            return false;
        }
    }

    /** Añade una lista; devuelve cuántas se guardaron. Nunca lanza. */
    public int addAll(List<DexCalls.StringRef> in) {
        int n = 0;
        try {
            if (in == null) return 0;
            for (DexCalls.StringRef s : in) {
                if (add(s)) n++;
            }
        } catch (Throwable ignored) {
        }
        return n;
    }

    /** Métodos que cargan exactamente este literal, en orden. Nunca lanza. */
    public List<String> usersOf(String value) {
        try {
            if (value == null) return new ArrayList<>();
            Set<String> set = users.get(value);
            if (set == null) return new ArrayList<>();
            return new ArrayList<>(set);
        } catch (Throwable ignored) {
            return new ArrayList<>();
        }
    }

    /**
     * Métodos que cargan un literal que CONTIENE el texto (p.ej. una URL
     * dentro de un script). Recorre las claves; el llamador acota lo mostrado.
     * Nunca lanza.
     */
    public List<String> usersOfContaining(String sub) {
        List<String> out = new ArrayList<>();
        try {
            if (sub == null || sub.isEmpty()) return out;
            Set<String> seen = new LinkedHashSet<>();
            for (Map.Entry<String, Set<String>> e : users.entrySet()) {
                String key = e.getKey();
                if (key == null || key.length() < sub.length()) continue;
                if (!key.contains(sub)) continue;
                if (e.getValue() == null) continue;
                for (String u : e.getValue()) {
                    if (u != null && seen.add(u)) out.add(u);
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Variante con tope y salida temprana (PHANTOM). Nunca lanza.
     */
    public List<String> usersOfContaining(String sub, int cap) {
        List<String> out = new ArrayList<>();
        try {
            if (sub == null || sub.isEmpty()) return out;
            int lim = cap <= 0 ? 25 : Math.min(cap, 500);
            Set<String> seen = new LinkedHashSet<>();
            for (Map.Entry<String, Set<String>> e : users.entrySet()) {
                if (out.size() >= lim) break;
                String key = e.getKey();
                if (key == null || key.length() < sub.length()) continue;
                if (!key.contains(sub)) continue;
                if (e.getValue() == null) continue;
                for (String u : e.getValue()) {
                    if (u != null && seen.add(u)) out.add(u);
                    if (out.size() >= lim) break;
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Literales que carga un método (índice inverso acotado para PHANTOM).
     * Orden de primer uso por el método; tope cap. Nunca lanza.
     */
    public List<String> literalsOf(String method, int cap) {
        List<String> out = new ArrayList<>();
        try {
            if (method == null || method.isEmpty()) return out;
            int lim = cap <= 0 ? 50 : Math.min(cap, 500);
            Set<String> set = byUser.get(method);
            if (set == null) return out;
            for (String v : set) {
                if (out.size() >= lim) break;
                if (v != null) out.add(v);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Un literal y sus métodos usuario (para barridos PHANTOM). Nunca lanza. */
    public static class LitHit {
        public String value = "";
        public List<String> users = new ArrayList<>();
    }

    /**
     * Barrido acotado: literales que contienen alguna aguja (p. ej. "SELECT",
     * ".db"). Una pasada; tope cap pares. Nunca lanza.
     */
    public List<LitHit> scanContains(String[] needles, int cap) {
        List<LitHit> out = new ArrayList<>();
        try {
            if (needles == null || needles.length == 0) return out;
            int lim = cap <= 0 ? 50 : Math.min(cap, 500);
            for (Map.Entry<String, Set<String>> e : users.entrySet()) {
                if (out.size() >= lim) break;
                String key = e.getKey();
                if (key == null || key.isEmpty() || e.getValue() == null) continue;
                boolean hit = false;
                for (String n : needles) {
                    if (n != null && !n.isEmpty() && key.contains(n)) {
                        hit = true;
                        break;
                    }
                }
                if (!hit) continue;
                LitHit h = new LitHit();
                h.value = key;
                for (String u : e.getValue()) {
                    if (u != null) h.users.add(u);
                    if (h.users.size() >= 5) break;
                }
                out.add(h);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    public int valueCount() {
        return users.size();
    }

    public int pairCount() {
        return pairs;
    }

    public int dropped() {
        return dropped;
    }

    public boolean truncated() {
        return dropped > 0;
    }
}
