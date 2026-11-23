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
