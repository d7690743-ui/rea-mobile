package com.nexos.reamobile.intelligence;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Colector de hallazgos del núcleo REA Intelligence: los motores registran
 * aquí y el correlador/blueprint consultan. Con tope anti-OOM, ids
 * deterministas (F-0001…) y consultas por categoría y clase.
 * Java puro. Nunca lanza.
 */
public final class IntelRegistry {

    public static final int MAX_FINDINGS = 5000;

    private final List<IntelFinding> findings = new ArrayList<>();
    private final int maxFindings;
    private int seq;
    private int dropped;

    public IntelRegistry() {
        this(MAX_FINDINGS);
    }

    /** Variante con tope inyectable (tests). */
    IntelRegistry(int maxFindings) {
        this.maxFindings = maxFindings <= 0 ? MAX_FINDINGS : maxFindings;
    }

    /**
     * Registra un hallazgo válido; asigna id si está vacío. Devuelve false
     * (y cuenta descarte) si es nulo, inválido o se alcanzó el tope.
     * Nunca lanza.
     */
    public boolean add(IntelFinding f) {
        try {
            if (f == null || !f.isValid()) {
                dropped++;
                return false;
            }
            if (findings.size() >= maxFindings) {
                dropped++;
                return false;
            }
            if (f.id == null || f.id.isEmpty()) {
                seq++;
                f.id = String.format(Locale.US, "F-%04d", seq);
            }
            findings.add(f);
            return true;
        } catch (Throwable ignored) {
            dropped++;
            return false;
        }
    }

    /** Todos los hallazgos (copia). Nunca lanza. */
    public List<IntelFinding> all() {
        try {
            return new ArrayList<>(findings);
        } catch (Throwable ignored) {
            return new ArrayList<>();
        }
    }

    /** Filtro exacto por categoría. Nunca lanza. */
    public List<IntelFinding> byCategory(String category) {
        List<IntelFinding> out = new ArrayList<>();
        try {
            if (category == null) return out;
            for (IntelFinding f : findings) {
                if (category.equals(f.category)) out.add(f);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Filtro exacto por clase (descriptor `Lcom/x/A;`). Nunca lanza. */
    public List<IntelFinding> byClass(String className) {
        List<IntelFinding> out = new ArrayList<>();
        try {
            if (className == null) return out;
            for (IntelFinding f : findings) {
                if (className.equals(f.className)) out.add(f);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    public int size() {
        return findings.size();
    }

    public int dropped() {
        return dropped;
    }

    public boolean truncated() {
        return dropped > 0;
    }
}
