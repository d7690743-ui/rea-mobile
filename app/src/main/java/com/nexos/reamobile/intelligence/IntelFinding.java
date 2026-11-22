package com.nexos.reamobile.intelligence;

import java.util.ArrayList;
import java.util.List;

/**
 * Hallazgo unificado del núcleo REA Intelligence: la unidad que comparten la
 * ingeniería inversa (grafo, flujos, estructura, features, red, crypto,
 * nativas) y el análisis forense (correlación, blueprint).
 * Contenedor de datos con los 12 campos del plan OMEGA. Java puro. Nunca lanza.
 */
public final class IntelFinding {

    /** Origen de la evidencia: medida en estático, vista en ejecución o deducida. */
    public enum EvidenceType {
        STATIC, DYNAMIC, INFERRED
    }

    /** Confianza en la conclusión, no en la evidencia (esta siempre se cita). */
    public enum Confidence {
        LOW, MEDIUM, HIGH
    }

    public String id = "";
    public String category = "?";
    public String description = "";
    public String sourceFile = "";
    public String className = "";
    public String methodName = "";
    public String position = "";
    public String evidence = "";
    public List<String> relatedIds = new ArrayList<>();
    public Confidence confidence = Confidence.LOW;
    public EvidenceType evidenceType = EvidenceType.STATIC;
    public String limitations = "";

    /** Fábrica nula-segura con categoría y descripción. Nunca lanza. */
    public static IntelFinding create(String category, String description) {
        IntelFinding f = new IntelFinding();
        try {
            if (category != null && !category.isEmpty()) f.category = category;
            if (description != null) f.description = description;
        } catch (Throwable ignored) {
        }
        return f;
    }

    /** Añade un id relacionado (sin duplicados ni nulos). Nunca lanza. */
    public void relate(String otherId) {
        try {
            if (otherId == null || otherId.isEmpty()) return;
            if (!relatedIds.contains(otherId)) relatedIds.add(otherId);
        } catch (Throwable ignored) {
        }
    }

    /** Válido para registrar: categoría y descripción no vacías. Nunca lanza. */
    public boolean isValid() {
        try {
            return category != null && !category.isEmpty() && !"?".equals(category)
                    && description != null && !description.isEmpty();
        } catch (Throwable ignored) {
            return false;
        }
    }
}
