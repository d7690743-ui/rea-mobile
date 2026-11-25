package com.nexos.reamobile.engine.auth;

/**
 * Lógica de tres estados del motor de autenticidad.
 * Un valor no comprobado o no soportado es UNKNOWN, nunca FALSE automático.
 * Java puro. Nunca lanza.
 */
public enum AuthTri {
    TRUE,
    FALSE,
    UNKNOWN;

    public static AuthTri of(boolean b) {
        return b ? TRUE : FALSE;
    }

    public static AuthTri of(Boolean b) {
        if (b == null) return UNKNOWN;
        return b ? TRUE : FALSE;
    }

    /** AND de Kleene: FALSE domina, UNKNOWN solo si no hay FALSE. */
    public AuthTri and(AuthTri o) {
        if (o == null) return this;
        if (this == FALSE || o == FALSE) return FALSE;
        if (this == TRUE && o == TRUE) return TRUE;
        return UNKNOWN;
    }

    /** OR de Kleene: TRUE domina, UNKNOWN solo si no hay TRUE. */
    public AuthTri or(AuthTri o) {
        if (o == null) return this;
        if (this == TRUE || o == TRUE) return TRUE;
        if (this == FALSE && o == FALSE) return FALSE;
        return UNKNOWN;
    }

    public AuthTri not() {
        if (this == TRUE) return FALSE;
        if (this == FALSE) return TRUE;
        return UNKNOWN;
    }

    /** Token JSON: true | false | "unknown". Nunca lanza. */
    public String toJson() {
        if (this == TRUE) return "true";
        if (this == FALSE) return "false";
        return "\"unknown\"";
    }

    @Override
    public String toString() {
        if (this == TRUE) return "true";
        if (this == FALSE) return "false";
        return "unknown";
    }
}
