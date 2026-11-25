package com.nexos.reamobile.engine.auth;

/**
 * Evidencia trazable del motor de autenticidad: cada resultado remite a su
 * fuente y método. Nada aquí inventa valores esperados: expected vacío = sin
 * referencia. Java puro. Nunca lanza.
 */
public final class AuthEvidence {
    /** ID estable, p.ej. "sig.v2.digest". */
    public String id = "";
    /** Categoría: signature|signer|provenance|rotation|baseline|repack|verdict. */
    public String category = "";
    /** Resultado: PASS|FAIL|UNKNOWN|INFO|ERROR. */
    public String result = "UNKNOWN";
    /** Fuente: apksig|bloque-firma|zip|manifest|allowlist|baseline|motor. */
    public String source = "";
    /** Método de verificación, p.ej. "apksig-8.7.3 verify()". */
    public String method = "";
    public String observed = "";
    public String expected = "";
    /** Referencia al APK (nombre de fichero, nunca ruta completa). */
    public String apkRef = "";
    public String errorDetail = "";

    public AuthEvidence() {
    }

    public AuthEvidence(String id, String category, String result, String source,
                        String method, String observed, String expected,
                        String apkRef, String errorDetail) {
        this.id = nz(id);
        this.category = nz(category);
        this.result = nz(result);
        this.source = nz(source);
        this.method = nz(method);
        this.observed = nz(observed);
        this.expected = nz(expected);
        this.apkRef = nz(apkRef);
        this.errorDetail = nz(errorDetail);
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    /** Una línea legible para el informe TXT. Nunca lanza. */
    public String toText() {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(id).append(" [").append(result).append("] ");
            sb.append(observed == null || observed.isEmpty() ? "-" : observed);
            if (expected != null && !expected.isEmpty()) {
                sb.append(" (esperado: ").append(expected).append(')');
            }
            sb.append(" {").append(source);
            if (method != null && !method.isEmpty()) sb.append('/').append(method);
            sb.append('}');
            if (errorDetail != null && !errorDetail.isEmpty()) {
                sb.append(" !! ").append(errorDetail);
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "?";
        }
    }

    /** Objeto JSON de la evidencia. Nunca lanza. */
    public String toJson() {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            AuthJson.field(sb, "id", id, true);
            AuthJson.field(sb, "category", category, false);
            AuthJson.field(sb, "result", result, false);
            AuthJson.field(sb, "source", source, false);
            AuthJson.field(sb, "method", method, false);
            AuthJson.field(sb, "observed", observed, false);
            AuthJson.field(sb, "expected", expected, false);
            AuthJson.field(sb, "apk_ref", apkRef, false);
            AuthJson.field(sb, "error_detail", errorDetail, false);
            sb.append('}');
            return sb.toString();
        } catch (Throwable ignored) {
            return "{}";
        }
    }
}
