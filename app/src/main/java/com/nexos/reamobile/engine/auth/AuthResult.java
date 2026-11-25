package com.nexos.reamobile.engine.auth;

import java.util.ArrayList;
import java.util.List;

/**
 * Objeto estructurado de autenticidad (salida del motor).
 * Esquema versionado "rea-authenticity-v1". Java puro. Nunca lanza.
 */
public final class AuthResult {
    private AuthResult() {
    }

    public static class Report {
        public String schema = ReaAuthenticityEngine.SCHEMA;
        public String packageName = "?";
        public long versionCode = -1;
        public String versionName = "";
        public AuthVerdict.Verdict verdict = new AuthVerdict.Verdict();
        public AuthSignature.SigResult signature = new AuthSignature.SigResult();
        public AuthProvenance.ProvResult provenance = new AuthProvenance.ProvResult();
        public AuthRotation.RotResult rotation = new AuthRotation.RotResult();
        public AuthBaseline.BaseResult baseline = new AuthBaseline.BaseResult();
        public AuthRepack.RepackResult repack = new AuthRepack.RepackResult();
        public List<AuthEvidence> evidence = new ArrayList<>();
        // Metadatos.
        public String engineVersion = ReaAuthenticityEngine.ENGINE_VERSION;
        public String profile = ReaAuthenticityEngine.PROFILE;
        public boolean apksigUsed;
        public String allowlistVersion = "";
        public String baselineVersion = "";
        public List<String> notes = new ArrayList<>();

        /** JSON completo versionado. Nunca lanza. */
        public String toJson() {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                AuthJson.field(sb, "schema", schema, true);
                AuthJson.field(sb, "package", packageName, false);
                sb.append(",\"version\":{\"name\":");
                AuthJson.quote(sb, versionName);
                sb.append(",\"code\":").append(versionCode).append('}');
                sb.append(",\"verdict\":").append(verdict.toJson());
                sb.append(",\"signature\":").append(signature.toJson());
                sb.append(",\"provenance\":").append(provenance.toJson());
                sb.append(",\"rotation\":").append(rotation.toJson());
                sb.append(",\"baseline\":").append(baseline.toJson());
                sb.append(",\"repack\":").append(repack.toJson());
                sb.append(",\"evidence\":[");
                for (int i = 0; i < evidence.size(); i++) {
                    if (i > 0) sb.append(',');
                    sb.append(evidence.get(i).toJson());
                }
                sb.append(']');
                sb.append(",\"metadata\":{");
                AuthJson.field(sb, "engine", ReaAuthenticityEngine.ENGINE_NAME, true);
                AuthJson.field(sb, "engine_version", engineVersion, false);
                AuthJson.field(sb, "verification_profile", profile, false);
                sb.append(",\"apksig_used\":").append(apksigUsed);
                AuthJson.field(sb, "allowlist_version", allowlistVersion, false);
                AuthJson.field(sb, "baseline_version", baselineVersion, false);
                AuthJson.strList(sb, "notes", notes);
                sb.append('}');
                sb.append('}');
                return sb.toString();
            } catch (Throwable ignored) {
                return "{\"schema\":\"rea-authenticity-v1\"}";
            }
        }

        /** Una línea de resumen para la UI. Nunca lanza. */
        public String summaryLine() {
            try {
                return "veredicto=" + verdict.overall + " confianza=" + verdict.confidence
                        + " firma=" + verdict.apkSignatureValid
                        + " firmante=" + verdict.officialSignerMatch
                        + " baseline=" + verdict.officialBaselineMatch
                        + " play=" + verdict.playProvenance;
            } catch (Throwable ignored) {
                return "veredicto=?";
            }
        }

        /**
         * Sección "AUTENTICIDAD Y PROCEDENCIA" para el informe TXT
         * (amplía la sección FIRMA, no la sustituye). Nunca lanza.
         */
        public String toTextSection() {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append("\n=== AUTENTICIDAD Y PROCEDENCIA (")
                        .append(ReaAuthenticityEngine.ENGINE_NAME)
                        .append(' ').append(engineVersion).append(") ===\n");
                sb.append("veredicto=").append(verdict.overall)
                        .append(" confianza=").append(verdict.confidence).append('\n');
                sb.append("firma: v1=").append(schemeText(signature.v1))
                        .append(" v2=").append(schemeText(signature.v2))
                        .append(" v3=").append(schemeText(signature.v3))
                        .append(" v3.1=").append(schemeText(signature.v31))
                        .append(" integridad=").append(signature.integrityOk).append('\n');
                sb.append("firmante: ").append(signerText()).append('\n');
                sb.append("rotacion: ").append(rotationText()).append('\n');
                sb.append("sello: ").append(stampText()).append('\n');
                sb.append("baseline: ").append(baseline.detail.isEmpty()
                        ? "?" : baseline.detail).append('\n');
                sb.append("repack: ").append(repack.detail.isEmpty()
                        ? "?" : repack.detail).append('\n');
                if (!verdict.reasons.isEmpty()) {
                    sb.append("motivos:\n");
                    for (String s : verdict.reasons) {
                        sb.append("  - ").append(s).append('\n');
                    }
                }
                if (!verdict.warnings.isEmpty()) {
                    sb.append("avisos:\n");
                    for (String s : verdict.warnings) {
                        sb.append("  - ").append(s).append('\n');
                    }
                }
                if (!verdict.unknowns.isEmpty()) {
                    sb.append("sin-comprobar:\n");
                    for (String s : verdict.unknowns) {
                        sb.append("  - ").append(s).append('\n');
                    }
                }
                sb.append("evidencias(").append(evidence.size()).append("):\n");
                int cap = Math.min(evidence.size(), 60);
                for (int i = 0; i < cap; i++) {
                    sb.append("  - ").append(evidence.get(i).toText()).append('\n');
                }
                if (evidence.size() > cap) {
                    sb.append("  [...").append(evidence.size() - cap)
                            .append(" mas en autenticidad.json...]\n");
                }
                if (!notes.isEmpty()) {
                    sb.append("notas-motor:\n");
                    for (String s : notes) {
                        sb.append("  - ").append(s).append('\n');
                    }
                }
                return sb.toString();
            } catch (Throwable ignored) {
                return "\n=== AUTENTICIDAD Y PROCEDENCIA ===\n(no disponible)\n";
            }
        }

        private static String schemeText(AuthSignature.SchemeResult s) {
            try {
                if (s.present != AuthTri.TRUE) return "ausente";
                if (s.verified == AuthTri.TRUE) return "verificado";
                if (s.verified == AuthTri.FALSE) return "INVALIDO";
                return "no-comprobado";
            } catch (Throwable ignored) {
                return "?";
            }
        }

        private String signerText() {
            try {
                StringBuilder sb = new StringBuilder();
                if (signature.signerCerts.isEmpty()) {
                    sb.append("desconocido");
                } else {
                    AuthCert.Info c = signature.signerCerts.get(0);
                    sb.append(c.shortPrint.isEmpty() ? "?" : c.shortPrint);
                    if (signature.signerCount > 1) {
                        sb.append(" (+").append(signature.signerCount - 1).append(")");
                    }
                }
                sb.append(" allowlist=").append(signature.allowMatch);
                if (!signature.allowVersion.isEmpty()
                        && !"none".equals(signature.allowVersion)) {
                    sb.append(" v").append(signature.allowVersion);
                }
                return sb.toString();
            } catch (Throwable ignored) {
                return "?";
            }
        }

        private String rotationText() {
            try {
                if (rotation.lineagePresent != AuthTri.TRUE) return "sin linaje";
                return "linaje " + rotation.certificates.size() + " nivel(es)"
                        + " válido=" + rotation.lineageValid
                        + " oficial=" + rotation.lineageMatchesOfficial;
            } catch (Throwable ignored) {
                return "?";
            }
        }

        private String stampText() {
            try {
                if (provenance.stampPresent != AuthTri.TRUE) {
                    return "ausente; procedencia Play no demostrada";
                }
                return "presente verificado=" + provenance.stampVerified
                        + " identidad=" + provenance.stampMatchesTrusted
                        + " play=" + provenance.distributedByPlay;
            } catch (Throwable ignored) {
                return "?";
            }
        }
    }
}
