package com.nexos.reamobile.engine.auth;

import java.util.ArrayList;
import java.util.List;

/**
 * Capa 7 — agregador de veredicto independiente.
 * OFFICIAL exige identidad oficial acreditada + firma válida + ausencia de
 * discrepancias; NOT_OFFICIAL exige discrepancia confirmada (con linaje y
 * variante comprobados); SUSPICIOUS ante contradicciones o modificaciones
 * demostradas; UNKNOWN cuando la información no basta.
 * La confianza depende de la calidad y procedencia de la evidencia, no de
 * sumas de puntos. La procedencia Play es una dimensión independiente.
 * Nunca lanza.
 */
public final class AuthVerdict {
    private AuthVerdict() {
    }

    public static class Verdict {
        public String overall = "UNKNOWN";
        public String confidence = "LOW";
        /** TRUE = firma válida (≥1 esquema verificado, ninguno fallido). */
        public AuthTri apkSignatureValid = AuthTri.UNKNOWN;
        /** TRUE = firmante oficial (MATCH directo o por linaje). */
        public AuthTri officialSignerMatch = AuthTri.UNKNOWN;
        /** TRUE = linaje observado coincide con linaje oficial. */
        public AuthTri rotationLineageMatch = AuthTri.UNKNOWN;
        /** TRUE = distribución atribuida (sello válido + identidad). */
        public AuthTri playProvenance = AuthTri.UNKNOWN;
        /** TRUE = coincide con referencia exacta del baseline. */
        public AuthTri officialBaselineMatch = AuthTri.UNKNOWN;
        /**
         * TRUE = hay indicadores o modificaciones; FALSE = nada detectado;
         * UNKNOWN = no valorable. (Polaridad documentada: afirma presencia.)
         */
        public AuthTri modificationIndicators = AuthTri.UNKNOWN;
        public List<String> reasons = new ArrayList<>();
        public List<String> warnings = new ArrayList<>();
        public List<String> unknowns = new ArrayList<>();

        public String toJson() {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                AuthJson.field(sb, "overall", overall, true);
                AuthJson.field(sb, "confidence", confidence, false);
                sb.append(",\"dimensions\":{");
                sb.append("\"apk_signature_valid\":").append(apkSignatureValid.toJson());
                sb.append(",\"official_signer_match\":").append(officialSignerMatch.toJson());
                sb.append(",\"rotation_lineage_match\":").append(rotationLineageMatch.toJson());
                sb.append(",\"play_provenance\":").append(playProvenance.toJson());
                sb.append(",\"official_baseline_match\":").append(officialBaselineMatch.toJson());
                sb.append(",\"modification_indicators\":")
                        .append(modificationIndicators.toJson());
                sb.append('}');
                AuthJson.strList(sb, "reasons", reasons);
                AuthJson.strList(sb, "warnings", warnings);
                AuthJson.strList(sb, "unknowns", unknowns);
                sb.append('}');
                return sb.toString();
            } catch (Throwable ignored) {
                return "{}";
            }
        }
    }

    /**
     * Agrega el veredicto. lineageCovers: la allowlist cubre la clave
     * observada en un linaje oficial. Nunca null. Nunca lanza.
     */
    public static Verdict decide(AuthSignature.SigResult sig,
                                 AuthAllowlist.MatchResult allow,
                                 boolean lineageCovers,
                                 AuthRotation.RotResult rot,
                                 AuthProvenance.ProvResult prov,
                                 AuthBaseline.BaseResult base,
                                 AuthRepack.RepackResult rep) {
        Verdict v = new Verdict();
        try {
            if (sig == null || allow == null || rot == null || prov == null
                    || base == null || rep == null) {
                v.unknowns.add("datos incompletos para el veredicto");
                return v;
            }
            v.apkSignatureValid = sigDimension(sig, v);
            v.officialSignerMatch = signerDimension(sig, allow, lineageCovers, rot, v);
            v.rotationLineageMatch = rot.lineageMatchesOfficial;
            if (rot.lineagePresent == AuthTri.FALSE) {
                v.rotationLineageMatch = AuthTri.UNKNOWN;
                v.unknowns.add("sin linaje de rotación observado ni esperado");
            }
            v.playProvenance = prov.distributedByPlay;
            v.officialBaselineMatch = baselineDimension(base, v);
            v.modificationIndicators = modDimension(base, rep, v);
            collectWarnings(sig, allow, rot, prov, base, rep, v);

            // Regla NOT_OFFICIAL: discrepancia confirmada (linaje+variante OK).
            boolean variantBlocks = base.variantMatch == AuthTri.FALSE;
            if (v.officialSignerMatch == AuthTri.FALSE && !variantBlocks) {
                v.overall = "NOT_OFFICIAL";
                v.reasons.add("firmante distinto a las referencias oficiales del paquete"
                        + " (linaje de rotación comprobado)");
                v.confidence = (v.officialBaselineMatch == AuthTri.FALSE
                        || v.apkSignatureValid == AuthTri.TRUE) ? "HIGH" : "MEDIUM";
                return v;
            }
            if (!variantBlocks && contentMismatch(base)) {
                v.overall = "NOT_OFFICIAL";
                v.reasons.add("contenido distinto a la referencia oficial exacta"
                        + " (misma versión y variante compatible)");
                v.confidence = "MEDIUM";
                if (v.officialSignerMatch == AuthTri.TRUE) {
                    v.reasons.add("contradicción: firmante oficial con bytes no oficiales");
                    v.confidence = "MEDIUM";
                }
                return v;
            }
            // Regla SUSPICIOUS: contradicciones, fallos cripto o modificaciones.
            if (v.apkSignatureValid == AuthTri.FALSE
                    || demonstratedMods(rep, base)
                    || ("MISMATCH".equals(allow.status)
                    && v.officialSignerMatch == AuthTri.UNKNOWN)) {
                v.overall = "SUSPICIOUS";
                if (v.apkSignatureValid == AuthTri.FALSE) {
                    v.reasons.add("firma inválida o contenido alterado tras la firma");
                }
                if (demonstratedMods(rep, base)) {
                    v.reasons.add("modificaciones demostradas respecto a la referencia");
                }
                if ("MISMATCH".equals(allow.status)
                        && v.officialSignerMatch == AuthTri.UNKNOWN) {
                    v.reasons.add("firmante no reconocido y linaje sin comprobar");
                }
                v.confidence = v.apkSignatureValid == AuthTri.FALSE ? "MEDIUM" : "LOW";
                return v;
            }
            // Regla OFFICIAL: identidad + firma + sin discrepancias.
            if (v.officialSignerMatch == AuthTri.TRUE && v.apkSignatureValid == AuthTri.TRUE
                    && v.officialBaselineMatch != AuthTri.FALSE
                    && !demonstratedMods(rep, base)) {
                v.overall = "OFFICIAL";
                v.reasons.add("identidad oficial del firmante acreditada"
                        + ("MATCH".equals(allow.status) && allow.historic
                        ? " (certificado histórico)" : "")
                        + (lineageCovers ? " (vía linaje de rotación)" : ""));
                v.reasons.add("firma válida y sin discrepancias relevantes");
                if (v.officialBaselineMatch == AuthTri.TRUE) {
                    v.confidence = "HIGH";
                    v.reasons.add("coincide con la referencia oficial exacta");
                } else {
                    v.confidence = allow.historic ? "LOW" : "MEDIUM";
                    v.unknowns.add("sin comparación byte a byte (no hay baseline exacto)");
                }
                if (v.playProvenance != AuthTri.TRUE) {
                    v.reasons.add("canal de distribución no demostrado"
                            + " (no impide el veredicto)");
                }
                return v;
            }
            // Resto: UNKNOWN con motivos.
            v.overall = "UNKNOWN";
            v.confidence = "LOW";
            if (v.officialSignerMatch == AuthTri.UNKNOWN) {
                v.unknowns.add("identidad del firmante no acreditada"
                        + ("ERROR".equals(allow.status) ? " (allowlist con error)"
                        : " (sin referencias oficiales)"));
            }
            if (v.apkSignatureValid == AuthTri.UNKNOWN) {
                v.unknowns.add("validez de la firma no comprobada");
            }
            if (v.reasons.isEmpty()) {
                v.reasons.add("información insuficiente para concluir");
            }
        } catch (Throwable ignored) {
            v.overall = "UNKNOWN";
            v.confidence = "LOW";
        }
        return v;
    }

    private static AuthTri sigDimension(AuthSignature.SigResult sig, Verdict v) {
        try {
            boolean anyPresent = sig.v1.present == AuthTri.TRUE
                    || sig.v2.present == AuthTri.TRUE
                    || sig.v3.present == AuthTri.TRUE
                    || sig.v31.present == AuthTri.TRUE;
            if (!anyPresent && sig.integrityOk == AuthTri.FALSE) {
                v.reasons.add("APK sin firma: integridad no demostrable");
                return AuthTri.FALSE;
            }
            if (sig.v1.verified == AuthTri.FALSE || sig.v2.verified == AuthTri.FALSE
                    || sig.v3.verified == AuthTri.FALSE || sig.v31.verified == AuthTri.FALSE
                    || sig.integrityOk == AuthTri.FALSE) {
                return AuthTri.FALSE;
            }
            if (sig.v1.verified == AuthTri.TRUE || sig.v2.verified == AuthTri.TRUE
                    || sig.v3.verified == AuthTri.TRUE || sig.v31.verified == AuthTri.TRUE) {
                return AuthTri.TRUE;
            }
            return AuthTri.UNKNOWN;
        } catch (Throwable ignored) {
            return AuthTri.UNKNOWN;
        }
    }

    private static AuthTri signerDimension(AuthSignature.SigResult sig,
                                           AuthAllowlist.MatchResult allow,
                                           boolean lineageCovers,
                                           AuthRotation.RotResult rot, Verdict v) {
        try {
            if ("MATCH".equals(allow.status)) {
                if (allow.historic) {
                    v.warnings.add("certificado oficial histórico (rotado)");
                }
                return AuthTri.TRUE;
            }
            if (lineageCovers || rot.lineageMatchesOfficial == AuthTri.TRUE) {
                v.reasons.add("clave observada amparada por linaje oficial de rotación");
                return AuthTri.TRUE;
            }
            if ("MISMATCH".equals(allow.status)) {
                // ¿Queda linaje oficial por comprobar?
                if (rot.lineagePresent == AuthTri.TRUE
                        && rot.lineageMatchesOfficial == AuthTri.UNKNOWN) {
                    return AuthTri.UNKNOWN;
                }
                return AuthTri.FALSE;
            }
            return AuthTri.UNKNOWN;
        } catch (Throwable ignored) {
            return AuthTri.UNKNOWN;
        }
    }

    private static AuthTri baselineDimension(AuthBaseline.BaseResult base, Verdict v) {
        try {
            if (!"EXACT".equals(base.lookupKind)) {
                v.unknowns.add("sin referencia exacta de baseline ("
                        + base.detail + ")");
                return AuthTri.UNKNOWN;
            }
            if (base.variantMatch == AuthTri.FALSE) {
                v.unknowns.add("variante distinta a la referencia: no comparable");
                return AuthTri.UNKNOWN;
            }
            boolean anyFalse = base.apkSha256Match == AuthTri.FALSE
                    || base.dexHashesMatch == AuthTri.FALSE
                    || base.manifestNormMatch == AuthTri.FALSE
                    || base.splitsMatch == AuthTri.FALSE
                    || (base.permissionsDiff != null
                    && base.permissionsDiff.match == AuthTri.FALSE)
                    || (base.exportedComponentsDiff != null
                    && base.exportedComponentsDiff.match == AuthTri.FALSE)
                    || (base.nativeLibsDiff != null
                    && base.nativeLibsDiff.match == AuthTri.FALSE);
            if (anyFalse) return AuthTri.FALSE;
            boolean anyTrue = base.apkSha256Match == AuthTri.TRUE
                    || base.dexHashesMatch == AuthTri.TRUE
                    || base.manifestNormMatch == AuthTri.TRUE;
            if (anyTrue) return AuthTri.TRUE;
            v.unknowns.add("referencia exacta sin campos comparables");
            return AuthTri.UNKNOWN;
        } catch (Throwable ignored) {
            return AuthTri.UNKNOWN;
        }
    }

    private static AuthTri modDimension(AuthBaseline.BaseResult base,
                                        AuthRepack.RepackResult rep, Verdict v) {
        try {
            if (demonstratedMods(rep, base)) return AuthTri.TRUE;
            if (rep.debuggable == AuthTri.TRUE || rep.testOnly == AuthTri.TRUE
                    || rep.cleartextTraffic == AuthTri.TRUE) {
                return AuthTri.TRUE;
            }
            if (rep.debuggable == AuthTri.UNKNOWN && rep.testOnly == AuthTri.UNKNOWN
                    && rep.cleartextTraffic == AuthTri.UNKNOWN) {
                return AuthTri.UNKNOWN;
            }
            return AuthTri.FALSE;
        } catch (Throwable ignored) {
            return AuthTri.UNKNOWN;
        }
    }

    private static boolean demonstratedMods(AuthRepack.RepackResult rep,
                                            AuthBaseline.BaseResult base) {
        try {
            if (rep.manifestModified == AuthTri.TRUE
                    || rep.dexModified == AuthTri.TRUE
                    || rep.nativeLibsModified == AuthTri.TRUE
                    || rep.allowBackupAnomaly == AuthTri.TRUE
                    || rep.v1Unexpected == AuthTri.TRUE
                    || rep.splitsMissing == AuthTri.TRUE) {
                return true;
            }
            if (base != null && "EXACT".equals(base.lookupKind)
                    && base.variantMatch != AuthTri.FALSE) {
                if (base.permissionsDiff != null
                        && base.permissionsDiff.match == AuthTri.FALSE) return true;
                if (base.exportedComponentsDiff != null
                        && base.exportedComponentsDiff.match == AuthTri.FALSE) return true;
            }
            return false;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean contentMismatch(AuthBaseline.BaseResult base) {
        try {
            if (base == null || !"EXACT".equals(base.lookupKind)) return false;
            if (base.variantMatch == AuthTri.FALSE) return false;
            return base.apkSha256Match == AuthTri.FALSE
                    || base.dexHashesMatch == AuthTri.FALSE;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void collectWarnings(AuthSignature.SigResult sig,
                                        AuthAllowlist.MatchResult allow,
                                        AuthRotation.RotResult rot,
                                        AuthProvenance.ProvResult prov,
                                        AuthBaseline.BaseResult base,
                                        AuthRepack.RepackResult rep, Verdict v) {
        try {
            if ("ERROR".equals(allow.status)) {
                v.warnings.add("allowlist con error: " + allow.note);
            }
            if (sig.v1.present == AuthTri.TRUE && sig.v2.present != AuthTri.TRUE
                    && sig.v3.present != AuthTri.TRUE && sig.v31.present != AuthTri.TRUE) {
                v.warnings.add("solo firma v1 (JAR): protección débil en Android 7+");
            }
            if (prov.stampPresent == AuthTri.TRUE
                    && prov.stampVerified != AuthTri.TRUE) {
                v.warnings.add("Source Stamp presente pero no verificado");
            }
            if (prov.stampMatchesTrusted == AuthTri.FALSE) {
                v.warnings.add("Source Stamp de emisor no reconocido");
            }
            if (rot.lineagePresent == AuthTri.TRUE
                    && rot.lineageValid == AuthTri.UNKNOWN) {
                v.warnings.add("linaje de rotación sin validar criptográficamente");
            }
            if (rep.debuggable == AuthTri.TRUE) {
                v.warnings.add("debuggable=true: build de depuración");
            }
            if (rep.testOnly == AuthTri.TRUE) {
                v.warnings.add("testOnly=true: build de pruebas");
            }
            if (sig.signerCount > 1) {
                v.warnings.add("firmantes múltiples: " + sig.signerCount);
            }
            if (sig.method != null && sig.method.startsWith("interno")) {
                v.warnings.add("verificación con motor interno (apksig no usado)");
            }
        } catch (Throwable ignored) {
        }
    }
}
