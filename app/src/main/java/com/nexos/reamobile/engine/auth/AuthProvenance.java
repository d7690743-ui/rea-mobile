package com.nexos.reamobile.engine.auth;

import com.nexos.reamobile.engine.ApkSigBlock;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Capa 3 — Source Stamp y procedencia de distribución.
 * Un sello válido NO se atribuye a Google Play sin comprobar su identidad
 * contra una referencia confiable; la ausencia de sello NO es evidencia
 * negativa. Ejecutable individualmente. Java puro + apksig. Nunca lanza.
 */
public final class AuthProvenance {
    private AuthProvenance() {
    }

    public static class ProvResult {
        public AuthTri stampPresent = AuthTri.UNKNOWN;
        public AuthTri stampVerified = AuthTri.UNKNOWN;
        public String stampCertSha256 = "";
        public AuthTri stampMatchesTrusted = AuthTri.UNKNOWN;
        public AuthTri distributedByPlay = AuthTri.UNKNOWN;
        public String detail = "";
        public List<AuthEvidence> evidence = new ArrayList<>();

        public String toJson() {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                sb.append("\"source_stamp_present\":").append(stampPresent.toJson());
                sb.append(",\"source_stamp_verified\":").append(stampVerified.toJson());
                AuthJson.field(sb, "source_stamp_cert_sha256", stampCertSha256, false);
                sb.append(",\"source_stamp_matches_trusted_identity\":")
                        .append(stampMatchesTrusted.toJson());
                sb.append(",\"distributed_by_play\":").append(distributedByPlay.toJson());
                AuthJson.field(sb, "detail", detail, false);
                sb.append('}');
                return sb.toString();
            } catch (Throwable ignored) {
                return "{}";
            }
        }
    }

    /**
     * Inspección del sello. trustedStampSha256: huellas de referencia
     * confiable (vacío = sin referencia → UNKNOWN, nunca afirmación).
     * Nunca null. Nunca lanza.
     */
    public static ProvResult inspect(File apk, ApkSigAdapter.Result sw,
                                     Set<String> trustedStampSha256) {
        ProvResult r = new ProvResult();
        String apkRef = apk == null ? "?" : apk.getName();
        try {
            if (apk == null || !apk.isFile()) {
                r.detail = "archivo no válido";
                return r;
            }
            boolean useApkSig = sw != null && sw.available;
            boolean blockStamp = ApkSigBlock.hasStampBlock(apk);
            boolean swStamp = useApkSig && sw.stamp != null && sw.stamp.present;

            // 1. Presencia (observable, sin apksig si hace falta).
            if (swStamp || blockStamp) {
                r.stampPresent = AuthTri.TRUE;
            } else if (useApkSig && sw.stamp != null
                    && "STAMP_MISSING".equals(sw.stamp.status)) {
                r.stampPresent = AuthTri.FALSE;
            } else {
                // Sin bloque de sello legible: ausencia observada.
                r.stampPresent = AuthTri.FALSE;
            }
            r.evidence.add(new AuthEvidence("prov.stamp.present", "provenance",
                    r.stampPresent == AuthTri.TRUE ? "PASS" : "INFO",
                    "bloque-firma", useApkSig ? ApkSigAdapter.LIB + "+bloque" : "bloque",
                    "sello " + (r.stampPresent == AuthTri.TRUE ? "presente" : "ausente"),
                    "", apkRef, ""));

            if (r.stampPresent != AuthTri.TRUE) {
                r.stampVerified = AuthTri.UNKNOWN;
                r.stampMatchesTrusted = AuthTri.UNKNOWN;
                r.distributedByPlay = AuthTri.UNKNOWN;
                r.detail = "sin Source Stamp: el canal de distribución no es atribuible "
                        + "(la ausencia no es evidencia negativa)";
                r.evidence.add(new AuthEvidence("prov.play", "provenance", "UNKNOWN",
                        "motor", "regla",
                        "canal no demostrado", "", apkRef, ""));
                return r;
            }

            // 2. Validez criptográfica (solo apksig la demuestra).
            if (useApkSig && sw.stamp != null) {
                String st = sw.stamp.status == null ? "" : sw.stamp.status;
                if (sw.stampVerified && "STAMP_VERIFIED".equals(st)) {
                    r.stampVerified = AuthTri.TRUE;
                } else if ("STAMP_VERIFICATION_FAILED".equals(st)
                        || "CERT_DIGEST_MISMATCH".equals(st)) {
                    r.stampVerified = AuthTri.FALSE;
                } else {
                    r.stampVerified = AuthTri.UNKNOWN;
                }
                r.evidence.add(new AuthEvidence("prov.stamp.verified", "provenance",
                        r.stampVerified == AuthTri.TRUE ? "PASS"
                                : (r.stampVerified == AuthTri.FALSE ? "FAIL" : "UNKNOWN"),
                        "bloque-firma", ApkSigAdapter.LIB + " verify()",
                        "estado=" + (st.isEmpty() ? "?" : st), "", apkRef,
                        r.stampVerified == AuthTri.FALSE ? join(sw.stamp.errors) : ""));
            } else {
                r.stampVerified = AuthTri.UNKNOWN;
                r.evidence.add(new AuthEvidence("prov.stamp.verified", "provenance",
                        "UNKNOWN", "bloque-firma", "no-ejecutado",
                        "sello presente pero no verificado (requiere apksig)",
                        "", apkRef, ""));
            }

            // 3. Identidad del certificado del sello.
            X509Certificate stampCert = useApkSig && sw.stamp != null ? sw.stamp.cert : null;
            if (stampCert != null) {
                try {
                    byte[] enc = stampCert.getEncoded();
                    r.stampCertSha256 = AuthCert.sha256OfDer(enc);
                } catch (Throwable ignored) {
                }
            }
            if (r.stampCertSha256.isEmpty()) {
                r.stampCertSha256 = stampCertFallback(apk);
            }
            r.evidence.add(new AuthEvidence("prov.stamp.cert", "provenance",
                    r.stampCertSha256.isEmpty() ? "UNKNOWN" : "INFO",
                    "bloque-firma", useApkSig ? ApkSigAdapter.LIB : "der-best-effort",
                    r.stampCertSha256.isEmpty() ? "certificado no extraíble"
                            : ("sha256=" + r.stampCertSha256), "", apkRef, ""));

            // 4. Coincidencia con referencia confiable.
            boolean hasRef = trustedStampSha256 != null && !trustedStampSha256.isEmpty();
            if (r.stampCertSha256.isEmpty() || !hasRef) {
                r.stampMatchesTrusted = AuthTri.UNKNOWN;
            } else {
                boolean hit = false;
                String norm = AuthCert.normHash(r.stampCertSha256);
                for (String t : trustedStampSha256) {
                    if (norm.equals(AuthCert.normHash(t))) {
                        hit = true;
                        break;
                    }
                }
                r.stampMatchesTrusted = AuthTri.of(hit);
            }
            r.evidence.add(new AuthEvidence("prov.stamp.identity", "provenance",
                    r.stampMatchesTrusted == AuthTri.TRUE ? "PASS"
                            : (r.stampMatchesTrusted == AuthTri.FALSE ? "FAIL" : "UNKNOWN"),
                    "allowlist", "comparación-sha256",
                    hasRef ? ("coincide=" + r.stampMatchesTrusted) : "sin referencia confiable",
                    "", apkRef, ""));

            // 5. Atribución a Play: requiere sello válido + identidad confiable.
            if (r.stampVerified == AuthTri.TRUE && r.stampMatchesTrusted == AuthTri.TRUE) {
                r.distributedByPlay = AuthTri.TRUE;
                r.detail = "sello válido de identidad confiable: distribución atribuida";
            } else if (r.stampVerified == AuthTri.TRUE
                    && r.stampMatchesTrusted == AuthTri.FALSE && hasRef) {
                r.distributedByPlay = AuthTri.FALSE;
                r.detail = "sello válido pero de emisor no reconocido: no atribuible a Play";
            } else {
                r.distributedByPlay = AuthTri.UNKNOWN;
                r.detail = "procedencia no demostrada (verificado=" + r.stampVerified
                        + ", identidad=" + r.stampMatchesTrusted + ")";
            }
            r.evidence.add(new AuthEvidence("prov.play", "provenance",
                    r.distributedByPlay == AuthTri.TRUE ? "PASS"
                            : (r.distributedByPlay == AuthTri.FALSE ? "FAIL" : "UNKNOWN"),
                    "motor", "regla", r.detail, "", apkRef, ""));
        } catch (Throwable ignored) {
            r.detail = "fallo inspeccionando procedencia";
        }
        return r;
    }

    /**
     * Extracción best-effort del certificado del sello sin apksig: primer
     * registro LP del bloque de sello que parsee como X.509. "" si no hay.
     * Nunca lanza.
     */
    static String stampCertFallback(File apk) {
        try {
            for (ApkSigBlock.Block b : ApkSigBlock.blocks(apk)) {
                if (b.id != ApkSigBlock.ID_STAMP_V2 && b.id != ApkSigBlock.ID_STAMP_V1) continue;
                if (b.value == null) continue;
                String sha = scanForCert(b.value, 0);
                if (!sha.isEmpty()) return sha;
            }
        } catch (Throwable ignored) {
        }
        return "";
    }

    private static String scanForCert(byte[] buf, int depth) {
        try {
            if (buf == null || depth > 2) return "";
            int p = 0;
            // Intento 1: el valor completo es un certificado.
            if (AuthCert.parseDer(buf) != null) return AuthCert.sha256OfDer(buf);
            // Intento 2: secuencia de registros LP; probar cada uno y un nivel.
            if (buf.length >= 4) {
                int seqLen = (int) u32(buf, 0);
                int seqEnd = Math.min(buf.length, 4 + seqLen);
                if (seqLen > 0 && seqLen <= buf.length - 4) {
                    p = 4;
                    int guard = 0;
                    while (p + 4 <= seqEnd && guard++ < 64) {
                        int recLen = (int) u32(buf, p);
                        if (recLen <= 0 || recLen > seqEnd - p - 4) break;
                        byte[] rec = new byte[recLen];
                        System.arraycopy(buf, p + 4, rec, 0, recLen);
                        if (AuthCert.parseDer(rec) != null) {
                            return AuthCert.sha256OfDer(rec);
                        }
                        String deep = scanForCert(rec, depth + 1);
                        if (!deep.isEmpty()) return deep;
                        p += 4 + recLen;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return "";
    }

    private static long u32(byte[] b, int p) {
        return ((b[p] & 0xFFL) | ((b[p + 1] & 0xFFL) << 8)
                | ((b[p + 2] & 0xFFL) << 16) | ((b[p + 3] & 0xFFL) << 24));
    }

    private static String join(List<String> l) {
        try {
            StringBuilder sb = new StringBuilder();
            for (String s : l) {
                if (sb.length() > 0) sb.append("; ");
                sb.append(s);
                if (sb.length() > 400) break;
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }
}
