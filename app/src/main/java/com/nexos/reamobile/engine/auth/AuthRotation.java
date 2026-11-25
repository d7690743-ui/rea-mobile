package com.nexos.reamobile.engine.auth;

import com.nexos.reamobile.engine.ApkSigBlock;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Capa 4 — inspección del linaje de rotación (proof-of-rotation v3/v3.1).
 * observedKey es la clave firmante observada, nunca inferida de la versión
 * de Android. Una clave distinta no implica falsificación: el linaje
 * oficial decide. Ejecutable individualmente. Nunca lanza.
 */
public final class AuthRotation {
    private AuthRotation() {
    }

    public static class RotResult {
        public AuthTri lineagePresent = AuthTri.UNKNOWN;
        public AuthTri lineageValid = AuthTri.UNKNOWN;
        /** Cadena oldest→newest según apksig. Vacía sin apksig. */
        public List<AuthCert.Info> certificates = new ArrayList<>();
        /** SHA-256 del firmante observado (clave actual del APK). */
        public String observedKey = "";
        public AuthTri lineageMatchesOfficial = AuthTri.UNKNOWN;
        public String detail = "";
        public String sdkNote = "";
        public String capsNote = "";
        public List<AuthEvidence> evidence = new ArrayList<>();

        public String toJson() {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                sb.append("\"lineage_present\":").append(lineagePresent.toJson());
                sb.append(",\"lineage_valid\":").append(lineageValid.toJson());
                sb.append(",\"certificates\":[");
                for (int i = 0; i < certificates.size(); i++) {
                    if (i > 0) sb.append(',');
                    sb.append(certificates.get(i).toJson());
                }
                sb.append(']');
                AuthJson.field(sb, "observed_key", observedKey, false);
                sb.append(",\"lineage_matches_official\":")
                        .append(lineageMatchesOfficial.toJson());
                AuthJson.field(sb, "detail", detail, false);
                AuthJson.field(sb, "sdk_note", sdkNote, false);
                AuthJson.field(sb, "caps_note", capsNote, false);
                sb.append('}');
                return sb.toString();
            } catch (Throwable ignored) {
                return "{}";
            }
        }
    }

    /**
     * Inspección del linaje. observedKeySha256: firmante observado (Capa 1).
     * allow: allowlist con linajes oficiales (puede ser null).
     * Nunca null. Nunca lanza.
     */
    public static RotResult inspect(File apk, ApkSigAdapter.Result sw,
                                    String observedKeySha256,
                                    AuthAllowlist.Store allow, String pkg) {
        RotResult r = new RotResult();
        String apkRef = apk == null ? "?" : apk.getName();
        try {
            r.observedKey = AuthCert.normHash(observedKeySha256);
            if (apk == null || !apk.isFile()) {
                r.detail = "archivo no válido";
                return r;
            }
            boolean useApkSig = sw != null && sw.available;
            if (useApkSig) {
                inspectApkSig(r, sw, apkRef);
            } else {
                inspectFallback(r, apk, apkRef);
            }
            matchOfficial(r, allow, pkg, apkRef);
            if (r.detail.isEmpty()) {
                r.detail = "linaje=" + r.lineagePresent + " válido=" + r.lineageValid;
            }
        } catch (Throwable ignored) {
            r.detail = "fallo inspeccionando rotación";
        }
        return r;
    }

    private static void inspectApkSig(RotResult r, ApkSigAdapter.Result sw, String apkRef) {
        List<ApkSigAdapter.SignerInfo> all = new ArrayList<>();
        all.addAll(sw.v3);
        all.addAll(sw.v31);
        ApkSigAdapter.SignerInfo withLin = null;
        for (ApkSigAdapter.SignerInfo s : all) {
            if (s != null && s.lineagePresent) {
                withLin = s;
                break;
            }
        }
        StringBuilder sdk = new StringBuilder();
        for (ApkSigAdapter.SignerInfo s : all) {
            if (s == null) continue;
            if (s.minSdk >= 0 || s.maxSdk >= 0) {
                if (sdk.length() > 0) sdk.append("; ");
                sdk.append("minSdk=").append(s.minSdk).append(" maxSdk=").append(s.maxSdk);
                if (s.devRelease) sdk.append(" devRelease");
            }
        }
        r.sdkNote = sdk.toString();
        if (withLin == null) {
            r.lineagePresent = AuthTri.FALSE;
            r.lineageValid = AuthTri.UNKNOWN;
            r.detail = "sin proof-of-rotation en v3/v3.1";
            r.evidence.add(new AuthEvidence("rot.lineage", "rotation", "INFO",
                    "bloque-firma", ApkSigAdapter.LIB,
                    all.isEmpty() ? "sin firmantes v3/v3.1" : "sin atributo de rotación",
                    "", apkRef, ""));
            return;
        }
        r.lineagePresent = AuthTri.TRUE;
        for (X509Certificate c : withLin.lineage) {
            AuthCert.Info i = AuthCert.from(c);
            if (!i.sha256.isEmpty()) r.certificates.add(i);
            if (r.certificates.size() >= 16) break;
        }
        StringBuilder caps = new StringBuilder();
        for (int i = 0; i < withLin.lineageCaps.size()
                && i < r.certificates.size(); i++) {
            if (caps.length() > 0) caps.append("; ");
            caps.append("nivel").append(i).append("=[")
                    .append(withLin.lineageCaps.get(i)).append(']');
        }
        r.capsNote = caps.toString();
        boolean bad = withLin.hasErrors || sw.lineageErrors;
        r.lineageValid = bad ? AuthTri.FALSE : AuthTri.TRUE;
        r.evidence.add(new AuthEvidence("rot.lineage", "rotation",
                bad ? "FAIL" : "PASS", "bloque-firma", ApkSigAdapter.LIB + " verify()",
                "linaje de " + r.certificates.size() + " nivel(es), orden oldest→newest",
                "", apkRef, bad ? join(withLin.errors) : ""));
        if (!r.observedKey.isEmpty() && !r.certificates.isEmpty()) {
            String last = r.certificates.get(r.certificates.size() - 1).sha256;
            boolean latest = r.observedKey.equals(AuthCert.normHash(last));
            r.evidence.add(new AuthEvidence("rot.observed", "rotation",
                    latest ? "PASS" : "INFO", "bloque-firma", ApkSigAdapter.LIB,
                    "clave observada " + (latest ? "es la más reciente del linaje"
                            : "no es la más reciente del linaje"),
                    "", apkRef, ""));
        }
    }

    private static void inspectFallback(RotResult r, File apk, String apkRef) {
        boolean anyV3 = false;
        boolean anyAttr = false;
        int levels = 0;
        try {
            for (ApkSigBlock.Block b : ApkSigBlock.blocks(apk)) {
                boolean v3l = b.id == ApkSigBlock.ID_V3 || b.id == ApkSigBlock.ID_V31;
                if (!v3l) continue;
                anyV3 = true;
                for (ApkSigBlock.SignerData sd : ApkSigBlock.signersOf(b.value, true)) {
                    if (sd != null && sd.rotationAttr != null) {
                        anyAttr = true;
                        levels++;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        if (!anyV3) {
            r.lineagePresent = AuthTri.FALSE;
            r.lineageValid = AuthTri.UNKNOWN;
            r.detail = "sin firmantes v3/v3.1: rotación no aplicable";
            r.evidence.add(new AuthEvidence("rot.lineage", "rotation", "INFO",
                    "bloque-firma", "presencia", "sin v3/v3.1", "", apkRef, ""));
            return;
        }
        r.lineagePresent = AuthTri.of(anyAttr);
        r.lineageValid = AuthTri.UNKNOWN;
        r.detail = anyAttr ? ("proof-of-rotation presente (" + levels
                + " firmante(s)); validez y cadena requieren apksig")
                : "sin atributo proof-of-rotation";
        r.evidence.add(new AuthEvidence("rot.lineage", "rotation",
                anyAttr ? "UNKNOWN" : "INFO", "bloque-firma", "atributo-0x3ba06f8c",
                r.detail, "", apkRef, ""));
    }

    private static void matchOfficial(RotResult r, AuthAllowlist.Store allow,
                                      String pkg, String apkRef) {
        try {
            if (r.lineagePresent != AuthTri.TRUE) {
                r.lineageMatchesOfficial = AuthTri.UNKNOWN;
                return;
            }
            if (allow == null || !allow.loadError.isEmpty()) {
                r.lineageMatchesOfficial = AuthTri.UNKNOWN;
                r.evidence.add(new AuthEvidence("rot.official", "rotation", "UNKNOWN",
                        "allowlist", "sin-referencia",
                        allow == null ? "sin allowlist" : allow.loadError,
                        "", apkRef, ""));
                return;
            }
            List<List<String>> official = allow.lineages.get(pkg == null ? "" : pkg.trim());
            if (official == null || official.isEmpty()) {
                r.lineageMatchesOfficial = AuthTri.UNKNOWN;
                r.evidence.add(new AuthEvidence("rot.official", "rotation", "UNKNOWN",
                        "allowlist", "sin-referencia",
                        "paquete sin linajes oficiales", "", apkRef, ""));
                return;
            }
            List<String> observed = new ArrayList<>();
            for (AuthCert.Info i : r.certificates) {
                observed.add(AuthCert.normHash(i.sha256));
            }
            if (observed.isEmpty()) {
                r.lineageMatchesOfficial = AuthTri.UNKNOWN;
                r.evidence.add(new AuthEvidence("rot.official", "rotation", "UNKNOWN",
                        "allowlist", "sin-cadena",
                        "cadena observada no extraíble (requiere apksig)", "", apkRef, ""));
                return;
            }
            boolean hit = false;
            for (List<String> chain : official) {
                if (chain != null && isSubsequence(observed, chain)) {
                    hit = true;
                    break;
                }
            }
            r.lineageMatchesOfficial = AuthTri.of(hit);
            r.evidence.add(new AuthEvidence("rot.official", "rotation",
                    hit ? "PASS" : "FAIL", "allowlist", "comparación-cadenas",
                    hit ? "cadena observada contenida en linaje oficial"
                            : "cadena observada fuera de linajes oficiales (" + official.size()
                            + " referencia(s))",
                    "", apkRef, ""));
        } catch (Throwable ignored) {
            r.lineageMatchesOfficial = AuthTri.UNKNOWN;
        }
    }

    /** true si obs aparece en orden dentro de ref (subsecuencia). Nunca lanza. */
    static boolean isSubsequence(List<String> obs, List<String> ref) {
        try {
            if (obs == null || obs.isEmpty() || ref == null) return false;
            int j = 0;
            for (String o : obs) {
                boolean found = false;
                while (j < ref.size()) {
                    String x = ref.get(j++);
                    if (o != null && o.equals(x)) {
                        found = true;
                        break;
                    }
                }
                if (!found) return false;
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
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
