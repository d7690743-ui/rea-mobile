package com.nexos.reamobile.engine.auth;

import com.android.apksig.ApkVerifier;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Adaptador fino sobre la biblioteca oficial apksig (Google, misma versión
 * que el AGP del proyecto). Toda llamada está blindada: si apksig falta,
 * falla o rechaza el APK, el resultado lo indica y el motor sigue con su
 * verificador interno (nunca se simula una verificación).
 * Java puro + apksig. Nunca lanza.
 */
public final class ApkSigAdapter {
    private ApkSigAdapter() {
    }

    public static final String LIB = "apksig-8.7.3";

    public static class SignerInfo {
        public X509Certificate cert;
        public List<X509Certificate> chain = new ArrayList<>();
        public boolean hasErrors;
        public List<String> errors = new ArrayList<>();
        public List<String> warnings = new ArrayList<>();
        public int minSdk = -1;
        public int maxSdk = -1;
        public boolean devRelease;
        /** Cadena del linaje de rotación (v3/v3.1), vacía si no hay. */
        public List<X509Certificate> lineage = new ArrayList<>();
        public boolean lineagePresent;
        /** Capacidades por certificado del linaje (paralelo a lineage). */
        public List<String> lineageCaps = new ArrayList<>();
    }

    public static class StampInfo {
        public boolean present;
        /** STAMP_VERIFIED|STAMP_VERIFICATION_FAILED|CERT_DIGEST_MISMATCH|... */
        public String status = "";
        public X509Certificate cert;
        public List<X509Certificate> lineage = new ArrayList<>();
        public long timestamp;
        public List<String> errors = new ArrayList<>();
        public List<String> warnings = new ArrayList<>();
    }

    public static class Result {
        public boolean available;
        public String unavailableReason = "";
        public boolean verified;
        public boolean v1ok;
        public boolean v2ok;
        public boolean v3ok;
        public boolean v31ok;
        public List<X509Certificate> signerCerts = new ArrayList<>();
        public List<SignerInfo> v1 = new ArrayList<>();
        public List<SignerInfo> v1ignored = new ArrayList<>();
        public List<SignerInfo> v2 = new ArrayList<>();
        public List<SignerInfo> v3 = new ArrayList<>();
        public List<SignerInfo> v31 = new ArrayList<>();
        public StampInfo stamp = new StampInfo();
        public boolean stampVerified;
        public List<String> errors = new ArrayList<>();
        public List<String> warnings = new ArrayList<>();
        public boolean lineageErrors;
    }

    /** true si las clases apksig están disponibles en runtime. Nunca lanza. */
    public static boolean probe() {
        try {
            Class.forName("com.android.apksig.ApkVerifier");
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Verificación completa con apksig. Nunca null. Nunca lanza.
     * Cada getter va blindado: un bloque malformado degrada ese campo,
     * no todo el resultado.
     */
    public static Result verify(File apk, int minSdk, int maxSdk) {
        Result r = new Result();
        try {
            if (!probe()) {
                r.unavailableReason = "apksig no disponible en runtime";
                return r;
            }
            if (apk == null || !apk.isFile()) {
                r.unavailableReason = "archivo no válido";
                return r;
            }
            ApkVerifier v;
            try {
                v = new ApkVerifier.Builder(apk)
                        .setMinCheckedPlatformVersion(Math.max(1, minSdk))
                        .setMaxCheckedPlatformVersion(Math.max(1, maxSdk))
                        .build();
            } catch (Throwable t) {
                r.unavailableReason = "apksig: " + shortMsg(t);
                return r;
            }
            ApkVerifier.Result res;
            try {
                res = v.verify();
            } catch (Throwable t) {
                r.unavailableReason = "apksig verify(): " + shortMsg(t);
                return r;
            }
            if (res == null) {
                r.unavailableReason = "apksig devolvió null";
                return r;
            }
            r.available = true;
            r.verified = safeBool(new BoolGetter() {
                @Override public boolean get() { return res.isVerified(); }
            });
            r.v1ok = safeBool(new BoolGetter() {
                @Override public boolean get() { return res.isVerifiedUsingV1Scheme(); }
            });
            r.v2ok = safeBool(new BoolGetter() {
                @Override public boolean get() { return res.isVerifiedUsingV2Scheme(); }
            });
            r.v3ok = safeBool(new BoolGetter() {
                @Override public boolean get() { return res.isVerifiedUsingV3Scheme(); }
            });
            r.v31ok = safeBool(new BoolGetter() {
                @Override public boolean get() { return res.isVerifiedUsingV31Scheme(); }
            });
            r.stampVerified = safeBool(new BoolGetter() {
                @Override public boolean get() { return res.isSourceStampVerified(); }
            });
            try {
                List<X509Certificate> sc = res.getSignerCertificates();
                if (sc != null) r.signerCerts.addAll(boundCerts(sc));
            } catch (Throwable ignored) {
            }
            try {
                List<ApkVerifier.Result.V1SchemeSignerInfo> l = res.getV1SchemeSigners();
                if (l != null) for (ApkVerifier.Result.V1SchemeSignerInfo s : l) {
                    if (s != null) r.v1.add(v1of(s));
                }
            } catch (Throwable ignored) {
            }
            try {
                List<ApkVerifier.Result.V1SchemeSignerInfo> l = res.getV1SchemeIgnoredSigners();
                if (l != null) for (ApkVerifier.Result.V1SchemeSignerInfo s : l) {
                    if (s != null) r.v1ignored.add(v1of(s));
                }
            } catch (Throwable ignored) {
            }
            try {
                List<ApkVerifier.Result.V2SchemeSignerInfo> l = res.getV2SchemeSigners();
                if (l != null) for (ApkVerifier.Result.V2SchemeSignerInfo s : l) {
                    if (s != null) r.v2.add(v2of(s));
                }
            } catch (Throwable ignored) {
            }
            try {
                List<ApkVerifier.Result.V3SchemeSignerInfo> l = res.getV3SchemeSigners();
                if (l != null) for (ApkVerifier.Result.V3SchemeSignerInfo s : l) {
                    if (s != null) r.v3.add(v3of(s));
                }
            } catch (Throwable ignored) {
            }
            try {
                List<ApkVerifier.Result.V3SchemeSignerInfo> l = res.getV31SchemeSigners();
                if (l != null) for (ApkVerifier.Result.V3SchemeSignerInfo s : l) {
                    if (s != null) r.v31.add(v3of(s));
                }
            } catch (Throwable ignored) {
            }
            try {
                ApkVerifier.Result.SourceStampInfo st = res.getSourceStampInfo();
                if (st != null) r.stamp = stampOf(st);
            } catch (Throwable ignored) {
            }
            try {
                r.errors.addAll(issues(res.getErrors()));
            } catch (Throwable ignored) {
            }
            try {
                r.warnings.addAll(issues(res.getWarnings()));
            } catch (Throwable ignored) {
            }
            try {
                r.lineageErrors = ApkVerifier.containsLineageErrors(res);
            } catch (Throwable ignored) {
            }
        } catch (Throwable t) {
            if (!r.available) r.unavailableReason = "apksig: " + shortMsg(t);
        }
        return r;
    }

    private interface BoolGetter {
        boolean get();
    }

    private static boolean safeBool(BoolGetter g) {
        try {
            return g.get();
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static SignerInfo v1of(ApkVerifier.Result.V1SchemeSignerInfo s) {
        SignerInfo o = new SignerInfo();
        try { o.cert = s.getCertificate(); } catch (Throwable ignored) { }
        try {
            List<X509Certificate> c = s.getCertificateChain();
            if (c != null) o.chain.addAll(boundCerts(c));
        } catch (Throwable ignored) { }
        try { o.hasErrors = s.containsErrors(); } catch (Throwable ignored) { }
        try { o.errors.addAll(issues(s.getErrors())); } catch (Throwable ignored) { }
        try { o.warnings.addAll(issues(s.getWarnings())); } catch (Throwable ignored) { }
        return o;
    }

    private static SignerInfo v2of(ApkVerifier.Result.V2SchemeSignerInfo s) {
        SignerInfo o = new SignerInfo();
        try { o.cert = s.getCertificate(); } catch (Throwable ignored) { }
        try {
            List<X509Certificate> c = s.getCertificates();
            if (c != null) o.chain.addAll(boundCerts(c));
        } catch (Throwable ignored) { }
        try { o.hasErrors = s.containsErrors(); } catch (Throwable ignored) { }
        try { o.errors.addAll(issues(s.getErrors())); } catch (Throwable ignored) { }
        try { o.warnings.addAll(issues(s.getWarnings())); } catch (Throwable ignored) { }
        return o;
    }

    private static SignerInfo v3of(ApkVerifier.Result.V3SchemeSignerInfo s) {
        SignerInfo o = v2fields(s);
        try { o.minSdk = s.getMinSdkVersion(); } catch (Throwable ignored) { }
        try { o.maxSdk = s.getMaxSdkVersion(); } catch (Throwable ignored) { }
        try { o.devRelease = s.getRotationTargetsDevRelease(); } catch (Throwable ignored) { }
        try {
            com.android.apksig.SigningCertificateLineage lin = s.getSigningCertificateLineage();
            if (lin != null) {
                o.lineagePresent = true;
                List<X509Certificate> cs = lin.getCertificatesInLineage();
                if (cs != null) {
                    o.lineage.addAll(boundCerts(cs));
                    for (X509Certificate c : o.lineage) {
                        o.lineageCaps.add(capsOf(lin, c));
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return o;
    }

    private static String capsOf(com.android.apksig.SigningCertificateLineage lin,
                                 X509Certificate c) {
        try {
            if (lin == null || c == null) return "";
            com.android.apksig.SigningCertificateLineage.SignerCapabilities caps =
                    lin.getSignerCapabilities(c);
            if (caps == null) return "";
            StringBuilder sb = new StringBuilder();
            if (caps.hasInstalledData()) sb.append("installedData,");
            if (caps.hasSharedUid()) sb.append("sharedUid,");
            if (caps.hasPermission()) sb.append("permission,");
            if (caps.hasRollback()) sb.append("rollback,");
            if (caps.hasAuth()) sb.append("auth,");
            if (sb.length() > 0) sb.setLength(sb.length() - 1);
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static SignerInfo v2fields(ApkVerifier.Result.V3SchemeSignerInfo s) {
        SignerInfo o = new SignerInfo();
        try { o.cert = s.getCertificate(); } catch (Throwable ignored) { }
        try {
            List<X509Certificate> c = s.getCertificates();
            if (c != null) o.chain.addAll(boundCerts(c));
        } catch (Throwable ignored) { }
        try { o.hasErrors = s.containsErrors(); } catch (Throwable ignored) { }
        try { o.errors.addAll(issues(s.getErrors())); } catch (Throwable ignored) { }
        try { o.warnings.addAll(issues(s.getWarnings())); } catch (Throwable ignored) { }
        return o;
    }

    private static StampInfo stampOf(ApkVerifier.Result.SourceStampInfo st) {
        StampInfo o = new StampInfo();
        try {
            Object status = st.getSourceStampVerificationStatus();
            o.status = status == null ? "" : status.toString();
            o.present = !"STAMP_MISSING".equals(o.status);
        } catch (Throwable ignored) {
        }
        try { o.cert = st.getCertificate(); } catch (Throwable ignored) { }
        try {
            List<X509Certificate> c = st.getCertificatesInLineage();
            if (c != null) o.lineage.addAll(boundCerts(c));
        } catch (Throwable ignored) { }
        try { o.timestamp = st.getTimestampEpochSeconds(); } catch (Throwable ignored) { }
        try { o.errors.addAll(issues(st.getErrors())); } catch (Throwable ignored) { }
        try { o.warnings.addAll(issues(st.getWarnings())); } catch (Throwable ignored) { }
        return o;
    }

    private static List<X509Certificate> boundCerts(List<X509Certificate> in) {
        List<X509Certificate> out = new ArrayList<>();
        try {
            for (X509Certificate c : in) {
                if (c != null) out.add(c);
                if (out.size() >= 32) break;
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static List<String> issues(List<?> list) {
        List<String> out = new ArrayList<>();
        try {
            if (list == null) return out;
            for (Object o : list) {
                if (o == null) continue;
                String s;
                try {
                    s = o.toString();
                } catch (Throwable ignored) {
                    s = "?";
                }
                if (s != null) {
                    if (s.length() > 300) s = s.substring(0, 300);
                    out.add(s);
                }
                if (out.size() >= 20) break;
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static String shortMsg(Throwable t) {
        try {
            String m = t == null ? "?" : (t.getClass().getSimpleName()
                    + (t.getMessage() == null ? "" : ": " + t.getMessage()));
            if (m.length() > 200) m = m.substring(0, 200);
            return m;
        } catch (Throwable ignored) {
            return "?";
        }
    }
}
