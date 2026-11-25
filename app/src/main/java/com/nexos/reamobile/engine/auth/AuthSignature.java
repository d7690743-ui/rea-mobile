package com.nexos.reamobile.engine.auth;

import com.nexos.reamobile.engine.ApkSigBlock;
import java.io.File;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Capa 1 — integridad y esquemas de firma (v1/v2/v3/v3.1).
 * Primario: biblioteca oficial apksig. Respaldo: verificador interno
 * (digests de contenido AOSP + firma asimétrica JCA sobre signed-data).
 * Ejecutable individualmente. Java puro + apksig. Nunca lanza.
 */
public final class AuthSignature {
    private AuthSignature() {
    }

    public static class SchemeResult {
        public AuthTri present = AuthTri.UNKNOWN;
        public AuthTri verified = AuthTri.UNKNOWN;
        public String detail = "";
        public String method = "";
    }

    public static class SigResult {
        public SchemeResult v1 = new SchemeResult();
        public SchemeResult v2 = new SchemeResult();
        public SchemeResult v3 = new SchemeResult();
        public SchemeResult v31 = new SchemeResult();
        public AuthTri integrityOk = AuthTri.UNKNOWN;
        public List<String> verificationErrors = new ArrayList<>();
        public List<AuthCert.Info> signerCerts = new ArrayList<>();
        public String primarySignerSha256 = "";
        public int signerCount;
        public String multiSignerNote = "";
        public String compatNote = "";
        public String method = "";
        // Capa 2 (lo rellena el motor tras consultar la allowlist).
        public String allowMatch = "UNKNOWN";
        public String allowId = "";
        public String allowVersion = "";
        public String allowSource = "";
        public List<AuthEvidence> evidence = new ArrayList<>();

        /** Objeto "signature" completo. Nunca lanza. */
        public String toJson() {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                sb.append("\"v1\":").append(schemeJson(v1));
                sb.append(",\"v2\":").append(schemeJson(v2));
                sb.append(",\"v3\":").append(schemeJson(v3));
                sb.append(",\"v3_1\":").append(schemeJson(v31));
                sb.append(",\"integrity_ok\":").append(integrityOk.toJson());
                AuthJson.strList(sb, "verification_errors", verificationErrors);
                AuthJson.field(sb, "signer_cert_sha256", primarySignerSha256, false);
                sb.append(",\"signer_certs\":[");
                for (int i = 0; i < signerCerts.size(); i++) {
                    if (i > 0) sb.append(',');
                    sb.append(signerCerts.get(i).toJson());
                }
                sb.append(']');
                sb.append(",\"signer_count\":").append(signerCount);
                AuthJson.field(sb, "multi_signer_note", multiSignerNote, false);
                AuthJson.field(sb, "compat_note", compatNote, false);
                AuthJson.field(sb, "method", method, false);
                AuthJson.field(sb, "signer_matches_official_allowlist", allowMatch, false);
                AuthJson.field(sb, "signer_allowlist_id", allowId, false);
                AuthJson.field(sb, "signer_allowlist_version", allowVersion, false);
                AuthJson.field(sb, "signer_allowlist_source", allowSource, false);
                sb.append('}');
                return sb.toString();
            } catch (Throwable ignored) {
                return "{}";
            }
        }

        private static String schemeJson(SchemeResult s) {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                sb.append("\"present\":").append(s.present.toJson());
                sb.append(",\"verified\":").append(s.verified.toJson());
                AuthJson.field(sb, "detail", s.detail, false);
                AuthJson.field(sb, "method", s.method, false);
                sb.append('}');
                return sb.toString();
            } catch (Throwable ignored) {
                return "{}";
            }
        }
    }

    /** Inspección con apksig si está disponible. Nunca null. Nunca lanza. */
    public static SigResult inspect(File apk) {
        ApkSigAdapter.Result sw = null;
        try {
            sw = ApkSigAdapter.verify(apk, ReaAuthenticityEngine.MIN_PLATFORM_VERSION,
                    ReaAuthenticityEngine.MAX_PLATFORM_VERSION);
        } catch (Throwable ignored) {
            sw = null;
        }
        return inspect(apk, sw);
    }

    /** Inspección con un resultado apksig dado (puede ser null). Nunca lanza. */
    public static SigResult inspect(File apk, ApkSigAdapter.Result sw) {
        SigResult r = new SigResult();
        String apkRef = apk == null ? "?" : apk.getName();
        if (apk == null || !apk.isFile()) {
            addError(r, "archivo no válido");
            r.evidence.add(new AuthEvidence("sig.input", "signature", "ERROR",
                    "motor", "entrada", "archivo no válido", "", apkRef, ""));
            return r;
        }
        boolean useApkSig = sw != null && sw.available;
        try {
            // Presencia interna (bloque + ZIP), independiente de apksig.
            boolean zipBroken = !readableZip(apk);
            List<ApkSigBlock.Block> blocks = ApkSigBlock.blocks(apk);
            boolean bV2 = hasId(blocks, ApkSigBlock.ID_V2);
            boolean bV3 = hasId(blocks, ApkSigBlock.ID_V3);
            boolean bV31 = hasId(blocks, ApkSigBlock.ID_V31);
            boolean v1zip = v1PresentZip(apk);

            ApkSigBlock.BlockVerify bv = null;
            try {
                bv = ApkSigBlock.verifyByBlock(apk);
            } catch (Throwable ignored) {
            }

            fillV1(r, apkRef, sw, useApkSig, v1zip, zipBroken);
            fillV2V3(r, "sig.v2", r.v2, "v2", ApkSigBlock.ID_V2, bV2, apkRef,
                    sw == null ? null : sw.v2, useApkSig, blocks, bv, zipBroken);
            fillV2V3(r, "sig.v3", r.v3, "v3", ApkSigBlock.ID_V3, bV3, apkRef,
                    sw == null ? null : sw.v3, useApkSig, blocks, bv, zipBroken);
            fillV2V3(r, "sig.v31", r.v31, "v3.1", ApkSigBlock.ID_V31, bV31, apkRef,
                    sw == null ? null : sw.v31, useApkSig, blocks, bv, zipBroken);

            // Integridad: digest interno (real, siempre intentado).
            if (bv != null && ("OK".equals(bv.all.integrity) || "FALLA".equals(bv.all.integrity))) {
                r.integrityOk = "OK".equals(bv.all.integrity) ? AuthTri.TRUE : AuthTri.FALSE;
                r.evidence.add(new AuthEvidence("sig.digest", "signature",
                        "OK".equals(bv.all.integrity) ? "PASS" : "FAIL",
                        "bloque-firma", "digest-v2v3-aosp",
                        "integridad=" + bv.all.integrity, "",
                        apkRef, "OK".equals(bv.all.integrity) ? "" : bv.all.detail));
            } else if (!bV2 && !bV3 && !bV31 && r.v1.present == AuthTri.TRUE) {
                if (useApkSig && r.v1.verified == AuthTri.TRUE) {
                    r.integrityOk = AuthTri.TRUE;
                    r.evidence.add(new AuthEvidence("sig.digest", "signature", "PASS",
                            "zip", ApkSigAdapter.LIB + " v1",
                            "v1 verificado", "", apkRef, ""));
                } else if (useApkSig && r.v1.verified == AuthTri.FALSE) {
                    r.integrityOk = AuthTri.FALSE;
                    r.evidence.add(new AuthEvidence("sig.digest", "signature", "FAIL",
                            "zip", ApkSigAdapter.LIB + " v1",
                            "v1 con errores", "", apkRef, join(r.verificationErrors)));
                } else {
                    r.integrityOk = AuthTri.UNKNOWN;
                    r.evidence.add(new AuthEvidence("sig.digest", "signature", "UNKNOWN",
                            "zip", "v1-sin-verificar",
                            "solo v1 y no verificado", "", apkRef, ""));
                }
            } else if (!bV2 && !bV3 && !bV31 && r.v1.present != AuthTri.TRUE) {
                if (zipBroken) {
                    r.integrityOk = AuthTri.UNKNOWN;
                    r.evidence.add(new AuthEvidence("sig.digest", "signature", "UNKNOWN",
                            "zip", "presencia",
                            "archivo no legible como ZIP: nada valorable", "", apkRef, ""));
                } else {
                    r.integrityOk = AuthTri.FALSE;
                    r.evidence.add(new AuthEvidence("sig.digest", "signature", "FAIL",
                            "zip", "presencia",
                            "sin firma: sin integridad demostrable", "", apkRef, ""));
                }
            } else {
                r.integrityOk = AuthTri.UNKNOWN;
                r.evidence.add(new AuthEvidence("sig.digest", "signature", "UNKNOWN",
                        "bloque-firma", "digest-v2v3-aosp",
                        bv == null ? "no comprobable" : bv.all.detail, "", apkRef, ""));
            }

            collectCerts(r, sw, useApkSig, blocks);
            if (useApkSig) {
                for (String e : sw.errors) addError(r, e);
                for (String w : sw.warnings) addError(r, "aviso: " + w);
            }
            r.method = useApkSig ? ApkSigAdapter.LIB + "+interno" : "interno";
            if (sw != null && !sw.available && !sw.unavailableReason.isEmpty()) {
                addError(r, "apksig no usado: " + sw.unavailableReason);
            }
        } catch (Throwable t) {
            addError(r, "fallo inspeccionando firma");
        }
        return r;
    }

    private static void fillV1(SigResult r, String apkRef, ApkSigAdapter.Result sw,
                               boolean useApkSig, boolean v1zip, boolean zipBroken) {
        try {
            boolean swHas = useApkSig && (!sw.v1.isEmpty() || !sw.v1ignored.isEmpty());
            boolean present = swHas || v1zip;
            if (!present && zipBroken && !useApkSig) {
                r.v1.present = AuthTri.UNKNOWN;
                r.v1.verified = AuthTri.UNKNOWN;
                r.v1.detail = "ZIP ilegible: v1 no valorable";
                r.evidence.add(new AuthEvidence("sig.v1", "signature", "UNKNOWN",
                        "zip", "presencia", "ZIP ilegible", "", apkRef, ""));
                return;
            }
            r.v1.present = AuthTri.of(present);
            r.v1.method = useApkSig ? ApkSigAdapter.LIB : "zip";
            if (!present) {
                r.v1.verified = AuthTri.UNKNOWN;
                r.v1.detail = "sin firma v1";
                r.evidence.add(new AuthEvidence("sig.v1", "signature", "INFO",
                        "zip", "presencia", "ausente", "", apkRef, ""));
                return;
            }
            if (useApkSig && !sw.v1.isEmpty()) {
                boolean errs = false;
                for (ApkSigAdapter.SignerInfo s : sw.v1) {
                    if (s.hasErrors) {
                        errs = true;
                        for (String e : s.errors) addError(r, "v1: " + e);
                    }
                }
                r.v1.verified = errs ? AuthTri.FALSE : AuthTri.TRUE;
                r.v1.detail = errs ? "v1 con errores" : "v1 verificado (" + sw.v1.size()
                        + " firmante(s))";
                r.evidence.add(new AuthEvidence("sig.v1", "signature",
                        errs ? "FAIL" : "PASS", "zip", ApkSigAdapter.LIB + " verify()",
                        r.v1.detail, "", apkRef, errs ? join(r.verificationErrors) : ""));
            } else if (useApkSig && !sw.v1ignored.isEmpty()) {
                r.v1.verified = AuthTri.UNKNOWN;
                r.v1.detail = "v1 ignorado por apksig (" + sw.v1ignored.size() + ")";
                r.evidence.add(new AuthEvidence("sig.v1", "signature", "UNKNOWN",
                        "zip", ApkSigAdapter.LIB, r.v1.detail, "", apkRef, ""));
            } else {
                r.v1.verified = AuthTri.UNKNOWN;
                r.v1.detail = "v1 presente; verificación JAR requiere apksig";
                r.evidence.add(new AuthEvidence("sig.v1", "signature", "UNKNOWN",
                        "zip", "presencia",
                        "META-INF presente, contenido no verificado", "", apkRef, ""));
            }
        } catch (Throwable ignored) {
            r.v1.verified = AuthTri.UNKNOWN;
        }
    }

    private static void fillV2V3(SigResult r, String evId, SchemeResult dst, String name,
                                 int blockId, boolean blockPresent, String apkRef,
                                 List<ApkSigAdapter.SignerInfo> swSigners, boolean useApkSig,
                                 List<ApkSigBlock.Block> blocks, ApkSigBlock.BlockVerify bv,
                                 boolean zipBroken) {
        try {
            boolean swHas = useApkSig && swSigners != null && !swSigners.isEmpty();
            boolean present = swHas || blockPresent;
            if (!present) {
                if (zipBroken && !useApkSig) {
                    dst.present = AuthTri.UNKNOWN;
                    dst.verified = AuthTri.UNKNOWN;
                    dst.detail = "archivo ilegible: " + name + " no valorable";
                    r.evidence.add(new AuthEvidence(evId, "signature", "UNKNOWN",
                            "bloque-firma", "presencia", "archivo ilegible", "", apkRef, ""));
                } else {
                    dst.present = AuthTri.FALSE;
                    dst.verified = AuthTri.UNKNOWN;
                    dst.detail = "sin firma " + name;
                    r.evidence.add(new AuthEvidence(evId, "signature", "INFO",
                            "bloque-firma", "presencia", "ausente", "", apkRef, ""));
                }
                return;
            }
            dst.present = AuthTri.TRUE;
            if (swHas) {
                boolean errs = false;
                StringBuilder eb = new StringBuilder();
                for (ApkSigAdapter.SignerInfo s : swSigners) {
                    if (s.hasErrors) {
                        errs = true;
                        for (String e : s.errors) {
                            addError(r, name + ": " + e);
                            if (eb.length() > 0) eb.append("; ");
                            eb.append(e);
                        }
                    }
                }
                dst.verified = errs ? AuthTri.FALSE : AuthTri.TRUE;
                dst.method = ApkSigAdapter.LIB;
                dst.detail = errs ? (name + " con errores: " + eb) :
                        (name + " verificado (" + swSigners.size() + " firmante(s))");
                r.evidence.add(new AuthEvidence(evId, "signature",
                        errs ? "FAIL" : "PASS", "bloque-firma",
                        ApkSigAdapter.LIB + " verify()", dst.detail, "", apkRef,
                        errs ? eb.toString() : ""));
                return;
            }
            // Respaldo interno: digest del bloque + firma JCA por firmante.
            dst.method = "interno";
            ApkSigBlock.Verify dv = bv == null ? null : bv.byId.get(blockId);
            AuthTri digestTri = AuthTri.UNKNOWN;
            if (dv != null) {
                if ("OK".equals(dv.integrity)) digestTri = AuthTri.TRUE;
                else if ("FALLA".equals(dv.integrity)) digestTri = AuthTri.FALSE;
            }
            byte[] value = valueOf(blocks, blockId);
            boolean v3layout = blockId == ApkSigBlock.ID_V3 || blockId == ApkSigBlock.ID_V31;
            List<ApkSigBlock.SignerData> signers = ApkSigBlock.signersOf(value, v3layout);
            if (signers.isEmpty()) {
                dst.verified = AuthTri.UNKNOWN;
                dst.detail = name + " presente pero sin firmantes legibles";
                r.evidence.add(new AuthEvidence(evId, "signature", "UNKNOWN",
                        "bloque-firma", "interno", dst.detail, "", apkRef, ""));
                return;
            }
            boolean anyUnsupported = false;
            boolean allSigOk = true;
            for (ApkSigBlock.SignerData sd : signers) {
                AuthTri st = verifySignerSigs(sd);
                if (st == AuthTri.FALSE) allSigOk = false;
                else if (st == AuthTri.UNKNOWN) anyUnsupported = true;
            }
            if (!allSigOk) {
                dst.verified = AuthTri.FALSE;
                dst.detail = name + ": firma asimétrica inválida (JCA)";
            } else if (digestTri == AuthTri.FALSE) {
                dst.verified = AuthTri.FALSE;
                dst.detail = name + ": digest no coincide (contenido alterado)";
            } else if (digestTri == AuthTri.TRUE && !anyUnsupported) {
                dst.verified = AuthTri.TRUE;
                dst.detail = name + ": digest + firma JCA válidos (" + signers.size()
                        + " firmante(s))";
            } else {
                dst.verified = AuthTri.UNKNOWN;
                dst.detail = name + ": comprobación parcial (digest=" + digestTri
                        + (anyUnsupported ? ", firmas no soportadas" : "") + ")";
            }
            r.evidence.add(new AuthEvidence(evId, "signature",
                    dst.verified == AuthTri.TRUE ? "PASS"
                            : (dst.verified == AuthTri.FALSE ? "FAIL" : "UNKNOWN"),
                    "bloque-firma", "digest-aosp+jca", dst.detail, "", apkRef, ""));
        } catch (Throwable ignored) {
            dst.verified = AuthTri.UNKNOWN;
        }
    }

    /**
     * Verifica las firmas asimétricas de un firmante con JCA sobre sus bytes
     * de signed-data y la clave pública de su certificado.
     * TRUE si ≥1 firma valida; FALSE si alguna falla criptográficamente;
     * UNKNOWN si solo hay algoritmos no soportados o claves ilegibles.
     */
    static AuthTri verifySignerSigs(ApkSigBlock.SignerData sd) {
        try {
            if (sd == null || sd.signedData == null || sd.sigs.isEmpty()) {
                return AuthTri.UNKNOWN;
            }
            PublicKey pk = null;
            for (byte[] c : sd.certs) {
                try {
                    X509Certificate xc = AuthCert.parseDer(c);
                    if (xc != null && xc.getPublicKey() != null) {
                        pk = xc.getPublicKey();
                        break;
                    }
                } catch (Throwable ignored) {
                }
            }
            if (pk == null) return AuthTri.UNKNOWN;
            boolean anyValid = false;
            boolean anyUnsupported = false;
            for (ApkSigBlock.SigRec sr : sd.sigs) {
                if (sr == null || sr.sig == null) continue;
                String jca = ApkSigBlock.jcaSigForAlg(sr.alg);
                if (jca == null) {
                    anyUnsupported = true;
                    continue;
                }
                try {
                    Signature sig = Signature.getInstance(jca);
                    if (sr.alg == 0x0101) {
                        sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
                                MGF1ParameterSpec.SHA256, 32, 1));
                    } else if (sr.alg == 0x0102) {
                        sig.setParameter(new PSSParameterSpec("SHA-512", "MGF1",
                                MGF1ParameterSpec.SHA512, 64, 1));
                    }
                    sig.initVerify(pk);
                    sig.update(sd.signedData);
                    if (sig.verify(sr.sig)) {
                        anyValid = true;
                    } else {
                        return AuthTri.FALSE;
                    }
                } catch (java.security.InvalidKeyException
                        | java.security.NoSuchAlgorithmException
                        | java.security.InvalidAlgorithmParameterException e) {
                    anyUnsupported = true;
                } catch (Throwable t) {
                    // SignatureException (codificación rota) = no comprobable.
                    anyUnsupported = true;
                }
            }
            if (anyValid) return AuthTri.TRUE;
            return AuthTri.UNKNOWN;
        } catch (Throwable ignored) {
            return AuthTri.UNKNOWN;
        }
    }

    private static void collectCerts(SigResult r, ApkSigAdapter.Result sw,
                                     boolean useApkSig, List<ApkSigBlock.Block> blocks) {
        try {
            List<X509Certificate> fromSw = new ArrayList<>();
            if (useApkSig && sw != null) {
                fromSw.addAll(sw.signerCerts);
                if (fromSw.isEmpty()) {
                    for (List<ApkSigAdapter.SignerInfo> l : v3v2v1(sw)) {
                        for (ApkSigAdapter.SignerInfo s : l) {
                            if (s.cert != null) fromSw.add(s.cert);
                        }
                    }
                }
            }
            for (X509Certificate c : fromSw) {
                AuthCert.Info i = AuthCert.from(c);
                if (!i.sha256.isEmpty() && !hasSha(r.signerCerts, i.sha256)) {
                    r.signerCerts.add(i);
                }
                if (r.signerCerts.size() >= 8) break;
            }
            if (r.signerCerts.isEmpty()) {
                for (int id : new int[]{ApkSigBlock.ID_V3, ApkSigBlock.ID_V31,
                        ApkSigBlock.ID_V2}) {
                    byte[] v = valueOf(blocks, id);
                    if (v == null) continue;
                    boolean v3l = id != ApkSigBlock.ID_V2;
                    for (ApkSigBlock.SignerData sd : ApkSigBlock.signersOf(v, v3l)) {
                        for (byte[] c : sd.certs) {
                            AuthCert.Info i = AuthCert.fromDer(c);
                            if (!i.sha256.isEmpty() && !hasSha(r.signerCerts, i.sha256)) {
                                r.signerCerts.add(i);
                            }
                            if (r.signerCerts.size() >= 8) break;
                        }
                    }
                    if (!r.signerCerts.isEmpty()) break;
                }
            }
            // Compatibilidad Android declarada por v3/v3.1.
            if (useApkSig && sw != null) {
                StringBuilder cb = new StringBuilder();
                for (List<ApkSigAdapter.SignerInfo> l : v3v31(sw)) {
                    for (ApkSigAdapter.SignerInfo s : l) {
                        if (s.minSdk >= 0 || s.maxSdk >= 0) {
                            if (cb.length() > 0) cb.append("; ");
                            cb.append("minSdk=").append(s.minSdk)
                                    .append(" maxSdk=").append(s.maxSdk);
                            if (s.devRelease) cb.append(" devRelease");
                        }
                    }
                }
                r.compatNote = cb.toString();
            }
            if (!r.signerCerts.isEmpty()) {
                r.primarySignerSha256 = r.signerCerts.get(0).sha256;
            }
            r.signerCount = r.signerCerts.size();
            if (r.signerCount <= 1) {
                r.multiSignerNote = r.signerCerts.isEmpty() ? "sin firmantes"
                        : "firmante único";
            } else {
                r.multiSignerNote = "firmantes múltiples: " + r.signerCount;
            }
        } catch (Throwable ignored) {
        }
    }

    private static List<List<ApkSigAdapter.SignerInfo>> v3v2v1(ApkSigAdapter.Result sw) {
        List<List<ApkSigAdapter.SignerInfo>> out = new ArrayList<>();
        out.add(sw.v3);
        out.add(sw.v31);
        out.add(sw.v2);
        out.add(sw.v1);
        return out;
    }

    private static List<List<ApkSigAdapter.SignerInfo>> v3v31(ApkSigAdapter.Result sw) {
        List<List<ApkSigAdapter.SignerInfo>> out = new ArrayList<>();
        out.add(sw.v3);
        out.add(sw.v31);
        return out;
    }

    private static boolean hasSha(List<AuthCert.Info> l, String sha) {
        for (AuthCert.Info i : l) {
            if (sha.equals(i.sha256)) return true;
        }
        return false;
    }

    private static boolean hasId(List<ApkSigBlock.Block> blocks, int id) {
        try {
            for (ApkSigBlock.Block b : blocks) {
                if (b.id == id) return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static byte[] valueOf(List<ApkSigBlock.Block> blocks, int id) {
        try {
            for (ApkSigBlock.Block b : blocks) {
                if (b.id == id) return b.value;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** true si el ZIP abre (EOCD + directorio legibles). Nunca lanza. */
    static boolean readableZip(File apk) {
        ZipFile zip = null;
        try {
            if (apk == null || !apk.isFile()) return false;
            zip = new ZipFile(apk);
            zip.entries();
            return true;
        } catch (Throwable ignored) {
            return false;
        } finally {
            if (zip != null) {
                try {
                    zip.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    /** Presencia v1 por entradas META-INF (nombres, sin leer contenido). */
    static boolean v1PresentZip(File apk) {
        ZipFile zip = null;
        try {
            if (apk == null || !apk.isFile()) return false;
            zip = new ZipFile(apk);
            boolean mf = false;
            boolean sf = false;
            boolean blk = false;
            Enumeration<? extends ZipEntry> en = zip.entries();
            int guard = 0;
            while (en.hasMoreElements() && guard++ < 200000) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                String n = e.getName();
                if (!n.startsWith("META-INF/")) continue;
                String u = n.toUpperCase();
                if (u.equals("META-INF/MANIFEST.MF")) mf = true;
                else if (u.endsWith(".SF")) sf = true;
                else if (u.endsWith(".RSA") || u.endsWith(".DSA") || u.endsWith(".EC")) blk = true;
                if (mf && sf && blk) return true;
            }
            return mf && (sf || blk);
        } catch (Throwable ignored) {
            return false;
        } finally {
            if (zip != null) {
                try {
                    zip.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static void addError(SigResult r, String e) {
        try {
            if (e == null || e.isEmpty()) return;
            if (r.verificationErrors.size() >= 20) return;
            String v = e.length() > 300 ? e.substring(0, 300) : e;
            if (!r.verificationErrors.contains(v)) r.verificationErrors.add(v);
        } catch (Throwable ignored) {
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
