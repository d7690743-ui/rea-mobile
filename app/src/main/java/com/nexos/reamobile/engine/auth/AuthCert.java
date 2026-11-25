package com.nexos.reamobile.engine.auth;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Identidad criptográfica de un certificado de firmante (Capa 2).
 * El Subject DN se registra como dato descriptivo, NUNCA como prueba de
 * identidad: la identidad es el hash del certificado / clave pública.
 * Java puro. Nunca lanza.
 */
public final class AuthCert {
    private AuthCert() {
    }

    public static class Info {
        public String sha256 = "";
        public String sha1 = "";
        public String md5 = "";
        public String subjectDn = "";
        public String issuerDn = "";
        public String serial = "";
        public String notBefore = "";
        public String notAfter = "";
        public String sigAlg = "";
        public String pubkeySha256 = "";
        /** Huella legible corta para informes ("AB12…EF34"). */
        public String shortPrint = "";

        public String toJson() {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                AuthJson.field(sb, "sha256", sha256, true);
                AuthJson.field(sb, "sha1", sha1, false);
                AuthJson.field(sb, "md5", md5, false);
                AuthJson.field(sb, "subject_dn", subjectDn, false);
                AuthJson.field(sb, "issuer_dn", issuerDn, false);
                AuthJson.field(sb, "serial", serial, false);
                AuthJson.field(sb, "not_before", notBefore, false);
                AuthJson.field(sb, "not_after", notAfter, false);
                AuthJson.field(sb, "sig_alg", sigAlg, false);
                AuthJson.field(sb, "pubkey_sha256", pubkeySha256, false);
                sb.append('}');
                return sb.toString();
            } catch (Throwable ignored) {
                return "{}";
            }
        }
    }

    /** Detalles desde un X509Certificate. Nunca null. Nunca lanza. */
    public static Info from(X509Certificate c) {
        Info i = new Info();
        try {
            if (c == null) return i;
            byte[] enc;
            try {
                enc = c.getEncoded();
            } catch (Throwable ignored) {
                enc = null;
            }
            if (enc != null) {
                i.sha256 = hex(digest("SHA-256", enc));
                i.sha1 = hex(digest("SHA-1", enc));
                i.md5 = hex(digest("MD5", enc));
            }
            try {
                i.subjectDn = String.valueOf(c.getSubjectDN());
            } catch (Throwable ignored) {
            }
            try {
                i.issuerDn = String.valueOf(c.getIssuerDN());
            } catch (Throwable ignored) {
            }
            try {
                i.serial = c.getSerialNumber() == null ? ""
                        : c.getSerialNumber().toString(16).toUpperCase();
            } catch (Throwable ignored) {
            }
            try {
                i.notBefore = c.getNotBefore() == null ? ""
                        : c.getNotBefore().toInstant().toString();
            } catch (Throwable ignored) {
            }
            try {
                i.notAfter = c.getNotAfter() == null ? ""
                        : c.getNotAfter().toInstant().toString();
            } catch (Throwable ignored) {
            }
            try {
                i.sigAlg = nz(c.getSigAlgName());
            } catch (Throwable ignored) {
            }
            try {
                byte[] pk = c.getPublicKey() == null ? null : c.getPublicKey().getEncoded();
                if (pk != null) i.pubkeySha256 = hex(digest("SHA-256", pk));
            } catch (Throwable ignored) {
            }
            i.shortPrint = shortOf(i.sha256);
        } catch (Throwable ignored) {
        }
        return i;
    }

    /** Detalles desde bytes DER. Nunca null. Nunca lanza. */
    public static Info fromDer(byte[] der) {
        try {
            X509Certificate c = parseDer(der);
            if (c == null) return new Info();
            return from(c);
        } catch (Throwable ignored) {
            return new Info();
        }
    }

    /** Lista de detalles desde DERs. Nunca null. Nunca lanza. */
    public static List<Info> listFromDer(List<byte[]> ders) {
        List<Info> out = new ArrayList<>();
        try {
            if (ders == null) return out;
            for (byte[] d : ders) {
                if (d == null) continue;
                Info i = fromDer(d);
                if (!i.sha256.isEmpty()) out.add(i);
                if (out.size() >= 32) break;
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** SHA-256 hex de bytes DER ("" si falla). Nunca lanza. */
    public static String sha256OfDer(byte[] der) {
        try {
            if (der == null) return "";
            return hex(digest("SHA-256", der));
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** Parse DER → X509Certificate, null si no parsea. Nunca lanza. */
    public static X509Certificate parseDer(byte[] der) {
        try {
            if (der == null || der.length == 0 || der.length > 1024 * 1024) return null;
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** Normaliza un hash hex para comparar (mayúsculas, sin ":"). Nunca lanza. */
    public static String normHash(String h) {
        try {
            if (h == null) return "";
            StringBuilder sb = new StringBuilder(h.length());
            for (int i = 0; i < h.length(); i++) {
                char c = h.charAt(i);
                if (c == ':' || c == ' ' || c == '\t' || c == '\n') continue;
                sb.append(Character.toUpperCase(c));
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static byte[] digest(String alg, byte[] data) {
        try {
            return MessageDigest.getInstance(alg).digest(data);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String hex(byte[] b) {
        try {
            if (b == null) return "";
            StringBuilder sb = new StringBuilder(b.length * 2);
            for (byte x : b) {
                int v = x & 0xFF;
                if (v < 16) sb.append('0');
                sb.append(Integer.toHexString(v).toUpperCase());
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static String shortOf(String sha256) {
        try {
            if (sha256 == null || sha256.length() < 12) return "";
            return sha256.substring(0, 4) + "…" + sha256.substring(sha256.length() - 4);
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
