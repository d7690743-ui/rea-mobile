package com.nexos.reamobile.engine.auth;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Fixtures controlados para las pruebas del motor de autenticidad: claves
 * RSA + certificados autofirmados (DER escrito a mano, sin BouncyCastle),
 * APKs mínimos y firmado real con apksig (v1/v2/v3, linaje, sello).
 * Solo tests. Limitación: los APKs son mínimos sintéticos (manifest en
 * claro, dex ficticio), no APKs de producción; la criptografía sí es real.
 */
public final class AuthFixture {
    private AuthFixture() {
    }

    public static class KeyCert {
        public PrivateKey priv;
        public X509Certificate cert;
        public String sha256 = "";
    }

    /** RSA-2048 + autofirmado SHA256withRSA (semilla fija → reproducible). */
    public static KeyCert genRsa(String cn, long seed) throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, sr);
        KeyPair kp = kpg.generateKeyPair();
        byte[] der = selfSigned(kp, cn, BigInteger.valueOf(seed & 0x7FFFFFFFFFFFFFFFL));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(der));
        KeyCert kc = new KeyCert();
        kc.priv = kp.getPrivate();
        kc.cert = cert;
        kc.sha256 = hex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        return kc;
    }

    // ---- Certificado autofirmado v1 (DER mínimo) ----

    private static byte[] selfSigned(KeyPair kp, String cn, BigInteger serial) throws Exception {
        RSAPublicKey rsa = (RSAPublicKey) kp.getPublic();
        byte[] modBytes = unsigned(rsa.getModulus());
        byte[] expBytes = unsigned(rsa.getPublicExponent());
        byte[] rsaPub = seq(concat(integer(modBytes), integer(expBytes)));
        byte[] rsaAlgId = seq(concat(oid("1.2.840.113549.1.1.1"), bytes(new byte[]{0x05, 0x00})));
        byte[] spki = seq(concat(rsaAlgId, bitString(rsaPub)));
        byte[] sigAlgId = seq(concat(oid("1.2.840.113549.1.1.11"), bytes(new byte[]{0x05, 0x00})));
        byte[] name = seq(bytes(set(seq(concat(oid("2.5.4.3"), utf8(cn))))));
        Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        c.add(Calendar.DAY_OF_YEAR, -1);
        byte[] nb = utcTime(c);
        c.add(Calendar.YEAR, 10);
        byte[] na = utcTime(c);
        byte[] validity = seq(concat(nb, na));
        byte[] serialB = integer(unsigned(serial));
        byte[] tbs = seq(concat(serialB, sigAlgId, name, validity, name, spki));
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(kp.getPrivate());
        s.update(tbs);
        byte[] sig = s.sign();
        return seq(concat(tbs, sigAlgId, bitString(sig)));
    }

    private static byte[] unsigned(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length > 1 && b[0] == 0) {
            byte[] t = new byte[b.length - 1];
            System.arraycopy(b, 1, t, 0, t.length);
            return t;
        }
        return b;
    }

    private static byte[] bytes(byte[] b) {
        return b;
    }

    private static byte[] concat(byte[]... parts) {
        try {
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            for (byte[] p : parts) o.write(p);
            return o.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private static byte[] tlv(int tag, byte[] content) {
        byte[] len;
        if (content.length < 128) {
            len = new byte[]{(byte) content.length};
        } else {
            int n = content.length;
            int nb = 0;
            for (int t = n; t > 0; t >>= 8) nb++;
            len = new byte[1 + nb];
            len[0] = (byte) (0x80 | nb);
            for (int i = nb; i > 0; i--) {
                len[i] = (byte) (n & 0xFF);
                n >>= 8;
            }
        }
        byte[] out = new byte[1 + len.length + content.length];
        out[0] = (byte) tag;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(content, 0, out, 1 + len.length, content.length);
        return out;
    }

    private static byte[] seq(byte[] c) {
        return tlv(0x30, c);
    }

    private static byte[] set(byte[] c) {
        return tlv(0x31, c);
    }

    private static byte[] integer(byte[] c) {
        if (c.length > 0 && (c[0] & 0x80) != 0) {
            byte[] t = new byte[c.length + 1];
            System.arraycopy(c, 0, t, 1, c.length);
            c = t;
        }
        return tlv(0x02, c);
    }

    private static byte[] bitString(byte[] c) {
        byte[] t = new byte[c.length + 1];
        System.arraycopy(c, 0, t, 1, c.length);
        return tlv(0x03, t);
    }

    private static byte[] oid(String dotted) {
        String[] arcs = dotted.split("\\.");
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(40 * Integer.parseInt(arcs[0]) + Integer.parseInt(arcs[1]));
        for (int i = 2; i < arcs.length; i++) {
            long v = Long.parseLong(arcs[i]);
            int nb = 1;
            for (long t = v; t > 127; t >>= 7) nb++;
            for (int j = nb - 1; j >= 0; j--) {
                int b = (int) ((v >> (7 * j)) & 0x7F);
                if (j > 0) b |= 0x80;
                o.write(b);
            }
        }
        return tlv(0x06, o.toByteArray());
    }

    private static byte[] utf8(String s) {
        try {
            return tlv(0x0C, s.getBytes("UTF-8"));
        } catch (Exception e) {
            return tlv(0x0C, new byte[0]);
        }
    }

    private static byte[] utcTime(Calendar c) {
        String s = String.format("%02d%02d%02d%02d%02d%02dZ",
                c.get(Calendar.YEAR) % 100, c.get(Calendar.MONTH) + 1,
                c.get(Calendar.DAY_OF_MONTH), c.get(Calendar.HOUR_OF_DAY),
                c.get(Calendar.MINUTE), c.get(Calendar.SECOND));
        try {
            return tlv(0x17, s.getBytes("ASCII"));
        } catch (Exception e) {
            return tlv(0x17, new byte[0]);
        }
    }

    // ---- APK mínimo ----

    public static class ManifestSpec {
        public String pkg = "com.example.app";
        public long versionCode = 1;
        public String versionName = "1.0";
        public boolean debuggable;
        public boolean testOnly;
        public boolean allowBackup = true;
        public boolean cleartext;
        public boolean netSecConfig;
        public String split = "";
        public List<String> permissions = new ArrayList<>();
        public List<String> activities = new ArrayList<>();
        public List<String> exportedActivities = new ArrayList<>();
    }

    public static String manifestXml(ManifestSpec m) {
        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        sb.append("<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"");
        sb.append(" package=\"").append(m.pkg).append("\"");
        sb.append(" android:versionCode=\"").append(m.versionCode).append("\"");
        sb.append(" android:versionName=\"").append(m.versionName).append("\"");
        if (!m.split.isEmpty()) sb.append(" android:split=\"").append(m.split).append("\"");
        sb.append(">\n");
        for (String p : m.permissions) {
            sb.append("  <uses-permission android:name=\"").append(p).append("\"/>\n");
        }
        sb.append("  <application");
        if (m.debuggable) sb.append(" android:debuggable=\"true\"");
        if (m.testOnly) sb.append(" android:testOnly=\"true\"");
        sb.append(" android:allowBackup=\"").append(m.allowBackup ? "true" : "false").append("\"");
        if (m.cleartext) sb.append(" android:usesCleartextTraffic=\"true\"");
        if (m.netSecConfig) sb.append(" android:networkSecurityConfig=\"@xml/netsec\"");
        sb.append(">\n");
        for (String a : m.activities) {
            sb.append("    <activity android:name=\"").append(a).append("\"/>\n");
        }
        for (String a : m.exportedActivities) {
            sb.append("    <activity android:name=\"").append(a)
                    .append("\" android:exported=\"true\"/>\n");
        }
        sb.append("  </application>\n</manifest>\n");
        return sb.toString();
    }

    /** APK sin firmar con manifest + dex ficticio + extras. */
    public static void writeUnsignedApk(File out, ManifestSpec m,
                                        java.util.Map<String, byte[]> extra) throws Exception {
        writeUnsignedApk(out, m, extra, dexBytes(1));
    }

    /** Igual con bytes de dex controlados. */
    public static void writeUnsignedApk(File out, ManifestSpec m,
                                        java.util.Map<String, byte[]> extra,
                                        byte[] dex) throws Exception {
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(out));
        try {
            put(zos, "AndroidManifest.xml", manifestXml(m).getBytes("UTF-8"));
            put(zos, "classes.dex", dex == null ? dexBytes(1) : dex);
            if (extra != null) {
                for (java.util.Map.Entry<String, byte[]> e : extra.entrySet()) {
                    put(zos, e.getKey(), e.getValue());
                }
            }
        } finally {
            zos.close();
        }
    }

    public static byte[] dexBytes(int fill) {
        byte[] dex = new byte[64];
        for (int i = 0; i < dex.length; i++) dex[i] = (byte) (i * 3 + fill);
        return dex;
    }

    private static void put(ZipOutputStream zos, String name, byte[] data) throws Exception {
        ZipEntry e = new ZipEntry(name);
        e.setTime(1600000000000L);
        zos.putNextEntry(e);
        zos.write(data);
        zos.closeEntry();
    }

    // ---- Firmado real con apksig ----

    public static class SignSpec {
        public boolean v1 = true;
        public boolean v2 = true;
        public boolean v3;
        public int minSdk = 24;
        public Object lineage;
        public KeyCert stamp;
        public boolean debuggablePermitted = true;
        public int rotationMinSdk;
    }

    public static void sign(File in, File out, KeyCert kc, SignSpec spec) throws Exception {
        com.android.apksig.ApkSigner.Builder b =
                new com.android.apksig.ApkSigner.Builder(signerConfigs(kc));
        b.setInputApk(in);
        b.setOutputApk(out);
        b.setV1SigningEnabled(spec.v1);
        b.setV2SigningEnabled(spec.v2);
        b.setV3SigningEnabled(spec.v3);
        b.setMinSdkVersion(spec.minSdk);
        b.setDebuggableApkPermitted(spec.debuggablePermitted);
        if (spec.rotationMinSdk > 0) {
            b.setMinSdkVersionForRotation(spec.rotationMinSdk);
        }
        if (spec.lineage != null) {
            b.setSigningCertificateLineage(
                    (com.android.apksig.SigningCertificateLineage) spec.lineage);
        }
        if (spec.stamp != null) {
            java.util.List<X509Certificate> certs = new ArrayList<>();
            certs.add(spec.stamp.cert);
            com.android.apksig.ApkSigner.SignerConfig stampCfg =
                    new com.android.apksig.ApkSigner.SignerConfig.Builder(
                            "stamp", spec.stamp.priv, certs).build();
            b.setSourceStampSignerConfig(stampCfg);
        }
        b.build().sign();
    }

    private static java.util.List<com.android.apksig.ApkSigner.SignerConfig> signerConfigs(
            KeyCert kc) {
        java.util.List<X509Certificate> certs = new ArrayList<>();
        certs.add(kc.cert);
        com.android.apksig.ApkSigner.SignerConfig cfg =
                new com.android.apksig.ApkSigner.SignerConfig.Builder(
                        "test", kc.priv, certs).build();
        java.util.List<com.android.apksig.ApkSigner.SignerConfig> out = new ArrayList<>();
        out.add(cfg);
        return out;
    }

    /**
     * Linaje old→new vía reflexión (createSigningLineage es privado en
     * apksig; las clases van en classpath así que setAccessible funciona).
     * Solo fixtures de test.
     */
    public static Object lineage(KeyCert oldKc, KeyCert newKc) throws Exception {
        Class<?> linCls = Class.forName("com.android.apksig.SigningCertificateLineage");
        Class<?> scCls = Class.forName(
                "com.android.apksig.SigningCertificateLineage$SignerConfig");
        Class<?> capsCls = Class.forName(
                "com.android.apksig.SigningCertificateLineage$SignerCapabilities");
        Class<?> keyCfgCls = Class.forName("com.android.apksig.KeyConfig");
        Class<?> jcaCls = Class.forName("com.android.apksig.KeyConfig$Jca");
        java.lang.reflect.Constructor<?> jcaCtor = jcaCls.getConstructor(PrivateKey.class);
        java.lang.reflect.Constructor<?> scCtor =
                scCls.getDeclaredConstructor(keyCfgCls, X509Certificate.class);
        scCtor.setAccessible(true);
        Object oldSc = scCtor.newInstance(jcaCtor.newInstance(oldKc.priv), oldKc.cert);
        Object newSc = scCtor.newInstance(jcaCtor.newInstance(newKc.priv), newKc.cert);
        Class<?> builderCls = Class.forName(
                "com.android.apksig.SigningCertificateLineage$SignerCapabilities$Builder");
        Object caps = builderCls.getConstructor().newInstance();
        java.lang.reflect.Method build = builderCls.getMethod("build");
        Object capsObj = build.invoke(caps);
        java.lang.reflect.Method create = linCls.getDeclaredMethod("createSigningLineage",
                int.class, scCls, capsCls);
        create.setAccessible(true);
        Object lin = create.invoke(null, 24, oldSc, capsObj);
        java.lang.reflect.Method spawn = linCls.getMethod("spawnDescendant", scCls, scCls);
        return spawn.invoke(lin, oldSc, newSc);
    }

    // ---- Mutaciones ----

    /** Voltea un byte de contenido (fuera del bloque de firma). */
    public static void tamperContent(File apk) throws Exception {
        java.io.RandomAccessFile raf = new java.io.RandomAccessFile(apk, "rw");
        try {
            raf.seek(20);
            int b = raf.read();
            raf.seek(20);
            raf.write(b ^ 0xFF);
        } finally {
            raf.close();
        }
    }

    /**
     * Voltea un byte dentro de un valor de firma v2/v3/v3.1 (firma
     * inválida), cerca del final del valor (zona de firmas/clave pública)
     * para no romper el parseado: la cripto debe fallar, no el lector.
     */
    public static void tamperSignature(File apk) throws Exception {
        long[] range = com.nexos.reamobile.engine.ApkSigBlock.blockRange(apk);
        if (range == null) throw new IllegalStateException("sin bloque de firma");
        long pairsStart = range[0] + 8;
        long pairsEnd = range[0] + range[1] - 24;
        java.io.RandomAccessFile raf = new java.io.RandomAccessFile(apk, "rw");
        try {
            long p = pairsStart;
            int guard = 0;
            while (p + 12 <= pairsEnd && guard++ < 64) {
                raf.seek(p);
                byte[] h = new byte[12];
                raf.readFully(h);
                long size = u64(h, 0);
                long id = u32(h, 8);
                if (size < 4 || p + 8 + size > pairsEnd + 24) break;
                boolean isSig = id == 0x7109871aL || id == 0xf05368c0L || id == 0x1b93ad61L;
                long vlen = size - 4;
                if (isSig && vlen > 64) {
                    long off = p + 12 + vlen - 300;
                    if (off < p + 16) off = p + 16;
                    raf.seek(off);
                    int b = raf.read();
                    raf.seek(off);
                    raf.write(b ^ 0x01);
                    return;
                }
                p += 8 + size;
            }
            throw new IllegalStateException("sin valor v2/v3 donde tocar");
        } finally {
            raf.close();
        }
    }

    private static long u32(byte[] b, int p) {
        return ((b[p] & 0xFFL) | ((b[p + 1] & 0xFFL) << 8)
                | ((b[p + 2] & 0xFFL) << 16) | ((b[p + 3] & 0xFFL) << 24));
    }

    private static long u64(byte[] b, int p) {
        return (u32(b, p) & 0xFFFFFFFFL) | ((u32(b, p + 4) & 0xFFFFFFFFL) << 32);
    }

    // ---- JSON de referencias ----

    public static String allowlistJson(String id, String version, String pkg,
                                       String sha256, boolean historic) {
        return "{\"schema\":\"rea-allowlist-v1\",\"id\":\"" + id + "\",\"version\":\""
                + version + "\",\"source\":\"test\",\"updated\":\"2026-11-25\","
                + "\"entries\":[{\"package\":\"" + pkg + "\",\"certs\":[{\"sha256\":\""
                + sha256 + "\",\"historic\":" + historic + "}]}],\"lineages\":[]}";
    }

    public static String allowlistWithLineage(String pkg, String oldSha, String newSha,
                                              String curSha) {
        return "{\"schema\":\"rea-allowlist-v1\",\"id\":\"t\",\"version\":\"1\","
                + "\"source\":\"test\",\"updated\":\"\",\"entries\":[{\"package\":\"" + pkg
                + "\",\"certs\":[{\"sha256\":\"" + curSha + "\"}]}],"
                + "\"lineages\":[{\"package\":\"" + pkg + "\",\"chain\":[\""
                + oldSha + "\",\"" + newSha + "\"]}]}";
    }

    public static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            int v = x & 0xFF;
            if (v < 16) sb.append('0');
            sb.append(Integer.toHexString(v).toUpperCase());
        }
        return sb.toString();
    }
}
