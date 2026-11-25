package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.Arrays;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** Pruebas del lector del bloque de firma con APK sintético. */
public class ApkSigBlockTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    static final byte[] FAKE_CERT = {0x30, 0x03, 0x02, 0x01, 0x05};

    @Test
    public void extraeCertificadoV2() throws Exception {
        File apk = new File(tmp.getRoot(), "firmado.apk");
        writeApk(apk, true);
        ApkSigBlock.SigInfo si = ApkSigBlock.parse(apk);
        assertEquals("v2", si.scheme);
        assertTrue(Arrays.equals(FAKE_CERT, si.cert));
        assertNull(si.error);
    }

    @Test
    public void sinBloque() throws Exception {
        File apk = new File(tmp.getRoot(), "plano.apk");
        writeApk(apk, false);
        ApkSigBlock.SigInfo si = ApkSigBlock.parse(apk);
        assertNull(si.cert);
        assertTrue(si.error != null);
        ApkSigBlock.SigInfo no = ApkSigBlock.parse(new File(tmp.getRoot(), "noexiste.apk"));
        assertNull(no.cert);
    }

    @Test
    public void valoresMalosNoLanzan() {
        assertNull(ApkSigBlock.firstCert(null));
        assertNull(ApkSigBlock.firstCert(new byte[0]));
        assertNull(ApkSigBlock.firstCert(new byte[]{1, 2, 3, 4, 5}));
        assertTrue(ApkSigBlock.splitPairs(new byte[4]).isEmpty());
    }

    @Test
    public void verificaDigestOk() throws Exception {
        File apk = new File(tmp.getRoot(), "ok.apk");
        // Los digests no cubren el bloque: se calculan con ceros y se reescriben.
        writeApk(apk, true, new byte[32]);
        byte[] real = digestDe(apk, "SHA-256");
        writeApk(apk, true, real);
        ApkSigBlock.Verify v = ApkSigBlock.verify(apk);
        assertEquals("OK", v.integrity);
    }

    @Test
    public void detectaManipulacion() throws Exception {
        File apk = new File(tmp.getRoot(), "tocado.apk");
        writeApk(apk, true, new byte[32]);
        writeApk(apk, true, digestDe(apk, "SHA-256"));
        assertEquals("OK", ApkSigBlock.verify(apk).integrity);
        java.io.RandomAccessFile raf = new java.io.RandomAccessFile(apk, "rw");
        raf.seek(10);
        raf.write(raf.read() ^ 0xFF);
        raf.close();
        assertEquals("FALLA", ApkSigBlock.verify(apk).integrity);
    }

    @Test
    public void estadosSinDigest() throws Exception {
        File plano = new File(tmp.getRoot(), "plano2.apk");
        writeApk(plano, false);
        assertEquals("sin-bloque", ApkSigBlock.verify(plano).integrity);
        File sinDig = new File(tmp.getRoot(), "sindig.apk");
        writeApk(sinDig, true);
        assertEquals("no-comprobable", ApkSigBlock.verify(sinDig).integrity);
        assertEquals("sin-bloque",
                ApkSigBlock.verify(new File(tmp.getRoot(), "noexiste.apk")).integrity);
    }

    static byte[] digestDe(File apk, String jca) throws Exception {
        long[] loc = ApkSigBlock.locate(apk);
        java.io.RandomAccessFile raf = new java.io.RandomAccessFile(apk, "r");
        byte[] d = ApkSigBlock.contentDigest(raf, loc[0], loc[2], loc[3], loc[4], loc[5], jca);
        raf.close();
        return d;
    }

    static void lp(ByteArrayOutputStream b, byte[] data) {
        ReaEngineTest.le32(b, data.length);
        b.write(data, 0, data.length);
    }

    /** Mini-APK con o sin bloque de firma v2 sintético (sin digests). */
    static void writeApk(File out, boolean sig) throws Exception {
        writeApk(out, sig, null);
    }

    /** Mini-APK con bloque v2 y un digest SHA-256 (puede ser null). */
    static void writeApk(File out, boolean sig, byte[] digest) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] name = "a.txt".getBytes("UTF-8");
        byte[] data = "hi".getBytes("UTF-8");
        ReaEngineTest.le32(b, 0x04034b50);
        ReaEngineTest.le16(b, 20);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le32(b, 0);
        ReaEngineTest.le32(b, data.length);
        ReaEngineTest.le32(b, data.length);
        ReaEngineTest.le16(b, name.length);
        ReaEngineTest.le16(b, 0);
        b.write(name);
        b.write(data);
        if (sig) {
            // value v2 = lp(firmante); firmante = lp(signedData)+lp(vacío)+lp(pubkey)
            ByteArrayOutputStream certs = new ByteArrayOutputStream();
            lp(certs, FAKE_CERT);
            ByteArrayOutputStream sd = new ByteArrayOutputStream();
            if (digest == null) {
                lp(sd, new byte[0]);
            } else {
                ByteArrayOutputStream rec = new ByteArrayOutputStream();
                ReaEngineTest.le32(rec, 0x0101);
                ReaEngineTest.le32(rec, digest.length);
                rec.write(digest, 0, digest.length);
                ByteArrayOutputStream dig = new ByteArrayOutputStream();
                lp(dig, rec.toByteArray());
                lp(sd, dig.toByteArray());
            }
            lp(sd, certs.toByteArray());
            lp(sd, new byte[0]);
            ByteArrayOutputStream signer = new ByteArrayOutputStream();
            lp(signer, sd.toByteArray());
            lp(signer, new byte[0]);
            lp(signer, new byte[]{9, 9});
            // value = secuencia externa con prefijo + firmante(s) con prefijo (formato AOSP)
            ByteArrayOutputStream seq = new ByteArrayOutputStream();
            lp(seq, signer.toByteArray());
            ByteArrayOutputStream value = new ByteArrayOutputStream();
            lp(value, seq.toByteArray());
            byte[] v = value.toByteArray();
            ByteArrayOutputStream pairs = new ByteArrayOutputStream();
            ReaEngineTest.le64(pairs, 4 + v.length);
            ReaEngineTest.le32(pairs, ApkSigBlock.ID_V2);
            pairs.write(v);
            byte[] p = pairs.toByteArray();
            ReaEngineTest.le64(b, p.length + 24);
            b.write(p);
            ReaEngineTest.le64(b, p.length + 24);
            b.write("APK Sig Block 42".getBytes("UTF-8"));
        }
        int cdOff = b.size();
        ReaEngineTest.le32(b, 0x02014b50);
        ReaEngineTest.le16(b, 20);
        ReaEngineTest.le16(b, 20);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le32(b, 0);
        ReaEngineTest.le32(b, data.length);
        ReaEngineTest.le32(b, data.length);
        ReaEngineTest.le16(b, name.length);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le32(b, 0);
        ReaEngineTest.le32(b, 0);
        ReaEngineTest.le32(b, 0);
        b.write(name);
        int cdSize = b.size() - cdOff;
        ReaEngineTest.le32(b, 0x06054b50);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le16(b, 0);
        ReaEngineTest.le16(b, 1);
        ReaEngineTest.le16(b, 1);
        ReaEngineTest.le32(b, cdSize);
        ReaEngineTest.le32(b, cdOff);
        ReaEngineTest.le16(b, 0);
        FileOutputStream fos = new FileOutputStream(out);
        fos.write(b.toByteArray());
        fos.close();
    }
}
