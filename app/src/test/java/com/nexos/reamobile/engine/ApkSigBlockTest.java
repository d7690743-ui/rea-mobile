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

    static void lp(ByteArrayOutputStream b, byte[] data) {
        ReaEngineTest.le32(b, data.length);
        b.write(data, 0, data.length);
    }

    /** Mini-APK con o sin bloque de firma v2 sintético. */
    static void writeApk(File out, boolean sig) throws Exception {
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
            lp(sd, new byte[0]);
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
