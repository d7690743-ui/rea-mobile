package com.nexos.reamobile.engine.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Capa 6 + Capa 7: semántica de indicadores repack, datos incompletos
 * (escenario 18) y matriz de veredictos.
 */
public class AuthRepackVerdictTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private File buildSigned(String name, AuthFixture.ManifestSpec m) throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa("CN=Repack", 6001);
        File in = new File(tmp.getRoot(), name + "-in.apk");
        File out = new File(tmp.getRoot(), name + ".apk");
        AuthFixture.writeUnsignedApk(in, m, null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        AuthFixture.sign(in, out, kc, s);
        return out;
    }

    @Test
    public void debuggableEsIndicadorNoPrueba() throws Exception {
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        m.debuggable = true;
        File apk = buildSigned("dbg", m);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk);
        assertEquals(AuthTri.TRUE, r.repack.debuggable);
        assertEquals(AuthTri.FALSE, r.repack.manifestModified);
        assertEquals(AuthTri.FALSE, r.repack.dexModified);
        // Indicador aislado: UNKNOWN, jamás NOT_OFFICIAL ni SUSPICIOUS solo.
        assertEquals("UNKNOWN", r.verdict.overall);
        assertEquals(AuthTri.TRUE, r.verdict.modificationIndicators);
    }

    @Test
    public void allowBackupSinReferenciaNoEsAnomalia() throws Exception {
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        m.allowBackup = true;
        File apk = buildSigned("bak", m);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk);
        assertEquals(AuthTri.FALSE, r.repack.allowBackupAnomaly);
    }

    @Test
    public void datosIncompletosDanUnknown() throws Exception {
        File trunc = new File(tmp.getRoot(), "trunc.apk");
        FileOutputStream fos = new FileOutputStream(trunc);
        fos.write(new byte[]{0x50, 0x4B, 0x03, 0x04, 0x01, 0x02});
        fos.close();
        AuthResult.Report r = ReaAuthenticityEngine.analyze(trunc);
        assertEquals("UNKNOWN", r.verdict.overall);
        assertEquals("LOW", r.verdict.confidence);
        assertTrue(!r.verdict.unknowns.isEmpty());
        assertTrue(r.toJson().contains("rea-authenticity-v1"));
    }

    @Test
    public void sinFirmaEsSuspiciousNoNotOfficial() throws Exception {
        File in = new File(tmp.getRoot(), "unsigned.apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(in);
        assertEquals(AuthTri.FALSE, r.verdict.apkSignatureValid);
        assertEquals("SUSPICIOUS", r.verdict.overall);
    }

    @Test
    public void oficialCompletoConBaseline() throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa("CN=Full", 6002);
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        File in = new File(tmp.getRoot(), "full-in.apk");
        File out = new File(tmp.getRoot(), "full.apk");
        AuthFixture.writeUnsignedApk(in, m, null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        AuthFixture.sign(in, out, kc, s);
        AuthBaseline.Observed o = AuthBaseline.observe(out, null);
        StringBuilder sb = new StringBuilder();
        sb.append("{\"schema\":\"rea-baseline-v1\",\"id\":\"t\",\"version\":\"1\",");
        sb.append("\"source\":\"test\",\"updated\":\"\",\"entries\":[{\"package\":\"");
        sb.append(o.packageName).append("\",\"version_code\":").append(o.versionCode);
        sb.append(",\"apk_sha256\":\"").append(o.apkSha256).append("\",\"dex_hashes\":{");
        boolean first = true;
        for (java.util.Map.Entry<String, String> e : o.dex.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append("\"").append(e.getKey()).append("\":\"").append(e.getValue()).append("\"");
        }
        sb.append("},\"permissions\":[],\"exported\":[]}]}");
        ReaAuthenticityEngine.Options opts = new ReaAuthenticityEngine.Options();
        opts.baselineJson = sb.toString();
        opts.allowlistJson = AuthFixture.allowlistJson("t", "1", o.packageName,
                kc.sha256, false);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(out, opts);
        assertEquals("OFFICIAL", r.verdict.overall);
        assertEquals("HIGH", r.verdict.confidence);
        boolean playNote = false;
        for (String reason : r.verdict.reasons) {
            if (reason.contains("canal de distribución")) playNote = true;
        }
        assertTrue(playNote);
    }

    @Test
    public void dimensionesPlayNoBloqueanOfficial() throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa("CN=NoPlay", 6003);
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        File in = new File(tmp.getRoot(), "np-in.apk");
        File out = new File(tmp.getRoot(), "np.apk");
        AuthFixture.writeUnsignedApk(in, m, null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        AuthFixture.sign(in, out, kc, s);
        ReaAuthenticityEngine.Options opts = new ReaAuthenticityEngine.Options();
        opts.allowlistJson = AuthFixture.allowlistJson("t", "1", "com.example.app",
                kc.sha256, false);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(out, opts);
        assertEquals(AuthTri.UNKNOWN, r.verdict.playProvenance);
        assertEquals("OFFICIAL", r.verdict.overall);
    }
}
