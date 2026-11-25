package com.nexos.reamobile.engine.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Capa 4: linaje de rotación válido y linaje desconocido (escenarios 7 y 8).
 */
public class AuthRotationTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void linajeValidoConApksig() throws Exception {
        AuthFixture.KeyCert oldKc = AuthFixture.genRsa("CN=Old", 3001);
        AuthFixture.KeyCert newKc = AuthFixture.genRsa("CN=New", 3002);
        Object lin = AuthFixture.lineage(oldKc, newKc);
        File in = new File(tmp.getRoot(), "rot-in.apk");
        File out = new File(tmp.getRoot(), "rot.apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        s.v2 = false;
        s.v3 = true;
        s.lineage = lin;
        s.rotationMinSdk = 24;
        AuthFixture.sign(in, out, newKc, s);

        AuthResult.Report r = ReaAuthenticityEngine.analyze(out);
        assertEquals(AuthTri.TRUE, r.rotation.lineagePresent);
        assertEquals(AuthTri.TRUE, r.rotation.lineageValid);
        assertEquals(2, r.rotation.certificates.size());
        // observed_key es la clave firmante real, la más reciente.
        assertEquals(newKc.sha256, r.rotation.observedKey);
        assertEquals(newKc.sha256,
                r.rotation.certificates.get(r.rotation.certificates.size() - 1).sha256);
        assertEquals(oldKc.sha256, r.rotation.certificates.get(0).sha256);
        assertTrue(!r.rotation.sdkNote.isEmpty());
    }

    @Test
    public void linajeOficialAmparaRotacion() throws Exception {
        AuthFixture.KeyCert oldKc = AuthFixture.genRsa("CN=Old", 3003);
        AuthFixture.KeyCert newKc = AuthFixture.genRsa("CN=New", 3004);
        Object lin = AuthFixture.lineage(oldKc, newKc);
        File in = new File(tmp.getRoot(), "rot2-in.apk");
        File out = new File(tmp.getRoot(), "rot2.apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        s.v2 = false;
        s.v3 = true;
        s.lineage = lin;
        s.rotationMinSdk = 24;
        AuthFixture.sign(in, out, newKc, s);

        // Allowlist solo conoce la clave antigua + linaje oficial old→new.
        ReaAuthenticityEngine.Options o = new ReaAuthenticityEngine.Options();
        o.allowlistJson = AuthFixture.allowlistWithLineage("com.example.app",
                oldKc.sha256, newKc.sha256, oldKc.sha256);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(out, o);
        assertEquals("MISMATCH", r.signature.allowMatch);
        assertEquals(AuthTri.TRUE, r.rotation.lineageMatchesOfficial);
        // La rotación legítima no es NOT_OFFICIAL.
        assertTrue(!"NOT_OFFICIAL".equals(r.verdict.overall));
        assertEquals(AuthTri.TRUE, r.verdict.officialSignerMatch);
    }

    @Test
    public void v3SinLinajeEsUnknownNoFallo() throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa("CN=Solo", 3005);
        File in = new File(tmp.getRoot(), "norot-in.apk");
        File out = new File(tmp.getRoot(), "norot.apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        s.v2 = false;
        s.v3 = true;
        AuthFixture.sign(in, out, kc, s);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(out);
        assertEquals(AuthTri.FALSE, r.rotation.lineagePresent);
        assertEquals(AuthTri.UNKNOWN, r.rotation.lineageValid);
        assertEquals(AuthTri.UNKNOWN, r.rotation.lineageMatchesOfficial);
    }

    @Test
    public void linajeSinApksigDetectaPresencia() throws Exception {
        AuthFixture.KeyCert oldKc = AuthFixture.genRsa("CN=Old", 3006);
        AuthFixture.KeyCert newKc = AuthFixture.genRsa("CN=New", 3007);
        Object lin = AuthFixture.lineage(oldKc, newKc);
        File in = new File(tmp.getRoot(), "rotfb-in.apk");
        File out = new File(tmp.getRoot(), "rotfb.apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        s.v2 = false;
        s.v3 = true;
        s.lineage = lin;
        s.rotationMinSdk = 24;
        AuthFixture.sign(in, out, newKc, s);
        ReaAuthenticityEngine.Options o = new ReaAuthenticityEngine.Options();
        o.forceInternal = true;
        AuthResult.Report r = ReaAuthenticityEngine.analyze(out, o);
        // Presencia por atributo, validez honesta UNKNOWN.
        assertEquals(AuthTri.TRUE, r.rotation.lineagePresent);
        assertEquals(AuthTri.UNKNOWN, r.rotation.lineageValid);
        assertEquals(newKc.sha256, r.rotation.observedKey);
    }

    @Test
    public void etapaRotacionIndividual() throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa("CN=Solo", 3008);
        File in = new File(tmp.getRoot(), "st-in.apk");
        File out = new File(tmp.getRoot(), "st.apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        s.v2 = false;
        s.v3 = true;
        AuthFixture.sign(in, out, kc, s);
        AuthRotation.RotResult r = ReaAuthenticityEngine.stageRotation(
                out, kc.sha256, null, "com.example.app");
        assertEquals(AuthTri.FALSE, r.lineagePresent);
        assertEquals(kc.sha256, r.observedKey);
    }
}
