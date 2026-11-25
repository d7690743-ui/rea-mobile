package com.nexos.reamobile.engine.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Capa 2: certificado desconocido, oficial reconocido y error de allowlist
 * (escenarios 5, 6 y 20). El DN nunca acredita identidad.
 */
public class AuthIdentityTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private File signedApk(String cn, long seed) throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa(cn, seed);
        File in = new File(tmp.getRoot(), "id-in.apk");
        File out = new File(tmp.getRoot(), "id.apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        AuthFixture.sign(in, out, kc, s);
        return out;
    }

    @Test
    public void certificadoDesconocidoDaUnknown() throws Exception {
        File apk = signedApk("CN=Unknown", 2001);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk);
        assertEquals("UNKNOWN", r.signature.allowMatch);
        assertEquals(AuthTri.UNKNOWN, r.verdict.officialSignerMatch);
        // UNKNOWN jamás produce NOT_OFFICIAL por sí solo.
        assertTrue(!"NOT_OFFICIAL".equals(r.verdict.overall));
    }

    @Test
    public void certificadoOficialReconocidoDaMatch() throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa("CN=Official", 2002);
        File in = new File(tmp.getRoot(), "of-in.apk");
        File out = new File(tmp.getRoot(), "of.apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        AuthFixture.sign(in, out, kc, s);
        ReaAuthenticityEngine.Options o = new ReaAuthenticityEngine.Options();
        o.allowlistJson = AuthFixture.allowlistJson("t", "7", "com.example.app",
                kc.sha256, false);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(out, o);
        assertEquals("MATCH", r.signature.allowMatch);
        assertEquals("7", r.signature.allowVersion);
        assertEquals(AuthTri.TRUE, r.verdict.officialSignerMatch);
        // Identidad + firma válida + sin discrepancias = OFFICIAL.
        assertEquals("OFFICIAL", r.verdict.overall);
    }

    @Test
    public void nombreGoogleEnDnNoAcreditaNada() throws Exception {
        // CN=Google sin allowlist: UNKNOWN, jamás oficial por el nombre.
        File apk = signedApk("CN=Google Inc.", 2003);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk);
        assertEquals("UNKNOWN", r.signature.allowMatch);
        assertTrue(!"OFFICIAL".equals(r.verdict.overall));
        assertTrue(r.signature.signerCerts.get(0).subjectDn.contains("Google"));
    }

    @Test
    public void discrepanciaDaMismatchYNotOfficial() throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa("CN=Attacker", 2004);
        AuthFixture.KeyCert official = AuthFixture.genRsa("CN=Official", 2005);
        File in = new File(tmp.getRoot(), "mm-in.apk");
        File out = new File(tmp.getRoot(), "mm.apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        AuthFixture.sign(in, out, kc, s);
        ReaAuthenticityEngine.Options o = new ReaAuthenticityEngine.Options();
        o.allowlistJson = AuthFixture.allowlistJson("t", "1", "com.example.app",
                official.sha256, false);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(out, o);
        assertEquals("MISMATCH", r.signature.allowMatch);
        // Sin linaje oficial aplicable: discrepancia confirmada.
        assertEquals("NOT_OFFICIAL", r.verdict.overall);
    }

    @Test
    public void certificadoHistoricoSigueMatch() throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa("CN=Old", 2006);
        File in = new File(tmp.getRoot(), "hi-in.apk");
        File out = new File(tmp.getRoot(), "hi.apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        AuthFixture.sign(in, out, kc, s);
        ReaAuthenticityEngine.Options o = new ReaAuthenticityEngine.Options();
        o.allowlistJson = AuthFixture.allowlistJson("t", "1", "com.example.app",
                kc.sha256, true);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(out, o);
        assertEquals("MATCH", r.signature.allowMatch);
        assertEquals("OFFICIAL", r.verdict.overall);
        boolean warned = false;
        for (String w : r.verdict.warnings) {
            if (w.contains("histórico")) warned = true;
        }
        assertTrue(warned);
    }

    @Test
    public void allowlistRotaDaError() throws Exception {
        File apk = signedApk("CN=X", 2007);
        ReaAuthenticityEngine.Options o = new ReaAuthenticityEngine.Options();
        o.allowlistJson = "{json roto,,";
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk, o);
        assertEquals("ERROR", r.signature.allowMatch);
        assertEquals(AuthTri.UNKNOWN, r.verdict.officialSignerMatch);
        // Un error de allowlist jamás acredita ni acusa.
        assertTrue(!"OFFICIAL".equals(r.verdict.overall));
        assertTrue(!"NOT_OFFICIAL".equals(r.verdict.overall));
    }

    @Test
    public void etapaIdentidadIndividual() {
        AuthAllowlist.MatchResult m = ReaAuthenticityEngine.stageIdentity(
                "com.example.app", "AA11",
                AuthFixture.allowlistJson("t", "1", "com.example.app", "AA11", false));
        assertEquals("MATCH", m.status);
        AuthAllowlist.MatchResult u = ReaAuthenticityEngine.stageIdentity(
                "com.other.app", "AA11",
                AuthFixture.allowlistJson("t", "1", "com.example.app", "AA11", false));
        assertEquals("UNKNOWN", u.status);
    }
}
