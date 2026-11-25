package com.nexos.reamobile.engine.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.HashSet;
import java.util.Set;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Capa 3: sello válido, ausencia de sello y emisor no reconocido
 * (escenarios 9, 10 y 11).
 */
public class AuthProvenanceTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private File signedApk(String name, AuthFixture.KeyCert stamp) throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa("CN=Signer", 4001);
        File in = new File(tmp.getRoot(), name + "-in.apk");
        File out = new File(tmp.getRoot(), name + ".apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        s.v2 = true;
        s.stamp = stamp;
        AuthFixture.sign(in, out, kc, s);
        return out;
    }

    @Test
    public void selloValidoConIdentidadConfiable() throws Exception {
        AuthFixture.KeyCert stamp = AuthFixture.genRsa("CN=Play", 4002);
        File apk = signedApk("stampok", stamp);
        ReaAuthenticityEngine.Options o = new ReaAuthenticityEngine.Options();
        Set<String> trusted = new HashSet<>();
        trusted.add(stamp.sha256);
        o.trustedStamps = trusted;
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk, o);
        assertEquals(AuthTri.TRUE, r.provenance.stampPresent);
        assertEquals(AuthTri.TRUE, r.provenance.stampVerified);
        assertEquals(stamp.sha256, r.provenance.stampCertSha256);
        assertEquals(AuthTri.TRUE, r.provenance.stampMatchesTrusted);
        assertEquals(AuthTri.TRUE, r.provenance.distributedByPlay);
    }

    @Test
    public void selloValidoSinReferenciaNoAtribuye() throws Exception {
        AuthFixture.KeyCert stamp = AuthFixture.genRsa("CN=Play", 4003);
        File apk = signedApk("stampnoref", stamp);
        // Sin referencia confiable: verificado pero no atribuido.
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk);
        assertEquals(AuthTri.TRUE, r.provenance.stampPresent);
        assertEquals(AuthTri.TRUE, r.provenance.stampVerified);
        assertEquals(AuthTri.UNKNOWN, r.provenance.stampMatchesTrusted);
        assertEquals(AuthTri.UNKNOWN, r.provenance.distributedByPlay);
    }

    @Test
    public void ausenciaDeSelloNoEsNegativa() throws Exception {
        File apk = signedApk("nostamp", null);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk);
        assertEquals(AuthTri.FALSE, r.provenance.stampPresent);
        assertEquals(AuthTri.UNKNOWN, r.provenance.stampVerified);
        assertEquals(AuthTri.UNKNOWN, r.provenance.distributedByPlay);
        assertTrue(!"NOT_OFFICIAL".equals(r.verdict.overall));
        assertTrue(!"SUSPICIOUS".equals(r.verdict.overall));
    }

    @Test
    public void emisorNoReconocido() throws Exception {
        AuthFixture.KeyCert stamp = AuthFixture.genRsa("CN=Unknown-Stamp", 4004);
        AuthFixture.KeyCert play = AuthFixture.genRsa("CN=Play", 4005);
        File apk = signedApk("stampunknown", stamp);
        ReaAuthenticityEngine.Options o = new ReaAuthenticityEngine.Options();
        Set<String> trusted = new HashSet<>();
        trusted.add(play.sha256);
        o.trustedStamps = trusted;
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk, o);
        assertEquals(AuthTri.TRUE, r.provenance.stampPresent);
        assertEquals(AuthTri.TRUE, r.provenance.stampVerified);
        assertEquals(AuthTri.FALSE, r.provenance.stampMatchesTrusted);
        assertEquals(AuthTri.FALSE, r.provenance.distributedByPlay);
        boolean warned = false;
        for (String w : r.verdict.warnings) {
            if (w.contains("no reconocido")) warned = true;
        }
        assertTrue(warned);
    }

    @Test
    public void selloNoDecideVeredictoGlobal() throws Exception {
        // Sello válido + firmante desconocido: UNKNOWN, no OFFICIAL.
        AuthFixture.KeyCert stamp = AuthFixture.genRsa("CN=Play", 4006);
        File apk = signedApk("stamponly", stamp);
        ReaAuthenticityEngine.Options o = new ReaAuthenticityEngine.Options();
        Set<String> trusted = new HashSet<>();
        trusted.add(stamp.sha256);
        o.trustedStamps = trusted;
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk, o);
        assertEquals(AuthTri.TRUE, r.provenance.distributedByPlay);
        assertTrue(!"OFFICIAL".equals(r.verdict.overall));
    }
}
