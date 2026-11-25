package com.nexos.reamobile.engine.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Capa 1: firma v2 válida, v3 válida, firma inválida, contenido alterado
 * y error de lectura del bloque (escenarios 1-4 y 19).
 */
public class AuthSignatureTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private File signedApk(String name, boolean v1, boolean v2, boolean v3) throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa("CN=Test", 1001);
        File in = new File(tmp.getRoot(), name + "-in.apk");
        File out = new File(tmp.getRoot(), name + ".apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = v1;
        s.v2 = v2;
        s.v3 = v3;
        AuthFixture.sign(in, out, kc, s);
        return out;
    }

    @Test
    public void firmaV2Valida() throws Exception {
        File apk = signedApk("v2ok", false, true, false);
        AuthSignature.SigResult r = AuthSignature.inspect(apk);
        assertEquals(AuthTri.TRUE, r.v2.present);
        assertEquals(AuthTri.TRUE, r.v2.verified);
        assertEquals(AuthTri.TRUE, r.integrityOk);
        assertTrue(!r.primarySignerSha256.isEmpty());
        assertEquals(1, r.signerCerts.size());
    }

    @Test
    public void firmaV3Valida() throws Exception {
        File apk = signedApk("v3ok", false, false, true);
        AuthSignature.SigResult r = AuthSignature.inspect(apk);
        assertEquals(AuthTri.TRUE, r.v3.present);
        assertEquals(AuthTri.TRUE, r.v3.verified);
        assertEquals(AuthTri.TRUE, r.integrityOk);
    }

    @Test
    public void firmaInvalidaTrasTocarBloque() throws Exception {
        File apk = signedApk("sigbad", false, true, false);
        AuthFixture.tamperSignature(apk);
        AuthSignature.SigResult r = AuthSignature.inspect(apk);
        assertEquals(AuthTri.TRUE, r.v2.present);
        assertEquals(AuthTri.FALSE, r.v2.verified);
        assertTrue(!r.verificationErrors.isEmpty());
    }

    @Test
    public void contenidoAlteradoTrasFirmar() throws Exception {
        File apk = signedApk("tocado", false, true, false);
        assertEquals(AuthTri.TRUE, AuthSignature.inspect(apk).integrityOk);
        AuthFixture.tamperContent(apk);
        AuthSignature.SigResult r = AuthSignature.inspect(apk);
        assertEquals(AuthTri.FALSE, r.integrityOk);
        assertEquals(AuthTri.FALSE, r.v2.verified);
    }

    @Test
    public void bloqueIlegibleDaUnknownSinLanzar() throws Exception {
        File bad = new File(tmp.getRoot(), "basura.apk");
        FileOutputStream fos = new FileOutputStream(bad);
        byte[] junk = new byte[200];
        for (int i = 0; i < junk.length; i++) junk[i] = (byte) i;
        fos.write(junk);
        fos.close();
        AuthSignature.SigResult r = AuthSignature.inspect(bad);
        // Sin bloque legible: presencia falsa o desconocida, jamás verificado.
        assertTrue(r.v2.verified != AuthTri.TRUE);
        assertTrue(r.v3.verified != AuthTri.TRUE);
        assertTrue(r.v2.present != AuthTri.TRUE);
        // Fichero inexistente: igual de seguro.
        AuthSignature.SigResult r2 = AuthSignature.inspect(
                new File(tmp.getRoot(), "noexiste.apk"));
        assertTrue(r2.v2.verified != AuthTri.TRUE);
        assertEquals(AuthTri.UNKNOWN, r2.integrityOk);
    }

    @Test
    public void sinFirmarDaIntegridadFalsa() throws Exception {
        File in = new File(tmp.getRoot(), "plain.apk");
        AuthFixture.writeUnsignedApk(in, new AuthFixture.ManifestSpec(), null);
        AuthSignature.SigResult r = AuthSignature.inspect(in);
        assertEquals(AuthTri.FALSE, r.v1.present);
        assertEquals(AuthTri.FALSE, r.v2.present);
        assertEquals(AuthTri.FALSE, r.integrityOk);
    }

    @Test
    public void respaldoInternoCoincideConApksig() throws Exception {
        File apk = signedApk("fb", false, true, false);
        ReaAuthenticityEngine.Options o = new ReaAuthenticityEngine.Options();
        o.forceInternal = true;
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk, o);
        assertEquals(AuthTri.TRUE, r.signature.v2.verified);
        assertEquals(AuthTri.TRUE, r.signature.integrityOk);
        assertTrue(r.signature.method.startsWith("interno"));
        AuthFixture.tamperContent(apk);
        AuthResult.Report r2 = ReaAuthenticityEngine.analyze(apk, o);
        assertEquals(AuthTri.FALSE, r2.signature.v2.verified);
        assertEquals(AuthTri.FALSE, r2.signature.integrityOk);
    }

    @Test
    public void v1SoloPresenteNoSeDaPorVerificadoSinApksig() throws Exception {
        File apk = signedApk("v1only", true, false, false);
        ReaAuthenticityEngine.Options o = new ReaAuthenticityEngine.Options();
        o.forceInternal = true;
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk, o);
        assertEquals(AuthTri.TRUE, r.signature.v1.present);
        // Sin apksig la v1 (JAR) no se verifica: UNKNOWN honesto.
        assertEquals(AuthTri.UNKNOWN, r.signature.v1.verified);
    }
}
