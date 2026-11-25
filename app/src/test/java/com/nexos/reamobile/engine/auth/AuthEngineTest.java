package com.nexos.reamobile.engine.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.nexos.reamobile.engine.ReaEngine;
import java.io.File;
import java.util.HashSet;
import java.util.zip.ZipFile;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Motor end-to-end: esquema JSON, sección TXT, trazabilidad de evidencia,
 * etapas individuales e integración con ReaEngine/ZIP.
 */
public class AuthEngineTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private File signedApk() throws Exception {
        AuthFixture.KeyCert kc = AuthFixture.genRsa("CN=Engine", 7001);
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        m.permissions.add("android.permission.INTERNET");
        File in = new File(tmp.getRoot(), "eng-in.apk");
        File out = new File(tmp.getRoot(), "eng.apk");
        AuthFixture.writeUnsignedApk(in, m, null);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        AuthFixture.sign(in, out, kc, s);
        return out;
    }

    @Test
    public void jsonVersionadoConClavesDeLaEspecificacion() throws Exception {
        File apk = signedApk();
        String json = ReaAuthenticityEngine.analyze(apk).toJson();
        assertTrue(json.contains("\"schema\":\"rea-authenticity-v1\""));
        assertTrue(json.contains("\"package\":\"com.example.app\""));
        assertTrue(json.contains("\"version\":{\"name\":\"1.0\",\"code\":1}"));
        assertTrue(json.contains("\"overall\""));
        assertTrue(json.contains("\"confidence\""));
        assertTrue(json.contains("\"apk_signature_valid\""));
        assertTrue(json.contains("\"official_signer_match\""));
        assertTrue(json.contains("\"rotation_lineage_match\""));
        assertTrue(json.contains("\"play_provenance\""));
        assertTrue(json.contains("\"official_baseline_match\""));
        assertTrue(json.contains("\"modification_indicators\""));
        assertTrue(json.contains("\"reasons\""));
        assertTrue(json.contains("\"warnings\""));
        assertTrue(json.contains("\"unknowns\""));
        // Capa 1.
        assertTrue(json.contains("\"v1\":{\"present\""));
        assertTrue(json.contains("\"v3_1\":{\"present\""));
        assertTrue(json.contains("\"integrity_ok\""));
        assertTrue(json.contains("\"verification_errors\""));
        assertTrue(json.contains("\"signer_cert_sha256\""));
        assertTrue(json.contains("\"signer_matches_official_allowlist\""));
        assertTrue(json.contains("\"signer_allowlist_version\""));
        // Capa 3-6.
        assertTrue(json.contains("\"source_stamp_present\""));
        assertTrue(json.contains("\"distributed_by_play\""));
        assertTrue(json.contains("\"lineage_present\""));
        assertTrue(json.contains("\"observed_key\""));
        assertTrue(json.contains("\"package_match\""));
        assertTrue(json.contains("\"dex_hashes_match\""));
        assertTrue(json.contains("\"permissions_diff\""));
        assertTrue(json.contains("\"debuggable\""));
        assertTrue(json.contains("\"dex_modified\""));
        // Metadatos.
        assertTrue(json.contains("\"engine\":\"REA APK Authenticity Engine\""));
        assertTrue(json.contains("\"engine_version\":\"1.0\""));
        assertTrue(json.contains("\"verification_profile\":\"rea-apk-auth-v1\""));
    }

    @Test
    public void seccionTxtCompleta() throws Exception {
        File apk = signedApk();
        String txt = ReaAuthenticityEngine.analyze(apk).toTextSection();
        assertTrue(txt.contains("=== AUTENTICIDAD Y PROCEDENCIA ===")
                || txt.contains("=== AUTENTICIDAD Y PROCEDENCIA ("));
        assertTrue(txt.contains("veredicto="));
        assertTrue(txt.contains("confianza="));
        assertTrue(txt.contains("firma:"));
        assertTrue(txt.contains("firmante:"));
        assertTrue(txt.contains("rotacion:"));
        assertTrue(txt.contains("sello:"));
        assertTrue(txt.contains("baseline:"));
        assertTrue(txt.contains("repack:"));
        assertTrue(txt.contains("evidencias("));
    }

    @Test
    public void evidenciaTrazable() throws Exception {
        File apk = signedApk();
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk);
        assertTrue(!r.evidence.isEmpty());
        for (AuthEvidence e : r.evidence) {
            assertNotNull(e);
            assertTrue(!e.id.isEmpty());
            assertTrue(!e.category.isEmpty());
            assertTrue(!e.result.isEmpty());
            assertTrue(!e.source.isEmpty());
            assertTrue(e.toJson().contains("\"id\""));
        }
    }

    @Test
    public void etapasIndividuales() throws Exception {
        File apk = signedApk();
        assertNotNull(ReaAuthenticityEngine.stageSignature(apk));
        assertNotNull(ReaAuthenticityEngine.stageIdentity(
                "com.example.app", "00", null));
        assertNotNull(ReaAuthenticityEngine.stageProvenance(apk, new HashSet<String>()));
        assertNotNull(ReaAuthenticityEngine.stageRotation(apk, "00", null,
                "com.example.app"));
        assertNotNull(ReaAuthenticityEngine.stageBaseline(apk, null, null));
        AuthManifest.AppFlags f = new AuthManifest.AppFlags();
        assertNotNull(ReaAuthenticityEngine.stageRepack(f,
                new AuthSignature.SigResult(), new AuthBaseline.BaseResult()));
        // Nulos: UNKNOWNs, nunca excepciones.
        assertNotNull(ReaAuthenticityEngine.analyze(null));
        assertNotNull(ReaAuthenticityEngine.stageSignature(null));
    }

    @Test
    public void integracionReaEngine() throws Exception {
        File apk = signedApk();
        ReaEngine.ApkReport r = ReaEngine.analyze(apk);
        assertNotNull(r.auth);
        assertTrue(r.toText().contains("AUTENTICIDAD Y PROCEDENCIA"));
        // La sección FIRMA clásica se conserva y amplía, no se sustituye.
        assertTrue(r.toText().contains("=== FIRMA ==="));
        assertTrue(r.toJson().contains("\"authenticity\""));
        ReaEngine.ApkReport s = ReaEngine.analyzeStatic(apk);
        assertNull(s.auth);
        assertTrue(!s.toText().contains("AUTENTICIDAD Y PROCEDENCIA"));
    }

    @Test
    public void zipIncluyeAutenticidadJson() throws Exception {
        File apk = signedApk();
        File out = new File(tmp.getRoot(), "salida.zip");
        ReaEngine.ExtractResult r = ReaEngine.extractToZip(apk, out);
        assertTrue(r.error == null);
        assertTrue(out.isFile());
        ZipFile zip = new ZipFile(out);
        try {
            assertNotNull(zip.getEntry("rea/autenticidad.json"));
            assertNotNull(zip.getEntry("rea/INFORME.txt"));
        } finally {
            zip.close();
        }
    }

    @Test
    public void resumenUnaLinea() throws Exception {
        File apk = signedApk();
        String s = ReaAuthenticityEngine.analyze(apk).summaryLine();
        assertTrue(s.contains("veredicto="));
        assertTrue(s.contains("firma="));
    }
}
