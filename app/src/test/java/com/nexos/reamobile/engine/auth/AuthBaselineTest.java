package com.nexos.reamobile.engine.auth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Capa 5: baseline idéntico, dex modificado, permisos añadidos, exportados
 * modificados, variante distinta y ausencia de baseline (escenarios 12-17).
 */
public class AuthBaselineTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private AuthFixture.KeyCert key;

    private File buildSigned(String name, AuthFixture.ManifestSpec m, byte[] dex,
                             Map<String, byte[]> extra) throws Exception {
        if (key == null) key = AuthFixture.genRsa("CN=Baseline", 5001);
        File in = new File(tmp.getRoot(), name + "-in.apk");
        File out = new File(tmp.getRoot(), name + ".apk");
        AuthFixture.writeUnsignedApk(in, m, extra, dex);
        AuthFixture.SignSpec s = new AuthFixture.SignSpec();
        s.v1 = false;
        AuthFixture.sign(in, out, key, s);
        return out;
    }

    /** Baseline JSON generado desde lo observado en la referencia. */
    private static String baselineJson(AuthBaseline.Observed o, String variant,
                                       String abisJsonOrNull) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"schema\":\"rea-baseline-v1\",\"id\":\"t\",\"version\":\"3\",");
        sb.append("\"source\":\"test\",\"updated\":\"\",\"entries\":[{");
        sb.append("\"package\":\"").append(o.packageName).append("\",");
        sb.append("\"version_code\":").append(o.versionCode).append(",");
        sb.append("\"version_name\":\"").append(o.versionName).append("\",");
        if (variant != null) sb.append("\"variant\":\"").append(variant).append("\",");
        if (abisJsonOrNull != null) sb.append("\"abis\":").append(abisJsonOrNull).append(",");
        sb.append("\"channel\":\"test\",\"apk_sha256\":\"").append(o.apkSha256).append("\",");
        sb.append("\"dex_hashes\":{");
        boolean first = true;
        for (Map.Entry<String, String> e : o.dex.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append("\"").append(e.getKey()).append("\":\"").append(e.getValue()).append("\"");
        }
        sb.append("},\"native_libs\":{},");
        sb.append("\"manifest_norm_sha256\":\"").append(o.manifestNormSha256).append("\",");
        sb.append("\"permissions\":[");
        for (int i = 0; i < o.permissions.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append("\"").append(o.permissions.get(i)).append("\"");
        }
        sb.append("],\"components\":[],\"exported\":[");
        for (int i = 0; i < o.exported.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append("\"").append(o.exported.get(i)).append("\"");
        }
        sb.append("],\"splits\":[],\"split_total\":0,");
        sb.append("\"schemes\":[\"v2\"],\"app_flags\":{\"debuggable\":false,");
        sb.append("\"test_only\":false,\"allow_backup\":true,\"cleartext\":false}");
        sb.append("}]}");
        return sb.toString();
    }

    @Test
    public void apkIdenticoAlBaseline() throws Exception {
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        m.permissions.add("android.permission.INTERNET");
        File ref = buildSigned("ref", m, AuthFixture.dexBytes(1), null);
        AuthBaseline.Observed o = AuthBaseline.observe(ref, null);
        ReaAuthenticityEngine.Options opts = new ReaAuthenticityEngine.Options();
        opts.baselineJson = baselineJson(o, null, null);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(ref, opts);
        assertEquals(AuthTri.TRUE, r.baseline.packageMatch);
        assertEquals(AuthTri.TRUE, r.baseline.versionKnownOfficial);
        assertEquals(AuthTri.TRUE, r.baseline.apkSha256Match);
        assertEquals(AuthTri.TRUE, r.baseline.dexHashesMatch);
        assertEquals(AuthTri.TRUE, r.baseline.permissionsDiff.match);
        assertEquals(AuthTri.TRUE, r.verdict.officialBaselineMatch);
    }

    @Test
    public void dexModificadoEsNotOfficial() throws Exception {
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        File ref = buildSigned("refd", m, AuthFixture.dexBytes(1), null);
        AuthBaseline.Observed o = AuthBaseline.observe(ref, null);
        File mod = buildSigned("modd", m, AuthFixture.dexBytes(99), null);
        ReaAuthenticityEngine.Options opts = new ReaAuthenticityEngine.Options();
        opts.baselineJson = baselineJson(o, null, null);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(mod, opts);
        assertEquals(AuthTri.FALSE, r.baseline.dexHashesMatch);
        assertEquals(AuthTri.FALSE, r.baseline.apkSha256Match);
        assertEquals(AuthTri.TRUE, r.repack.dexModified);
        assertEquals("NOT_OFFICIAL", r.verdict.overall);
    }

    @Test
    public void permisosAdicionalesSeRegistran() throws Exception {
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        File ref = buildSigned("refp", m, AuthFixture.dexBytes(1), null);
        AuthBaseline.Observed o = AuthBaseline.observe(ref, null);
        AuthFixture.ManifestSpec m2 = new AuthFixture.ManifestSpec();
        m2.permissions.add("android.permission.READ_SMS");
        File mod = buildSigned("modp", m2, AuthFixture.dexBytes(1), null);
        ReaAuthenticityEngine.Options opts = new ReaAuthenticityEngine.Options();
        opts.baselineJson = baselineJson(o, null, null);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(mod, opts);
        assertEquals(AuthTri.FALSE, r.baseline.permissionsDiff.match);
        assertTrue(r.baseline.permissionsDiff.added.contains("android.permission.READ_SMS"));
        assertEquals("NOT_OFFICIAL", r.verdict.overall);
    }

    @Test
    public void exportadosModificadosSeRegistran() throws Exception {
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        m.exportedActivities.add("com.example.app.Main");
        File ref = buildSigned("refe", m, AuthFixture.dexBytes(1), null);
        AuthBaseline.Observed o = AuthBaseline.observe(ref, null);
        AuthFixture.ManifestSpec m2 = new AuthFixture.ManifestSpec();
        m2.exportedActivities.add("com.example.app.Main");
        m2.exportedActivities.add("com.example.app.Evil");
        File mod = buildSigned("mode", m2, AuthFixture.dexBytes(1), null);
        ReaAuthenticityEngine.Options opts = new ReaAuthenticityEngine.Options();
        opts.baselineJson = baselineJson(o, null, null);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(mod, opts);
        assertEquals(AuthTri.FALSE, r.baseline.exportedComponentsDiff.match);
        assertEquals(1, r.baseline.exportedComponentsDiff.added.size());
    }

    @Test
    public void varianteDistintaNoSeCompara() throws Exception {
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        Map<String, byte[]> libsArm = new HashMap<>();
        libsArm.put("lib/arm64-v8a/libx.so", new byte[]{1, 2, 3});
        File ref = buildSigned("refv", m, AuthFixture.dexBytes(1), libsArm);
        AuthBaseline.Observed o = AuthBaseline.observe(ref, null);
        Map<String, byte[]> libsUni = new HashMap<>();
        libsUni.put("lib/arm64-v8a/libx.so", new byte[]{1, 2, 3});
        libsUni.put("lib/x86/libx.so", new byte[]{1, 2, 3});
        File uni = buildSigned("univ", m, AuthFixture.dexBytes(1), libsUni);
        ReaAuthenticityEngine.Options opts = new ReaAuthenticityEngine.Options();
        opts.baselineJson = baselineJson(o, "arm64", "[\"arm64-v8a\"]");
        AuthResult.Report r = ReaAuthenticityEngine.analyze(uni, opts);
        assertEquals(AuthTri.FALSE, r.baseline.variantMatch);
        // Variante distinta: contenido no comparable, jamás discrepancia.
        assertEquals(AuthTri.UNKNOWN, r.baseline.apkSha256Match);
        assertEquals(AuthTri.UNKNOWN, r.baseline.dexHashesMatch);
        assertTrue(!"NOT_OFFICIAL".equals(r.verdict.overall));
    }

    @Test
    public void versionDistintaNoSeCompara() throws Exception {
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        m.versionCode = 1;
        File ref = buildSigned("refvv", m, AuthFixture.dexBytes(1), null);
        AuthBaseline.Observed o = AuthBaseline.observe(ref, null);
        AuthFixture.ManifestSpec m2 = new AuthFixture.ManifestSpec();
        m2.versionCode = 2;
        File v2 = buildSigned("vv2", m2, AuthFixture.dexBytes(1), null);
        ReaAuthenticityEngine.Options opts = new ReaAuthenticityEngine.Options();
        opts.baselineJson = baselineJson(o, null, null);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(v2, opts);
        assertEquals(AuthTri.TRUE, r.baseline.packageMatch);
        assertEquals(AuthTri.FALSE, r.baseline.versionKnownOfficial);
        assertEquals(AuthTri.UNKNOWN, r.baseline.apkSha256Match);
        assertTrue(!"NOT_OFFICIAL".equals(r.verdict.overall));
    }

    @Test
    public void sinBaselineTodoUnknown() throws Exception {
        AuthFixture.ManifestSpec m = new AuthFixture.ManifestSpec();
        File apk = buildSigned("nobase", m, AuthFixture.dexBytes(1), null);
        AuthResult.Report r = ReaAuthenticityEngine.analyze(apk);
        assertEquals(AuthTri.UNKNOWN, r.baseline.packageMatch);
        assertEquals(AuthTri.UNKNOWN, r.baseline.apkSha256Match);
        assertEquals(AuthTri.UNKNOWN, r.verdict.officialBaselineMatch);
        assertEquals(AuthTri.FALSE, r.repack.dexModified);
    }
}
