package com.nexos.reamobile.engine.auth;

import com.nexos.reamobile.engine.AxmlDecoder;
import com.nexos.reamobile.engine.ManifestChecks;
import java.io.File;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Capa 5 — baseline de versiones oficiales.
 * Solo compara contra la referencia EXACTA (paquete + versión + variante
 * compatible): jamás mezcla base/universal/split ni versiones distintas.
 * Sin referencia exacta todo es UNKNOWN, nunca discrepancia.
 * Importable vía JSON; sin servicio remoto. Java puro. Nunca lanza.
 */
public final class AuthBaseline {
    private AuthBaseline() {
    }

    public static final String SCHEMA = "rea-baseline-v1";
    public static final long MAX_HASH_TOTAL = 512L * 1024 * 1024;
    public static final long MAX_LIB_HASH = 32L * 1024 * 1024;
    public static final int MAX_DEX_HASHED = 64;
    public static final int MAX_LIB_HASHED = 64;

    public static final String DEFAULT_JSON = "{"
            + "\"schema\":\"rea-baseline-v1\","
            + "\"id\":\"rea-default\","
            + "\"version\":\"none\","
            + "\"source\":\"bundled-empty\","
            + "\"updated\":\"\","
            + "\"entries\":[]"
            + "}";

    public static class BaselineEntry {
        public String pkg = "";
        public long versionCode = -1;
        public String versionName = "";
        public String variant = "";
        public List<String> abis = new ArrayList<>();
        public List<String> densities = new ArrayList<>();
        public String channel = "";
        public String date = "";
        public String apkSha256 = "";
        public Map<String, String> dexHashes = new LinkedHashMap<>();
        public Map<String, String> nativeLibs = new LinkedHashMap<>();
        public String manifestNormSha256 = "";
        public List<String> permissions = new ArrayList<>();
        public List<String> components = new ArrayList<>();
        public List<String> exported = new ArrayList<>();
        public List<String> splits = new ArrayList<>();
        public long splitTotal;
        /** Esquemas declarados por la referencia ("" si no declara). */
        public List<String> schemes = new ArrayList<>();
        /** Flags de app declarados: "true"/"false"/"" (sin declarar). */
        public String flagDebuggable = "";
        public String flagTestOnly = "";
        public String flagAllowBackup = "";
        public String flagCleartext = "";
    }

    public static class Store {
        public String id = "";
        public String version = "";
        public String source = "";
        public String updated = "";
        public String loadError = "";
        public List<BaselineEntry> entries = new ArrayList<>();
    }

    /** Hechos observados del APK bajo análisis. */
    public static class Observed {
        public String apkSha256 = "";
        public boolean apkShaTruncated;
        public Map<String, String> dex = new LinkedHashMap<>();
        public boolean dexTruncated;
        public Map<String, String> nativeLibs = new LinkedHashMap<>();
        public List<String> nativeSkipped = new ArrayList<>();
        public String manifestNormSha256 = "";
        public boolean manifestMissing;
        public List<String> permissions = new ArrayList<>();
        public List<String> components = new ArrayList<>();
        public List<String> exported = new ArrayList<>();
        public List<String> abis = new ArrayList<>();
        public List<String> densities = new ArrayList<>();
        public String splitName = "";
        public String packageName = "?";
        public long versionCode = -1;
        public String versionName = "";
        public AuthManifest.AppFlags flags = new AuthManifest.AppFlags();
    }

    public static class Diff {
        public AuthTri match = AuthTri.UNKNOWN;
        public List<String> added = new ArrayList<>();
        public List<String> removed = new ArrayList<>();
        public List<String> modified = new ArrayList<>();

        public String toJson() {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append("{\"match\":").append(match.toJson());
                AuthJson.strList(sb, "added", added);
                AuthJson.strList(sb, "removed", removed);
                AuthJson.strList(sb, "modified", modified);
                sb.append('}');
                return sb.toString();
            } catch (Throwable ignored) {
                return "{}";
            }
        }
    }

    public static class BaseResult {
        public AuthTri packageMatch = AuthTri.UNKNOWN;
        public AuthTri versionKnownOfficial = AuthTri.UNKNOWN;
        public AuthTri apkSha256Match = AuthTri.UNKNOWN;
        public AuthTri dexHashesMatch = AuthTri.UNKNOWN;
        public Diff permissionsDiff = new Diff();
        public Diff exportedComponentsDiff = new Diff();
        public Diff nativeLibsDiff = new Diff();
        public AuthTri splitsMatch = AuthTri.UNKNOWN;
        public AuthTri variantMatch = AuthTri.UNKNOWN;
        /** Comparación del manifest normalizado (alimenta repack). */
        public AuthTri manifestNormMatch = AuthTri.UNKNOWN;
        /** Referencia exacta (vacío si no hubo lookup EXACT). */
        public List<String> refSchemes = new ArrayList<>();
        public String refDebuggable = "";
        public String refTestOnly = "";
        public String refAllowBackup = "";
        public String refCleartext = "";
        public String lookupKind = "NONE";
        public String baselineId = "";
        public String baselineVersion = "";
        public String baselineSource = "";
        public String detail = "";
        public List<AuthEvidence> evidence = new ArrayList<>();

        public String toJson() {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                sb.append("\"package_match\":").append(packageMatch.toJson());
                sb.append(",\"version_known_official\":").append(versionKnownOfficial.toJson());
                sb.append(",\"apk_sha256_match\":").append(apkSha256Match.toJson());
                sb.append(",\"dex_hashes_match\":").append(dexHashesMatch.toJson());
                sb.append(",\"permissions_diff\":").append(permissionsDiff.toJson());
                sb.append(",\"exported_components_diff\":")
                        .append(exportedComponentsDiff.toJson());
                sb.append(",\"native_libs_diff\":").append(nativeLibsDiff.toJson());
                sb.append(",\"splits_match\":").append(splitsMatch.toJson());
                sb.append(",\"variant_match\":").append(variantMatch.toJson());
                sb.append(",\"manifest_norm_match\":").append(manifestNormMatch.toJson());
                AuthJson.field(sb, "lookup", lookupKind, false);
                AuthJson.field(sb, "baseline_id", baselineId, false);
                AuthJson.field(sb, "baseline_version", baselineVersion, false);
                AuthJson.field(sb, "baseline_source", baselineSource, false);
                AuthJson.field(sb, "detail", detail, false);
                sb.append('}');
                return sb.toString();
            } catch (Throwable ignored) {
                return "{}";
            }
        }
    }

    /** Carga un baseline desde JSON. Nunca null. Nunca lanza. */
    public static Store load(String json) {
        Store s = new Store();
        try {
            if (json == null || json.trim().isEmpty()) {
                s.loadError = "baseline vacío";
                return s;
            }
            AuthJson.Parsed p = AuthJson.parse(json);
            if (p.error != null) {
                s.loadError = "JSON inválido: " + p.error;
                return s;
            }
            Map<String, Object> o = AuthJson.asObject(p.root);
            if (o == null) {
                s.loadError = "raíz no es objeto";
                return s;
            }
            s.id = AuthJson.str(o, "id");
            s.version = AuthJson.str(o, "version");
            s.source = AuthJson.str(o, "source");
            s.updated = AuthJson.str(o, "updated");
            List<Object> entries = AuthJson.asList(o.get("entries"));
            if (entries == null) return s;
            int guard = 0;
            for (Object eo : entries) {
                if (guard++ >= 2000) break;
                Map<String, Object> e = AuthJson.asObject(eo);
                if (e == null) continue;
                BaselineEntry be = new BaselineEntry();
                be.pkg = AuthJson.str(e, "package").trim();
                if (be.pkg.isEmpty()) continue;
                be.versionCode = AuthJson.num(e, "version_code", -1);
                be.versionName = AuthJson.str(e, "version_name");
                be.variant = AuthJson.str(e, "variant");
                be.abis = AuthJson.strList(e, "abis");
                be.densities = AuthJson.strList(e, "densities");
                be.channel = AuthJson.str(e, "channel");
                be.date = AuthJson.str(e, "date");
                be.apkSha256 = AuthCert.normHash(AuthJson.str(e, "apk_sha256"));
                be.dexHashes = strMap(e.get("dex_hashes"));
                be.nativeLibs = strMap(e.get("native_libs"));
                be.manifestNormSha256 = AuthCert.normHash(AuthJson.str(e, "manifest_norm_sha256"));
                be.permissions = AuthJson.strList(e, "permissions");
                be.components = AuthJson.strList(e, "components");
                be.exported = AuthJson.strList(e, "exported");
                be.splits = AuthJson.strList(e, "splits");
                be.splitTotal = AuthJson.num(e, "split_total", 0);
                be.schemes = AuthJson.strList(e, "schemes");
                Map<String, Object> af = AuthJson.asObject(e.get("app_flags"));
                if (af != null) {
                    be.flagDebuggable = boolStr(af.get("debuggable"));
                    be.flagTestOnly = boolStr(af.get("test_only"));
                    be.flagAllowBackup = boolStr(af.get("allow_backup"));
                    be.flagCleartext = boolStr(af.get("cleartext"));
                }
                s.entries.add(be);
            }
        } catch (Throwable t) {
            s.loadError = "fallo cargando baseline";
        }
        return s;
    }

    private static String boolStr(Object o) {
        try {
            if (o instanceof Boolean) return ((Boolean) o) ? "true" : "false";
            if (o instanceof String) {
                String s = ((String) o).trim().toLowerCase();
                if ("true".equals(s) || "false".equals(s)) return s;
            }
        } catch (Throwable ignored) {
        }
        return "";
    }

    private static Map<String, String> strMap(Object o) {
        Map<String, String> out = new LinkedHashMap<>();
        try {
            Map<String, Object> m = AuthJson.asObject(o);
            if (m == null) return out;
            for (Map.Entry<String, Object> e : m.entrySet()) {
                if (e.getKey() == null || !(e.getValue() instanceof String)) continue;
                out.put(e.getKey(), AuthCert.normHash((String) e.getValue()));
                if (out.size() >= 256) break;
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Calcula los hechos observados del APK (hashes por streaming, sin
     * retener el APK en memoria). manifestXml puede ser null (se decodifica).
     * Nunca null. Nunca lanza.
     */
    public static Observed observe(File apk, String manifestXml) {
        Observed o = new Observed();
        try {
            if (apk == null || !apk.isFile()) {
                o.manifestMissing = true;
                return o;
            }
            o.apkSha256 = shaFile(apk, MAX_HASH_TOTAL);
            o.apkShaTruncated = o.apkSha256.isEmpty() && apk.length() > 0;
            ZipFile zip = null;
            try {
                zip = new ZipFile(apk);
                List<String> names = new ArrayList<>();
                Enumeration<? extends ZipEntry> en = zip.entries();
                int guard = 0;
                while (en.hasMoreElements() && guard++ < 200000) {
                    ZipEntry e = en.nextElement();
                    if (e.isDirectory()) continue;
                    names.add(e.getName());
                }
                o.abis = AuthManifest.abisFromEntries(names);
                o.densities = AuthManifest.densitiesFromEntries(names);
                // DEX por streaming.
                for (String n : names) {
                    if (!n.matches("classes\\d*\\.dex")) continue;
                    if (o.dex.size() >= MAX_DEX_HASHED) {
                        o.dexTruncated = true;
                        break;
                    }
                    ZipEntry e = zip.getEntry(n);
                    String h = e == null ? "" : shaEntry(zip, e, MAX_HASH_TOTAL);
                    if (!h.isEmpty()) o.dex.put(n, h);
                    else o.dexTruncated = true;
                }
                // Nativas por streaming (tope por lib).
                for (String n : names) {
                    if (!n.startsWith("lib/") || !n.endsWith(".so")) continue;
                    if (o.nativeLibs.size() >= MAX_LIB_HASHED) break;
                    ZipEntry e = zip.getEntry(n);
                    if (e == null) continue;
                    long sz = e.getSize();
                    if (sz > MAX_LIB_HASH) {
                        o.nativeSkipped.add(n + " (>" + MAX_LIB_HASH + " B)");
                        continue;
                    }
                    String h = shaEntry(zip, e, MAX_LIB_HASH);
                    if (!h.isEmpty()) o.nativeLibs.put(n, h);
                }
                // Manifest.
                String xml = manifestXml;
                if (xml == null) {
                    ZipEntry man = zip.getEntry("AndroidManifest.xml");
                    if (man != null && man.getSize() > 0
                            && man.getSize() < 20 * 1024 * 1024) {
                        byte[] mb = readEntry(zip, man, 20 * 1024 * 1024);
                        if (mb != null) xml = decodeManifestBytes(mb);
                    }
                }
                if (xml == null || xml.isEmpty()) {
                    o.manifestMissing = true;
                } else {
                    o.flags = AuthManifest.flags(xml);
                    o.manifestNormSha256 = shaString(AuthManifest.normalize(xml));
                    AuthManifest.Identity id = AuthManifest.identity(xml);
                    o.packageName = id.packageName;
                    o.versionCode = id.versionCode;
                    o.versionName = id.versionName;
                    o.splitName = id.splitName;
                    try {
                        o.permissions = AxmlDecoder.usesPermissions(xml);
                    } catch (Throwable ignored) {
                    }
                    try {
                        ManifestChecks.Result mc = ManifestChecks.check(xml, o.permissions);
                        o.components = mc.components;
                        o.exported = mc.exported;
                    } catch (Throwable ignored) {
                    }
                }
            } catch (Throwable ignored) {
            } finally {
                if (zip != null) {
                    try {
                        zip.close();
                    } catch (Throwable ignored) {
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return o;
    }

    /**
     * Compara observado contra la referencia exacta del baseline.
     * Nunca null. Nunca lanza.
     */
    public static BaseResult compare(Store s, Observed o, String apkRef) {
        BaseResult r = new BaseResult();
        try {
            if (o == null) o = new Observed();
            if (s == null || !s.loadError.isEmpty()) {
                r.detail = s == null ? "sin baseline" : ("baseline: " + s.loadError);
                r.evidence.add(new AuthEvidence("base.lookup", "baseline", "UNKNOWN",
                        "baseline", "sin-referencia", r.detail, "", nz(apkRef), ""));
                return r;
            }
            r.baselineId = s.id;
            r.baselineVersion = s.version;
            r.baselineSource = s.source;
            if (s.entries.isEmpty()) {
                r.detail = "baseline vacío: nada que comparar";
                r.evidence.add(new AuthEvidence("base.lookup", "baseline", "UNKNOWN",
                        "baseline", "sin-referencia", r.detail, "", nz(apkRef), ""));
                return r;
            }
            String pkg = o.packageName == null ? "?" : o.packageName;
            List<BaselineEntry> pack = new ArrayList<>();
            for (BaselineEntry e : s.entries) {
                if (e != null && pkg.equals(e.pkg)) pack.add(e);
            }
            if (pack.isEmpty()) {
                r.packageMatch = AuthTri.FALSE;
                r.detail = "paquete sin referencias oficiales en baseline";
                r.evidence.add(new AuthEvidence("base.lookup", "baseline", "UNKNOWN",
                        "baseline", "búsqueda-paquete", r.detail, "", nz(apkRef), ""));
                return r;
            }
            r.packageMatch = AuthTri.TRUE;
            BaselineEntry versionHit = null;
            for (BaselineEntry e : pack) {
                if (e.versionCode >= 0 && o.versionCode >= 0
                        && e.versionCode == o.versionCode) {
                    versionHit = e;
                    break;
                }
            }
            if (versionHit == null && o.versionCode < 0 && !o.versionName.isEmpty()) {
                for (BaselineEntry e : pack) {
                    if (o.versionName.equals(e.versionName)) {
                        versionHit = e;
                        break;
                    }
                }
            }
            if (versionHit == null) {
                r.versionKnownOfficial = AuthTri.FALSE;
                r.detail = "versión no listada entre " + pack.size()
                        + " referencia(s) del paquete: no se comparan versiones distintas";
                r.evidence.add(new AuthEvidence("base.lookup", "baseline", "UNKNOWN",
                        "baseline", "búsqueda-versión", r.detail, "", nz(apkRef), ""));
                return r;
            }
            r.versionKnownOfficial = AuthTri.TRUE;
            r.lookupKind = "EXACT";
            BaselineEntry e = versionHit;
            r.refSchemes = new ArrayList<>(e.schemes);
            r.refDebuggable = e.flagDebuggable;
            r.refTestOnly = e.flagTestOnly;
            r.refAllowBackup = e.flagAllowBackup;
            r.refCleartext = e.flagCleartext;
            if (!e.manifestNormSha256.isEmpty() && !o.manifestNormSha256.isEmpty()) {
                r.manifestNormMatch = AuthTri.of(
                        e.manifestNormSha256.equals(o.manifestNormSha256));
            }

            // Variante/ABI/densidad: si la referencia declara y difiere, no comparable.
            VariantCheck vc = checkVariant(e, o);
            r.variantMatch = vc.match;
            r.splitsMatch = checkSplits(e, o);
            if (vc.blocking) {
                r.detail = "variante distinta a la referencia (" + vc.note
                        + "): contenido no comparable";
                r.evidence.add(new AuthEvidence("base.variant", "baseline", "FAIL",
                        "baseline", "comparación-variante", r.detail, "", nz(apkRef), ""));
                return r;
            }
            r.evidence.add(new AuthEvidence("base.variant", "baseline",
                    r.variantMatch == AuthTri.TRUE ? "PASS" : "UNKNOWN",
                    "baseline", "comparación-variante",
                    vc.note.isEmpty() ? "variante compatible" : vc.note, "", nz(apkRef), ""));

            // APK completo.
            if (!e.apkSha256.isEmpty() && !o.apkSha256.isEmpty()) {
                r.apkSha256Match = AuthTri.of(e.apkSha256.equals(o.apkSha256));
                r.evidence.add(new AuthEvidence("base.apk", "baseline",
                        r.apkSha256Match == AuthTri.TRUE ? "PASS" : "FAIL",
                        "baseline", "sha256-archivo",
                        r.apkSha256Match == AuthTri.TRUE ? "APK idéntico a la referencia"
                                : "APK distinto a la referencia",
                        e.apkSha256, nz(apkRef), ""));
            } else {
                r.evidence.add(new AuthEvidence("base.apk", "baseline", "UNKNOWN",
                        "baseline", "sin-hash",
                        o.apkSha256.isEmpty() ? "hash del APK no calculado"
                                : "referencia sin hash de APK",
                        "", nz(apkRef), ""));
            }
            // DEX.
            if (!e.dexHashes.isEmpty() && !o.dexTruncated) {
                r.dexHashesMatch = diffMaps(e.dexHashes, o.dex, null);
                r.evidence.add(new AuthEvidence("base.dex", "baseline",
                        r.dexHashesMatch == AuthTri.TRUE ? "PASS" : "FAIL",
                        "baseline", "sha256-por-dex",
                        r.dexHashesMatch == AuthTri.TRUE ? (o.dex.size() + " dex idénticos")
                                : "dex añadidos/eliminados/modificados",
                        "", nz(apkRef), ""));
            } else {
                r.evidence.add(new AuthEvidence("base.dex", "baseline", "UNKNOWN",
                        "baseline", "sin-hash",
                        e.dexHashes.isEmpty() ? "referencia sin hashes dex"
                                : "hashes dex incompletos",
                        "", nz(apkRef), ""));
            }
            // Permisos / exportados / nativas.
            r.permissionsDiff = diffLists(e.permissions, o.permissions);
            r.exportedComponentsDiff = diffLists(e.exported, o.exported);
            r.nativeLibsDiff = diffNativeLibs(e.nativeLibs, o.nativeLibs, o.nativeSkipped);
            r.evidence.add(new AuthEvidence("base.perms", "baseline",
                    triOf(r.permissionsDiff.match), "baseline", "diff-listas",
                    diffText("permisos", r.permissionsDiff), "", nz(apkRef), ""));
            r.evidence.add(new AuthEvidence("base.exported", "baseline",
                    triOf(r.exportedComponentsDiff.match), "baseline", "diff-listas",
                    diffText("exportados", r.exportedComponentsDiff), "", nz(apkRef), ""));
            r.evidence.add(new AuthEvidence("base.nativelibs", "baseline",
                    triOf(r.nativeLibsDiff.match), "baseline", "diff-listas",
                    diffText("nativas", r.nativeLibsDiff), "", nz(apkRef), ""));
            if (r.detail.isEmpty()) {
                r.detail = "comparado contra referencia exacta " + pkg + " v" + o.versionCode;
            }
        } catch (Throwable ignored) {
            r.detail = "fallo comparando baseline";
        }
        return r;
    }

    private static class VariantCheck {
        AuthTri match = AuthTri.UNKNOWN;
        boolean blocking;
        String note = "";
    }

    private static VariantCheck checkVariant(BaselineEntry e, Observed o) {
        VariantCheck v = new VariantCheck();
        try {
            boolean declared = !e.variant.isEmpty() || !e.abis.isEmpty()
                    || !e.densities.isEmpty();
            if (!declared) {
                v.note = "referencia sin variante declarada";
                return v;
            }
            List<String> problems = new ArrayList<>();
            if (!e.variant.isEmpty()) {
                String obsVar = o.splitName.isEmpty() ? "base" : o.splitName;
                if (!e.variant.equals(obsVar) && !e.variant.equals("any")) {
                    problems.add("variante ref=" + e.variant + " obs=" + obsVar);
                }
            }
            if (!e.abis.isEmpty()) {
                List<String> a = new ArrayList<>(e.abis);
                List<String> b = new ArrayList<>(o.abis);
                Collections.sort(a);
                Collections.sort(b);
                if (!a.equals(b)) problems.add("abis ref=" + a + " obs=" + b);
            }
            if (!e.densities.isEmpty()) {
                List<String> a = new ArrayList<>(e.densities);
                List<String> b = new ArrayList<>(o.densities);
                Collections.sort(a);
                Collections.sort(b);
                if (!a.equals(b)) problems.add("densidades ref=" + a + " obs=" + b);
            }
            if (problems.isEmpty()) {
                v.match = AuthTri.TRUE;
                v.note = "variante/ABI/densidad compatibles";
            } else {
                v.match = AuthTri.FALSE;
                v.blocking = true;
                StringBuilder sb = new StringBuilder();
                for (String p : problems) {
                    if (sb.length() > 0) sb.append("; ");
                    sb.append(p);
                }
                v.note = sb.toString();
            }
        } catch (Throwable ignored) {
        }
        return v;
    }

    private static AuthTri checkSplits(BaselineEntry e, Observed o) {
        try {
            if (e.splits.isEmpty() && e.splitTotal <= 0) return AuthTri.UNKNOWN;
            String obs = o.splitName.isEmpty() ? "base" : o.splitName;
            if (!e.splits.isEmpty() && !e.splits.contains(obs)) return AuthTri.FALSE;
            return AuthTri.TRUE;
        } catch (Throwable ignored) {
            return AuthTri.UNKNOWN;
        }
    }

    private static AuthTri diffMaps(Map<String, String> ref, Map<String, String> obs,
                                    List<String> problems) {
        try {
            if (ref.size() != obs.size()) return AuthTri.FALSE;
            for (Map.Entry<String, String> en : ref.entrySet()) {
                String ov = obs.get(en.getKey());
                if (ov == null || !ov.equals(en.getValue())) return AuthTri.FALSE;
            }
            return AuthTri.TRUE;
        } catch (Throwable ignored) {
            return AuthTri.UNKNOWN;
        }
    }

    static Diff diffLists(List<String> ref, List<String> obs) {
        Diff d = new Diff();
        try {
            if (ref == null) ref = new ArrayList<>();
            if (obs == null) obs = new ArrayList<>();
            for (String s : obs) {
                if (s != null && !ref.contains(s) && d.added.size() < 100) d.added.add(s);
            }
            for (String s : ref) {
                if (s != null && !obs.contains(s) && d.removed.size() < 100) d.removed.add(s);
            }
            d.match = (d.added.isEmpty() && d.removed.isEmpty()) ? AuthTri.TRUE : AuthTri.FALSE;
        } catch (Throwable ignored) {
            d.match = AuthTri.UNKNOWN;
        }
        return d;
    }

    private static Diff diffNativeLibs(Map<String, String> ref, Map<String, String> obs,
                                       List<String> skipped) {
        Diff d = new Diff();
        try {
            if (ref == null || ref.isEmpty()) {
                d.match = AuthTri.UNKNOWN;
                return d;
            }
            for (Map.Entry<String, String> en : obs.entrySet()) {
                String rv = ref.get(en.getKey());
                if (rv == null) {
                    if (d.added.size() < 100) d.added.add(en.getKey());
                } else if (!rv.equals(en.getValue()) && d.modified.size() < 100) {
                    d.modified.add(en.getKey());
                }
            }
            for (String k : ref.keySet()) {
                if (!obs.containsKey(k) && d.removed.size() < 100) d.removed.add(k);
            }
            if (skipped != null && !skipped.isEmpty()) {
                d.match = AuthTri.UNKNOWN;
                return d;
            }
            d.match = (d.added.isEmpty() && d.removed.isEmpty() && d.modified.isEmpty())
                    ? AuthTri.TRUE : AuthTri.FALSE;
        } catch (Throwable ignored) {
            d.match = AuthTri.UNKNOWN;
        }
        return d;
    }

    private static String diffText(String what, Diff d) {
        try {
            if (d.match == AuthTri.UNKNOWN) return what + ": sin referencia";
            if (d.match == AuthTri.TRUE) return what + ": idénticos";
            return what + ": +" + d.added.size() + " -" + d.removed.size()
                    + " ~" + d.modified.size();
        } catch (Throwable ignored) {
            return what;
        }
    }

    private static String triOf(AuthTri t) {
        if (t == AuthTri.TRUE) return "PASS";
        if (t == AuthTri.FALSE) return "FAIL";
        return "UNKNOWN";
    }

    private static String nz(String s) {
        return s == null ? "?" : s;
    }

    /**
     * Decodifica bytes de manifest: AXML binario o, si no lo es, XML en
     * claro (APKs de prueba). "" si ilegible. Nunca lanza.
     */
    static String decodeManifestBytes(byte[] mb) {
        try {
            if (mb == null || mb.length == 0) return "";
            String dec = AxmlDecoder.decode(mb);
            if (dec != null && dec.contains("<manifest")) return dec;
            String raw = new String(mb, "UTF-8");
            if (raw.contains("<manifest")) {
                return raw.length() > 2000000 ? raw.substring(0, 2000000) : raw;
            }
            return "";
        } catch (Throwable ignored) {
            return "";
        }
    }

    // ---- Hash por streaming (sin retener entradas) ----

    private static String shaFile(File f, long cap) {
        java.io.FileInputStream in = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            in = new java.io.FileInputStream(f);
            byte[] buf = new byte[256 * 1024];
            long total = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                total += n;
                if (total > cap) return "";
                md.update(buf, 0, n);
            }
            return hex(md.digest());
        } catch (Throwable ignored) {
            return "";
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static String shaEntry(ZipFile zip, ZipEntry e, long cap) {
        InputStream in = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            in = zip.getInputStream(e);
            byte[] buf = new byte[256 * 1024];
            long total = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                total += n;
                if (total > cap) return "";
                md.update(buf, 0, n);
            }
            return hex(md.digest());
        } catch (Throwable ignored) {
            return "";
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static String shaString(String s) {
        try {
            if (s == null || s.isEmpty()) return "";
            return hex(MessageDigest.getInstance("SHA-256").digest(s.getBytes("UTF-8")));
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static byte[] readEntry(ZipFile zip, ZipEntry e, long cap) {
        InputStream in = null;
        try {
            long sz = e.getSize();
            if (sz <= 0 || sz > cap) return null;
            in = zip.getInputStream(e);
            byte[] out = new byte[(int) sz];
            int off = 0;
            int n;
            while (off < out.length && (n = in.read(out, off, out.length - off)) > 0) {
                off += n;
            }
            if (off != out.length) return null;
            return out;
        } catch (Throwable ignored) {
            return null;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static String hex(byte[] b) {
        try {
            if (b == null) return "";
            StringBuilder sb = new StringBuilder(b.length * 2);
            for (byte x : b) {
                int v = x & 0xFF;
                if (v < 16) sb.append('0');
                sb.append(Integer.toHexString(v).toUpperCase());
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }
}
