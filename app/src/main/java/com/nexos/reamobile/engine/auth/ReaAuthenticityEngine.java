package com.nexos.reamobile.engine.auth;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * REA APK Authenticity Engine: motor independiente de verificación de
 * autenticidad, firma y procedencia de APK.
 *
 * Entrada: un APK. Salida: {@link AuthResult.Report} estructurado.
 * Independiente de OMEGA, ALFA, ECO y PHANTOM: no importa ninguno de esos
 * motores y reutiliza solo utilidades base (bloque de firma, AXML, manifest).
 *
 * Cada etapa puede ejecutarse individualmente (métodos stage*).
 * Java puro + apksig. Nunca lanza.
 */
public final class ReaAuthenticityEngine {
    private ReaAuthenticityEngine() {
    }

    public static final String ENGINE_ID = "ReaAuthenticityEngine";
    public static final String ENGINE_NAME = "REA APK Authenticity Engine";
    public static final String ENGINE_VERSION = "1.0";
    public static final String SCHEMA = "rea-authenticity-v1";
    public static final String PROFILE = "rea-apk-auth-v1";
    public static final int MAX_EVIDENCE = 120;
    /**
     * Plataforma mínima comprobada por apksig (= minSdk de REA Mobile).
     * Con 1, apksig exige v1 en APKs v2/v3 puros ("Missing MANIFEST.MF") y
     * suprime el SourceStampInfo; con 24 cada esquema se juzga limpio.
     */
    public static final int MIN_PLATFORM_VERSION = 24;
    public static final int MAX_PLATFORM_VERSION = 100000;

    /** Opciones de análisis (todo opcional). */
    public static class Options {
        /** JSON de allowlist (null = bundled vacío). */
        public String allowlistJson;
        /** JSON de baseline (null = bundled vacío). */
        public String baselineJson;
        /** Huellas de sellos confiables para atribuir distribución. */
        public Set<String> trustedStamps = new HashSet<>();
        /** true = no usar apksig (verificador interno + UNKNOWNs honestos). */
        public boolean forceInternal;
        /** Manifest ya decodificado (integración); null = decodificar. */
        public String manifestXml;
    }

    /** Análisis con referencias bundled (vacías → UNKNOWNs honestos). */
    public static AuthResult.Report analyze(File apk) {
        return analyze(apk, null);
    }

    /** Análisis completo por etapas. Nunca null. Nunca lanza. */
    public static AuthResult.Report analyze(File apk, Options o) {
        AuthResult.Report r = new AuthResult.Report();
        String apkRef = apk == null ? "?" : apk.getName();
        if (o == null) o = new Options();
        try {
            if (apk == null || !apk.isFile()) {
                r.notes.add("archivo no válido");
                r.verdict.unknowns.add("sin APK que analizar");
                return r;
            }
            // Etapa 0: apksig (una sola pasada, compartida por las capas).
            ApkSigAdapter.Result sw = null;
            if (o.forceInternal) {
                sw = new ApkSigAdapter.Result();
                sw.available = false;
                sw.unavailableReason = "verificador interno forzado por opciones";
                r.notes.add("apksig desactivado por opciones");
            } else {
                try {
                    sw = ApkSigAdapter.verify(apk, MIN_PLATFORM_VERSION, MAX_PLATFORM_VERSION);
                } catch (Throwable t) {
                    sw = new ApkSigAdapter.Result();
                    sw.available = false;
                    sw.unavailableReason = "fallo ejecutando apksig";
                }
            }
            r.apksigUsed = sw.available;
            if (!sw.available) {
                r.notes.add("apksig no usado (" + sw.unavailableReason
                        + "): respaldo interno");
            }
            // Etapa 0b: manifest (decodificado o el aportado).
            String xml = o.manifestXml;
            if (xml == null) xml = decodeManifest(apk);
            if (xml == null) xml = "";

            // Capa 1: firma e integridad.
            try {
                r.signature = AuthSignature.inspect(apk, sw);
            } catch (Throwable t) {
                r.notes.add("capa firma no disponible");
            }
            // Capa 2: identidad + allowlist.
            AuthAllowlist.Store allow = null;
            AuthAllowlist.MatchResult match = new AuthAllowlist.MatchResult();
            boolean lineageCovers = false;
            try {
                allow = AuthAllowlist.load(o.allowlistJson == null
                        ? AuthAllowlist.DEFAULT_JSON : o.allowlistJson);
                r.allowlistVersion = allow.version;
                r.signature.allowId = allow.id;
                r.signature.allowVersion = allow.version;
                r.signature.allowSource = allow.source;
            } catch (Throwable t) {
                r.notes.add("allowlist no disponible");
            }
            // Capa 5a: hechos observados (identidad del paquete incluida).
            AuthBaseline.Observed obs = new AuthBaseline.Observed();
            try {
                obs = AuthBaseline.observe(apk, xml.isEmpty() ? null : xml);
            } catch (Throwable t) {
                r.notes.add("observación baseline no disponible");
            }
            r.packageName = obs.packageName;
            r.versionCode = obs.versionCode;
            r.versionName = obs.versionName;
            try {
                if (allow != null) {
                    match = AuthAllowlist.match(allow, r.packageName,
                            r.signature.primarySignerSha256);
                    if (!"MATCH".equals(match.status)
                            && !r.signature.signerCerts.isEmpty()) {
                        String pk = r.signature.signerCerts.get(0).pubkeySha256;
                        AuthAllowlist.MatchResult pkM = AuthAllowlist.matchPubkey(
                                allow, r.packageName, pk);
                        if ("MATCH".equals(pkM.status)) match = pkM;
                    }
                    lineageCovers = AuthAllowlist.lineageCovers(allow, r.packageName,
                            r.signature.primarySignerSha256);
                }
                r.signature.allowMatch = match.status;
                r.signature.evidence.add(new AuthEvidence("sig.allowlist", "signer",
                        "MATCH".equals(match.status) ? "PASS"
                                : ("MISMATCH".equals(match.status) ? "FAIL"
                                : ("ERROR".equals(match.status) ? "ERROR" : "UNKNOWN")),
                        "allowlist", "comparación-sha256",
                        match.toText(), "", apkRef, ""));
            } catch (Throwable t) {
                r.notes.add("identidad no disponible");
            }
            // Capa 3: procedencia.
            try {
                r.provenance = AuthProvenance.inspect(apk, sw, o.trustedStamps);
            } catch (Throwable t) {
                r.notes.add("capa procedencia no disponible");
            }
            // Capa 4: rotación.
            try {
                r.rotation = AuthRotation.inspect(apk, sw,
                        r.signature.primarySignerSha256, allow, r.packageName);
            } catch (Throwable t) {
                r.notes.add("capa rotación no disponible");
            }
            // Capa 5b: comparación baseline.
            AuthBaseline.Store bstore = null;
            try {
                bstore = AuthBaseline.load(o.baselineJson == null
                        ? AuthBaseline.DEFAULT_JSON : o.baselineJson);
                r.baselineVersion = bstore.version;
                r.baseline = AuthBaseline.compare(bstore, obs, apkRef);
            } catch (Throwable t) {
                r.notes.add("capa baseline no disponible");
            }
            // Capa 6: repack.
            try {
                r.repack = AuthRepack.inspect(obs.flags, r.signature, r.baseline, apkRef);
            } catch (Throwable t) {
                r.notes.add("capa repack no disponible");
            }
            // Capa 7: veredicto.
            try {
                r.verdict = AuthVerdict.decide(r.signature, match, lineageCovers,
                        r.rotation, r.provenance, r.baseline, r.repack);
            } catch (Throwable t) {
                r.notes.add("veredicto no disponible");
            }
            // Evidencia agregada (acotada, sin duplicar).
            try {
                List<AuthEvidence> all = new ArrayList<>();
                all.addAll(r.signature.evidence);
                all.addAll(r.provenance.evidence);
                all.addAll(r.rotation.evidence);
                all.addAll(r.baseline.evidence);
                all.addAll(r.repack.evidence);
                for (AuthEvidence e : all) {
                    if (e != null) r.evidence.add(e);
                    if (r.evidence.size() >= MAX_EVIDENCE) {
                        r.notes.add("evidencia recortada a " + MAX_EVIDENCE);
                        break;
                    }
                }
            } catch (Throwable ignored) {
            }
        } catch (Throwable t) {
            r.notes.add("fallo general del motor");
        }
        return r;
    }

    // ---- Etapas individuales ----

    public static AuthSignature.SigResult stageSignature(File apk) {
        try {
            return AuthSignature.inspect(apk);
        } catch (Throwable ignored) {
            return new AuthSignature.SigResult();
        }
    }

    public static AuthAllowlist.MatchResult stageIdentity(String packageName,
                                                          String observedSha256,
                                                          String allowlistJson) {
        try {
            AuthAllowlist.Store s = AuthAllowlist.load(allowlistJson == null
                    ? AuthAllowlist.DEFAULT_JSON : allowlistJson);
            return AuthAllowlist.match(s, packageName, observedSha256);
        } catch (Throwable ignored) {
            AuthAllowlist.MatchResult m = new AuthAllowlist.MatchResult();
            m.note = "fallo en etapa";
            return m;
        }
    }

    public static AuthProvenance.ProvResult stageProvenance(File apk,
                                                           Set<String> trusted) {
        try {
            return AuthProvenance.inspect(apk, ApkSigAdapter.verify(apk, MIN_PLATFORM_VERSION, MAX_PLATFORM_VERSION),
                    trusted);
        } catch (Throwable ignored) {
            return new AuthProvenance.ProvResult();
        }
    }

    public static AuthRotation.RotResult stageRotation(File apk, String observedKey,
                                                       String allowlistJson,
                                                       String packageName) {
        try {
            AuthAllowlist.Store s = AuthAllowlist.load(allowlistJson == null
                    ? AuthAllowlist.DEFAULT_JSON : allowlistJson);
            return AuthRotation.inspect(apk, ApkSigAdapter.verify(apk, MIN_PLATFORM_VERSION, MAX_PLATFORM_VERSION),
                    observedKey, s, packageName);
        } catch (Throwable ignored) {
            return new AuthRotation.RotResult();
        }
    }

    public static AuthBaseline.BaseResult stageBaseline(File apk, String baselineJson,
                                                        String manifestXml) {
        try {
            AuthBaseline.Store s = AuthBaseline.load(baselineJson == null
                    ? AuthBaseline.DEFAULT_JSON : baselineJson);
            String xml = manifestXml != null ? manifestXml : decodeManifest(apk);
            AuthBaseline.Observed o = AuthBaseline.observe(apk,
                    xml == null || xml.isEmpty() ? null : xml);
            return AuthBaseline.compare(s, o, apk == null ? "?" : apk.getName());
        } catch (Throwable ignored) {
            return new AuthBaseline.BaseResult();
        }
    }

    public static AuthRepack.RepackResult stageRepack(AuthManifest.AppFlags flags,
                                                      AuthSignature.SigResult sig,
                                                      AuthBaseline.BaseResult base) {
        try {
            return AuthRepack.inspect(flags, sig, base, "?");
        } catch (Throwable ignored) {
            return new AuthRepack.RepackResult();
        }
    }

    /**
     * Decodifica el manifest del APK (AXML binario o XML en claro).
     * "" si ausente o ilegible. Nunca lanza.
     */
    public static String decodeManifest(File apk) {
        ZipFile zip = null;
        try {
            if (apk == null || !apk.isFile()) return "";
            zip = new ZipFile(apk);
            ZipEntry man = zip.getEntry("AndroidManifest.xml");
            if (man == null || man.getSize() <= 0 || man.getSize() > 20 * 1024 * 1024) {
                return "";
            }
            byte[] mb = new byte[(int) man.getSize()];
            InputStream in = null;
            try {
                in = zip.getInputStream(man);
                int off = 0;
                int n;
                while (off < mb.length
                        && (n = in.read(mb, off, mb.length - off)) > 0) {
                    off += n;
                }
                if (off != mb.length) return "";
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (Throwable ignored) {
                    }
                }
            }
            return AuthBaseline.decodeManifestBytes(mb);
        } catch (Throwable ignored) {
            return "";
        } finally {
            if (zip != null) {
                try {
                    zip.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }
}
