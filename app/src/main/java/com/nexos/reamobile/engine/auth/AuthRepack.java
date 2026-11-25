package com.nexos.reamobile.engine.auth;

import java.util.ArrayList;
import java.util.List;

/**
 * Capa 6 — indicadores de repack y modificación.
 * Distingue indicador observado / diferencia confirmada / modificación
 * demostrada / anomalía sin baseline. Ningún indicador aislado demuestra
 * repack: debuggable, allowBackup o splits ausentes tienen lecturas
 * legítimas. Ejecutable individualmente. Nunca lanza.
 */
public final class AuthRepack {
    private AuthRepack() {
    }

    public static class RepackResult {
        /** Indicador observado (build de depuración). */
        public AuthTri debuggable = AuthTri.UNKNOWN;
        public AuthTri testOnly = AuthTri.UNKNOWN;
        /** Anomalía SOLO vs referencia (sin baseline = FALSE). */
        public AuthTri allowBackupAnomaly = AuthTri.FALSE;
        public AuthTri cleartextTraffic = AuthTri.UNKNOWN;
        public AuthTri v1Unexpected = AuthTri.FALSE;
        public AuthTri splitsMissing = AuthTri.FALSE;
        /** Demostrado SOLO vs referencia exacta compatible. */
        public AuthTri manifestModified = AuthTri.FALSE;
        public AuthTri dexModified = AuthTri.FALSE;
        public AuthTri nativeLibsModified = AuthTri.FALSE;
        public String detail = "";
        public List<AuthEvidence> evidence = new ArrayList<>();

        public String toJson() {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                sb.append("\"debuggable\":").append(debuggable.toJson());
                sb.append(",\"test_only\":").append(testOnly.toJson());
                sb.append(",\"allow_backup_anomaly\":").append(allowBackupAnomaly.toJson());
                sb.append(",\"cleartext_traffic\":").append(cleartextTraffic.toJson());
                sb.append(",\"v1_unexpected\":").append(v1Unexpected.toJson());
                sb.append(",\"splits_missing\":").append(splitsMissing.toJson());
                sb.append(",\"manifest_modified\":").append(manifestModified.toJson());
                sb.append(",\"dex_modified\":").append(dexModified.toJson());
                sb.append(",\"native_libs_modified\":").append(nativeLibsModified.toJson());
                AuthJson.field(sb, "detail", detail, false);
                sb.append('}');
                return sb.toString();
            } catch (Throwable ignored) {
                return "{}";
            }
        }
    }

    /**
     * Analiza indicadores. flags: observados del manifest. sig: esquemas.
     * base: comparación baseline (puede ser null). apkRef: nombre APK.
     * Nunca null. Nunca lanza.
     */
    public static RepackResult inspect(AuthManifest.AppFlags flags,
                                       AuthSignature.SigResult sig,
                                       AuthBaseline.BaseResult base,
                                       String apkRef) {
        RepackResult r = new RepackResult();
        try {
            if (flags == null) flags = new AuthManifest.AppFlags();
            boolean exactRef = base != null && "EXACT".equals(base.lookupKind)
                    && base.variantMatch != AuthTri.FALSE;
            String apk = apkRef == null ? "?" : apkRef;

            // Indicadores observados del manifest.
            r.debuggable = flags.debuggable;
            r.testOnly = flags.testOnly;
            r.cleartextTraffic = flags.cleartextTraffic;
            ev(r, "rep.debuggable", flags.debuggable,
                    "debuggable=" + flags.debuggable
                            + " (indicador de build de depuración, no prueba de repack)",
                    apk);
            ev(r, "rep.testonly", flags.testOnly,
                    "testOnly=" + flags.testOnly + " (indicador de build de pruebas)", apk);
            ev(r, "rep.cleartext", flags.cleartextTraffic,
                    "usesCleartextTraffic=" + flags.cleartextTraffic
                            + " (indicador de tráfico sin cifrar)", apk);

            // allowBackup: anomalía solo con referencia que declare false.
            if (flags.allowBackup == AuthTri.TRUE && base != null
                    && "false".equals(base.refAllowBackup) && exactRef) {
                r.allowBackupAnomaly = AuthTri.TRUE;
                ev(r, "rep.allowbackup", AuthTri.TRUE,
                        "diferencia confirmada: allowBackup=true, referencia=false", apk);
            } else {
                r.allowBackupAnomaly = AuthTri.FALSE;
                ev(r, "rep.allowbackup", AuthTri.FALSE,
                        base == null || base.refAllowBackup.isEmpty() || !exactRef
                                ? "sin referencia apropiada: no anomalía"
                                : "coherente con referencia", apk);
            }
            // Matiz debuggable/testOnly vs referencia.
            if (exactRef && base != null) {
                if (flags.debuggable == AuthTri.TRUE && "false".equals(base.refDebuggable)) {
                    ev(r, "rep.debuggable.ref", AuthTri.TRUE,
                            "diferencia confirmada: debuggable=true, referencia=false", apk);
                }
                if (flags.testOnly == AuthTri.TRUE && "false".equals(base.refTestOnly)) {
                    ev(r, "rep.testonly.ref", AuthTri.TRUE,
                            "diferencia confirmada: testOnly=true, referencia=false", apk);
                }
            }

            // v1 inesperado: v1 presente y la referencia exacta no lo declara.
            boolean v1present = sig != null && sig.v1 != null
                    && sig.v1.present == AuthTri.TRUE;
            if (v1present && base != null && "EXACT".equals(base.lookupKind)
                    && !base.refSchemes.isEmpty() && !hasV1(base.refSchemes)) {
                r.v1Unexpected = AuthTri.TRUE;
                ev(r, "rep.v1", AuthTri.TRUE,
                        "v1 presente pero la referencia declara " + base.refSchemes, apk);
            } else {
                r.v1Unexpected = AuthTri.FALSE;
                ev(r, "rep.v1", AuthTri.FALSE,
                        !v1present ? "v1 ausente"
                                : "sin referencia de esquemas: no valorable", apk);
            }

            // Splits ausentes: solo split observado fuera de la referencia.
            if (base != null && "EXACT".equals(base.lookupKind)
                    && base.splitsMatch == AuthTri.FALSE) {
                r.splitsMissing = AuthTri.TRUE;
                ev(r, "rep.splits", AuthTri.TRUE,
                        "split observado fuera de la referencia", apk);
            } else {
                r.splitsMissing = AuthTri.FALSE;
                ev(r, "rep.splits", AuthTri.FALSE,
                        "ausencia de splits no demuestra modificación", apk);
            }

            // Modificaciones demostradas (solo referencia exacta compatible).
            if (exactRef && base != null && base.manifestNormMatch == AuthTri.FALSE) {
                r.manifestModified = AuthTri.TRUE;
            }
            ev(r, "rep.manifest", r.manifestModified,
                    exactRef ? ("manifest vs referencia: " + base.manifestNormMatch)
                            : "sin referencia exacta: modificación no demostrada", apk);
            if (exactRef && base != null && base.dexHashesMatch == AuthTri.FALSE) {
                r.dexModified = AuthTri.TRUE;
            }
            ev(r, "rep.dex", r.dexModified,
                    exactRef ? ("dex vs referencia: " + base.dexHashesMatch)
                            : "sin referencia exacta: modificación no demostrada", apk);
            if (exactRef && base != null && base.nativeLibsDiff != null
                    && base.nativeLibsDiff.match == AuthTri.FALSE) {
                r.nativeLibsModified = AuthTri.TRUE;
            }
            ev(r, "rep.nativelibs", r.nativeLibsModified,
                    exactRef ? ("nativas vs referencia: " + base.nativeLibsDiff.match)
                            : "sin referencia exacta: modificación no demostrada", apk);

            // Permisos/componentes añadidos (informativo, desde baseline).
            if (exactRef && base != null) {
                if (!base.permissionsDiff.added.isEmpty()
                        || !base.permissionsDiff.removed.isEmpty()) {
                    ev(r, "rep.perms", AuthTri.TRUE,
                            "permisos +"
                                    + base.permissionsDiff.added.size() + " -"
                                    + base.permissionsDiff.removed.size()
                                    + " vs referencia",
                            apk);
                }
                if (!base.exportedComponentsDiff.added.isEmpty()
                        || !base.exportedComponentsDiff.removed.isEmpty()) {
                    ev(r, "rep.exported", AuthTri.TRUE,
                            "exportados +"
                                    + base.exportedComponentsDiff.added.size() + " -"
                                    + base.exportedComponentsDiff.removed.size()
                                    + " vs referencia",
                            apk);
                }
            }
            r.detail = summary(r);
        } catch (Throwable ignored) {
            r.detail = "fallo analizando repack";
        }
        return r;
    }

    private static boolean hasV1(List<String> schemes) {
        try {
            for (String s : schemes) {
                if (s != null && ("v1".equalsIgnoreCase(s.trim())
                        || "1".equals(s.trim()))) return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static void ev(RepackResult r, String id, AuthTri v, String obs, String apk) {
        try {
            r.evidence.add(new AuthEvidence(id, "repack",
                    v == AuthTri.TRUE ? "INFO" : (v == AuthTri.FALSE ? "INFO" : "UNKNOWN"),
                    "manifest".equals(sourceOf(id)) ? "manifest" : "baseline",
                    "observación", obs, "", apk, ""));
        } catch (Throwable ignored) {
        }
    }

    private static String sourceOf(String id) {
        if (id.startsWith("rep.debuggable") || id.startsWith("rep.testonly")
                || id.startsWith("rep.cleartext") || id.startsWith("rep.allowbackup")) {
            return "manifest";
        }
        return "baseline";
    }

    private static String summary(RepackResult r) {
        try {
            List<String> hits = new ArrayList<>();
            if (r.manifestModified == AuthTri.TRUE) hits.add("manifest");
            if (r.dexModified == AuthTri.TRUE) hits.add("dex");
            if (r.nativeLibsModified == AuthTri.TRUE) hits.add("nativas");
            if (r.allowBackupAnomaly == AuthTri.TRUE) hits.add("allowBackup");
            if (r.v1Unexpected == AuthTri.TRUE) hits.add("v1");
            if (r.splitsMissing == AuthTri.TRUE) hits.add("splits");
            if (hits.isEmpty()) {
                boolean anyInd = r.debuggable == AuthTri.TRUE || r.testOnly == AuthTri.TRUE
                        || r.cleartextTraffic == AuthTri.TRUE;
                return anyInd ? "indicadores observados, sin modificación demostrada"
                        : "sin indicadores ni modificaciones";
            }
            StringBuilder sb = new StringBuilder("diferencias: ");
            for (int i = 0; i < hits.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append(hits.get(i));
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }
}
