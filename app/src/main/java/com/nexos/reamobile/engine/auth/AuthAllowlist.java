package com.nexos.reamobile.engine.auth;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Allowlist local de firmantes oficiales (Capa 2).
 * Independiente del APK analizado; se actualiza importando JSON sin tocar
 * el motor. Sin allowlist confiable el resultado es UNKNOWN, nunca negativo.
 * El Subject DN jamás se usa como prueba de identidad.
 * Java puro. Nunca lanza.
 */
public final class AuthAllowlist {
    private AuthAllowlist() {
    }

    public static final String SCHEMA = "rea-allowlist-v1";

    /** Esqueleto versionado por defecto: vacío → todo UNKNOWN. */
    public static final String DEFAULT_JSON = "{"
            + "\"schema\":\"rea-allowlist-v1\","
            + "\"id\":\"rea-default\","
            + "\"version\":\"none\","
            + "\"source\":\"bundled-empty\","
            + "\"updated\":\"\","
            + "\"entries\":[],"
            + "\"lineages\":[]"
            + "}";

    public static class CertEntry {
        public String sha256 = "";
        public String pubkeySha256 = "";
        public boolean historic;
        public List<String> versions = new ArrayList<>();
        public String variant = "";
    }

    public static class Store {
        public String id = "";
        public String version = "";
        public String source = "";
        public String updated = "";
        /** No vacío = la allowlist no cargó (consultas → ERROR). */
        public String loadError = "";
        public Map<String, List<CertEntry>> byPackage = new LinkedHashMap<>();
        /** Paquete → cadenas oficiales de rotación (sha256 en orden). */
        public Map<String, List<List<String>>> lineages = new LinkedHashMap<>();

        /** Nº de paquetes con entradas (0 = vacía). Nunca lanza. */
        public int packageCount() {
            try {
                return byPackage.size();
            } catch (Throwable ignored) {
                return 0;
            }
        }
    }

    public static class MatchResult {
        /** MATCH|MISMATCH|UNKNOWN|ERROR. */
        public String status = "UNKNOWN";
        public String note = "";
        public boolean historic;
        public String variant = "";

        public String toText() {
            if (note.isEmpty()) return status;
            return status + " (" + note + ")";
        }
    }

    /** Carga una allowlist desde JSON. Nunca null. Nunca lanza. */
    public static Store load(String json) {
        Store s = new Store();
        try {
            if (json == null || json.trim().isEmpty()) {
                s.loadError = "allowlist vacía";
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
            if (entries != null) {
                int guard = 0;
                for (Object eo : entries) {
                    if (guard++ >= 5000) break;
                    Map<String, Object> e = AuthJson.asObject(eo);
                    if (e == null) continue;
                    String pkg = AuthJson.str(e, "package").trim();
                    if (pkg.isEmpty()) continue;
                    List<CertEntry> list = s.byPackage.get(pkg);
                    if (list == null) {
                        list = new ArrayList<>();
                        s.byPackage.put(pkg, list);
                    }
                    List<Object> certs = AuthJson.asList(e.get("certs"));
                    if (certs == null) continue;
                    int guard2 = 0;
                    for (Object co : certs) {
                        if (guard2++ >= 64) break;
                        Map<String, Object> c = AuthJson.asObject(co);
                        if (c == null) continue;
                        CertEntry ce = new CertEntry();
                        ce.sha256 = AuthCert.normHash(AuthJson.str(c, "sha256"));
                        ce.pubkeySha256 = AuthCert.normHash(AuthJson.str(c, "pubkey_sha256"));
                        Object h = c.get("historic");
                        ce.historic = Boolean.TRUE.equals(h);
                        ce.versions = AuthJson.strList(c, "versions");
                        ce.variant = AuthJson.str(c, "variant");
                        if (!ce.sha256.isEmpty() || !ce.pubkeySha256.isEmpty()) {
                            list.add(ce);
                        }
                        if (list.size() >= 64) break;
                    }
                }
            }
            List<Object> lins = AuthJson.asList(o.get("lineages"));
            if (lins != null) {
                int guard = 0;
                for (Object lo : lins) {
                    if (guard++ >= 1000) break;
                    Map<String, Object> e = AuthJson.asObject(lo);
                    if (e == null) continue;
                    String pkg = AuthJson.str(e, "package").trim();
                    if (pkg.isEmpty()) continue;
                    List<String> chain = new ArrayList<>();
                    for (String h : AuthJson.strList(e, "chain")) {
                        String n = AuthCert.normHash(h);
                        if (!n.isEmpty()) chain.add(n);
                        if (chain.size() >= 32) break;
                    }
                    if (chain.isEmpty()) continue;
                    List<List<String>> ll = s.lineages.get(pkg);
                    if (ll == null) {
                        ll = new ArrayList<>();
                        s.lineages.put(pkg, ll);
                    }
                    if (ll.size() < 16) ll.add(chain);
                }
            }
        } catch (Throwable t) {
            s.loadError = "fallo cargando allowlist";
        }
        return s;
    }

    /** Consulta paquete+sha256 observado. Nunca null. Nunca lanza. */
    public static MatchResult match(Store s, String pkg, String observedSha256) {
        MatchResult r = new MatchResult();
        try {
            if (s == null) {
                r.status = "UNKNOWN";
                r.note = "sin allowlist";
                return r;
            }
            if (!s.loadError.isEmpty()) {
                r.status = "ERROR";
                r.note = s.loadError;
                return r;
            }
            String obs = AuthCert.normHash(observedSha256);
            if (obs.isEmpty()) {
                r.status = "UNKNOWN";
                r.note = "sin firmante observado";
                return r;
            }
            List<CertEntry> list = s.byPackage.get(pkg == null ? "" : pkg.trim());
            if (list == null || list.isEmpty()) {
                r.status = "UNKNOWN";
                r.note = "paquete sin entradas oficiales";
                return r;
            }
            for (CertEntry ce : list) {
                if (ce == null) continue;
                if (!ce.sha256.isEmpty() && ce.sha256.equals(obs)) {
                    r.status = "MATCH";
                    r.historic = ce.historic;
                    r.variant = ce.variant;
                    r.note = ce.historic ? "certificado histórico oficial"
                            : "certificado oficial reconocido";
                    return r;
                }
            }
            r.status = "MISMATCH";
            r.note = "firmante distinto a " + list.size() + " referencia(s) oficial(es)";
            return r;
        } catch (Throwable ignored) {
            r.status = "UNKNOWN";
            r.note = "fallo consultando allowlist";
            return r;
        }
    }

    /** Consulta por huella de clave pública (respaldo). Nunca null. Nunca lanza. */
    public static MatchResult matchPubkey(Store s, String pkg, String observedPubkeySha256) {
        MatchResult r = new MatchResult();
        try {
            if (s == null || !s.loadError.isEmpty()) {
                r.status = s == null ? "UNKNOWN" : "ERROR";
                r.note = s == null ? "sin allowlist" : s.loadError;
                return r;
            }
            String obs = AuthCert.normHash(observedPubkeySha256);
            if (obs.isEmpty()) {
                r.note = "sin clave observada";
                return r;
            }
            List<CertEntry> list = s.byPackage.get(pkg == null ? "" : pkg.trim());
            if (list == null || list.isEmpty()) {
                r.note = "paquete sin entradas oficiales";
                return r;
            }
            for (CertEntry ce : list) {
                if (ce != null && !ce.pubkeySha256.isEmpty()
                        && ce.pubkeySha256.equals(obs)) {
                    r.status = "MATCH";
                    r.historic = ce.historic;
                    r.note = "clave pública oficial reconocida";
                    return r;
                }
            }
            r.status = "MISMATCH";
            r.note = "clave distinta a las referencias oficiales";
            return r;
        } catch (Throwable ignored) {
            r.status = "UNKNOWN";
            return r;
        }
    }

    /**
     * true si el sha observado figura en alguna cadena oficial de rotación
     * del paquete (clave rotada legítima). Nunca lanza.
     */
    public static boolean lineageCovers(Store s, String pkg, String observedSha256) {
        try {
            if (s == null || !s.loadError.isEmpty()) return false;
            String obs = AuthCert.normHash(observedSha256);
            if (obs.isEmpty()) return false;
            List<List<String>> ll = s.lineages.get(pkg == null ? "" : pkg.trim());
            if (ll == null) return false;
            for (List<String> chain : ll) {
                if (chain != null && chain.contains(obs)) return true;
            }
            return false;
        } catch (Throwable ignored) {
            return false;
        }
    }
}
