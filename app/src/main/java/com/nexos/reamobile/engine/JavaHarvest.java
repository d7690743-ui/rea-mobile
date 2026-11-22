package com.nexos.reamobile.engine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Cosecha sobre fuentes Java descompiladas: búsqueda global, secretos y ZIP.
 * Java puro. Nunca lanza.
 */
public final class JavaHarvest {
    private JavaHarvest() {
    }

    public static class Hit {
        public String className = "?";
        public int line;
        public String snippet = "";
    }

    public static class ZipResult {
        public byte[] zip;
        public int files;
        public boolean truncated;
    }

    public static final int MAX_HITS = 200;
    public static final int MAX_SNIPPET = 160;
    public static final int MAX_ZIP_FILES = 2000;
    public static final long MAX_ZIP_BYTES = 60L * 1024 * 1024;

    private static final Pattern[] SECRET_RES = new Pattern[]{
            Pattern.compile("AKIA[0-9A-Z]{16}"),
            Pattern.compile("AIza[0-9A-Za-z_\\-]{35}"),
            Pattern.compile("ghp_[0-9A-Za-z]{20,}|gho_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{20,}"),
            Pattern.compile("xox[bpas]-[0-9A-Za-z\\-]+"),
            Pattern.compile("sk\\-(live|test)\\-[0-9A-Za-z]+"),
            Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            Pattern.compile("(?i)(api[_-]?key|apikey|secret|passwd|password)\\s*[=:]\\s*\"[^\"]+\""),
    };

    /** Búsqueda global (subcadena) en todas las fuentes. Nunca lanza. */
    public static List<Hit> search(Map<String, String> sources, String query,
                                   boolean ignoreCase, int maxHits) {
        List<Hit> out = new ArrayList<>();
        try {
            if (sources == null || query == null || query.isEmpty()) return out;
            int cap = maxHits <= 0 ? MAX_HITS : Math.min(maxHits, MAX_HITS);
            String q = ignoreCase ? query.toLowerCase(Locale.US) : query;
            for (Map.Entry<String, String> e : sources.entrySet()) {
                String code = e.getValue();
                if (code == null || code.isEmpty()) continue;
                String[] lines = code.split("\n", -1);
                for (int i = 0; i < lines.length; i++) {
                    String ln = lines[i];
                    String h = ignoreCase ? ln.toLowerCase(Locale.US) : ln;
                    if (h.contains(q)) {
                        Hit hit = new Hit();
                        hit.className = e.getKey() == null ? "?" : e.getKey();
                        hit.line = i + 1;
                        hit.snippet = snippet(ln);
                        out.add(hit);
                        if (out.size() >= cap) return out;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Secretos de alta señal en las fuentes. Nunca lanza. */
    public static List<Hit> findSecrets(Map<String, String> sources, int maxHits) {
        List<Hit> out = new ArrayList<>();
        try {
            if (sources == null) return out;
            int cap = maxHits <= 0 ? MAX_HITS : Math.min(maxHits, MAX_HITS);
            for (Map.Entry<String, String> e : sources.entrySet()) {
                String code = e.getValue();
                if (code == null || code.isEmpty()) continue;
                String[] lines = code.split("\n", -1);
                for (int i = 0; i < lines.length; i++) {
                    if (isSecretLine(lines[i])) {
                        Hit hit = new Hit();
                        hit.className = e.getKey() == null ? "?" : e.getKey();
                        hit.line = i + 1;
                        hit.snippet = snippet(lines[i]);
                        out.add(hit);
                        if (out.size() >= cap) return out;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static boolean isSecretLine(String ln) {
        if (ln == null) return false;
        for (Pattern p : SECRET_RES) {
            try {
                Matcher m = p.matcher(ln);
                if (m.find()) return true;
            } catch (Throwable ignored) {
            }
        }
        if (!SecretRules.match(ln).isEmpty()) return true;
        return SecretRules.hasEntropyToken(ln);
    }

    private static String snippet(String ln) {
        try {
            String s = ln.trim().replace('\t', ' ');
            if (s.length() > MAX_SNIPPET) s = s.substring(0, MAX_SNIPPET) + "…";
            return s;
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** Empaqueta las fuentes en ZIP (claves con puntos a rutas). Nunca lanza. */
    public static ZipResult zip(Map<String, String> sources) {
        ZipResult r = new ZipResult();
        try {
            if (sources == null || sources.isEmpty()) {
                r.zip = emptyZip();
                return r;
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(bos);
            long total = 0;
            try {
                for (Map.Entry<String, String> e : sources.entrySet()) {
                    if (e.getKey() == null || e.getValue() == null
                            || e.getValue().trim().isEmpty()) continue;
                    if (r.files >= MAX_ZIP_FILES) {
                        r.truncated = true;
                        break;
                    }
                    byte[] data = e.getValue().getBytes("UTF-8");
                    if (total + data.length > MAX_ZIP_BYTES) {
                        r.truncated = true;
                        break;
                    }
                    String name = e.getKey().replace('.', '/') + ".java";
                    zos.putNextEntry(new ZipEntry(name));
                    zos.write(data);
                    zos.closeEntry();
                    total += data.length;
                    r.files++;
                }
            } finally {
                try {
                    zos.close();
                } catch (Throwable ignored) {
                }
            }
            r.zip = bos.toByteArray();
        } catch (Throwable t) {
            r.zip = null;
        }
        return r;
    }

    private static byte[] emptyZip() {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ZipOutputStream zos = new ZipOutputStream(bos);
            zos.close();
            return bos.toByteArray();
        } catch (Throwable t) {
            return new byte[0];
        }
    }

    /** Para tests: abre el ZIP devuelto sin tocar disco. Nunca lanza. */
    static List<String> zipNames(byte[] zip) {
        List<String> out = new ArrayList<>();
        try {
            java.util.zip.ZipInputStream zis =
                    new java.util.zip.ZipInputStream(new ByteArrayInputStream(zip));
            try {
                ZipEntry e;
                while ((e = zis.getNextEntry()) != null) out.add(e.getName());
            } finally {
                try {
                    zis.close();
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }
}
