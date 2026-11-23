package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Secretos de alta confianza: set reducido de reglas por formato (estilo
 * Gitleaks) + entropía de Shannon para literales sin formato conocido.
 * Java puro. Nunca lanza.
 */
public final class SecretRules {
    private SecretRules() {
    }

    private static final class Rule {
        final String id;
        final Pattern re;

        Rule(String id, String re) {
            this.id = id;
            this.re = Pattern.compile(re);
        }
    }

    private static final Rule[] RULES = {
            new Rule("aws-access", "AKIA[0-9A-Z]{16}"),
            new Rule("aws-secret", "(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]"),
            new Rule("google-api", "AIza[0-9A-Za-z_\\-]{35}"),
            new Rule("github", "ghp_[0-9A-Za-z]{20,}|gho_[0-9A-Za-z]{20,}|"
                    + "ghu_[0-9A-Za-z]{20,}|ghr_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{20,}"),
            new Rule("slack-token", "xox[bpas]-[0-9A-Za-z\\-]+"),
            new Rule("slack-webhook", "hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
            new Rule("stripe", "sk\\-(live|test)\\-[0-9A-Za-z]+"),
            new Rule("private-key", "-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            new Rule("jwt", "eyJ[A-Za-z0-9_\\-]{8,}\\.eyJ[A-Za-z0-9_\\-]{8,}\\.[A-Za-z0-9_\\-]+"),
            new Rule("firebase-db", "https://[a-z0-9\\-]+\\.firebaseio\\.com"),
            new Rule("bearer", "(?i)bearer\\s+[A-Za-z0-9\\-._~+/]{20,}"),
            new Rule("asignacion",
                    "(?i)(api[_-]?key|apikey|client[_-]?secret|consumer[_-]?secret|"
                            + "auth[_-]?token|secret|passwd|password|pwd)\\s*[=:]\\s*['\"][^'\"]{3,}['\"]"),
    };

    /** Ids de reglas que casan en s (vacío si ninguna). Nunca lanza. */
    public static List<String> match(String s) {
        List<String> out = new ArrayList<>();
        try {
            if (s == null || s.isEmpty()) return out;
            for (Rule r : RULES) {
                Matcher m = r.re.matcher(s);
                if (m.find()) out.add(r.id);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Entropía de Shannon en bits/caracter. Nunca lanza. */
    public static double shannon(String s) {
        try {
            if (s == null || s.isEmpty()) return 0;
            int[] freq = new int[256];
            int n = 0;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c < 256) {
                    freq[c]++;
                    n++;
                }
            }
            if (n == 0) return 0;
            double h = 0;
            for (int f : freq) {
                if (f == 0) continue;
                double p = (double) f / n;
                h -= p * (Math.log(p) / Math.log(2));
            }
            return h;
        } catch (Throwable t) {
            return 0;
        }
    }

    /**
     * true si s parece un token opaco: alfabeto de credencial, 20-200
     * caracteres y entropía alta. Rechaza URLs y rutas. Nunca lanza.
     */
    public static boolean isTokenLike(String s) {
        try {
            if (s == null) return false;
            String t = s.trim();
            if (t.length() < 20 || t.length() > 200) return false;
            for (int i = 0; i < t.length(); i++) {
                char c = t.charAt(i);
                boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                        || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
                        || c == '_' || c == '-' || c == '.';
                if (!ok) return false;
            }
            if (t.contains("://") || t.indexOf(':') >= 0 || t.indexOf('@') >= 0) return false;
            if (t.startsWith("http") || t.startsWith("www.") || t.startsWith("//")) return false;
            // Alfabetos base32/base64/hex de librerías: entropía alta pero no secretos.
            String up = t.toUpperCase(java.util.Locale.US);
            if (up.contains("ABCDEF") || up.contains("012345") || up.contains("234567")) return false;
            return shannon(t) >= 4.5;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static final Pattern QUOTED = Pattern.compile("['\"]([^'\"]{20,200})['\"]");

    /** true si alguna cadena entre comillas de la línea es token opaco. Nunca lanza. */
    public static boolean hasEntropyToken(String line) {
        try {
            if (line == null || line.length() > 2000) return false;
            Matcher m = QUOTED.matcher(line);
            while (m.find()) {
                if (isTokenLike(m.group(1))) return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }
}
