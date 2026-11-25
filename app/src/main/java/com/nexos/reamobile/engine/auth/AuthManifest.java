package com.nexos.reamobile.engine.auth;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Atributos de aplicación leídos del manifest decodificado (texto).
 * Solo observa: no clasifica nada como malicioso por sí mismo.
 * Java puro. Nunca lanza.
 */
public final class AuthManifest {
    private AuthManifest() {
    }

    public static class AppFlags {
        public AuthTri debuggable = AuthTri.UNKNOWN;
        public AuthTri testOnly = AuthTri.UNKNOWN;
        /** allowBackup declarado (true/false); anomalía solo vs baseline. */
        public AuthTri allowBackup = AuthTri.UNKNOWN;
        public AuthTri cleartextTraffic = AuthTri.UNKNOWN;
        public AuthTri networkSecurityConfig = AuthTri.UNKNOWN;
        /** Manifest ausente o ilegible. */
        public boolean missing = true;
    }

    public static class Identity {
        public String packageName = "?";
        public long versionCode = -1;
        public String versionName = "";
        /** Nombre de split (manifest split=) o "" si base/desconocido. */
        public String splitName = "";
    }

    /** Banderas de <application>. Nunca null. Nunca lanza. */
    public static AppFlags flags(String manifestXml) {
        AppFlags f = new AppFlags();
        try {
            if (manifestXml == null || manifestXml.isEmpty()) return f;
            String xml = manifestXml.length() > 2000000
                    ? manifestXml.substring(0, 2000000) : manifestXml;
            Matcher m = Pattern.compile("<application\\b([^>]*)>",
                    Pattern.CASE_INSENSITIVE).matcher(xml);
            if (!m.find()) return f;
            f.missing = false;
            String attrs = m.group(1);
            f.debuggable = AuthTri.of("true".equals(attr(attrs, "android:debuggable")));
            f.testOnly = AuthTri.of("true".equals(attr(attrs, "android:testOnly")));
            String backup = attr(attrs, "android:allowBackup");
            f.allowBackup = backup.isEmpty() ? AuthTri.of(true) : AuthTri.of("true".equals(backup));
            f.cleartextTraffic = AuthTri.of("true".equals(
                    attr(attrs, "android:usesCleartextTraffic")));
            f.networkSecurityConfig = AuthTri.of(
                    !attr(attrs, "android:networkSecurityConfig").isEmpty());
        } catch (Throwable ignored) {
        }
        return f;
    }

    /** Identidad del paquete desde <manifest>. Nunca null. Nunca lanza. */
    public static Identity identity(String manifestXml) {
        Identity id = new Identity();
        try {
            if (manifestXml == null || manifestXml.isEmpty()) return id;
            String xml = manifestXml.length() > 2000000
                    ? manifestXml.substring(0, 2000000) : manifestXml;
            Matcher m = Pattern.compile("<manifest\\b([^>]*)>",
                    Pattern.CASE_INSENSITIVE).matcher(xml);
            if (!m.find()) return id;
            String attrs = m.group(1);
            String pkg = attr(attrs, "package");
            if (!pkg.isEmpty()) id.packageName = pkg;
            String vc = attr(attrs, "android:versionCode");
            if (!vc.isEmpty()) {
                try {
                    id.versionCode = Long.parseLong(vc.trim());
                } catch (NumberFormatException nfe) {
                    id.versionCode = -1;
                }
            }
            id.versionName = attr(attrs, "android:versionName");
            String split = attr(attrs, "android:split");
            if (split.isEmpty()) split = attr(attrs, "split");
            id.splitName = split;
        } catch (Throwable ignored) {
        }
        return id;
    }

    /**
     * Normalización débil del manifest para comparar: colapsa blancos.
     * No reordena nada; cambios de orden dan hash distinto (documentado).
     * Nunca lanza.
     */
    public static String normalize(String manifestXml) {
        try {
            if (manifestXml == null || manifestXml.isEmpty()) return "";
            String xml = manifestXml.length() > 2000000
                    ? manifestXml.substring(0, 2000000) : manifestXml;
            StringBuilder sb = new StringBuilder(xml.length());
            boolean ws = false;
            for (int i = 0; i < xml.length(); i++) {
                char c = xml.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    if (!ws) {
                        sb.append(' ');
                        ws = true;
                    }
                } else {
                    sb.append(c);
                    ws = false;
                }
            }
            return sb.toString().trim();
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** ABIs observadas desde entradas lib/<abi>/*. Nunca null. Nunca lanza. */
    public static List<String> abisFromEntries(List<String> entryNames) {
        List<String> out = new ArrayList<>();
        try {
            if (entryNames == null) return out;
            for (String n : entryNames) {
                if (n == null || !n.startsWith("lib/")) continue;
                int a = 4;
                int b = n.indexOf('/', a);
                if (b <= a) continue;
                String abi = n.substring(a, b);
                if (!abi.isEmpty() && !out.contains(abi) && out.size() < 16) out.add(abi);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Densidades observadas desde res/drawable-<d>/. Nunca null. Nunca lanza. */
    public static List<String> densitiesFromEntries(List<String> entryNames) {
        List<String> out = new ArrayList<>();
        try {
            if (entryNames == null) return out;
            for (String n : entryNames) {
                if (n == null || !n.startsWith("res/drawable-")) continue;
                int a = "res/drawable-".length();
                int b = n.indexOf('/', a);
                if (b <= a) continue;
                String d = n.substring(a, b);
                if (!d.isEmpty() && !out.contains(d) && out.size() < 16) out.add(d);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    static String attr(String attrs, String name) {
        try {
            Matcher m = Pattern.compile(Pattern.quote(name) + "\\s*=\\s*\"([^\"]*)\"")
                    .matcher(attrs);
            if (m.find()) return m.group(1);
        } catch (Throwable ignored) {
        }
        return "";
    }
}
