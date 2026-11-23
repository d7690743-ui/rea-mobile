package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Chequeos sobre el manifest decodificado: autoarranque, permisos intrusivos,
 * componentes exportados, deep links e higiene. Regex acotadas sobre texto.
 * Java puro. Nunca lanza.
 */
public final class ManifestChecks {
    private ManifestChecks() {
    }

    public static final int MAX_ITEMS = 30;
    public static final int MAX_COMPONENTS = 300;

    private static final String[][] INTRUSIVE = {
            {"MANAGE_EXTERNAL_STORAGE", "acceso total al almacenamiento"},
            {"REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "evita Doze/reposo"},
            {"SYSTEM_ALERT_WINDOW", "ventanas sobre otras apps"},
            {"BIND_ACCESSIBILITY_SERVICE", "servicio de accesibilidad (lee pantalla)"},
            {"REQUEST_INSTALL_PACKAGES", "puede instalar paquetes"},
            {"READ_SMS", "lee SMS"},
            {"SEND_SMS", "envía SMS"},
            {"RECEIVE_SMS", "recibe SMS"},
            {"READ_CALL_LOG", "lee registro de llamadas"},
            {"PROCESS_OUTGOING_CALLS", "intercepta llamadas salientes"},
            {"READ_PHONE_NUMBERS", "lee números de teléfono"},
            {"ACCESS_BACKGROUND_LOCATION", "ubicación en segundo plano"},
            {"QUERY_ALL_PACKAGES", "lista todas las apps instaladas"},
            {"BIND_DEVICE_ADMIN", "administrador del dispositivo"},
            {"USE_FULL_SCREEN_INTENT", "pantalla completa desde fondo"},
            {"RECORD_AUDIO", "micrófono"},
            {"CAMERA", "cámara"},
    };

    public static class Result {
        public List<String> bootReceivers = new ArrayList<>();
        public List<String> intrusivePerms = new ArrayList<>();
        public List<String> exported = new ArrayList<>();
        public List<String> components = new ArrayList<>();
        public List<String> deepLinks = new ArrayList<>();
        public List<String> hygiene = new ArrayList<>();
    }

    /**
     * Nombre de componente → descriptor (`Lcom/x/A;`); resuelve relativos
     * (".A", "A") con el paquete. null si no hay nombre. Nunca lanza.
     */
    public static String resolveDescriptor(String raw, String pkg) {
        try {
            if (raw == null || raw.isEmpty() || "?".equals(raw)) return null;
            String fq;
            if (raw.startsWith(".")) fq = (pkg == null ? "" : pkg) + raw;
            else if (raw.contains(".")) fq = raw;
            else fq = (pkg == null || pkg.isEmpty() ? raw : pkg + "." + raw);
            if (fq.startsWith(".")) fq = fq.substring(1);
            if (fq.isEmpty()) return null;
            return "L" + fq.replace('.', '/') + ";";
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** Analiza el XML decodificado + permisos. Nunca lanza. */
    public static Result check(String xml, List<String> perms) {
        Result r = new Result();
        try {
            if (xml == null) xml = "";
            if (xml.length() > 2000000) xml = xml.substring(0, 2000000);
            checkBoot(xml, r);
            checkExported(xml, r);
            checkLinks(xml, r);
            checkHygiene(xml, r);
            if (perms != null) {
                for (String p : perms) {
                    if (p == null) continue;
                    String motive = motiveOf(p);
                    if (motive != null && r.intrusivePerms.size() < MAX_ITEMS) {
                        r.intrusivePerms.add(shortName(p) + " — " + motive);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return r;
    }

    private static void checkBoot(String xml, Result r) {
        try {
            Pattern rec = Pattern.compile("<receiver\\b([^>]*)>(.*?)</receiver>",
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
            Matcher m = rec.matcher(xml);
            int guard = 0;
            while (m.find() && guard++ < 500 && r.bootReceivers.size() < MAX_ITEMS) {
                String attrs = m.group(1);
                String body = m.group(2);
                if (body.contains("BOOT_COMPLETED") || body.contains("QUICKBOOT_POWERON")) {
                    String name = attr(attrs, "android:name");
                    String exp = attr(attrs, "android:exported");
                    r.bootReceivers.add((name.isEmpty() ? "?" : name)
                            + ("true".equals(exp) ? " (exportado)" : " (no exportado)"));
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void checkExported(String xml, Result r) {
        try {
            Pattern comp = Pattern.compile("<(activity|service|receiver|provider)\\b([^>]*)>",
                    Pattern.CASE_INSENSITIVE);
            Matcher m = comp.matcher(xml);
            int guard = 0;
            while (m.find() && guard++ < 2000 && (r.exported.size() < MAX_ITEMS
                    || r.components.size() < MAX_COMPONENTS)) {
                String attrs = m.group(2);
                String name = attr(attrs, "android:name");
                if (!name.isEmpty() && r.components.size() < MAX_COMPONENTS
                        && !r.components.contains(name)) r.components.add(name);
                if ("true".equals(attr(attrs, "android:exported"))
                        && r.exported.size() < MAX_ITEMS) {
                    r.exported.add(m.group(1) + ":" + (name.isEmpty() ? "?" : name));
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void checkLinks(String xml, Result r) {
        try {
            Pattern data = Pattern.compile("<data\\b([^>]*)/?>", Pattern.CASE_INSENSITIVE);
            Matcher m = data.matcher(xml);
            int guard = 0;
            while (m.find() && guard++ < 1000 && r.deepLinks.size() < MAX_ITEMS) {
                String scheme = attr(m.group(1), "android:scheme");
                String host = attr(m.group(1), "android:host");
                if (!scheme.isEmpty()) {
                    String link = host.isEmpty() ? scheme + "://" : scheme + "://" + host;
                    if (!r.deepLinks.contains(link)) r.deepLinks.add(link);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void checkHygiene(String xml, Result r) {
        try {
            Pattern app = Pattern.compile("<application\\b([^>]*)>", Pattern.CASE_INSENSITIVE);
            Matcher m = app.matcher(xml);
            if (m.find()) {
                String attrs = m.group(1);
                if ("true".equals(attr(attrs, "android:debuggable"))) {
                    r.hygiene.add("debuggable=true (app depurable)");
                }
                String backup = attr(attrs, "android:allowBackup");
                if (!"false".equals(backup)) {
                    r.hygiene.add("allowBackup no es false (copias admitidas)");
                }
                if ("true".equals(attr(attrs, "android:usesCleartextTraffic"))) {
                    r.hygiene.add("usesCleartextTraffic=true (HTTP sin cifrar)");
                }
                if (!attr(attrs, "android:networkSecurityConfig").isEmpty()) {
                    r.hygiene.add("networkSecurityConfig presente");
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static String motiveOf(String perm) {
        String s = shortName(perm);
        for (String[] e : INTRUSIVE) {
            if (e[0].equals(s)) return e[1];
        }
        return null;
    }

    private static String shortName(String perm) {
        int dot = perm.lastIndexOf('.');
        return dot >= 0 ? perm.substring(dot + 1) : perm;
    }

    private static String attr(String attrs, String name) {
        try {
            Pattern p = Pattern.compile(Pattern.quote(name) + "\\s*=\\s*\"([^\"]*)\"");
            Matcher m = p.matcher(attrs);
            if (m.find()) return m.group(1);
        } catch (Throwable ignored) {
        }
        return "";
    }
}
