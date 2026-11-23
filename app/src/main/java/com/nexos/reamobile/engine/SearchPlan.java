package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Fase D: plan de búsqueda dirigido por el RAG (OMEGA_APK_RAG_Knowledge_Base).
 * Clasifica el APK en un perfil (§19), ordena los checks (§23) y declara por
 * cada uno su estado honesto (§0.1), derivado de los módulos existentes.
 * Utilidad estática sin estado. Nunca lanza.
 */
public final class SearchPlan {
    private SearchPlan() {
    }

    /** Perfiles §19. El motor de ejecución manda; luego ofuscación, tamaño. */
    public enum Profile {
        SENCILLO("sencillo"),
        MEDIANO("mediano"),
        GRANDE("grande"),
        FRAMEWORK("framework"),
        OFUSCADO("ofuscado");

        public final String label;

        Profile(String label) {
            this.label = label;
        }
    }

    /** Estados §0.1. Nunca afirmar ausencia desde NOT_FOUND/NO-EJECUTADO. */
    public enum State {
        FOUND,
        NOT_FOUND_IN_SCOPE,
        NOT_EXECUTED,
        UNSUPPORTED,
        PARTIAL,
        ERROR,
        INCONCLUSIVE,
    }

    /** Señales de inventario para clasificar. Listas opcionales (null = no). */
    public static class Signals {
        public int dexCount;
        public int classes;
        public int strings;
        public double ratio;
        public List<String> frameworks;
        public List<String> nativeLibs;
        public List<String> packers;
    }

    /** Check del plan: id estable, título y sección RAG. */
    public static class Check {
        public String id = "?";
        public String title = "?";
        public String rag = "?";
    }

    /** Check evaluado sobre un informe. */
    public static class CheckState {
        public String id = "?";
        public State state = State.INCONCLUSIVE;
        public String detail = "-";
    }

    /** Plan evaluado: perfil + checks en orden + nota de estrategia. */
    public static class Plan {
        public Profile profile = Profile.SENCILLO;
        public List<CheckState> checks = new ArrayList<>();
        public String note = "";
    }

    private static final String[][] CHECKS = {
            {"identidad", "Identidad y firma", "§0.3+§1"},
            {"manifest", "Manifest y componentes", "§2"},
            {"recursos", "Recursos y assets", "§3"},
            {"dex", "Código DEX", "§4"},
            {"apis", "APIs y permisos", "§5"},
            {"red", "Red y endpoints", "§6"},
            {"secretos", "Secretos", "§7.1-7.3"},
            {"cripto", "Criptografía", "§7.4"},
            {"grafo", "Grafo de llamadas", "§8"},
            {"taint", "Flujo de datos", "§8"},
            {"superficie", "Superficie de ataque", "§9"},
            {"web", "WebView y Chromium", "§10"},
            {"frameworks", "Frameworks", "§11"},
            {"nativas", "Código nativo", "§12"},
            {"ofuscacion", "Ofuscación y empaquetado", "§13"},
            {"dinamico", "Comportamiento dinámico", "§14"},
            {"trackers", "Trackers y privacidad", "§15"},
            {"ia", "IA y modelos locales", "§16"},
            {"remota", "Configuración remota", "§17"},
            {"fuentes", "Fuentes Java", "§4.5/F3"},
    };

    private static final Map<Profile, String[]> PRIORITY = new HashMap<>();

    static {
        PRIORITY.put(Profile.GRANDE, new String[]{"dex", "identidad", "manifest"});
        PRIORITY.put(Profile.FRAMEWORK, new String[]{"nativas", "frameworks", "dex"});
        PRIORITY.put(Profile.OFUSCADO, new String[]{"ofuscacion", "dex", "identidad"});
    }

    /**
     * Clasifica el APK. Null → SENCILLO. Nunca null ni lanza.
     */
    public static Profile classify(Signals s) {
        try {
            if (s == null) return Profile.SENCILLO;
            if (hasMotor(s)) return Profile.FRAMEWORK;
            if (hasPacker(s) || (s.classes > 50 && s.ratio > 0.30)) return Profile.OFUSCADO;
            if (s.dexCount > 1 || s.classes > 20000) return Profile.GRANDE;
            if (s.classes > 500 || s.strings > 10000) return Profile.MEDIANO;
        } catch (Throwable ignored) {
        }
        return Profile.SENCILLO;
    }

    private static boolean hasMotor(Signals s) {
        if (s.frameworks != null) {
            for (String f : s.frameworks) {
                if (f == null) continue;
                if (f.contains("Unity") || f.contains("Flutter") || f.contains("React Native")) {
                    return true;
                }
            }
        }
        if (s.nativeLibs != null) {
            for (String n : s.nativeLibs) {
                if (n == null) continue;
                String l = n.toLowerCase(Locale.US);
                if (l.contains("libflutter") || l.contains("libapp.so") || l.contains("libunity")
                        || l.contains("libchrome") || l.contains("libchromium")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean hasPacker(Signals s) {
        return s.packers != null && !s.packers.isEmpty();
    }

    /**
     * Checks en orden de prioridad del perfil (null → base). Nunca null.
     */
    public static List<Check> planFor(Profile p) {
        List<Check> out = new ArrayList<>();
        try {
            if (p == null) p = Profile.SENCILLO;
            Set<String> seen = new HashSet<>();
            String[] prio = PRIORITY.get(p);
            if (prio != null) {
                for (String id : prio) {
                    Check c = byId(id);
                    if (c != null && seen.add(id)) out.add(c);
                }
            }
            for (String[] row : CHECKS) {
                if (seen.add(row[0])) out.add(mk(row));
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static Check byId(String id) {
        for (String[] row : CHECKS) {
            if (row[0].equals(id)) return mk(row);
        }
        return null;
    }

    private static Check mk(String[] row) {
        Check c = new Check();
        c.id = row[0];
        c.title = row[1];
        c.rag = row[2];
        return c;
    }

    /** Nota de estrategia por perfil. Nunca null. */
    public static String noteFor(Profile p) {
        try {
            if (p == null) return "";
            switch (p) {
                case GRANDE:
                    return "APK grande: muestreo con topes; los conteos son cotas";
                case FRAMEWORK:
                    return "Motor/framework: la lógica puede estar en nativo; DEX parcial";
                case OFUSCADO:
                    return "Nombres no fiables: interpretar por estructura, no por texto";
                case MEDIANO:
                    return "APK mediano: análisis completo";
                default:
                    return "APK pequeño: análisis completo sin muestreo";
            }
        } catch (Throwable ignored) {
            return "";
        }
    }

    /**
     * Evalúa el plan sobre un informe (null → todo NOT_EXECUTED).
     * Nunca null ni lanza.
     */
    public static Plan build(ReaEngine.ApkReport r) {
        Plan plan = new Plan();
        try {
            if (r == null) {
                for (Check c : planFor(Profile.SENCILLO)) plan.checks.add(state(c.id,
                        State.NOT_EXECUTED, "-"));
                plan.note = noteFor(Profile.SENCILLO);
                return plan;
            }
            Signals s = signalsOf(r);
            plan.profile = classify(s);
            plan.note = noteFor(plan.profile);
            Map<String, List<ClassRoles.Role>> roles = null;
            for (Check c : planFor(plan.profile)) {
                if ("cripto".equals(c.id) || "web".equals(c.id)) {
                    if (roles == null) {
                        roles = ClassRoles.assign(r.graph, r.superMap, null);
                    }
                }
                plan.checks.add(eval(c.id, r, roles));
            }
        } catch (Throwable ignored) {
        }
        return plan;
    }

    private static Signals signalsOf(ReaEngine.ApkReport r) {
        Signals s = new Signals();
        s.dexCount = r.dexFiles == null ? 0 : r.dexFiles.size();
        s.classes = r.totalClasses;
        s.strings = r.totalStrings;
        s.ratio = r.obfuscatedRatio;
        s.frameworks = r.frameworks;
        s.nativeLibs = r.nativeLibs;
        s.packers = r.packers;
        return s;
    }

    private static CheckState state(String id, State st, String detail) {
        CheckState c = new CheckState();
        c.id = id;
        c.state = st;
        c.detail = detail == null || detail.isEmpty() ? "-" : detail;
        return c;
    }

    private static CheckState eval(String id, ReaEngine.ApkReport r,
            Map<String, List<ClassRoles.Role>> roles) {
        if ("identidad".equals(id)) {
            if (r.sha256 != null && r.sha256.length() >= 32 && r.fileSize > 0) {
                return state(id, State.FOUND, r.sha256.substring(0, 8) + "… " + r.fileSize + " B");
            }
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin hash/tamaño");
        }
        if ("manifest".equals(id)) {
            int comps = r.manifestActivities + r.manifestServices + r.manifestReceivers
                    + r.manifestProviders;
            int perms = r.manifestPerms == null ? 0 : r.manifestPerms.size();
            if (perms > 0 || comps > 0 || (r.packageName != null && !"?".equals(r.packageName))) {
                return state(id, State.FOUND, perms + " permisos, " + comps + " componentes");
            }
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin manifest");
        }
        if ("recursos".equals(id)) {
            if (r.arscStringCount > 0 || r.resCount > 0 || r.assetCount > 0) {
                if (r.arscTruncated) return state(id, State.PARTIAL, "arsc muestra");
                return state(id, State.FOUND, r.arscStringCount + " arsc");
            }
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin recursos");
        }
        if ("dex".equals(id)) {
            if (r.totalClasses > 0) {
                if (hasTopes(r)) return state(id, State.PARTIAL, r.totalClasses + " clases, topes");
                return state(id, State.FOUND, r.totalClasses + " clases");
            }
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin dex");
        }
        if ("apis".equals(id)) {
            if (!empty(r.suspiciousApis) || !empty(r.usedPerms) || !empty(r.suspCalls)) {
                int a = r.suspiciousApis == null ? 0 : r.suspiciousApis.size();
                int c = r.suspCalls == null ? 0 : r.suspCalls.size();
                return state(id, State.FOUND, a + " apis, " + c + " llamadas");
            }
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin APIs sensibles");
        }
        if ("red".equals(id)) {
            if (r.urlTotal > 0 || r.ipTotal > 0) {
                return state(id, State.FOUND, r.urlTotal + " urls");
            }
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin red");
        }
        if ("secretos".equals(id)) {
            if (r.secretTotal + r.secretHighTotal > 0) {
                return state(id, State.FOUND, r.secretHighTotal + " alta");
            }
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin secretos");
        }
        if ("cripto".equals(id)) {
            String ev = roleEvidence(roles, "cripto");
            if (ev != null) return state(id, State.FOUND, ev);
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin cripto");
        }
        if ("grafo".equals(id)) {
            if (r.graph != null && r.graph.edgeCount() > 0) {
                if (r.graph.truncated()) {
                    return state(id, State.PARTIAL, r.graph.edgeCount() + " aristas, tope");
                }
                return state(id, State.FOUND, r.graph.edgeCount() + " aristas");
            }
            return state(id, State.NOT_FOUND_IN_SCOPE, "grafo vacío");
        }
        if ("taint".equals(id)) return state(id, State.UNSUPPORTED, "técnica no implementada");
        if ("superficie".equals(id)) {
            if (!empty(r.manifestExported) || !empty(r.manifestLinks)) {
                return state(id, State.FOUND, r.manifestExported.size() + " exp");
            }
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin superficie");
        }
        if ("web".equals(id)) {
            String ev = roleEvidence(roles, "web");
            if (ev != null) return state(id, State.FOUND, ev);
            if (hasChromium(r)) return state(id, State.FOUND, "chromium");
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin web");
        }
        if ("frameworks".equals(id)) {
            if (!empty(r.frameworks)) return state(id, State.FOUND, join(r.frameworks, 3));
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin frameworks");
        }
        if ("nativas".equals(id)) {
            if (empty(r.nativeLibs)) return state(id, State.NOT_FOUND_IN_SCOPE, "sin .so");
            return state(id, State.PARTIAL, "inventario ELF, sin desensamblado");
        }
        if ("ofuscacion".equals(id)) {
            if (!empty(r.packers)) return state(id, State.FOUND, "packer " + r.packers.get(0));
            if (r.totalClasses > 50 && r.obfuscatedRatio > 0.30) {
                return state(id, State.FOUND, "ratio " + fmt2(r.obfuscatedRatio));
            }
            return state(id, State.NOT_FOUND_IN_SCOPE, "ratio " + fmt2(r.obfuscatedRatio));
        }
        if ("dinamico".equals(id)) return state(id, State.UNSUPPORTED, "alcance estático");
        if ("trackers".equals(id)) {
            if (!empty(r.trackers)) return state(id, State.FOUND, join(r.trackers, 3));
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin trackers");
        }
        if ("ia".equals(id)) {
            if (r.libAppSize > 0 || !empty(r.libAppMarkers) || hasLlama(r)) {
                return state(id, State.FOUND, "ia local");
            }
            return state(id, State.NOT_FOUND_IN_SCOPE, "sin ia local");
        }
        if ("remota".equals(id)) return state(id, State.UNSUPPORTED, "sin módulo");
        if ("fuentes".equals(id)) return state(id, State.NOT_EXECUTED, "solo visor/extracción");
        return state(id, State.INCONCLUSIVE, "-");
    }

    private static boolean empty(List<String> l) {
        return l == null || l.isEmpty();
    }

    private static boolean hasTopes(ReaEngine.ApkReport r) {
        if (r.dexNotes == null) return false;
        for (String n : r.dexNotes) {
            if (n == null) continue;
            String l = n.toLowerCase(Locale.US);
            if (l.contains("tope") || l.contains("parcial")) return true;
        }
        return false;
    }

    private static String roleEvidence(Map<String, List<ClassRoles.Role>> roles, String label) {
        if (roles == null) return null;
        for (Map.Entry<String, List<ClassRoles.Role>> en : roles.entrySet()) {
            if (en.getValue() == null) continue;
            for (ClassRoles.Role role : en.getValue()) {
                if (role != null && label.equals(role.label) && !role.evidence.isEmpty()) {
                    return role.evidence.get(0);
                }
            }
        }
        return null;
    }

    private static boolean hasChromium(ReaEngine.ApkReport r) {
        if (r.nativeLibs != null) {
            for (String n : r.nativeLibs) {
                if (n == null) continue;
                String l = n.toLowerCase(Locale.US);
                if (l.contains("libchrome") || l.contains("libchromium")) return true;
            }
        }
        if (r.topPackages != null) {
            for (String p : r.topPackages) {
                if (p != null && p.contains("org/chromium")) return true;
            }
        }
        return false;
    }

    private static boolean hasLlama(ReaEngine.ApkReport r) {
        if (r.nativeLibs == null) return false;
        for (String n : r.nativeLibs) {
            if (n != null && n.toLowerCase(Locale.US).contains("llama")) return true;
        }
        return false;
    }

    private static String join(List<String> items, int n) {
        StringBuilder sb = new StringBuilder();
        int k = Math.min(n, items.size());
        for (int i = 0; i < k; i++) {
            if (i > 0) sb.append(", ");
            String v = items.get(i);
            sb.append(v == null ? "?" : v);
        }
        if (items.size() > k) sb.append("…");
        return sb.toString();
    }

    private static String fmt2(double v) {
        try {
            return String.format(Locale.US, "%.2f", v);
        } catch (Throwable ignored) {
            return "?";
        }
    }

    /** Mapa id→título para rótulos. Nunca null. */
    public static Map<String, String> titles() {
        Map<String, String> m = new LinkedHashMap<>();
        for (String[] row : CHECKS) m.put(row[0], row[1]);
        return m;
    }
}
