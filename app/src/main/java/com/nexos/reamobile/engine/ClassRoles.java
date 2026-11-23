package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Fase C: roles por clase. Agrega por llamador las llamadas sensibles del
 * grafo (los mismos patrones de DexParser, con herencia por supers) y los
 * resume en etiquetas cortas con evidencia. Utilidad estática sin estado,
 * como LogicNet. Nunca lanza.
 */
public final class ClassRoles {
    private ClassRoles() {
    }

    public static final int MAX_CLASSES = 200;
    public static final int MAX_EVIDENCE = 3;

    /** Prefijo suspicious → rol. Cubre la tabla de DexParser. */
    private static final String[][] ROLES = {
            {"Ldalvik/system/DexClassLoader;", "carga-dinamica"},
            {"Ldalvik/system/PathClassLoader;", "carga-dinamica"},
            {"Ldalvik/system/InMemoryDexClassLoader;", "carga-dinamica"},
            {"Ljava/lang/Runtime;", "proceso"},
            {"Ljava/lang/ProcessBuilder;", "proceso"},
            {"Ljava/lang/reflect/", "reflexion"},
            {"Ljavax/crypto/", "cripto"},
            {"Ljava/security/", "cripto"},
            {"Landroid/telephony/", "telefonia"},
            {"Landroid/location/", "ubicacion"},
            {"Ljava/net/URL;", "red"},
            {"Ljava/net/HttpURLConnection;", "red"},
            {"Lokhttp3/", "red"},
            {"Lorg/apache/http/", "red"},
            {"Landroid/webkit/WebView;", "web"},
            {"Ljava/lang/System;", "nativa"},
            {"Landroid/app/admin/DevicePolicyManager;", "admin"},
            {"Landroid/accessibilityservice/", "accesibilidad"},
            {"Landroid/provider/ContactsContract;", "contactos"},
            {"Landroid/hardware/fingerprint/", "biometrico"},
            {"Landroid/hardware/biometrics/", "biometrico"},
    };

    public static class Role {
        public String label = "sistema";
        public int count;
        public List<String> evidence = new ArrayList<>();
    }

    /**
     * Rol para una etiqueta suspicious (prefijo). "sistema" si no casa:
     * nunca null. Nunca lanza.
     */
    public static String roleFor(String label) {
        try {
            if (label != null) {
                for (String[] e : ROLES) {
                    if (label.startsWith(e[0])) return e[1];
                }
            }
        } catch (Throwable ignored) {
        }
        return "sistema";
    }

    /**
     * Roles por clase llamadora del grafo, en orden de aparición (tope
     * MAX_CLASSES). pkgSlash filtra propias ("com/x/"); null o vacío =
     * todas. Roles por conteo descendente, evidencia hasta MAX_EVIDENCE.
     * Nunca null ni lanza.
     */
    public static Map<String, List<Role>> assign(RefGraph g, Map<String, String> supers,
            String pkgSlash) {
        Map<String, List<Role>> out = new LinkedHashMap<>();
        try {
            if (g == null) return out;
            boolean ownOnly = pkgSlash != null && !pkgSlash.isEmpty();
            String prefix = ownOnly ? "L" + pkgSlash : null;
            Map<String, Map<String, Role>> acc = new LinkedHashMap<>();
            for (RefGraph.RefEdge e : g.edges()) {
                if (e == null || e.caller == null || e.callee == null) continue;
                String callerCls = RefGraph.split(e.caller)[0];
                if ("?".equals(callerCls)) continue;
                if (ownOnly && !callerCls.startsWith(prefix)) continue;
                String[] cal = RefGraph.split(e.callee);
                String label = DexParser.suspiciousLabelWithSupers(cal[0], cal[1], supers);
                if (label == null) continue;
                String role = roleFor(label);
                Map<String, Role> byRole = acc.get(callerCls);
                if (byRole == null) {
                    if (acc.size() >= MAX_CLASSES) continue;
                    byRole = new LinkedHashMap<>();
                    acc.put(callerCls, byRole);
                }
                Role r = byRole.get(role);
                if (r == null) {
                    r = new Role();
                    r.label = role;
                    byRole.put(role, r);
                }
                r.count++;
                if (r.evidence.size() < MAX_EVIDENCE && !r.evidence.contains(e.callee)) {
                    r.evidence.add(e.callee);
                }
            }
            for (Map.Entry<String, Map<String, Role>> en : acc.entrySet()) {
                List<Role> roles = new ArrayList<>(en.getValue().values());
                Collections.sort(roles, new Comparator<Role>() {
                    @Override
                    public int compare(Role a, Role b) {
                        return b.count - a.count;
                    }
                });
                out.put(en.getKey(), roles);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }
}
