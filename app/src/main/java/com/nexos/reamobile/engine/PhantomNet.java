package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * PHANTOM red: contratos endpoint+método+payload por llamador. ALFA-3 da
 * cadena→método→permiso; aquí se añade verbo HTTP, content-type y pistas de
 * payload desde los literales que cargan los mismos métodos (evidencia
 * citada; ausencia declarada, nunca inventada). Nunca lanza.
 */
public final class PhantomNet {
    private PhantomNet() {
    }

    public static final int MAX_CONTRACTS = 30;
    public static final int MAX_USERS = 3;
    public static final int MAX_HINTS = 3;

    private static final String[] VERBS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"};
    private static final String[] CT_HINTS = {"application/json", "application/x-www-form-urlencoded",
            "multipart/form-data", "text/xml", "application/xml", "application/octet-stream"};
    private static final String[] NET_PREFIXES = {"Ljava/net/", "Ljavax/net/",
            "Lokhttp3/", "Lcom/squareup/okhttp/", "Lcom/android/volley/",
            "Lretrofit2/", "Lorg/chromium/net/", "Lorg/apache/http/",
            "Landroid/webkit/"};

    /** Contrato de red observado estáticamente. Nunca lanza. */
    public static class Contract {
        public String url = "?";
        public String host = "?";
        public String origen = "?";
        public List<String> users = new ArrayList<>();
        public List<String> verbs = new ArrayList<>();
        public String contentType = "";
        public List<String> payloadHints = new ArrayList<>();
        public String permiso = "?";
        public boolean permisoDeclarado;
    }

    /**
     * Construye contratos para las URLs del informe. Una pasada por URL
     * sobre los índices OMEGA (sin re-parsear). Nunca null ni lanza.
     */
    public static List<Contract> contracts(List<String> urls, Map<String, String> urlOrigin,
                                           StringRefs stringRefs, RefGraph graph,
                                           List<String> manifestPerms,
                                           Map<String, String> callerPerm) {
        return contracts(urls, urlOrigin, stringRefs, graph, manifestPerms, callerPerm, null);
    }

    /**
     * Variante P2.3 con endpoints nativos (.so) como contratos sin llamador
     * pero con origen. Nunca null ni lanza.
     */
    public static List<Contract> contracts(List<String> urls, Map<String, String> urlOrigin,
                                           StringRefs stringRefs, RefGraph graph,
                                           List<String> manifestPerms,
                                           Map<String, String> callerPerm,
                                           List<AlfaElf.ElfInfo> elfs) {
        List<Contract> out = new ArrayList<>();
        try {
            Set<String> shortPerms = AlfaCorr.shortNames(manifestPerms);
            if (urls != null && stringRefs != null) {
                for (String u : urls) {
                    if (u == null || u.isEmpty() || out.size() >= MAX_CONTRACTS) break;
                    Contract c = new Contract();
                    c.url = u;
                    c.host = AlfaCorr.hostOf(u);
                    if (urlOrigin != null && urlOrigin.get(u) != null) {
                        c.origen = urlOrigin.get(u);
                    }
                    List<String> users = stringRefs.usersOf(u);
                    if (users.isEmpty() && graph != null) {
                        users = stringRefs.usersOfContaining(u, 25);
                    }
                    Set<String> seen = new LinkedHashSet<>();
                    for (String m : users) {
                        if (m == null || !seen.add(m)) continue;
                        if (c.users.size() >= MAX_USERS) break;
                        c.users.add(m);
                    }
                    observeLiterals(c, stringRefs);
                    applyPerm(c, callerPerm, shortPerms, graph);
                    out.add(c);
                }
            }
            if (elfs != null) {
                Set<String> seenU = new LinkedHashSet<>();
                for (AlfaElf.ElfInfo e : elfs) {
                    if (e == null || e.soUrls == null) continue;
                    for (String u : e.soUrls) {
                        if (u == null || out.size() >= MAX_CONTRACTS) break;
                        if (!seenU.add(u)) continue;
                        Contract c = new Contract();
                        c.url = u;
                        c.host = AlfaCorr.hostOf(u);
                        c.origen = "so:" + shortLib(e.name);
                        out.add(c);
                    }
                    if (out.size() >= MAX_CONTRACTS) break;
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Métodos que tocan APIs de red (P2.3: para PARCIAL de grupo cuando no
     * hay URL atribuida). Una pasada al grafo, tope 2000. Nunca null.
     */
    public static Set<String> touchers(RefGraph graph) {
        Set<String> out = new LinkedHashSet<>();
        try {
            if (graph == null) return out;
            for (RefGraph.RefEdge e : graph.edges()) {
                if (e == null || e.caller == null || e.callee == null) continue;
                if (out.size() >= 2000) break;
                for (String p : NET_PREFIXES) {
                    if (e.callee.startsWith(p)) {
                        out.add(e.caller);
                        break;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static String shortLib(String name) {
        try {
            if (name == null) return "?";
            int s = name.lastIndexOf('/');
            return s < 0 ? name : name.substring(s + 1);
        } catch (Throwable ignored) {
            return "?";
        }
    }

    private static void observeLiterals(Contract c, StringRefs refs) {
        try {
            Set<String> lits = new LinkedHashSet<>();
            for (String m : c.users) {
                for (String lit : refs.literalsOf(m, 50)) {
                    if (lit != null) lits.add(lit);
                }
            }
            for (String v : VERBS) {
                if (lits.contains(v) && !c.verbs.contains(v)) c.verbs.add(v);
            }
            for (String lit : lits) {
                if (lit == null) continue;
                if (c.contentType.isEmpty()) {
                    for (String ct : CT_HINTS) {
                        if (lit.contains(ct)) {
                            c.contentType = ct;
                            break;
                        }
                    }
                }
                if (c.payloadHints.size() < MAX_HINTS && isPayloadHint(lit, c.url)) {
                    c.payloadHints.add(trim(lit));
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void applyPerm(Contract c, Map<String, String> callerPerm,
                                  Set<String> shortPerms, RefGraph graph) {
        try {
            for (String m : c.users) {
                String hit = callerPerm == null ? null : callerPerm.get(m);
                if (hit == null && graph != null) {
                    for (String callee : graph.calleesOf(m)) {
                        String p = PermApiTable.permissionFor(callee);
                        if (p != null) {
                            hit = p + "|" + callee;
                            break;
                        }
                    }
                }
                if (hit != null) {
                    int bar = hit.indexOf('|');
                    c.permiso = bar < 0 ? hit : hit.substring(0, bar);
                    c.permisoDeclarado = shortPerms != null && shortPerms.contains(c.permiso);
                    return;
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /** Literal con pinta de cuerpo JSON/form (no la propia URL). Nunca lanza. */
    static boolean isPayloadHint(String lit, String url) {
        try {
            if (lit == null || lit.length() < 6 || lit.length() > 300) return false;
            if (url != null && lit.contains(url)) return false;
            String t = lit.trim();
            if (t.startsWith("{") || t.startsWith("[")) return true;
            return t.contains("\":") || t.contains("=\"") || t.contains("%7B");
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String trim(String s) {
        try {
            if (s == null) return "";
            String t = s.replace('\n', ' ').trim();
            return t.length() > 120 ? t.substring(0, 120) + "…" : t;
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** Una línea por contrato para el informe. Nunca lanza. */
    public static String summarize(Contract c) {
        try {
            if (c == null) return "?";
            StringBuilder sb = new StringBuilder();
            sb.append(c.host);
            sb.append(" metodo=").append(c.verbs.isEmpty() ? "?" : join(c.verbs));
            if (!c.contentType.isEmpty()) sb.append(" tipo=").append(c.contentType);
            sb.append(" permiso=").append(c.permiso);
            if (c.users.isEmpty()) {
                sb.append(c.origen != null && c.origen.startsWith("so:")
                        ? " [origen nativo]" : " [sin llamador]");
            } else {
                sb.append(" <=").append(c.users.get(0));
            }
            if (!c.payloadHints.isEmpty()) sb.append(" pista=").append(c.payloadHints.get(0));
            sb.append(" (").append(c.origen).append(')');
            return sb.toString();
        } catch (Throwable ignored) {
            return "?";
        }
    }

    private static String join(List<String> items) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(items.get(i));
        }
        return sb.toString();
    }
}
