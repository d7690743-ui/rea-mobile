package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * PHANTOM nativo: JNI dinámico (RegisterNatives). ALFA ya resuelve el JNI
 * estático (símbolos Java_paquete); aquí se buscan best-effort los métodos
 * registrados en runtime: pares nombre+firma en los bytes ya cargados
 * (head/tail del .so, sin retener nada nuevo salvo ≤40 candidatos).
 * Unión con métodos propios por nombre (LOW, declarado). Nunca lanza.
 */
public final class PhantomJni {
    private PhantomJni() {
    }

    public static final int MAX_CANDIDATES = 40;
    public static final int MAX_STR_LEN = 128;
    public static final int MIN_STR_LEN = 4;

    /** Método dinámico candidato con su librería y llamadores. Nunca lanza. */
    public static class DynLink {
        public String lib = "?";
        public String method = "?";
        public String sig = "";
        public List<String> callers = new ArrayList<>();
    }

    /**
     * Rastrea pares nombre+firma JNI en head/tail (ventana deslizante, sin
     * listas intermedias grandes). Formato: "nombre" o "nombre|firma".
     * Nunca null ni lanza.
     */
    public static List<String> scanStrings(byte[] head, byte[] tail) {
        return scanStrings(head, tail, MAX_CANDIDATES);
    }

    /** Variante con tope inyectable (tests). Nunca null ni lanza. */
    static List<String> scanStrings(byte[] head, byte[] tail, int cap) {
        List<String> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        try {
            int lim = cap <= 0 ? MAX_CANDIDATES : Math.min(cap, 200);
            List<String> window = new ArrayList<>();
            scanBuf(head, window, out, seen, lim);
            scanBuf(tail, window, out, seen, lim);
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static void scanBuf(byte[] buf, List<String> window, List<String> out,
                                Set<String> seen, int lim) {
        try {
            if (buf == null || out.size() >= lim) return;
            StringBuilder cur = new StringBuilder();
            for (int i = 0; i < buf.length && out.size() < lim; i++) {
                int c = buf[i] & 0xFF;
                if (c >= 32 && c < 127) {
                    if (cur.length() < MAX_STR_LEN) cur.append((char) c);
                } else {
                    if (cur.length() >= MIN_STR_LEN) {
                        consider(cur.toString(), window, out, seen, lim);
                    }
                    cur.setLength(0);
                }
            }
            if (cur.length() >= MIN_STR_LEN && out.size() < lim) {
                consider(cur.toString(), window, out, seen, lim);
            }
        } catch (Throwable ignored) {
        }
    }

    private static void consider(String s, List<String> window, List<String> out,
                                 Set<String> seen, int lim) {
        try {
            if (isJniSig(s)) {
                String name = null;
                for (int i = window.size() - 1; i >= 0; i--) {
                    String w = window.get(i);
                    if (isMethodName(w)) {
                        name = w;
                        break;
                    }
                }
                String cand = name == null ? s : name + "|" + s;
                if (seen.add(cand) && out.size() < lim) out.add(cand);
            } else if (isMethodName(s)) {
                window.add(s);
                if (window.size() > 4) window.remove(0);
            }
        } catch (Throwable ignored) {
        }
    }

    /** "(...)" con tipos JNI plausibles. Nunca lanza. */
    static boolean isJniSig(String s) {
        try {
            if (s == null || s.length() < 3 || s.charAt(0) != '(') return false;
            int close = s.indexOf(')');
            if (close < 1 || close > 64) return false;
            for (int i = 1; i < close; i++) {
                char c = s.charAt(i);
                if ("ZBCSIJFDV[L".indexOf(c) < 0 && c != ';' && c != '/'
                        && c != '_' && c != '$' && !(c >= 'a' && c <= 'z')
                        && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9')) return false;
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /** Identificador Java plausible (no ruta ni paquete). Nunca lanza. */
    static boolean isMethodName(String s) {
        try {
            if (s == null || s.length() < 3 || s.length() > 64) return false;
            if (s.indexOf('/') >= 0 || s.indexOf('.') >= 0 || s.indexOf(' ') >= 0) return false;
            char c0 = s.charAt(0);
            if (!(c0 == '_' || c0 == '$' || (c0 >= 'a' && c0 <= 'z')
                    || (c0 >= 'A' && c0 <= 'Z'))) return false;
            for (int i = 1; i < s.length(); i++) {
                char c = s.charAt(i);
                if (!(c == '_' || c == '$' || (c >= 'a' && c <= 'z')
                        || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) return false;
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Une candidatos dinámicos con llamadores propios (por nombre de método,
     * una pasada por el grafo). Tope 30 enlaces. Nunca null ni lanza.
     */
    public static List<DynLink> link(List<AlfaElf.ElfInfo> elfs, RefGraph graph) {
        List<DynLink> out = new ArrayList<>();
        try {
            if (elfs == null || elfs.isEmpty() || graph == null) return out;
            List<RefGraph.RefEdge> edges = graph.edges();
            for (AlfaElf.ElfInfo e : elfs) {
                if (e == null || e.jniDynamic == null) continue;
                for (String cand : e.jniDynamic) {
                    if (cand == null || out.size() >= 30) break;
                    String name = cand;
                    String sig = "";
                    int bar = cand.indexOf('|');
                    if (bar > 0) {
                        name = cand.substring(0, bar);
                        sig = cand.substring(bar + 1);
                    }
                    if (!isMethodName(name)) continue;
                    DynLink l = new DynLink();
                    l.lib = e.name == null ? "?" : e.name;
                    l.method = name;
                    l.sig = sig;
                    String suffix = "->" + name;
                    for (RefGraph.RefEdge re : edges) {
                        if (re == null || re.caller == null) continue;
                        if (re.caller.endsWith(suffix) && l.callers.size() < 3) {
                            l.callers.add(re.caller);
                        }
                    }
                    out.add(l);
                }
                if (out.size() >= 30) break;
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Una línea por enlace para el informe. Nunca lanza. */
    public static String summarize(DynLink l) {
        try {
            if (l == null) return "?";
            StringBuilder sb = new StringBuilder();
            sb.append(l.lib).append(' ').append(l.method);
            if (l.sig != null && !l.sig.isEmpty()) sb.append(l.sig);
            if (l.callers.isEmpty()) sb.append(" [sin llamador propio]");
            else sb.append(" <= ").append(l.callers.get(0));
            return sb.toString();
        } catch (Throwable ignored) {
            return "?";
        }
    }
}
