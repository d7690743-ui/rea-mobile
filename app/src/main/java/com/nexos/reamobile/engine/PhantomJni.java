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

    public static final int MAX_CANDIDATES = 100;
    public static final int MAX_SO_URLS = 40;
    public static final int MAX_STR_LEN = 128;
    public static final int MIN_STR_LEN = 4;

    /** Resultado del rastreo .so en una pasada (P2.6). Nunca lanza. */
    public static class SoResult {
        public List<String> jni = new ArrayList<>();
        public List<String> urls = new ArrayList<>();
    }

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
        try {
            SoResult r = scanSo(head, tail, cap, 0);
            return r == null ? new ArrayList<String>() : r.jni;
        } catch (Throwable ignored) {
            return new ArrayList<String>();
        }
    }

    /**
     * Una pasada sobre head/tail: pares JNI + URLs nativas (P2.3/P2.6).
     * Autolimitado; ventanilla mínima transitoria. Nunca null ni lanza.
     */
    public static SoResult scanSo(byte[] head, byte[] tail) {
        return scanSo(head, tail, MAX_CANDIDATES, MAX_SO_URLS);
    }

    /** Variante con topes inyectables (tests). Nunca null ni lanza. */
    static SoResult scanSo(byte[] head, byte[] tail, int capJni, int capUrls) {
        try {
            StreamScan s = new StreamScan(capJni, capUrls);
            s.feed(head, 0, head == null ? 0 : head.length);
            s.feed(tail, 0, tail == null ? 0 : tail.length);
            s.finish();
            return s.result();
        } catch (Throwable ignored) {
            return new SoResult();
        }
    }

    /**
     * Escáner incremental: alimenta trozos (p. ej. el .so entero durante
     * su lectura) y conserva estado entre trozos, incluidas cadenas
     * cortadas en el borde. Retiene solo candidatos (≤topes). Nunca lanza.
     */
    public static class StreamScan {
        private final SoResult r = new SoResult();
        private final Set<String> seenJ = new LinkedHashSet<>();
        private final Set<String> seenU = new LinkedHashSet<>();
        private final List<String> window = new ArrayList<>();
        private final StringBuilder cur = new StringBuilder();
        private final int limJ;
        private final int limU;

        public StreamScan(int capJni, int capUrls) {
            int lj = capJni <= 0 ? MAX_CANDIDATES : Math.min(capJni, 300);
            int lu = capUrls < 0 ? 0 : Math.min(capUrls, 200);
            limJ = lj;
            limU = lu;
        }

        public StreamScan() {
            this(MAX_CANDIDATES, MAX_SO_URLS);
        }

        /** Alimenta bytes (null-seguro). Nunca lanza. */
        public void feed(byte[] buf, int off, int len) {
            try {
                if (buf == null || len <= 0) return;
                int start = Math.max(0, off);
                int end = Math.min(buf.length, start + len);
                for (int i = start; i < end; i++) {
                    if (r.jni.size() >= limJ && r.urls.size() >= limU) return;
                    int c = buf[i] & 0xFF;
                    if (c >= 32 && c < 127) {
                        if (cur.length() < MAX_STR_LEN) cur.append((char) c);
                    } else {
                        if (cur.length() >= MIN_STR_LEN) {
                            consider(cur.toString(), window, r, seenJ, seenU, limJ, limU);
                        }
                        cur.setLength(0);
                    }
                }
            } catch (Throwable ignored) {
            }
        }

        /** Cierra la cadena pendiente. Nunca lanza. */
        public void finish() {
            try {
                if (cur.length() >= MIN_STR_LEN) {
                    consider(cur.toString(), window, r, seenJ, seenU, limJ, limU);
                }
                cur.setLength(0);
            } catch (Throwable ignored) {
            }
        }

        /** Resultado acumulado. Nunca null ni lanza. */
        public SoResult result() {
            return r;
        }
    }

    private static void consider(String s, List<String> window, SoResult r,
                                 Set<String> seenJ, Set<String> seenU,
                                 int limJ, int limU) {
        try {
            if (r.urls.size() < limU) {
                String u = extractUrl(s);
                if (u != null && seenU.add(u)) r.urls.add(u);
            }
            if (r.jni.size() >= limJ) return;
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
                if (seenJ.add(cand) && r.jni.size() < limJ) r.jni.add(cand);
            } else if (isMethodName(s)) {
                window.add(s);
                if (window.size() > 8) window.remove(0);
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Primera URL http(s) dentro del string, recortada por espacios y
     * comillas. Null si no hay. Nunca lanza.
     */
    static String extractUrl(String s) {
        try {
            if (s == null) return null;
            int i = s.indexOf("https://");
            int j = s.indexOf("http://");
            int k = i >= 0 ? i : j;
            if (i >= 0 && j >= 0) k = Math.min(i, j);
            if (k < 0) return null;
            int e = k;
            while (e < s.length()) {
                char c = s.charAt(e);
                if (c <= 32 || c == '"' || c == '\'' || c == '<' || c == '>'
                        || c == '\\') break;
                e++;
            }
            String u = s.substring(k, e);
            if (u.length() < 12 || u.endsWith("://")) return null;
            return u;
        } catch (Throwable ignored) {
            return null;
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
