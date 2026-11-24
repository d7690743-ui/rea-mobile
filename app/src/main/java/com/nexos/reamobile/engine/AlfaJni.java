package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.List;

/**
 * ALFA-1: puente JNI. Decodifica exportaciones {@code Java_*} a su clase y
 * método Java y las enlaza con llamadas reales del RefGraph (callee nativo
 * invocado desde código). Utilidad estática sin estado. Java puro.
 * Nunca lanza.
 */
public final class AlfaJni {
    private AlfaJni() {
    }

    public static final int MAX_LINKS = 100;

    /** Exportación JNI enlazada (o no) con el grafo. Nunca lanza. */
    public static class JniLink {
        public String symbol = "?";
        public String javaClass = "?";
        public String javaMethod = "?";
        /** Llamadores en el grafo (vacío = sin llamadas detectadas). */
        public List<String> callers = new ArrayList<>();
    }

    /**
     * Decodifica "Java_paquete_Clase_metodo" (con escapes _1 _2 _3 _0XXXX
     * y sufijo de sobrecarga "__firma") a ["Lpaquete/Clase;", "metodo"].
     * Null si no es un símbolo JNI válido. Nunca lanza.
     */
    public static String[] decode(String symbol) {
        try {
            if (symbol == null || !symbol.startsWith("Java_") || symbol.length() <= 5) return null;
            String body = symbol.substring(5);
            int over = body.indexOf("__");
            if (over >= 0) body = body.substring(0, over);
            if (body.isEmpty()) return null;
            StringBuilder cur = new StringBuilder();
            List<String> parts = new ArrayList<>();
            for (int i = 0; i < body.length(); i++) {
                char c = body.charAt(i);
                if (c != '_') {
                    cur.append(c);
                    continue;
                }
                if (i + 1 >= body.length()) {
                    parts.add(cur.toString());
                    cur.setLength(0);
                    continue;
                }
                char n = body.charAt(i + 1);
                if (n == '1') {
                    cur.append('_');
                    i++;
                } else if (n == '2') {
                    cur.append(';');
                    i++;
                } else if (n == '3') {
                    cur.append('[');
                    i++;
                } else if (n == '0' && i + 5 < body.length()) {
                    int cp = Integer.parseInt(body.substring(i + 2, i + 6), 16);
                    cur.append((char) cp);
                    i += 5;
                } else {
                    parts.add(cur.toString());
                    cur.setLength(0);
                }
            }
            parts.add(cur.toString());
            if (parts.size() < 2) return null;
            StringBuilder cls = new StringBuilder("L");
            for (int i = 0; i < parts.size() - 1; i++) {
                if (i > 0) cls.append('/');
                if (parts.get(i).isEmpty()) return null;
                cls.append(parts.get(i));
            }
            cls.append(';');
            String method = parts.get(parts.size() - 1);
            if (method.isEmpty()) return null;
            return new String[]{cls.toString(), method};
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Enlaza símbolos JNI con el grafo: llamadores de "Lcls;->m".
     * Tope MAX_LINKS. Nunca null ni lanza.
     */
    public static List<JniLink> link(List<String> symbols, RefGraph graph) {
        List<JniLink> out = new ArrayList<>();
        try {
            if (symbols == null) return out;
            for (String s : symbols) {
                if (out.size() >= MAX_LINKS) break;
                if (s == null) continue;
                String[] dec = decode(s);
                if (dec == null) continue;
                JniLink l = new JniLink();
                l.symbol = s;
                l.javaClass = dec[0];
                l.javaMethod = dec[1];
                if (graph != null) {
                    List<String> callers = graph.callersOf(dec[0] + "->" + dec[1]);
                    for (int i = 0; i < callers.size() && i < 5; i++) {
                        l.callers.add(callers.get(i));
                    }
                }
                out.add(l);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }
}
