package com.nexos.reamobile.engine.auth;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Utilidades JSON mínimas del motor de autenticidad: escape para escritura y
 * lector acotado para importar allowlist/baseline (formato propio).
 * Soporta objetos, arrays, strings (con escapes), números, true/false/null.
 * Topes anti-OOM: 2 MB de entrada, profundidad 16, 20000 valores.
 * Java puro. Nunca lanza.
 */
public final class AuthJson {
    private AuthJson() {
    }

    public static final int MAX_INPUT = 2 * 1024 * 1024;
    public static final int MAX_DEPTH = 16;
    public static final int MAX_VALUES = 20000;

    /** Añade una cadena entrecomillada con escapes. Nunca lanza. */
    public static void quote(StringBuilder sb, String s) {
        try {
            if (sb == null) return;
            if (s == null) {
                sb.append("null");
                return;
            }
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"': sb.append("\\\""); break;
                    case '\\': sb.append("\\\\"); break;
                    case '\n': sb.append("\\n"); break;
                    case '\r': sb.append("\\r"); break;
                    case '\t': sb.append("\\t"); break;
                    default:
                        if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                        else sb.append(c);
                }
            }
            sb.append('"');
        } catch (Throwable ignored) {
        }
    }

    public static void field(StringBuilder sb, String k, String v, boolean first) {
        try {
            if (!first) sb.append(',');
            quote(sb, k == null ? "" : k);
            sb.append(':');
            quote(sb, v == null ? "" : v);
        } catch (Throwable ignored) {
        }
    }

    public static void fieldRaw(StringBuilder sb, String k, String rawJson, boolean first) {
        try {
            if (!first) sb.append(',');
            quote(sb, k == null ? "" : k);
            sb.append(':');
            sb.append(rawJson == null || rawJson.isEmpty() ? "null" : rawJson);
        } catch (Throwable ignored) {
        }
    }

    public static void strList(StringBuilder sb, String k, List<String> items) {
        try {
            sb.append(",\"").append(k == null ? "" : k).append("\":[");
            if (items != null) {
                for (int i = 0; i < items.size(); i++) {
                    if (i > 0) sb.append(',');
                    quote(sb, items.get(i));
                }
            }
            sb.append(']');
        } catch (Throwable ignored) {
        }
    }

    /** Resultado del lector: valor raíz + error (null si OK). */
    public static class Parsed {
        public Object root;
        public String error;
    }

    /** Lee un documento JSON acotado. Nunca lanza. */
    public static Parsed parse(String text) {
        Parsed r = new Parsed();
        try {
            if (text == null || text.isEmpty()) {
                r.error = "documento vacío";
                return r;
            }
            if (text.length() > MAX_INPUT) {
                r.error = "documento mayor de 2 MB";
                return r;
            }
            Reader rd = new Reader(text);
            skipWs(rd);
            r.root = readValue(rd, 0);
            if (rd.fail != null) {
                r.error = rd.fail;
                r.root = null;
                return r;
            }
            skipWs(rd);
            if (rd.pos != rd.buf.length) {
                r.error = "contenido tras el valor raíz";
                r.root = null;
            }
        } catch (Throwable t) {
            r.error = "fallo leyendo JSON";
            r.root = null;
        }
        return r;
    }

    private static class Reader {
        final char[] buf;
        int pos;
        int count;
        String fail;

        Reader(String s) {
            buf = s.toCharArray();
        }
    }

    private static void skipWs(Reader rd) {
        while (rd.pos < rd.buf.length) {
            char c = rd.buf[rd.pos];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') rd.pos++;
            else break;
        }
    }

    @SuppressWarnings("unchecked")
    private static Object readValue(Reader rd, int depth) {
        if (rd.fail != null) return null;
        if (++rd.count > MAX_VALUES) {
            rd.fail = "demasiados valores";
            return null;
        }
        if (depth > MAX_DEPTH) {
            rd.fail = "demasiada profundidad";
            return null;
        }
        skipWs(rd);
        if (rd.pos >= rd.buf.length) {
            rd.fail = "fin inesperado";
            return null;
        }
        char c = rd.buf[rd.pos];
        if (c == '{') return readObject(rd, depth);
        if (c == '[') return readArray(rd, depth);
        if (c == '"') return readString(rd);
        if (c == 't' || c == 'f') return readBool(rd);
        if (c == 'n') return readNull(rd);
        if (c == '-' || (c >= '0' && c <= '9')) return readNumber(rd);
        rd.fail = "valor inesperado en " + rd.pos;
        return null;
    }

    private static Map<String, Object> readObject(Reader rd, int depth) {
        Map<String, Object> out = new LinkedHashMap<>();
        rd.pos++; // {
        skipWs(rd);
        if (rd.pos < rd.buf.length && rd.buf[rd.pos] == '}') {
            rd.pos++;
            return out;
        }
        int guard = 0;
        while (rd.fail == null) {
            if (guard++ > MAX_VALUES) {
                rd.fail = "objeto demasiado grande";
                return out;
            }
            skipWs(rd);
            if (rd.pos >= rd.buf.length || rd.buf[rd.pos] != '"') {
                rd.fail = "clave esperada en " + rd.pos;
                return out;
            }
            String k = readString(rd);
            skipWs(rd);
            if (rd.pos >= rd.buf.length || rd.buf[rd.pos] != ':') {
                rd.fail = "':' esperado en " + rd.pos;
                return out;
            }
            rd.pos++;
            Object v = readValue(rd, depth + 1);
            if (k != null) out.put(k, v);
            skipWs(rd);
            if (rd.pos >= rd.buf.length) {
                rd.fail = "fin inesperado en objeto";
                return out;
            }
            char c = rd.buf[rd.pos++];
            if (c == '}') return out;
            if (c != ',') {
                rd.fail = "',' o '}' esperado en " + rd.pos;
                return out;
            }
        }
        return out;
    }

    private static List<Object> readArray(Reader rd, int depth) {
        List<Object> out = new ArrayList<>();
        rd.pos++; // [
        skipWs(rd);
        if (rd.pos < rd.buf.length && rd.buf[rd.pos] == ']') {
            rd.pos++;
            return out;
        }
        int guard = 0;
        while (rd.fail == null) {
            if (guard++ > MAX_VALUES) {
                rd.fail = "array demasiado grande";
                return out;
            }
            out.add(readValue(rd, depth + 1));
            skipWs(rd);
            if (rd.pos >= rd.buf.length) {
                rd.fail = "fin inesperado en array";
                return out;
            }
            char c = rd.buf[rd.pos++];
            if (c == ']') return out;
            if (c != ',') {
                rd.fail = "',' o ']' esperado en " + rd.pos;
                return out;
            }
        }
        return out;
    }

    private static String readString(Reader rd) {
        rd.pos++; // "
        StringBuilder sb = new StringBuilder();
        while (rd.pos < rd.buf.length) {
            char c = rd.buf[rd.pos++];
            if (c == '"') return sb.toString();
            if (c == '\\' && rd.pos < rd.buf.length) {
                char e = rd.buf[rd.pos++];
                switch (e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (rd.pos + 4 <= rd.buf.length) {
                            try {
                                int cp = Integer.parseInt(
                                        new String(rd.buf, rd.pos, 4), 16);
                                sb.append((char) cp);
                                rd.pos += 4;
                            } catch (NumberFormatException nfe) {
                                rd.fail = "escape \\u inválido";
                                return sb.toString();
                            }
                        } else {
                            rd.fail = "escape \\u truncado";
                            return sb.toString();
                        }
                        break;
                    default: sb.append(e); break;
                }
            } else {
                sb.append(c);
            }
            if (sb.length() > MAX_INPUT) {
                rd.fail = "cadena demasiado larga";
                return sb.toString();
            }
        }
        rd.fail = "cadena sin cerrar";
        return sb.toString();
    }

    private static Boolean readBool(Reader rd) {
        if (matchWord(rd, "true")) return Boolean.TRUE;
        if (matchWord(rd, "false")) return Boolean.FALSE;
        rd.fail = "literal inválido en " + rd.pos;
        return Boolean.FALSE;
    }

    private static Object readNull(Reader rd) {
        if (matchWord(rd, "null")) return null;
        rd.fail = "literal inválido en " + rd.pos;
        return null;
    }

    private static boolean matchWord(Reader rd, String w) {
        if (rd.pos + w.length() > rd.buf.length) return false;
        for (int i = 0; i < w.length(); i++) {
            if (rd.buf[rd.pos + i] != w.charAt(i)) return false;
        }
        rd.pos += w.length();
        return true;
    }

    private static Number readNumber(Reader rd) {
        int start = rd.pos;
        if (rd.pos < rd.buf.length && rd.buf[rd.pos] == '-') rd.pos++;
        while (rd.pos < rd.buf.length && Character.isDigit(rd.buf[rd.pos])) rd.pos++;
        if (rd.pos < rd.buf.length && rd.buf[rd.pos] == '.') {
            rd.pos++;
            while (rd.pos < rd.buf.length && Character.isDigit(rd.buf[rd.pos])) rd.pos++;
        }
        if (rd.pos < rd.buf.length && (rd.buf[rd.pos] == 'e' || rd.buf[rd.pos] == 'E')) {
            rd.pos++;
            if (rd.pos < rd.buf.length && (rd.buf[rd.pos] == '+' || rd.buf[rd.pos] == '-')) rd.pos++;
            while (rd.pos < rd.buf.length && Character.isDigit(rd.buf[rd.pos])) rd.pos++;
        }
        String raw = new String(rd.buf, start, rd.pos - start);
        try {
            if (raw.indexOf('.') < 0 && raw.indexOf('e') < 0 && raw.indexOf('E') < 0) {
                return Long.parseLong(raw);
            }
            return Double.parseDouble(raw);
        } catch (NumberFormatException nfe) {
            rd.fail = "número inválido en " + start;
            return 0L;
        }
    }

    // ---- Accesores seguros sobre lo leído ----

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObject(Object o) {
        if (o instanceof Map) return (Map<String, Object>) o;
        return null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asList(Object o) {
        if (o instanceof List) return (List<Object>) o;
        return null;
    }

    public static String asString(Object o) {
        if (o instanceof String) return (String) o;
        return null;
    }

    public static String str(Map<String, Object> o, String k) {
        if (o == null) return "";
        String v = asString(o.get(k));
        return v == null ? "" : v;
    }

    public static long num(Map<String, Object> o, String k, long def) {
        if (o == null) return def;
        Object v = o.get(k);
        if (v instanceof Number) return ((Number) v).longValue();
        return def;
    }

    public static List<String> strList(Map<String, Object> o, String k) {
        List<String> out = new ArrayList<>();
        if (o == null) return out;
        List<Object> l = asList(o.get(k));
        if (l == null) return out;
        for (Object v : l) {
            if (v instanceof String) out.add((String) v);
        }
        return out;
    }
}
