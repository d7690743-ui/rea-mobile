package com.nexos.reamobile.engine;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Decodificador mínimo de XML binario Android (AXML). Java puro, sin dependencias.
 * Soporta pool de strings UTF-8/UTF-16, namespaces, elementos, atributos y CDATA.
 */
public final class AxmlDecoder {
    private AxmlDecoder() {
    }

    private static final int XML_HEADER = 0x0003;
    private static final int STRING_POOL = 0x0001;
    private static final int START_NAMESPACE = 0x0100;
    private static final int END_NAMESPACE = 0x0101;
    private static final int START_ELEMENT = 0x0102;
    private static final int END_ELEMENT = 0x0103;
    private static final int CDATA = 0x0104;

    private static final int UTF8_FLAG = 1 << 8;
    private static final int MAX_OUTPUT = 512 * 1024;

    private static final float[] RADIX_MULTS = {1.0f, 1.0f / 128.0f, 1.0f / 32768.0f, 1.0f / 8388608.0f};
    private static final String[] DIM_UNITS = {"px", "dp", "sp", "pt", "in", "mm"};

    /** Decodifica un AndroidManifest.xml binario a texto. Nunca lanza. */
    public static String decode(byte[] buf) {
        StringBuilder out = new StringBuilder();
        try {
            if (buf == null || buf.length < 8 || u16(buf, 0) != XML_HEADER) return "";
            List<String> pool = new ArrayList<>();
            Map<String, String> uriToPrefix = new HashMap<>();
            int pos = 8; // salta la cabecera del documento
            int depth = 0;
            while (pos + 8 <= buf.length) {
                int type = u16(buf, pos);
                int size = u32(buf, pos + 4);
                if (size < 8 || pos + size > buf.length || size > buf.length) break;
                switch (type) {
                    case STRING_POOL:
                        pool = parseStringPool(buf, pos);
                        break;
                    case START_NAMESPACE: {
                        check(buf, pos + 20, 4);
                        int prefix = u32(buf, pos + 16);
                        int uri = u32(buf, pos + 20);
                        uriToPrefix.put(str(pool, uri), str(pool, prefix));
                        break;
                    }
                    case END_NAMESPACE:
                        break;
                    case START_ELEMENT: {
                        check(buf, pos + 28, 8);
                        int ns = u32(buf, pos + 16);
                        int name = u32(buf, pos + 20);
                        int attrCount = u16(buf, pos + 28);
                        String tag = qname(pool, uriToPrefix, ns, name);
                        indent(out, depth);
                        out.append('<').append(tag);
                        int aoff = pos + 36;
                        for (int i = 0; i < attrCount; i++) {
                            int p = aoff + i * 20;
                            if (p + 20 > pos + size) break;
                            check(buf, p, 20);
                            int ans = u32(buf, p);
                            int aname = u32(buf, p + 4);
                            int raw = u32(buf, p + 8);
                            int vtype = buf[p + 15] & 0xFF;
                            int vdata = u32(buf, p + 16);
                            out.append(' ').append(qname(pool, uriToPrefix, ans, aname))
                                    .append("=\"")
                                    .append(escape(formatValue(pool, raw, vtype, vdata)))
                                    .append('"');
                        }
                        out.append(">\n");
                        depth++;
                        break;
                    }
                    case END_ELEMENT: {
                        check(buf, pos + 16, 8);
                        int ns = u32(buf, pos + 16);
                        int name = u32(buf, pos + 20);
                        depth = Math.max(0, depth - 1);
                        indent(out, depth);
                        out.append("</").append(qname(pool, uriToPrefix, ns, name)).append(">\n");
                        break;
                    }
                    case CDATA: {
                        check(buf, pos + 16, 4);
                        String t = str(pool, u32(buf, pos + 16));
                        if (!t.isEmpty()) {
                            indent(out, depth);
                            out.append(escape(t)).append('\n');
                        }
                        break;
                    }
                    default:
                        break; // RESOURCE_MAP y otros se ignoran
                }
                pos += size;
                if (out.length() > MAX_OUTPUT) {
                    out.append("<!-- truncado -->\n");
                    break;
                }
            }
        } catch (RuntimeException e) {
            out.append("<!-- aviso: AXML incompleto -->\n");
        }
        return out.toString();
    }

    /** Decodifica un chunk ResStringPool situado en chunkPos. Reutilizable para ARSC. */
    public static List<String> parseStringPool(byte[] buf, int chunkPos) {
        List<String> out = new ArrayList<>();
        try {
            check(buf, chunkPos, 28);
            if (u16(buf, chunkPos) != STRING_POOL) return out;
            int stringCount = u32(buf, chunkPos + 8);
            int flags = u32(buf, chunkPos + 16);
            int stringsStart = u32(buf, chunkPos + 20);
            boolean utf8 = (flags & UTF8_FLAG) != 0;
            int offsetsBase = chunkPos + 28;
            int stringsBase = chunkPos + stringsStart;
            if (stringCount < 0 || stringCount > 1000000) return out;
            for (int i = 0; i < stringCount; i++) {
                int offPos = offsetsBase + i * 4;
                if (offPos + 4 > buf.length) break;
                int p = stringsBase + u32(buf, offPos);
                if (p < 0 || p >= buf.length) {
                    out.add("");
                    continue;
                }
                try {
                    if (utf8) {
                        int[] r1 = readUleb128(buf, p);
                        int[] r2 = readUleb128(buf, r1[1]);
                        int len = r2[0];
                        int start = r2[1];
                        if (len < 0 || start + len > buf.length) {
                            out.add("");
                            continue;
                        }
                        out.add(new String(buf, start, len, StandardCharsets.UTF_8));
                    } else {
                        check(buf, p, 2);
                        int len = u16(buf, p);
                        int start = p + 2;
                        if ((len & 0x8000) != 0) {
                            check(buf, p, 4);
                            len = ((len & 0x7FFF) << 16) | u16(buf, p + 2);
                            start = p + 4;
                        }
                        if (len < 0 || start + len * 2 > buf.length) {
                            out.add("");
                            continue;
                        }
                        out.add(new String(buf, start, len * 2, StandardCharsets.UTF_16LE));
                    }
                } catch (RuntimeException e) {
                    out.add("");
                }
            }
        } catch (RuntimeException e) {
            // devuelve lo acumulado
        }
        return out;
    }

    /** Lee un uleb128. Devuelve {valor, siguientePos}. */
    public static int[] readUleb128(byte[] buf, int pos) {
        int result = 0;
        int shift = 0;
        int p = pos;
        for (int i = 0; i < 5; i++) {
            check(buf, p, 1);
            int b = buf[p++] & 0xFF;
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) return new int[]{result, p};
            shift += 7;
        }
        throw new IllegalArgumentException("uleb128 inválido");
    }

    /** Extrae el package del XML decodificado. */
    public static String packageName(String xml) {
        if (xml == null) return "?";
        Matcher m = Pattern.compile("package=\"([^\"]+)\"").matcher(xml);
        return m.find() ? m.group(1) : "?";
    }

    /** Extrae los android:name de uses-permission del XML decodificado. */
    public static List<String> usesPermissions(String xml) {
        List<String> out = new ArrayList<>();
        if (xml == null) return out;
        Matcher m = Pattern.compile("<uses-permission[^>]*:name=\"([^\"]+)\"").matcher(xml);
        while (m.find() && out.size() < 300) out.add(m.group(1));
        return out;
    }

    /** Cuenta ocurrencias de una etiqueta de apertura. */
    public static int countTag(String xml, String tag) {
        if (xml == null) return 0;
        int n = 0;
        int idx = 0;
        String needle = "<" + tag;
        while ((idx = xml.indexOf(needle, idx)) >= 0) {
            n++;
            idx += needle.length();
        }
        return n;
    }

    private static String qname(List<String> pool, Map<String, String> uriToPrefix, int ns, int name) {
        String local = str(pool, name);
        if (local.isEmpty()) local = "?";
        if (ns == -1 || ns == 0xFFFFFFFF) return local;
        String uri = str(pool, ns);
        String prefix = uriToPrefix.get(uri);
        if (prefix == null || prefix.isEmpty()) {
            if (uri.endsWith("/apk/res/android")) prefix = "android";
            else return local;
        }
        return prefix + ":" + local;
    }

    private static String str(List<String> pool, int idx) {
        if (idx < 0 || idx >= pool.size()) return "";
        return pool.get(idx);
    }

    private static String formatValue(List<String> pool, int raw, int type, int data) {
        switch (type) {
            case 0x00:
                return (raw != -1 && raw != 0xFFFFFFFF) ? str(pool, raw) : "null";
            case 0x01:
                return String.format("@0x%08X", data);
            case 0x02:
                return String.format("?0x%08X", data);
            case 0x03:
                return str(pool, data);
            case 0x04:
                return Float.toString(Float.intBitsToFloat(data));
            case 0x05:
                return formatDimen(data);
            case 0x06:
                return formatFraction(data);
            case 0x07:
                return data != 0 ? "true" : "false";
            case 0x10:
                return Integer.toString(data);
            case 0x11:
                return String.format("0x%08X", data);
            case 0x12:
                return data != 0 ? "true" : "false";
            case 0x1c:
            case 0x1d:
            case 0x1e:
            case 0x1f:
                return String.format("#%08X", data);
            default:
                return "{t" + type + ":0x" + Integer.toHexString(data) + "}";
        }
    }

    private static String complexFloat(int data) {
        int mantissa = data >> 8;
        float v = mantissa * RADIX_MULTS[(data >> 4) & 3];
        if (v == (int) v) return Integer.toString((int) v);
        return Float.toString(v);
    }

    private static String formatDimen(int data) {
        int u = data & 15;
        return complexFloat(data) + (u < DIM_UNITS.length ? DIM_UNITS[u] : "?");
    }

    private static String formatFraction(int data) {
        return complexFloat(data) + (((data & 15) == 1) ? "%p" : "%");
    }

    private static void indent(StringBuilder out, int depth) {
        int d = Math.min(depth, 32);
        for (int i = 0; i < d; i++) out.append("  ");
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    static int u16(byte[] b, int p) {
        check(b, p, 2);
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8);
    }

    static int u32(byte[] b, int p) {
        check(b, p, 4);
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8) | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }

    static void check(byte[] b, int p, int len) {
        if (p < 0 || len < 0 || p + len > b.length) throw new IndexOutOfBoundsException("fuera de rango");
    }
}
