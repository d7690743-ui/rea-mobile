package com.nexos.reamobile.engine;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pool de strings de un DEX con decodificación perezosa y caché acotada.
 * Sustituye a los {@code String[stringN]} completos (cientos de miles de
 * entradas en APKs grandes): solo decodifica lo que se pide y retiene como
 * mucho MAX_CACHED entradas recientes. Java puro. Nunca lanza.
 *
 * <p>Semántica idéntica al acceso directo: índice fuera de rango, nulo o
 * dato anómalo → "?". Hilo-no-seguro (cada análisis usa el suyo).</p>
 */
public final class DexStrings {

    /** Entradas retenidas (LRU). Cubre tipos y nombres calientes. */
    public static final int MAX_CACHED = 4096;

    private final byte[] buf;
    private final int off;
    private final int size;
    private final Map<Integer, String> cache;

    private DexStrings(byte[] buf, int off, int size) {
        this.buf = buf;
        this.off = off;
        this.size = size;
        this.cache = new LinkedHashMap<Integer, String>(64, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Integer, String> e) {
                return size() > MAX_CACHED;
            }
        };
    }

    /**
     * Pool sobre la tabla string_ids (off/size de cabecera). Nunca null:
     * ante tabla inválida devuelve un pool vacío ("?" para todo).
     * Nunca lanza.
     */
    public static DexStrings of(byte[] buf, int off, int size) {
        try {
            if (buf == null || off < 0 || size < 0 || size > 2000000) {
                return new DexStrings(new byte[0], 0, 0);
            }
            return new DexStrings(buf, off, size);
        } catch (Throwable ignored) {
            return new DexStrings(new byte[0], 0, 0);
        }
    }

    /** Nº de strings (stringIdsSize). Nunca lanza. */
    public int size() {
        return size;
    }

    /**
     * String idx-ésimo: "?" si el índice es inválido, "" si el dato está
     * corrupto (igual que el array completo al que sustituye). Nunca null
     * ni lanza.
     */
    public String get(int idx) {
        try {
            if (idx < 0 || idx >= size) return "?";
            String hit = cache.get(idx);
            if (hit != null) return hit;
            int idPos = off + idx * 4;
            if (idPos < 0 || idPos + 4 > buf.length) return "?";
            int dataOff = (buf[idPos] & 0xFF) | ((buf[idPos + 1] & 0xFF) << 8)
                    | ((buf[idPos + 2] & 0xFF) << 16) | ((buf[idPos + 3] & 0xFF) << 24);
            String s;
            try {
                int[] r = AxmlDecoder.readUleb128(buf, dataOff);
                s = DexParser.decodeMutf8(buf, r[1]);
                if (s == null) s = "";
            } catch (RuntimeException e) {
                s = "";
            }
            cache.put(idx, s);
            return s;
        } catch (Throwable ignored) {
            return "?";
        }
    }

    /** Entradas retenidas (diagnóstico/tests). Nunca lanza. */
    int cached() {
        try {
            return cache.size();
        } catch (Throwable ignored) {
            return 0;
        }
    }
}
