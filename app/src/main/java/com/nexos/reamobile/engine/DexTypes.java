package com.nexos.reamobile.engine;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Tabla type_ids de un DEX con resolución perezosa sobre {@link DexStrings}.
 * Sustituye a los {@code String[typeN]} completos: los descriptores se
 * resuelven al pedirlos y se retienen como mucho MAX_CACHED. Java puro.
 * Nunca lanza.
 */
public final class DexTypes {

    /** Descriptores retenidos (LRU). Los calientes (framework) repiten. */
    public static final int MAX_CACHED = 1024;

    private final byte[] buf;
    private final int off;
    private final int size;
    private final DexStrings strings;
    private final Map<Integer, String> cache;

    private DexTypes(byte[] buf, int off, int size, DexStrings strings) {
        this.buf = buf;
        this.off = off;
        this.size = size;
        this.strings = strings;
        this.cache = new LinkedHashMap<Integer, String>(64, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<Integer, String> e) {
                return size() > MAX_CACHED;
            }
        };
    }

    /**
     * Tabla sobre type_ids (off/size de cabecera). Nunca null: ante tabla
     * inválida devuelve vacía ("?" para todo). Nunca lanza.
     */
    public static DexTypes of(byte[] buf, int off, int size, DexStrings strings) {
        try {
            if (buf == null || off < 0 || size < 0 || size > 1000000 || strings == null) {
                return new DexTypes(new byte[0], 0, 0, DexStrings.of(null, 0, 0));
            }
            return new DexTypes(buf, off, size, strings);
        } catch (Throwable ignored) {
            return new DexTypes(new byte[0], 0, 0, DexStrings.of(null, 0, 0));
        }
    }

    /** Nº de tipos (typeIdsSize). Nunca lanza. */
    public int size() {
        return size;
    }

    /**
     * Descriptor idx-ésimo, "?" si inválido. Nunca null ni lanza.
     */
    public String get(int idx) {
        try {
            if (idx < 0 || idx >= size) return "?";
            String hit = cache.get(idx);
            if (hit != null) return hit;
            int idPos = off + idx * 4;
            if (idPos < 0 || idPos + 4 > buf.length) return "?";
            int descIdx = (buf[idPos] & 0xFF) | ((buf[idPos + 1] & 0xFF) << 8)
                    | ((buf[idPos + 2] & 0xFF) << 16) | ((buf[idPos + 3] & 0xFF) << 24);
            String s = strings.get(descIdx);
            if (s == null) s = "?";
            cache.put(idx, s);
            return s;
        } catch (Throwable ignored) {
            return "?";
        }
    }
}
