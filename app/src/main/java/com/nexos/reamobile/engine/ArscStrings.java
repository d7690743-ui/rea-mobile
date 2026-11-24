package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.List;

/**
 * Extrae el pool global de strings de resources.arsc. Java puro, sin dependencias.
 * Solo lectura del pool global (no decodifica paquetes ni tipos de recurso).
 */
public final class ArscStrings {
    private ArscStrings() {
    }

    public static final int MAX_STRINGS = 10000;

    public static class ArscInfo {
        public int packageCount;
        public int stringCount;
        public List<String> strings = new ArrayList<>();
        public boolean truncated;
        public String error;
    }

    public static ArscInfo parse(byte[] buf) {
        ArscInfo info = new ArscInfo();
        try {
            if (buf == null || buf.length < 32) {
                info.error = "arsc demasiado corto";
                return info;
            }
            if (AxmlDecoder.u16(buf, 0) != 0x0002) {
                info.error = "no es resources.arsc";
                return info;
            }
            info.packageCount = AxmlDecoder.u32(buf, 8);
            // ResTable_header = 12 bytes; sigue el pool global de strings.
            if (AxmlDecoder.u16(buf, 12) != 0x0001) {
                info.error = "arsc sin pool global";
                return info;
            }
            AxmlDecoder.PoolHead pool = AxmlDecoder.parseStringPoolHead(buf, 12, MAX_STRINGS);
            info.stringCount = pool.count;
            info.strings.addAll(pool.head);
            info.truncated = pool.count > MAX_STRINGS;
        } catch (RuntimeException e) {
            info.error = "error decodificando arsc";
        }
        return info;
    }
}
