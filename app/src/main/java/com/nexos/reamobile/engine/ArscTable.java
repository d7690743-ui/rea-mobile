package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tabla de recursos (resources.arsc): paquetes, tipos y entradas → mapa
 * ID→"tipo/nombre". Java puro. Solo lectura, con topes. Nunca lanza.
 */
public final class ArscTable {
    private ArscTable() {
    }

    public static final int MAX_PACKAGES = 16;
    public static final int MAX_TYPES = 512;
    public static final int MAX_TYPE_NAMES = 1024;
    public static final int MAX_KEY_NAMES = 65536;
    public static final int MAX_ENTRIES_PER_TYPE = 100000;

    public static class TableInfo {
        public int packageCount;
        /** Tipos distintos (paquete+tipo); configs aparte. */
        public int typeCount;
        public int configChunks;
        public int entryTotal;
        public int skipped;
        /** "0x7f0a001c" → "string/app_name" (primera config vista). */
        public Map<String, String> idToName = new LinkedHashMap<>();
        public boolean truncated;
        public String error;
    }

    /**
     * Parsea la tabla. maxEntries acota el mapa (resto solo cuenta);
     * con maxEntries&lt;=0 solo cuenta (sin mapa ni pools). Nunca null ni lanza.
     */
    public static TableInfo parse(byte[] buf, int maxEntries) {
        TableInfo info = new TableInfo();
        try {
            if (buf == null || buf.length < 12) {
                info.error = "arsc demasiado corto";
                return info;
            }
            if (AxmlDecoder.u16(buf, 0) != 0x0002) {
                info.error = "no es resources.arsc";
                return info;
            }
            int size = AxmlDecoder.u32(buf, 4);
            int end = size <= 0 || size > buf.length ? buf.length : size;
            int off = 12;
            int packages = 0;
            while (off + 8 <= end && packages < MAX_PACKAGES) {
                int type = AxmlDecoder.u16(buf, off);
                int chunkSize = AxmlDecoder.u32(buf, off + 4);
                if (chunkSize < 8 || off + chunkSize > end) break;
                if (type == 0x0200) {
                    parsePackage(buf, off, chunkSize, info, maxEntries);
                    packages++;
                }
                off += chunkSize;
            }
            info.packageCount = packages;
        } catch (Throwable t) {
            if (info.error == null) info.error = "error decodificando tabla";
        }
        return info;
    }

    private static void parsePackage(byte[] buf, int pkgOff, int pkgSize,
                                     TableInfo info, int maxEntries) {
        try {
            if (pkgOff + 268 > buf.length) return;
            int pkgId = AxmlDecoder.u32(buf, pkgOff + 8);
            int headerSize = AxmlDecoder.u16(buf, pkgOff + 2);
            int base = pkgOff + 12;
            if (base + 16 > buf.length) return;
            int typeStringsOff = AxmlDecoder.u32(buf, base + 256 + 0);
            int keyStringsOff = AxmlDecoder.u32(buf, base + 256 + 8);
            int typeIdOffset = 0;
            if (headerSize > 268 && base + 256 + 16 + 4 <= buf.length) {
                typeIdOffset = AxmlDecoder.u32(buf, base + 256 + 16);
            }
            int keep = maxEntries <= 0 ? 0 : 1;
            List<String> typeNames = poolAt(buf, pkgOff + typeStringsOff,
                    keep == 0 ? 0 : MAX_TYPE_NAMES);
            AxmlDecoder.PoolHead keys = poolHeadAt(buf, pkgOff + keyStringsOff,
                    keep == 0 ? 0 : MAX_KEY_NAMES);
            List<String> keyNames = keys.head;
            int keyCount = keys.count;
            int end = pkgOff + pkgSize;
            int off = pkgOff + headerSize;
            int types = 0;
            Map<String, Boolean> seen = new LinkedHashMap<>();
            while (off + 8 <= end && types < MAX_TYPES) {
                int type = AxmlDecoder.u16(buf, off);
                int chunkSize = AxmlDecoder.u32(buf, off + 4);
                if (chunkSize < 8 || off + chunkSize > end) break;
                if (type == 0x0201) {
                    parseType(buf, off, chunkSize, pkgId, typeIdOffset,
                            typeNames, keyNames, keyCount, info, maxEntries, seen);
                    types++;
                }
                off += chunkSize;
            }
            info.typeCount += seen.size();
        } catch (Throwable ignored) {
        }
    }

    private static void parseType(byte[] buf, int chOff, int chunkSize, int pkgId,
                                  int typeIdOffset, List<String> typeNames,
                                  List<String> keyNames, int keyCount, TableInfo info,
                                  int maxEntries, Map<String, Boolean> seen) {
        try {
            if (chOff + 20 > buf.length) return;
            int typeId = buf[chOff + 8] & 0xFF;
            boolean sparse = (buf[chOff + 9] & 0x01) != 0;
            int entryCount = AxmlDecoder.u32(buf, chOff + 12);
            int entriesStart = AxmlDecoder.u32(buf, chOff + 16);
            if (entryCount < 0 || entryCount > MAX_ENTRIES_PER_TYPE) {
                info.skipped += Math.max(0, entryCount);
                return;
            }
            // entriesStart apunta a los DATOS (tras el array); el array de
            // offsets está justo antes: arrayOff = entriesStart - count*4.
            long arrOffL = (long) chOff + entriesStart - (long) entryCount * 4;
            if (entriesStart < 20 || entriesStart > chunkSize
                    || arrOffL < chOff + 20 || arrOffL > Integer.MAX_VALUE) return;
            int arrOff = (int) arrOffL;
            if ((long) arrOff + (long) entryCount * 4 > buf.length) return;
            int nameIdx = typeId - 1 - typeIdOffset;
            String typeName = (nameIdx >= 0 && nameIdx < typeNames.size())
                    ? typeNames.get(nameIdx) : "tipo?";
            if (seen != null) seen.put(pkgId + ":" + typeId, Boolean.TRUE);
            info.configChunks++;
            for (int i = 0; i < entryCount; i++) {
                int eoff = AxmlDecoder.u32(buf, arrOff + i * 4);
                if (eoff == 0xFFFFFFFF) continue;
                int resIdx = i;
                long byteOff = eoff & 0xFFFFFFFFL;
                if (sparse) {
                    // ResTable_sparseTypeEntry: idx u16 + offset u16 (×4).
                    resIdx = (int) (eoff & 0xFFFF);
                    byteOff = ((eoff >>> 16) & 0xFFFF) * 4L;
                    if (resIdx < 0 || resIdx > 200000) {
                        info.skipped++;
                        continue;
                    }
                }
                long entryPos = (long) chOff + entriesStart + byteOff;
                if (entryPos + 8 > buf.length || entryPos + 8 > chOff + chunkSize) {
                    info.skipped++;
                    continue;
                }
                int keyIdx = AxmlDecoder.u32(buf, (int) entryPos + 4);
                if (keyIdx < 0 || keyIdx >= keyCount) {
                    info.skipped++;
                    continue;
                }
                String key = (keyIdx >= 0 && keyIdx < keyNames.size())
                        ? keyNames.get(keyIdx) : "?";
                info.entryTotal++;
                if (maxEntries <= 0) continue;
                if (info.idToName.size() >= maxEntries) {
                    info.truncated = true;
                    continue;
                }
                long id = ((long) (pkgId & 0xFF) << 24)
                        | ((long) (typeId & 0xFF) << 16) | (resIdx & 0xFFFF);
                String hex = "0x" + hex8(id);
                if (!info.idToName.containsKey(hex)) {
                    info.idToName.put(hex, typeName + "/" + key);
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static List<String> poolAt(byte[] buf, int pos, int maxKeep) {
        return poolHeadAt(buf, pos, maxKeep).head;
    }

    private static AxmlDecoder.PoolHead poolHeadAt(byte[] buf, int pos, int maxKeep) {
        try {
            if (pos < 0 || pos + 8 > buf.length) return new AxmlDecoder.PoolHead();
            if (AxmlDecoder.u16(buf, pos) != 0x0001) return new AxmlDecoder.PoolHead();
            return AxmlDecoder.parseStringPoolHead(buf, pos, maxKeep);
        } catch (Throwable ignored) {
            return new AxmlDecoder.PoolHead();
        }
    }

    private static String hex8(long v) {
        String s = Long.toHexString(v & 0xFFFFFFFFL);
        while (s.length() < 8) s = "0" + s;
        return s;
    }
}
