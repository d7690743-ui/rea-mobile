package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** Tablas DEX perezosas: equivalencia con el array completo + cotas. */
public class DexStringsTest {

    static int u32(byte[] b, int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8)
                | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }

    @Test
    public void equivaleAlArray() {
        byte[] dex = SmaliExtractTest.buildTestDex();
        DexStrings pool = DexStrings.of(dex, u32(dex, 60), u32(dex, 56));
        DexParser.DexInfo info = DexParser.parse(dex, "t");
        assertTrue(info.error == null);
        assertEquals(info.stringCount, pool.size());
        assertEquals(info.strings.size(), pool.size());
        for (int i = 0; i < pool.size(); i++) {
            assertEquals("idx " + i, info.strings.get(i), pool.get(i));
        }
        DexTypes types = DexTypes.of(dex, u32(dex, 68), u32(dex, 64), pool);
        assertEquals("Lcom/x/A;", types.get(0));
        assertEquals("?", types.get(-1));
        assertEquals("?", types.get(types.size()));
    }

    @Test
    public void cacheAcotada() {
        byte[] dex = SmaliExtractTest.buildTestDex();
        DexStrings pool = DexStrings.of(dex, u32(dex, 60), u32(dex, 56));
        for (int r = 0; r < 5; r++) {
            for (int i = 0; i < pool.size(); i++) pool.get(i);
        }
        assertTrue(pool.cached() <= DexStrings.MAX_CACHED);
        assertTrue(pool.cached() == pool.size());
    }

    @Test
    public void invalidezNoLanza() {
        assertEquals("?", DexStrings.of(null, 0, 0).get(0));
        assertEquals("", DexStrings.of(new byte[10], 0, 5).get(0));
        byte[] dex = SmaliExtractTest.buildTestDex();
        DexStrings pool = DexStrings.of(dex, u32(dex, 60), u32(dex, 56));
        assertEquals("?", pool.get(-1));
        assertEquals("?", pool.get(pool.size()));
        assertEquals("?", pool.get(99999));
        assertNotNull(DexTypes.of(null, 0, 0, null).get(0));
        assertEquals("?", DexTypes.of(dex, 99999, 10, pool).get(0));
    }

    @Test
    public void stringSinNulAcotado() {
        // T3: buffer sin 0x00 — antes leía hasta 100k chars; ahora 8k.
        byte[] buf = new byte[200000];
        java.util.Arrays.fill(buf, (byte) 'A');
        assertEquals(DexParser.MAX_STRING_CHARS, DexParser.decodeMutf8(buf, 0).length());
    }

    @Test
    public void respetaUtf16Size() {
        byte[] buf = new byte[100000];
        java.util.Arrays.fill(buf, (byte) 'B');
        // utf16_size pequeño: no escanea los 100KB aunque no haya NUL.
        assertTrue(DexParser.decodeMutf8(buf, 0, 5).length() <= 5 * 3 + 3);
        // NUL real sigue terminando.
        buf[3] = 0;
        assertEquals(3, DexParser.decodeMutf8(buf, 0, 100000).length());
    }
}
