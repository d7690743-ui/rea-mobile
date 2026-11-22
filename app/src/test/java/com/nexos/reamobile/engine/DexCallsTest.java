package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.Test;

/**
 * Pruebas del grafo de llamadas lite con DEX sintético:
 * Lcom/x/A;.foo() invoca a Ljava/lang/Runtime;.exec().
 */
public class DexCallsTest {

    @Test
    public void aristaPropia() {
        byte[] dex = buildInvokeDex();
        DexCalls.Result r = DexCalls.collect(dex, "com/x/");
        assertEquals(1, r.edges.size());
        assertEquals("Lcom/x/A;->foo", r.edges.get(0).caller);
        assertEquals("Ljava/lang/Runtime;->exec", r.edges.get(0).callee);
        assertTrue(!r.truncated);
        // La llamada es API sensible según DexParser.
        assertEquals("Ljava/lang/Runtime;",
                DexParser.suspiciousLabel("Ljava/lang/Runtime;", "exec"));
    }

    @Test
    public void filtroPaquete() {
        byte[] dex = buildInvokeDex();
        assertTrue(DexCalls.collect(dex, "otros/").edges.isEmpty());
        assertEquals(1, DexCalls.collect(dex, null).edges.size());
    }

    @Test
    public void entradasMalasNoLanzan() {
        assertTrue(DexCalls.collect(null, "com/x/").edges.isEmpty());
        assertTrue(DexCalls.collect(new byte[10], "com/x/").edges.isEmpty());
        assertTrue(DexCalls.collect(new byte[200], null).edges.isEmpty());
        assertTrue(DexParser.suspiciousLabel(null, "x") == null);
        assertTrue(DexParser.suspiciousLabel("Ljava/lang/String;", "length") == null);
    }

    /** DEX mínimo con un invoke-static a Runtime.exec + return-void. */
    static byte[] buildInvokeDex() {
        String[] strs = {"Lcom/x/A;", "Ljava/lang/Object;", "foo", "A.java", "V", "exec",
                "Ljava/lang/Runtime;"};
        SmaliExtractTest.DexBuilder d = new SmaliExtractTest.DexBuilder();
        d.bytes(new byte[]{'d', 'e', 'x', '\n', '0', '3', '5', 0});
        d.u32(0);
        for (int i = 0; i < 20; i++) d.u8(0);
        int pFileSize = d.pos;
        d.u32(0);
        d.u32(0x70);
        d.u32(0x12345678);
        d.u32(0);
        d.u32(0);
        int pMapOff = d.pos;
        d.u32(0);
        d.u32(strs.length);
        int pStrOff = d.pos;
        d.u32(0);
        d.u32(4);
        int pTypeOff = d.pos;
        d.u32(0);
        d.u32(1);
        int pProtoOff = d.pos;
        d.u32(0);
        d.u32(0);
        d.u32(0);
        d.u32(2);
        int pMethOff = d.pos;
        d.u32(0);
        d.u32(1);
        int pClsOff = d.pos;
        d.u32(0);
        int pDataSize = d.pos;
        d.u32(0);
        int pDataOff = d.pos;
        d.u32(0);
        int strIdsOff = d.pos;
        d.setU32(pStrOff, strIdsOff);
        int[] strIdPos = new int[strs.length];
        for (int i = 0; i < strs.length; i++) {
            strIdPos[i] = d.pos;
            d.u32(0);
        }
        int typeIdsOff = d.pos;
        d.setU32(pTypeOff, typeIdsOff);
        d.u32(0);
        d.u32(1);
        d.u32(4);
        d.u32(6);
        int protoIdsOff = d.pos;
        d.setU32(pProtoOff, protoIdsOff);
        d.u32(4);
        d.u32(2);
        d.u32(0);
        int methIdsOff = d.pos;
        d.setU32(pMethOff, methIdsOff);
        d.u16(0);
        d.u16(0);
        d.u32(2);
        d.u16(3);
        d.u16(0);
        d.u32(5);
        int clsDefsOff = d.pos;
        d.setU32(pClsOff, clsDefsOff);
        d.u32(0);
        d.u32(1);
        d.u32(1);
        d.u32(0);
        d.u32(3);
        d.u32(0);
        int pClassData = d.pos;
        d.u32(0);
        d.u32(0);
        int dataOff = d.pos;
        d.setU32(pDataOff, dataOff);
        int firstStrData = d.pos;
        for (int i = 0; i < strs.length; i++) {
            d.setU32(strIdPos[i], d.pos);
            byte[] sb = strs[i].getBytes(StandardCharsets.UTF_8);
            d.uleb(sb.length);
            d.bytes(sb);
            d.u8(0);
        }
        // foo: invoke-static {}, m#1; return-void
        d.align();
        int code0 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(4);
        d.u16(0x0071);
        d.u16(0x0001);
        d.u16(0x0000);
        d.u16(0x000e);
        int cd = d.pos;
        d.setU32(pClassData, cd);
        d.uleb(0);
        d.uleb(0);
        d.uleb(1);
        d.uleb(0);
        d.uleb(0);
        d.uleb(0x9);
        d.uleb(code0);
        d.align();
        int mapOff = d.pos;
        d.setU32(pMapOff, mapOff);
        d.u32(10);
        d.mapItem(0x0000, 1, 0);
        d.mapItem(0x0001, strs.length, strIdsOff);
        d.mapItem(0x0002, 4, typeIdsOff);
        d.mapItem(0x0003, 1, protoIdsOff);
        d.mapItem(0x0005, 2, methIdsOff);
        d.mapItem(0x0006, 1, clsDefsOff);
        d.mapItem(0x1000, 1, mapOff);
        d.mapItem(0x2000, 1, cd);
        d.mapItem(0x2001, 1, code0);
        d.mapItem(0x2002, strs.length, firstStrData);
        d.setU32(pDataSize, d.pos - dataOff);
        d.setU32(pFileSize, d.pos);
        return d.finish();
    }
}
