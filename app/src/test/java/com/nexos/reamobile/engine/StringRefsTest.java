package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

/**
 * OMEGA #2 StringRefs: qué método carga cada cadena (const-string).
 * Sintético + DEX reales (const-string y const-string/jumbo).
 */
public class StringRefsTest {

    static DexCalls.StringRef mkRef(String user, String value, String dex, int pos) {
        DexCalls.StringRef s = new DexCalls.StringRef();
        s.user = user;
        s.value = value;
        s.dex = dex;
        s.pos = pos;
        return s;
    }

    @Test
    public void exactoYContenido() {
        List<DexCalls.StringRef> in = new ArrayList<>();
        in.add(mkRef("Lcom/x/A;->a", "https://x.test/a", "classes.dex", 0));
        in.add(mkRef("Lcom/x/A;->b", "javascript:location='https://x.test/a'", "classes.dex", 4));
        in.add(mkRef("Lcom/x/B;->c", "hola", "classes.dex", 0));
        StringRefs ix = StringRefs.from(in);
        assertEquals(3, ix.valueCount());
        assertEquals(3, ix.pairCount());
        // Exacto: solo el dueño del literal.
        List<String> ex = ix.usersOf("https://x.test/a");
        assertEquals(1, ex.size());
        assertEquals("Lcom/x/A;->a", ex.get(0));
        // Contenido: también quien la lleva dentro de otro literal.
        List<String> co = ix.usersOfContaining("https://x.test/a");
        assertEquals(2, co.size());
        assertTrue(co.contains("Lcom/x/A;->a"));
        assertTrue(co.contains("Lcom/x/A;->b"));
        assertTrue(ix.usersOf("https://nadie.test/").isEmpty());
        assertTrue(ix.usersOf(null).isEmpty());
        assertTrue(ix.usersOfContaining(null).isEmpty());
        assertTrue(ix.usersOfContaining("").isEmpty());
        assertTrue(!ix.truncated());
    }

    @Test
    public void duplicadosColapsanYTopes() {
        List<DexCalls.StringRef> in = new ArrayList<>();
        in.add(mkRef("Lcom/x/A;->a", "s", "d", 0));
        in.add(mkRef("Lcom/x/A;->a", "s", "d", 9));
        in.add(mkRef("Lcom/x/A;->b", "s", "d", 1));
        StringRefs ix = StringRefs.from(in);
        assertEquals(1, ix.valueCount());
        assertEquals(2, ix.pairCount());
        assertEquals(2, ix.usersOf("s").size());
        assertTrue(!ix.truncated());
        // Tope: con cap 1, el segundo par distinto se descarta y cuenta.
        StringRefs ch = StringRefs.from(in, 1);
        assertEquals(1, ch.pairCount());
        assertEquals(1, ch.dropped());
        assertTrue(ch.truncated());
    }

    @Test
    public void dexRealConstString() {
        byte[] dex = buildStringDex(false);
        DexCalls.Result r = DexCalls.collect(dex, "com/x/", "classes.dex");
        assertEquals(1, r.strings.size());
        assertEquals("Lcom/x/A;->foo", r.strings.get(0).user);
        assertEquals("https://x.test/a", r.strings.get(0).value);
        assertEquals("classes.dex", r.strings.get(0).dex);
        assertEquals(0, r.strings.get(0).pos);
        assertTrue(!r.truncated);
        assertTrue(!r.stringsTruncated);
        StringRefs ix = StringRefs.from(r.strings);
        assertEquals(1, ix.usersOf("https://x.test/a").size());
        assertEquals("Lcom/x/A;->foo", ix.usersOf("https://x.test/a").get(0));
        // El filtro de paquete también aplica a cadenas.
        assertTrue(DexCalls.collect(dex, "otros/").strings.isEmpty());
        assertEquals(1, DexCalls.collect(dex, null).strings.size());
    }

    @Test
    public void dexRealJumbo() {
        byte[] dex = buildStringDex(true);
        DexCalls.Result r = DexCalls.collect(dex, null, "classes.dex");
        assertEquals(1, r.strings.size());
        assertEquals("Lcom/x/A;->foo", r.strings.get(0).user);
        assertEquals("https://x.test/a", r.strings.get(0).value);
        assertEquals(0, r.strings.get(0).pos);
        assertTrue(!r.truncated);
    }

    @Test
    public void dexSinStringsNoTocaAristas() {
        byte[] dex = DexCallsTest.buildInvokeDex();
        DexCalls.Result r = DexCalls.collect(dex, "com/x/");
        assertTrue(r.strings.isEmpty());
        assertEquals(1, r.edges.size());
        assertTrue(!r.truncated);
        assertTrue(!r.stringsTruncated);
    }

    @Test
    public void informeAtribuyeUrl() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.urls.add("https://x.test/a");
        r.urls.add("https://suelta.test/");
        r.stringRefs.add(mkRef("Lcom/x/A;->foo", "https://x.test/a", "classes.dex", 0));
        String txt = r.toText();
        assertTrue(txt, txt.contains("url=https://x.test/a <= Lcom/x/A;->foo"));
        assertTrue(txt, txt.contains("url=https://suelta.test/\n"));
    }

    @Test
    public void malasNoLanzan() {
        StringRefs ix = new StringRefs();
        assertTrue(!ix.add(null));
        DexCalls.StringRef vacio = new DexCalls.StringRef();
        vacio.user = null;
        vacio.value = "";
        assertTrue(!ix.add(vacio));
        assertEquals(0, ix.addAll(null));
        assertTrue(ix.usersOf(null).isEmpty());
        assertTrue(StringRefs.from(null).usersOf("x").isEmpty());
        assertTrue(ix.truncated());
    }

    /**
     * DEX mínimo: foo() carga s#5 ("https://x.test/a") con const-string
     * (o const-string/jumbo si jumbo) + return-void.
     */
    static byte[] buildStringDex(boolean jumbo) {
        String[] strs = {"Lcom/x/A;", "Ljava/lang/Object;", "foo", "A.java", "V",
                "https://x.test/a"};
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
        d.u32(3);
        int pTypeOff = d.pos;
        d.u32(0);
        d.u32(1);
        int pProtoOff = d.pos;
        d.u32(0);
        d.u32(0);
        d.u32(0);
        d.u32(1);
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
        d.align();
        int code0 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(jumbo ? 4 : 3);
        if (jumbo) {
            d.u16(0x001b);
            d.u16(5);
            d.u16(0);
        } else {
            d.u16(0x001a);
            d.u16(5);
        }
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
        d.mapItem(0x0002, 3, typeIdsOff);
        d.mapItem(0x0003, 1, protoIdsOff);
        d.mapItem(0x0005, 1, methIdsOff);
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
