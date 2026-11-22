package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.Adler32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Test mantenido del motor v0.2: smali de clases propias y extracción del árbol.
 * Usa un DEX sintético mínimo construido en código (sin fixtures binarias).
 */
public class SmaliExtractTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void smaliBasico() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildTestDex());
        SmaliDumper.DumpResult r = SmaliDumper.dumpAll(dexes, "com/x/");
        assertEquals(1, r.classes.size());
        String smali = r.classes.get(0).text;
        assertTrue(smali, smali.contains(".class public Lcom/x/A;"));
        assertTrue(smali, smali.contains(".super Ljava/lang/Object;"));
        assertTrue(smali, smali.contains(".source \"A.java\""));
        assertTrue(smali, smali.contains(".method public static foo()V"));
        assertTrue(smali, smali.contains("const-string v0, \"hello\""));
        assertTrue(smali, smali.contains("return-void"));
        assertTrue(smali, smali.contains("goto :L0001"));
        assertEquals("smali/com/x/A.smali", r.classes.get(0).path);
    }

    @Test
    public void extraccionArbol() throws Exception {
        File apk = new File(tmp.getRoot(), "mini.apk");
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk));
        put(zos, "AndroidManifest.xml", "no-es-axml".getBytes(StandardCharsets.UTF_8));
        put(zos, "classes.dex", buildTestDex());
        put(zos, "res/values/strings.xml", "<resources/>".getBytes(StandardCharsets.UTF_8));
        put(zos, "assets/n.txt", "hola".getBytes(StandardCharsets.UTF_8));
        zos.close();
        File out = new File(tmp.getRoot(), "out.zip");
        ReaEngine.ExtractResult r = ReaEngine.extractToZip(apk, out);
        assertNull(r.error);
        assertEquals(1, r.smaliClasses);
        assertEquals(4, r.copiedEntries);
        ZipFile zf = new ZipFile(out);
        assertNotNull(zf.getEntry("rea/smali/com/x/A.smali"));
        assertNotNull(zf.getEntry("rea/manifest.xml"));
        assertNotNull(zf.getEntry("rea/ARBOL.txt"));
        assertNotNull(zf.getEntry("rea/CLASES_PROPIAS.txt"));
        assertNotNull(zf.getEntry("rea/INFORME.txt"));
        assertNotNull(zf.getEntry("apk/res/values/strings.xml"));
        zf.close();
    }

    @Test
    public void payloadSwitches() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildTestDex());
        String smali = SmaliDumper.dumpSingleClass(dexes, "Lcom/x/A;");
        assertNotNull(smali);
        // sparse: size en units[p+1]; regresión: leía units[p+2] (55137=0xD761)
        assertTrue(smali, smali.contains("# sparse-switch: size=2"));
        assertTrue(smali, smali.contains("#   0x82b1d761 -> +0x3 (raw)"));
        assertTrue(smali, smali.contains("#   0x5 -> +0x3 (raw)"));
        assertTrue(smali, smali.contains("# packed-switch: size=3 first_key=0xa"));
        assertTrue(smali, smali.contains("#   0xa -> +0x1 (raw)"));
    }

    @Test
    public void ramaIfGoto() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildTestDex());
        String smali = SmaliDumper.dumpSingleClass(dexes, "Lcom/x/A;");
        assertNotNull(smali);
        assertTrue(smali, smali.contains(".method public static br()V"));
        assertTrue(smali, smali.contains("if-eqz v0, :L0004"));
        assertTrue(smali, smali.contains("const/4 v0, 0x1"));
        assertTrue(smali, smali.contains("goto :L0004"));
    }

    @Test
    public void invoke35cRegistros() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildTestDex());
        String smali = SmaliDumper.dumpSingleClass(dexes, "Lcom/x/A;");
        assertNotNull(smali);
        assertTrue(smali, smali.contains(".method public static iv()V"));
        // 35c es A|G|op: u0=0x1071 -> A=1 registro (v3). Regresión: leía A
        // en bits 8-11 y G en 12-15, así que imprimía {}.
        assertTrue(smali, smali.contains("invoke-static {v3}, Lcom/x/A;->foo()V"));
    }

    @Test
    public void invokeParametrosPN() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildTestDex());
        String smali = SmaliDumper.dumpSingleClass(dexes, "Lcom/x/A;");
        assertNotNull(smali);
        assertTrue(smali, smali.contains(".method public ip()V"));
        // regs=5, ins=2 -> firstParam=3: v3=p0, v4=p1, v1 sigue v1.
        assertTrue(smali, smali.contains("invoke-static {p0, p1, v1}, Lcom/x/A;->foo()V"));
    }

    @Test
    public void estaticoSinInsSoloV() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildTestDex());
        String smali = SmaliDumper.dumpSingleClass(dexes, "Lcom/x/A;");
        assertNotNull(smali);
        // iv: regs=4, ins=0 -> sin parámetros, nunca pN.
        int ini = smali.indexOf(".method public static iv()V");
        assertTrue(smali, ini >= 0);
        String sec = smali.substring(ini, smali.indexOf(".end method", ini));
        assertTrue(sec, sec.contains("{v3}"));
        assertFalse(sec, sec.contains("p0"));
    }

    @Test
    public void invoke35cQuintoEsG() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildTestDex());
        String smali = SmaliDumper.dumpSingleClass(dexes, "Lcom/x/A;");
        assertNotNull(smali);
        assertTrue(smali, smali.contains(".method public static q5()V"));
        // u0=0x5671 -> A=5, G=6: el quinto registro sale de G.
        assertTrue(smali, smali.contains("invoke-static {v0, v1, v2, v5, v6}, Lcom/x/A;->foo()V"));
    }

    @Test
    public void unaSolaClase() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildTestDex());
        String smali = SmaliDumper.dumpSingleClass(dexes, "Lcom/x/A;");
        assertNotNull(smali);
        assertTrue(smali, smali.contains(".class public Lcom/x/A;"));
        assertTrue(smali, smali.contains("const-string v0, \"hello\""));
        assertNull(SmaliDumper.dumpSingleClass(dexes, "Lno/Existe;"));
    }

    static void put(ZipOutputStream zos, String name, byte[] data) throws Exception {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(data);
        zos.closeEntry();
    }

    /** DEX mínimo: 1 clase Lcom/x/A; con foo(), bar(), sw(), pk(), br(), iv(), ip() y q5(). Con mapa válido. */
    static byte[] buildTestDex() {
        String[] strs = {"Lcom/x/A;", "Ljava/lang/Object;", "foo", "A.java", "V", "bar", "hello", "sw", "pk", "br", "iv", "ip", "q5"};
        DexBuilder d = new DexBuilder();
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
        d.u32(8);
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
        d.u16(0);
        d.u16(0);
        d.u32(5);
        d.u16(0);
        d.u16(0);
        d.u32(7);
        d.u16(0);
        d.u16(0);
        d.u32(8);
        d.u16(0);
        d.u16(0);
        d.u32(9);
        d.u16(0);
        d.u16(0);
        d.u32(10);
        d.u16(0);
        d.u16(0);
        d.u32(11);
        d.u16(0);
        d.u16(0);
        d.u32(12);
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
            d.u8(0); // string_data_item termina en 0x00 como en un dex real
        }
        // foo: const-string v0, "hello"; return-void
        d.align();
        int code0 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(3);
        d.u16(0x001a);
        d.u16(6);
        d.u16(0x000e);
        // bar: goto +1; return-void (1 registro: this al ser instancia)
        d.align();
        int code1 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(2);
        d.u16(0x0128);
        d.u16(0x000e);
        // sw: sparse-switch v0,+4; return-void; payload size=2 (key0=0x82B1D761)
        d.align();
        int code2 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(14);
        d.u16(0x002c);
        d.u16(0x0004);
        d.u16(0x0000);
        d.u16(0x000e);
        d.u16(0x0200);
        d.u16(0x0002);
        d.u16(0xD761);
        d.u16(0x82B1);
        d.u16(0x0005);
        d.u16(0x0000);
        d.u16(0x0003);
        d.u16(0x0000);
        d.u16(0x0003);
        d.u16(0x0000);
        // pk: packed-switch v0,+4; return-void; payload size=3 first=10
        d.align();
        int code3 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(14);
        d.u16(0x002b);
        d.u16(0x0004);
        d.u16(0x0000);
        d.u16(0x000e);
        d.u16(0x0100);
        d.u16(0x0003);
        d.u16(0x000A);
        d.u16(0x0000);
        d.u16(0x0001);
        d.u16(0x0000);
        d.u16(0x0002);
        d.u16(0x0000);
        d.u16(0x0003);
        d.u16(0x0000);
        // br: if-eqz v0,+4; const/4 v0,1; goto +1; return-void
        d.align();
        int code4 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(5);
        d.u16(0x0038);
        d.u16(0x0004);
        d.u16(0x1012);
        d.u16(0x0128);
        d.u16(0x000e);
        // iv: invoke-static {v3}, meth@0; return-void (u0=0x1071: A=1, G=0)
        d.align();
        int code5 = d.pos;
        d.u16(4);
        d.u16(0);
        d.u16(1);
        d.u16(0);
        d.u32(0);
        d.u32(4);
        d.u16(0x1071);
        d.u16(0x0000);
        d.u16(0x0003);
        d.u16(0x000e);
        // ip: instancia, regs=5, ins=2 (p0=v3, p1=v4); invoke {v3, v4, v1}
        d.align();
        int code6 = d.pos;
        d.u16(5);
        d.u16(2);
        d.u16(3);
        d.u16(0);
        d.u32(0);
        d.u32(4);
        d.u16(0x3071);
        d.u16(0x0000);
        d.u16(0x0143);
        d.u16(0x000e);
        // q5: invoke de 5 regs, u0=0x5671 (A=5, G=6); u2: C=0,D=1,E=2,F=5
        d.align();
        int code7 = d.pos;
        d.u16(7);
        d.u16(0);
        d.u16(5);
        d.u16(0);
        d.u32(0);
        d.u32(4);
        d.u16(0x5671);
        d.u16(0x0000);
        d.u16(0x5210);
        d.u16(0x000e);
        int cd = d.pos;
        d.setU32(pClassData, cd);
        d.uleb(0);
        d.uleb(0);
        d.uleb(8);
        d.uleb(0);
        d.uleb(0);
        d.uleb(0x9);
        d.uleb(code0);
        d.uleb(1);
        d.uleb(0x1);
        d.uleb(code1);
        d.uleb(1);
        d.uleb(0x9);
        d.uleb(code2);
        d.uleb(1);
        d.uleb(0x9);
        d.uleb(code3);
        d.uleb(1);
        d.uleb(0x9);
        d.uleb(code4);
        d.uleb(1);
        d.uleb(0x9);
        d.uleb(code5);
        d.uleb(1);
        d.uleb(0x1);
        d.uleb(code6);
        d.uleb(1);
        d.uleb(0x9);
        d.uleb(code7);
        // map_list ordenado por tipo, alineado a 4
        d.align();
        int mapOff = d.pos;
        d.setU32(pMapOff, mapOff);
        d.u32(10);
        d.mapItem(0x0000, 1, 0);
        d.mapItem(0x0001, strs.length, strIdsOff);
        d.mapItem(0x0002, 3, typeIdsOff);
        d.mapItem(0x0003, 1, protoIdsOff);
        d.mapItem(0x0005, 8, methIdsOff);
        d.mapItem(0x0006, 1, clsDefsOff);
        d.mapItem(0x1000, 1, mapOff);
        d.mapItem(0x2000, 1, cd);
        d.mapItem(0x2001, 8, code0);
        d.mapItem(0x2002, strs.length, firstStrData);
        d.setU32(pDataSize, d.pos - dataOff);
        d.setU32(pFileSize, d.pos);
        return d.finish();
    }

    /** DEX con inner anónima: Lcom/x/A; (5 métodos) + Lcom/x/A$1; (vacía). */
    static byte[] buildTestDexWithInner() {
        String[] strs = {"Lcom/x/A;", "Ljava/lang/Object;", "foo", "A.java", "V", "bar", "hello", "sw", "pk",
                "br", "Lcom/x/A$1;"};
        DexBuilder d = new DexBuilder();
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
        d.u32(5);
        int pMethOff = d.pos;
        d.u32(0);
        d.u32(2);
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
        d.u32(10);
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
        d.u16(0);
        d.u16(0);
        d.u32(5);
        d.u16(0);
        d.u16(0);
        d.u32(7);
        d.u16(0);
        d.u16(0);
        d.u32(8);
        d.u16(0);
        d.u16(0);
        d.u32(9);
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
        // Lcom/x/A$1;: pública, sin métodos
        d.u32(3);
        d.u32(1);
        d.u32(1);
        d.u32(0);
        d.u32(3);
        d.u32(0);
        int pClassData2 = d.pos;
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
        // foo: const-string v0, "hello"; return-void
        d.align();
        int code0 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(3);
        d.u16(0x001a);
        d.u16(6);
        d.u16(0x000e);
        // bar: goto +1; return-void (1 registro: this al ser instancia)
        d.align();
        int code1 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(2);
        d.u16(0x0128);
        d.u16(0x000e);
        // sw: sparse-switch v0,+4; return-void; payload size=2 (key0=0x82B1D761)
        d.align();
        int code2 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(14);
        d.u16(0x002c);
        d.u16(0x0004);
        d.u16(0x0000);
        d.u16(0x000e);
        d.u16(0x0200);
        d.u16(0x0002);
        d.u16(0xD761);
        d.u16(0x82B1);
        d.u16(0x0005);
        d.u16(0x0000);
        d.u16(0x0003);
        d.u16(0x0000);
        d.u16(0x0003);
        d.u16(0x0000);
        // pk: packed-switch v0,+4; return-void; payload size=3 first=10
        d.align();
        int code3 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(14);
        d.u16(0x002b);
        d.u16(0x0004);
        d.u16(0x0000);
        d.u16(0x000e);
        d.u16(0x0100);
        d.u16(0x0003);
        d.u16(0x000A);
        d.u16(0x0000);
        d.u16(0x0001);
        d.u16(0x0000);
        d.u16(0x0002);
        d.u16(0x0000);
        d.u16(0x0003);
        d.u16(0x0000);
        // br: if-eqz v0,+4; const/4 v0,1; goto +1; return-void
        d.align();
        int code4 = d.pos;
        d.u16(1);
        d.u16(0);
        d.u16(0);
        d.u16(0);
        d.u32(0);
        d.u32(5);
        d.u16(0x0038);
        d.u16(0x0004);
        d.u16(0x1012);
        d.u16(0x0128);
        d.u16(0x000e);
        int cd = d.pos;
        d.setU32(pClassData, cd);
        d.uleb(0);
        d.uleb(0);
        d.uleb(5);
        d.uleb(0);
        d.uleb(0);
        d.uleb(0x9);
        d.uleb(code0);
        d.uleb(1);
        d.uleb(0x1);
        d.uleb(code1);
        d.uleb(1);
        d.uleb(0x9);
        d.uleb(code2);
        d.uleb(1);
        d.uleb(0x9);
        d.uleb(code3);
        d.uleb(1);
        d.uleb(0x9);
        d.uleb(code4);
        int cd2 = d.pos;
        d.setU32(pClassData2, cd2);
        d.uleb(0);
        d.uleb(0);
        d.uleb(0);
        d.uleb(0);
        // map_list ordenado por tipo, alineado a 4
        d.align();
        int mapOff = d.pos;
        d.setU32(pMapOff, mapOff);
        d.u32(10);
        d.mapItem(0x0000, 1, 0);
        d.mapItem(0x0001, strs.length, strIdsOff);
        d.mapItem(0x0002, 4, typeIdsOff);
        d.mapItem(0x0003, 1, protoIdsOff);
        d.mapItem(0x0005, 5, methIdsOff);
        d.mapItem(0x0006, 2, clsDefsOff);
        d.mapItem(0x1000, 1, mapOff);
        d.mapItem(0x2000, 2, cd);
        d.mapItem(0x2001, 5, code0);
        d.mapItem(0x2002, strs.length, firstStrData);
        d.setU32(pDataSize, d.pos - dataOff);
        d.setU32(pFileSize, d.pos);
        return d.finish();
    }

    static class DexBuilder {
        byte[] b = new byte[4096];
        int pos = 0;

        void u8(int v) {
            b[pos++] = (byte) v;
        }

        void u16(int v) {
            u8(v);
            u8(v >> 8);
        }

        void u32(int v) {
            u8(v);
            u8(v >> 8);
            u8(v >> 16);
            u8(v >> 24);
        }

        void bytes(byte[] d) {
            System.arraycopy(d, 0, b, pos, d.length);
            pos += d.length;
        }

        void uleb(int v) {
            do {
                int c = v & 0x7F;
                v >>>= 7;
                if (v != 0) c |= 0x80;
                u8(c);
            } while (v != 0);
        }

        void align() {
            while ((pos & 3) != 0) u8(0);
        }

        void mapItem(int type, int size, int off) {
            u16(type);
            u16(0);
            u32(size);
            u32(off);
        }

        void setU32(int at, int v) {
            b[at] = (byte) v;
            b[at + 1] = (byte) (v >> 8);
            b[at + 2] = (byte) (v >> 16);
            b[at + 3] = (byte) (v >> 24);
        }

        byte[] trim() {
            byte[] o = new byte[pos];
            System.arraycopy(b, 0, o, 0, pos);
            return o;
        }

        /** Calcula firma SHA-1 y checksum Adler-32 como en un dex real. */
        byte[] finish() {
            try {
                MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
                sha1.update(b, 32, pos - 32);
                System.arraycopy(sha1.digest(), 0, b, 12, 20);
                Adler32 adler = new Adler32();
                adler.update(b, 12, pos - 12);
                setU32(8, (int) adler.getValue());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return trim();
        }
    }
}
