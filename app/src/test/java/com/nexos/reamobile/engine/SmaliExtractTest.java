package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
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
        assertNotNull(zf.getEntry("rea/smali/classes/com/x/A.smali"));
        assertNotNull(zf.getEntry("rea/manifest.xml"));
        assertNotNull(zf.getEntry("rea/ARBOL.txt"));
        assertNotNull(zf.getEntry("rea/CLASES_PROPIAS.txt"));
        assertNotNull(zf.getEntry("rea/INFORME.txt"));
        assertNotNull(zf.getEntry("rea/smali_index.json"));
        assertNotNull(zf.getEntry("rea/SMALI_FALLOS.txt"));
        assertNotNull(zf.getEntry("rea/NATIVO_simbolos.txt"));
        assertNotNull(zf.getEntry("apk/res/values/strings.xml"));
        zf.close();
    }

    @Test
    public void smaliPorDexConIndice() throws Exception {
        File apk = new File(tmp.getRoot(), "multi.apk");
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk));
        put(zos, "AndroidManifest.xml", "no-es-axml".getBytes(StandardCharsets.UTF_8));
        put(zos, "classes.dex", buildTestDex());
        put(zos, "classes2.dex", buildTestDex());
        zos.close();
        File out = new File(tmp.getRoot(), "out.zip");
        ReaEngine.ExtractResult r = ReaEngine.extractToZip(apk, out);
        assertNull(r.error);
        assertEquals(2, r.smaliClasses);
        ZipFile zf = new ZipFile(out);
        assertNotNull(zf.getEntry("rea/smali/classes/com/x/A.smali"));
        assertNotNull(zf.getEntry("rea/smali/classes2/com/x/A.smali"));
        String idx = readEntry(zf, "rea/smali_index.json");
        assertTrue(idx, idx.contains("\"dex\":\"classes.dex\""));
        assertTrue(idx, idx.contains("\"dex\":\"classes2.dex\""));
        assertTrue(idx, idx.contains("\"ok\":2"));
        assertTrue(idx, idx.contains("\"fallos\":0"));
        zf.close();
    }

    @Test
    public void smaliFalloConMotivo() {
        byte[] good = buildTestDex();
        byte[] bad = good.clone();
        int classOff = le32(bad, 100);
        bad[classOff + 24] = (byte) 0xFF;
        bad[classOff + 25] = (byte) 0xFF;
        bad[classOff + 26] = (byte) 0xFF;
        bad[classOff + 27] = (byte) 0x7F;
        SmaliDumper.FullDump full = new SmaliDumper.FullDump("com/x/", null);
        full.addDex(bad, "classes9.dex");
        assertEquals(1, full.r.scanned);
        assertEquals(0, full.r.dumped);
        assertEquals(1, full.r.failTotal);
        assertEquals(1, full.r.failures.size());
        assertTrue(full.r.failures.get(0),
                full.r.failures.get(0).startsWith("classes9|Lcom/x/A;|"));
        String motivo = full.r.failures.get(0).split("\\|", 3)[2];
        assertTrue("motivo vacío", motivo.length() > 0);
        assertEquals(1, full.r.dexStats.size());
        assertEquals("classes9.dex", full.r.dexStats.get(0).dex);
        assertEquals(1, full.r.dexStats.get(0).failed);
        full.addDex(good, "classes.dex");
        assertEquals(1, full.r.dumped);
        assertEquals(2, full.r.dexStats.size());
    }

    @Test
    public void descriptorIlegibleNoTumba() {
        byte[] bad = buildTestDex();
        int classOff = le32(bad, 100);
        bad[classOff] = (byte) 0xFF;
        bad[classOff + 1] = (byte) 0xFF;
        bad[classOff + 2] = (byte) 0xFF;
        bad[classOff + 3] = (byte) 0x7F;
        SmaliDumper.FullDump full = new SmaliDumper.FullDump("com/x/", null);
        full.addDex(bad, "classes.dex");
        assertEquals(1, full.r.scanned);
        assertEquals(0, full.r.dumped);
        assertEquals(1, full.r.failTotal);
        assertTrue(full.r.failures.get(0),
                full.r.failures.get(0).contains("descriptor ilegible"));
    }

    @Test
    public void dexDirSanea() {
        assertEquals("classes", SmaliDumper.dexDir("classes.dex"));
        assertEquals("classes2", SmaliDumper.dexDir("classes2.dex"));
        assertEquals("classes", SmaliDumper.dexDir(null));
        assertEquals("classes", SmaliDumper.dexDir(""));
        assertEquals("x", SmaliDumper.dexDir("../../x"));
        assertEquals("smali/com/x/A.smali",
                ReaEngine.shortSmaliPath("smali/classes2/com/x/A.smali"));
        assertEquals("", ReaEngine.shortSmaliPath(null));
    }

    @Test
    public void crudosYnativoGarantizados() throws Exception {
        File apk = new File(tmp.getRoot(), "raw.apk");
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk));
        put(zos, "AndroidManifest.xml", "no-es-axml".getBytes(StandardCharsets.UTF_8));
        put(zos, "classes.dex", buildTestDex());
        put(zos, "res/layout/a.xml", "<x/>".getBytes(StandardCharsets.UTF_8));
        put(zos, "resources.arsc", ArscTableTest.buildArsc());
        put(zos, "assets/x.txt", "hola".getBytes(StandardCharsets.UTF_8));
        put(zos, "lib/arm64-v8a/libt.so", AlfaElfTest.buildElf32());
        zos.close();
        File out = new File(tmp.getRoot(), "out.zip");
        ReaEngine.ExtractResult r = ReaEngine.extractToZip(apk, out);
        assertNull(r.error);
        ZipFile zf = new ZipFile(out);
        assertNotNull(zf.getEntry("apk/res/layout/a.xml"));
        assertNotNull(zf.getEntry("apk/resources.arsc"));
        assertNotNull(zf.getEntry("apk/assets/x.txt"));
        assertNotNull(zf.getEntry("apk/lib/arm64-v8a/libt.so"));
        String ids = readEntry(zf, "rea/recursos_ids.json");
        assertTrue(ids, ids.contains("0x7f010000"));
        String nat = readEntry(zf, "rea/NATIVO_simbolos.txt");
        assertTrue(nat, nat.contains("lib/arm64-v8a/libt.so"));
        zf.close();
        assertTrue(r.notes.toString(), r.notes.toString().contains("crudos: res=1"));
    }

    static String readEntry(ZipFile zf, String name) throws Exception {
        ZipEntry e = zf.getEntry(name);
        assertNotNull(name, e);
        InputStream in = zf.getInputStream(e);
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) b.write(buf, 0, n);
        in.close();
        return new String(b.toByteArray(), StandardCharsets.UTF_8);
    }

    static int le32(byte[] b, int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8)
                | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
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

    @Test
    public void streamDumpEquivale() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildTestDex());
        SmaliDumper.DumpResult a = SmaliDumper.dumpAll(dexes, "com/x/");
        SmaliDumper.StreamDump sd = new SmaliDumper.StreamDump("com/x/");
        for (byte[] d : dexes) sd.addDex(d);
        assertEquals(null, sd.altPrefix());
        assertEquals(a.classes.size(), sd.r.classes.size());
        for (int i = 0; i < a.classes.size(); i++) {
            assertEquals(a.classes.get(i).path, sd.r.classes.get(i).path);
            assertEquals(a.classes.get(i).text, sd.r.classes.get(i).text);
        }
        assertEquals(a.classSummaries, sd.r.classSummaries);
        assertEquals(a.truncated, sd.r.truncated);
        sd.addDex(null);
        sd.addDex(new byte[10]);
        assertTrue(sd.r.notes.size() >= 1);
    }

    @Test
    public void fidelidadInterfacesEstaticosTryAnotaciones() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildFidelityDex());
        SmaliDumper.DumpResult r = SmaliDumper.dumpAll(dexes, "com/x/");
        assertEquals(1, r.classes.size());
        String smali = r.classes.get(0).text;
        assertTrue(smali, smali.contains(".implements Ljava/io/Serializable;"));
        assertTrue(smali, smali.contains(
                ".field public static final TAG:Ljava/lang/String; = \"hello\""));
        assertTrue(smali, smali.contains(".annotation runtime Lfoo/Ann;"));
        assertTrue(smali, smali.contains("value = 0x0000002a"));
        assertTrue(smali, smali.contains(
                ".catch Ljava/lang/Object; { :L0000 .. :L0002 } :L0002"));
        assertTrue(smali, smali.contains(".end method"));
    }

    @Test
    public void fullDumpVuelcaTodas() {
        final List<String> paths = new ArrayList<>();
        SmaliDumper.ClassSink sink = new SmaliDumper.ClassSink() {
            public void accept(String path, String text) {
                paths.add(path);
            }
        };
        SmaliDumper.FullDump fd = new SmaliDumper.FullDump("com/otro/", sink);
        fd.addDex(buildTestDexWithInner());
        assertEquals(2, fd.r.scanned);
        assertEquals(2, fd.r.dumped);
        assertEquals(0, fd.r.ownMatched);
        assertTrue(fd.r.classSummaries.isEmpty());
        assertEquals(2, paths.size());
        assertTrue(paths.toString(), paths.contains("smali/classes/com/x/A.smali"));
        fd.addDex(null);
        fd.addDex(new byte[10]);
    }

    static void put(ZipOutputStream zos, String name, byte[] data) throws Exception {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(data);
        zos.closeEntry();
    }

    @Test
    public void metodoGiganteRecortado() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildHugeMethodDex(1, 40, 8192));
        String smali = SmaliDumper.dumpSingleClass(dexes, "Lcom/x/H;");
        assertNotNull(smali);
        assertTrue(smali, smali.contains("[...método recortado: tope 256K caracteres...]"));
        assertTrue(smali, smali.contains(".end method"));
        assertTrue("len=" + smali.length(), smali.length() < 300000);
    }

    @Test
    public void claseGiganteRecortada() {
        List<byte[]> dexes = new ArrayList<>();
        dexes.add(buildHugeMethodDex(10, 40, 8192));
        String smali = SmaliDumper.dumpSingleClass(dexes, "Lcom/x/H;");
        assertNotNull(smali);
        assertTrue(smali, smali.contains("# clase recortada (tope 2M caracteres)"));
        assertTrue("len=" + smali.length(), smali.length() < 2300000);
    }

    /** DEX T2: 1 clase con N métodos de M invoke-static a un nombre de L chars. */
    static byte[] buildHugeMethodDex(int methods, int invokesPerMethod, int nameLen) {
        StringBuilder ln = new StringBuilder("m");
        for (int i = 1; i < nameLen; i++) ln.append('n');
        String[] strs = {"Lcom/x/H;", "Ljava/lang/Object;", ln.toString(), "V"};
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
        d.u32(methods);
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
        d.u32(3);
        int protoIdsOff = d.pos;
        d.setU32(pProtoOff, protoIdsOff);
        d.u32(2);
        d.u32(2);
        d.u32(0);
        int methIdsOff = d.pos;
        d.setU32(pMethOff, methIdsOff);
        for (int i = 0; i < methods; i++) {
            d.u16(0);
            d.u16(0);
            d.u32(2);
        }
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
        for (int i = 0; i < strs.length; i++) {
            d.setU32(strIdPos[i], d.pos);
            byte[] sb = strs[i].getBytes(StandardCharsets.UTF_8);
            d.uleb(sb.length);
            d.bytes(sb);
            d.u8(0);
        }
        int[] codes = new int[methods];
        for (int m = 0; m < methods; m++) {
            d.align();
            codes[m] = d.pos;
            d.u16(1);
            d.u16(0);
            d.u16(0);
            d.u16(0);
            d.u32(0);
            d.u32(invokesPerMethod * 3 + 1);
            for (int k = 0; k < invokesPerMethod; k++) {
                d.u16(0x1071);
                d.u16(0);
                d.u16(0);
            }
            d.u16(0x000e);
        }
        int cd = d.pos;
        d.setU32(pClassData, cd);
        d.uleb(0);
        d.uleb(0);
        d.uleb(methods);
        d.uleb(0);
        for (int m = 0; m < methods; m++) {
            d.uleb(m == 0 ? 0 : 1);
            d.uleb(0x9);
            d.uleb(codes[m]);
        }
        d.align();
        int mapOff = d.pos;
        d.setU32(pMapOff, mapOff);
        d.u32(10);
        d.mapItem(0x0000, 1, 0);
        d.mapItem(0x0001, strs.length, strIdsOff);
        d.mapItem(0x0002, 3, typeIdsOff);
        d.mapItem(0x0003, 1, protoIdsOff);
        d.mapItem(0x0005, methods, methIdsOff);
        d.mapItem(0x0006, 1, clsDefsOff);
        d.mapItem(0x1000, 1, mapOff);
        d.mapItem(0x2000, 1, cd);
        d.mapItem(0x2001, methods, codes[0]);
        d.mapItem(0x2002, strs.length, dataOff);
        d.setU32(pDataSize, d.pos - dataOff);
        d.setU32(pFileSize, d.pos);
        return d.finish();
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

    /** DEX fidelidad: 1 clase con interfaz, estático con valor, try/catch y anotación. */
    static byte[] buildFidelityDex() {
        String[] strs = {"Lcom/x/F;", "Ljava/lang/Object;", "Ljava/io/Serializable;",
                "run", "F.java", "V", "TAG", "Ljava/lang/String;", "hello", "Lfoo/Ann;", "value"};
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
        d.u32(6);
        int pTypeOff = d.pos;
        d.u32(0);
        d.u32(1);
        int pProtoOff = d.pos;
        d.u32(0);
        d.u32(1);
        int pFieldOff = d.pos;
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
        int[] typeStr = {0, 1, 2, 5, 7, 9};
        for (int s : typeStr) d.u32(s);
        int protoIdsOff = d.pos;
        d.setU32(pProtoOff, protoIdsOff);
        d.u32(5);
        d.u32(3);
        d.u32(0);
        int fieldIdsOff = d.pos;
        d.setU32(pFieldOff, fieldIdsOff);
        d.u16(0);
        d.u16(4);
        d.u32(6);
        int methIdsOff = d.pos;
        d.setU32(pMethOff, methIdsOff);
        d.u16(0);
        d.u16(0);
        d.u32(3);
        int clsDefsOff = d.pos;
        d.setU32(pClsOff, clsDefsOff);
        d.u32(0);
        d.u32(1);
        d.u32(1);
        int pIfaces = d.pos;
        d.u32(0);
        d.u32(4);
        int pAnnot = d.pos;
        d.u32(0);
        int pClassData = d.pos;
        d.u32(0);
        int pStatics = d.pos;
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
        // run: 3 nop + return-void, try{0..2} catch Object -> 2
        d.align();
        int code0 = d.pos;
        d.u16(2);
        d.u16(1);
        d.u16(0);
        d.u16(1);
        d.u32(0);
        d.u32(4);
        d.u16(0x0000);
        d.u16(0x0000);
        d.u16(0x0000);
        d.u16(0x000e);
        d.u32(0);
        d.u16(2);
        d.u16(0);
        d.u8(0x01);
        d.u8(0x01);
        d.u8(0x02);
        int cd = d.pos;
        d.setU32(pClassData, cd);
        d.uleb(1);
        d.uleb(0);
        d.uleb(1);
        d.uleb(0);
        d.uleb(0);
        d.uleb(0x19);
        d.uleb(0);
        d.uleb(0x1);
        d.uleb(code0);
        d.align();
        int ifOff = d.pos;
        d.setU32(pIfaces, ifOff);
        d.u32(1);
        d.u16(2);
        int stOff = d.pos;
        d.setU32(pStatics, stOff);
        d.uleb(1);
        d.u8(0x17);
        d.u8(8);
        int anOff = d.pos;
        d.setU32(pAnnot, anOff);
        int pClsSet = d.pos;
        d.u32(0);
        d.u32(0);
        d.u32(1);
        d.u32(0);
        d.u32(0);
        int pMethSet = d.pos;
        d.u32(0);
        int setOff = d.pos;
        d.setU32(pClsSet, setOff);
        d.setU32(pMethSet, setOff);
        d.u32(1);
        int pItem = d.pos;
        d.u32(0);
        int itemOff = d.pos;
        d.setU32(pItem, itemOff);
        d.u8(1);
        d.uleb(5);
        d.uleb(1);
        d.uleb(10);
        d.u8(0x04);
        d.u8(0x2A);
        d.align();
        int mapOff = d.pos;
        d.setU32(pMapOff, mapOff);
        d.u32(11);
        d.mapItem(0x0000, 1, 0);
        d.mapItem(0x0001, strs.length, strIdsOff);
        d.mapItem(0x0002, 6, typeIdsOff);
        d.mapItem(0x0003, 1, protoIdsOff);
        d.mapItem(0x0004, 1, fieldIdsOff);
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
            if (pos >= b.length) {
                byte[] nb = new byte[b.length * 2];
                System.arraycopy(b, 0, nb, 0, b.length);
                b = nb;
            }
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
            while (pos + d.length > b.length) {
                byte[] nb = new byte[b.length * 2];
                System.arraycopy(b, 0, nb, 0, b.length);
                b = nb;
            }
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
