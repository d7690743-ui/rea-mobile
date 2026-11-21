package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
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

    static void put(ZipOutputStream zos, String name, byte[] data) throws Exception {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(data);
        zos.closeEntry();
    }

    /** DEX mínimo: 1 clase Lcom/x/A; con foo() y bar(). Con mapa válido. */
    static byte[] buildTestDex() {
        String[] strs = {"Lcom/x/A;", "Ljava/lang/Object;", "foo", "A.java", "V", "bar", "hello"};
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
        int cd = d.pos;
        d.setU32(pClassData, cd);
        d.uleb(0);
        d.uleb(0);
        d.uleb(2);
        d.uleb(0);
        d.uleb(0);
        d.uleb(0x9);
        d.uleb(code0);
        d.uleb(1);
        d.uleb(0x1);
        d.uleb(code1);
        // map_list ordenado por tipo, alineado a 4
        d.align();
        int mapOff = d.pos;
        d.setU32(pMapOff, mapOff);
        d.u32(10);
        d.mapItem(0x0000, 1, 0);
        d.mapItem(0x0001, strs.length, strIdsOff);
        d.mapItem(0x0002, 3, typeIdsOff);
        d.mapItem(0x0003, 1, protoIdsOff);
        d.mapItem(0x0005, 2, methIdsOff);
        d.mapItem(0x0006, 1, clsDefsOff);
        d.mapItem(0x1000, 1, mapOff);
        d.mapItem(0x2000, 1, cd);
        d.mapItem(0x2001, 2, code0);
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
