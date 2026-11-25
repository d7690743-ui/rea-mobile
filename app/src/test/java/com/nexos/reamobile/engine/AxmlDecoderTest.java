package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.Test;

/** AXML binario mínimo construido a mano: manifest + uses-permission. */
public class AxmlDecoderTest {

    static void u16(ByteArrayOutputStream b, int v) {
        b.write(v & 0xFF);
        b.write((v >> 8) & 0xFF);
    }

    static void u32(ByteArrayOutputStream b, int v) {
        b.write(v & 0xFF);
        b.write((v >> 8) & 0xFF);
        b.write((v >> 16) & 0xFF);
        b.write((v >> 24) & 0xFF);
    }

    static void utf16str(ByteArrayOutputStream b, String s) {
        byte[] w = s.getBytes(StandardCharsets.UTF_16LE);
        u16(b, w.length / 2);
        b.write(w, 0, w.length);
        u16(b, 0);
    }

    /** Chunk ResStringPool UTF-16. */
    static byte[] poolChunk(String[] strs) {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        int[] offs = new int[strs.length];
        for (int i = 0; i < strs.length; i++) {
            offs[i] = data.size();
            utf16str(data, strs[i]);
        }
        byte[] dd = data.toByteArray();
        ByteArrayOutputStream c = new ByteArrayOutputStream();
        u16(c, 0x0001);
        u16(c, 28);
        u32(c, 28 + strs.length * 4 + dd.length);
        u32(c, strs.length);
        u32(c, 0);
        u32(c, 0);
        u32(c, 28 + strs.length * 4);
        u32(c, 0);
        for (int o : offs) u32(c, o);
        c.write(dd, 0, dd.length);
        return c.toByteArray();
    }

    static byte[] nsChunk(int prefix, int uri) {
        ByteArrayOutputStream c = new ByteArrayOutputStream();
        u16(c, 0x0100);
        u16(c, 16);
        u32(c, 24);
        u32(c, 0);
        u32(c, 0xFFFFFFFF);
        u32(c, prefix);
        u32(c, uri);
        return c.toByteArray();
    }

    static byte[] startChunk(int ns, int name, int[][] attrs) {
        ByteArrayOutputStream c = new ByteArrayOutputStream();
        u16(c, 0x0102);
        u16(c, 16);
        u32(c, 36 + attrs.length * 20);
        u32(c, 0);
        u32(c, 0xFFFFFFFF);
        u32(c, ns);
        u32(c, name);
        u32(c, 20);
        u16(c, attrs.length);
        u16(c, 0);
        u16(c, 0);
        u16(c, 0);
        for (int[] a : attrs) {
            u32(c, a[0]);
            u32(c, a[1]);
            u32(c, a[2]);
            u16(c, 8);
            c.write(0);
            c.write(a[3]);
            u32(c, a[4]);
        }
        return c.toByteArray();
    }

    static byte[] endChunk(int ns, int name) {
        ByteArrayOutputStream c = new ByteArrayOutputStream();
        u16(c, 0x0103);
        u16(c, 16);
        u32(c, 24);
        u32(c, 0);
        u32(c, 0xFFFFFFFF);
        u32(c, ns);
        u32(c, name);
        return c.toByteArray();
    }

    static byte[] manifestBinario() {
        String[] pool = {"manifest", "package", "com.x.y", "uses-permission", "name",
            "android.permission.INTERNET", "http://schemas.android.com/apk/res/android", "android"};
        byte[] pc = poolChunk(pool);
        byte[] ns = nsChunk(7, 6);
        byte[] man = startChunk(0xFFFFFFFF, 0, new int[][]{{-1, 1, 2, 0x03, 2}});
        byte[] up = startChunk(0xFFFFFFFF, 3, new int[][]{{6, 4, -1, 0x03, 5}});
        byte[] upEnd = endChunk(0xFFFFFFFF, 3);
        byte[] manEnd = endChunk(0xFFFFFFFF, 0);
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int total = 8 + pc.length + ns.length + man.length + up.length
                + upEnd.length + manEnd.length;
        u16(b, 0x0003);
        u16(b, 8);
        u32(b, total);
        b.write(pc, 0, pc.length);
        b.write(ns, 0, ns.length);
        b.write(man, 0, man.length);
        b.write(up, 0, up.length);
        b.write(upEnd, 0, upEnd.length);
        b.write(manEnd, 0, manEnd.length);
        return b.toByteArray();
    }

    @Test
    public void manifestMinimo() {
        String xml = AxmlDecoder.decode(manifestBinario());
        assertTrue(xml, xml.contains("<manifest package=\"com.x.y\">"));
        assertTrue(xml, xml.contains("android:name=\"android.permission.INTERNET\""));
        assertTrue(xml, xml.contains("</manifest>"));
        assertEquals("com.x.y", AxmlDecoder.packageName(xml));
        List<String> perms = AxmlDecoder.usesPermissions(xml);
        assertEquals(1, perms.size());
        assertEquals("android.permission.INTERNET", perms.get(0));
        assertEquals(1, AxmlDecoder.countTag(xml, "uses-permission"));
    }

    @Test
    public void entradasMalasNoLanzan() {
        assertEquals("", AxmlDecoder.decode(null));
        assertEquals("", AxmlDecoder.decode(new byte[0]));
        assertEquals("", AxmlDecoder.decode(new byte[]{1, 2, 3}));
        assertEquals("?", AxmlDecoder.packageName(null));
        assertTrue(AxmlDecoder.usesPermissions(null).isEmpty());
        assertEquals(0, AxmlDecoder.countTag(null, "x"));
    }
}
