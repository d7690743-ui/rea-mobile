package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

/** Tabla ARSC sintética: mapa ID→nombre. */
public class ArscTableTest {

    static class B {
        List<Byte> b = new ArrayList<>();

        int pos() {
            return b.size();
        }

        void u8(int v) {
            b.add((byte) v);
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

        void uleb(int v) {
            if (v < 0x80) {
                u8(v);
                return;
            }
            u8((v & 0x7F) | 0x80);
            uleb(v >>> 7);
        }

        void bytes(byte[] d) {
            for (byte x : d) b.add(x);
        }

        void setU32(int at, int v) {
            b.set(at, (byte) v);
            b.set(at + 1, (byte) (v >> 8));
            b.set(at + 2, (byte) (v >> 16));
            b.set(at + 3, (byte) (v >> 24));
        }

        byte[] done() {
            byte[] o = new byte[b.size()];
            for (int i = 0; i < o.length; i++) o[i] = b.get(i);
            return o;
        }
    }

    static void pool(B d, String[] strs) {
        int start = d.pos();
        d.u16(0x0001);
        d.u16(28);
        int pSize = d.pos();
        d.u32(0);
        d.u32(strs.length);
        d.u32(0);
        d.u32(0x100);
        d.u32(28 + strs.length * 4);
        d.u32(0);
        int[] offs = new int[strs.length];
        for (int i = 0; i < strs.length; i++) {
            offs[i] = d.pos();
            d.u32(0);
        }
        for (int i = 0; i < strs.length; i++) {
            d.setU32(offs[i], d.pos() - (start + 28 + strs.length * 4));
            byte[] sb = strs[i].getBytes(StandardCharsets.UTF_8);
            d.uleb(sb.length);
            d.uleb(sb.length);
            d.bytes(sb);
            d.u8(0);
        }
        while (d.pos() % 4 != 0) d.u8(0);
        d.setU32(pSize, d.pos() - start);
    }

    static byte[] buildArsc() {
        B d = new B();
        d.u16(0x0002);
        d.u16(12);
        int pSize = d.pos();
        d.u32(0);
        d.u32(1);
        pool(d, new String[]{"g"});
        int pkg = d.pos();
        d.u16(0x0200);
        d.u16(288);
        int pPkgSize = d.pos();
        d.u32(0);
        d.u32(0x7f);
        for (int i = 0; i < 256; i++) d.u8(0);
        int pTypes = d.pos();
        d.u32(0);
        d.u32(0);
        int pKeys = d.pos();
        d.u32(0);
        d.u32(0);
        d.u32(0);
        d.setU32(pTypes, d.pos() - pkg);
        pool(d, new String[]{"string"});
        d.setU32(pKeys, d.pos() - pkg);
        pool(d, new String[]{"app_name", "otro"});
        while (d.pos() % 4 != 0) d.u8(0);
        int tch = d.pos();
        d.u16(0x0201);
        d.u16(20);
        int pTchSize = d.pos();
        d.u32(0);
        d.u8(1);
        d.u8(0);
        d.u16(0);
        d.u32(2);
        d.u32(92);
        for (int i = 0; i < 64; i++) d.u8(0);
        d.u32(0);
        d.u32(16);
        d.u16(8);
        d.u16(0);
        d.u32(0);
        d.u16(8);
        d.u8(0);
        d.u8(3);
        d.u32(0);
        d.u16(8);
        d.u16(0);
        d.u32(1);
        d.u16(8);
        d.u8(0);
        d.u8(3);
        d.u32(0);
        d.setU32(pTchSize, d.pos() - tch);
        // Segundo chunk del mismo tipo, SPARSE: 1 entrada {idx=5, off=0}.
        while (d.pos() % 4 != 0) d.u8(0);
        int tch2 = d.pos();
        d.u16(0x0201);
        d.u16(20);
        int pTch2Size = d.pos();
        d.u32(0);
        d.u8(1);
        d.u8(1);
        d.u16(0);
        d.u32(1);
        d.u32(88);
        for (int i = 0; i < 64; i++) d.u8(0);
        d.u32(5);
        d.u16(8);
        d.u16(0);
        d.u32(0);
        d.u16(8);
        d.u8(0);
        d.u8(3);
        d.u32(0);
        d.setU32(pTch2Size, d.pos() - tch2);
        d.setU32(pPkgSize, d.pos() - pkg);
        d.setU32(pSize, d.pos());
        return d.done();
    }

    @Test
    public void mapaIdNombre() {
        ArscTable.TableInfo t = ArscTable.parse(buildArsc(), 100);
        assertNull(t.error);
        assertEquals(1, t.packageCount);
        assertEquals(1, t.typeCount);
        assertEquals(2, t.configChunks);
        assertEquals(3, t.entryTotal);
        assertEquals("string/app_name", t.idToName.get("0x7f010000"));
        assertEquals("string/otro", t.idToName.get("0x7f010001"));
        assertEquals("string/app_name", t.idToName.get("0x7f010005"));
    }

    @Test
    public void basuraNoLanza() {
        assertTrue(ArscTable.parse(null, 10).error != null);
        assertTrue(ArscTable.parse(new byte[40], 10).error != null);
        ArscTable.TableInfo t = ArscTable.parse(new byte[200], 0);
        assertTrue(t.error != null || t.idToName.isEmpty());
    }
}
