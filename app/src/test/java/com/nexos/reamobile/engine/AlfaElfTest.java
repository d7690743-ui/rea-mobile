package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

/** ALFA-1: parser ELF sobre bibliotecas sintéticas. */
public class AlfaElfTest {

    static class W {
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

        void u32(long v) {
            u8((int) v);
            u8((int) (v >> 8));
            u8((int) (v >> 16));
            u8((int) (v >> 24));
        }

        void u64(long v) {
            u32(v);
            u32(v >> 32);
        }

        void bytes(byte[] x) {
            for (byte v : x) b.add(v);
        }

        void cstr(String s) {
            for (int i = 0; i < s.length(); i++) u8(s.charAt(i));
            u8(0);
        }

        void setU32(int p, long v) {
            b.set(p, (byte) v);
            b.set(p + 1, (byte) (v >> 8));
            b.set(p + 2, (byte) (v >> 16));
            b.set(p + 3, (byte) (v >> 24));
        }

        byte[] finish() {
            byte[] o = new byte[b.size()];
            for (int i = 0; i < o.length; i++) o[i] = b.get(i);
            return o;
        }
    }

    /** ELF32 ARM DYN: puts(import) + Java_com_x_A_foo, JNI_OnLoad(exports). */
    static byte[] buildElf32() {
        W d = new W();
        d.bytes(new byte[]{0x7F, 'E', 'L', 'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        d.u16(3);
        d.u16(40);
        d.u32(1);
        d.u32(0);
        int pPhoff = d.pos();
        d.u32(0);
        d.u32(0);
        d.u32(0);
        d.u16(52);
        d.u16(32);
        d.u16(2);
        d.u16(40);
        d.u16(0);
        d.u16(0);
        int phoff = d.pos();
        d.setU32(pPhoff, phoff);
        int dynOff = phoff + 64;
        int hashOff = dynOff + 64;
        int symOff = hashOff + 28;
        int strOff = symOff + 64;
        // PT_LOAD cubre todo.
        d.u32(1);
        d.u32(0);
        d.u32(0x1000);
        d.u32(0x1000);
        d.u32(2000);
        d.u32(2000);
        d.u32(5);
        d.u32(0x1000);
        // PT_DYNAMIC.
        d.u32(2);
        d.u32(dynOff);
        d.u32(0x1000 + dynOff);
        d.u32(0x1000 + dynOff);
        d.u32(64);
        d.u32(64);
        d.u32(4);
        d.u32(0x1000);
        // dynamic: NEEDED, STRTAB, STRSZ, SYMTAB, SYMENT, HASH, SONAME, NULL.
        int sLibc = 1;
        int sSoname = 1 + 8;
        int sPuts = sSoname + 8;
        int sJni = sPuts + 5;
        int sOnLoad = sJni + 17;
        int strsz = sOnLoad + 11;
        d.u32(1);
        d.u32(sLibc);
        d.u32(5);
        d.u32(0x1000 + strOff);
        d.u32(10);
        d.u32(strsz);
        d.u32(6);
        d.u32(0x1000 + symOff);
        d.u32(11);
        d.u32(16);
        d.u32(4);
        d.u32(0x1000 + hashOff);
        d.u32(14);
        d.u32(sSoname);
        d.u32(0);
        d.u32(0);
        // hash: nbucket=1 nchain=4.
        d.u32(1);
        d.u32(4);
        d.u32(1);
        d.u32(0);
        d.u32(2);
        d.u32(3);
        d.u32(0);
        // symtab: null, puts(UND), Java_..(def), OnLoad(def).
        for (int i = 0; i < 16; i++) d.u8(0);
        d.u32(sPuts);
        d.u32(0);
        d.u32(0);
        d.u8(0x12);
        d.u8(0);
        d.u16(0);
        d.u32(sJni);
        d.u32(0x1100);
        d.u32(16);
        d.u8(0x12);
        d.u8(0);
        d.u16(1);
        d.u32(sOnLoad);
        d.u32(0x1200);
        d.u32(16);
        d.u8(0x12);
        d.u8(0);
        d.u16(1);
        // dynstr.
        d.u8(0);
        d.cstr("libc.so");
        d.cstr("libx.so");
        d.cstr("puts");
        d.cstr("Java_com_x_A_foo");
        d.cstr("JNI_OnLoad");
        return d.finish();
    }

    /** ELF64 AArch64 DYN mínimo con 1 JNI exportado. */
    static byte[] buildElf64() {
        W d = new W();
        d.bytes(new byte[]{0x7F, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        d.u16(3);
        d.u16(183);
        d.u32(1);
        d.u64(0);
        int pPhoff = d.pos();
        d.u64(0);
        d.u64(0);
        d.u32(0);
        d.u16(64);
        d.u16(56);
        d.u16(2);
        d.u16(64);
        d.u16(0);
        d.u16(0);
        int phoff = d.pos();
        d.setU32(pPhoff, phoff);
        int dynOff = phoff + 112;
        int hashOff = dynOff + 96;
        int symOff = hashOff + 24;
        int strOff = symOff + 72;
        // PT_LOAD.
        d.u32(1);
        d.u32(5);
        d.u64(0);
        d.u64(0x2000);
        d.u64(0x2000);
        d.u64(4000);
        d.u64(4000);
        d.u64(0x1000);
        // PT_DYNAMIC.
        d.u32(2);
        d.u32(4);
        d.u64(dynOff);
        d.u64(0x2000 + dynOff);
        d.u64(0x2000 + dynOff);
        d.u64(96);
        d.u64(96);
        d.u64(8);
        int sJni = 1;
        int strsz = sJni + 17;
        d.u64(5);
        d.u64(0x2000 + strOff);
        d.u64(10);
        d.u64(strsz);
        d.u64(6);
        d.u64(0x2000 + symOff);
        d.u64(11);
        d.u64(24);
        d.u64(4);
        d.u64(0x2000 + hashOff);
        d.u64(0);
        d.u64(0);
        // hash: nbucket=1 nchain=3.
        d.u32(1);
        d.u32(3);
        d.u32(1);
        d.u32(0);
        d.u32(2);
        d.u32(0);
        // symtab: null, Java_..(def), puts(UND).
        for (int i = 0; i < 24; i++) d.u8(0);
        d.u32(sJni);
        d.u8(0x12);
        d.u8(0);
        d.u16(1);
        d.u64(0x2100);
        d.u64(16);
        d.u32(0);
        d.u8(0x12);
        d.u8(0);
        d.u16(0);
        d.u64(0);
        d.u64(0);
        d.u8(0);
        d.cstr("Java_com_x_B_bar");
        return d.finish();
    }

    @Test
    public void elf32SimbolosYJni() {
        byte[] so = buildElf32();
        AlfaElf.ElfInfo r = AlfaElf.parse("libx.so", so, new byte[0], so.length, so.length);
        assertTrue(r.error == null);
        assertTrue(!r.is64);
        assertEquals("ARM32", r.arch);
        assertEquals("DYN", r.elfType);
        assertEquals(1, r.needed.size());
        assertEquals("libc.so", r.needed.get(0));
        assertEquals("libx.so", r.soname);
        assertEquals(1, r.importCount);
        assertEquals("puts", r.imports.get(0));
        assertEquals(2, r.exportCount);
        assertEquals(1, r.jniExports.size());
        assertEquals("Java_com_x_A_foo", r.jniExports.get(0));
        assertTrue(r.hasJniOnLoad);
        assertTrue(r.stripped);
        assertTrue(!r.partial);
    }

    @Test
    public void elf64Minimo() {
        byte[] so = buildElf64();
        AlfaElf.ElfInfo r = AlfaElf.parse("liby.so", so, new byte[0], so.length, so.length);
        assertTrue(r.error == null);
        assertTrue(r.is64);
        assertEquals("ARM64", r.arch);
        assertEquals(1, r.jniExports.size());
        assertEquals("Java_com_x_B_bar", r.jniExports.get(0));
        assertTrue(!r.partial);
    }

    @Test
    public void ventanaCortaEsParcial() {
        byte[] so = buildElf32();
        byte[] head = new byte[100];
        System.arraycopy(so, 0, head, 0, 100);
        AlfaElf.ElfInfo r = AlfaElf.parse("libx.so", head, new byte[0], so.length, so.length);
        assertTrue(r.error == null);
        assertEquals("ARM32", r.arch);
        assertTrue(r.partial);
        assertTrue(r.jniExports.isEmpty());
    }

    @Test
    public void basuraNoLanza() {
        assertNotNull(AlfaElf.parse(null, null, null, 0, 0).error);
        assertNotNull(AlfaElf.parse("x", new byte[10], null, 0, 10).error);
        assertNotNull(AlfaElf.parse("x", new byte[100], null, 0, 100).error);
        byte[] so = buildElf32();
        so[5] = 2;
        assertNotNull(AlfaElf.parse("x", so, new byte[0], so.length, so.length).error);
    }
}
