package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import org.junit.Test;

/** F3.1: IR + bloques básicos + sucesores sobre el DEX sintético. */
public class IrBuilderTest {

    @Test
    public void bloquesIfGotoExactos() {
        byte[] dex = SmaliExtractTest.buildTestDex();
        IrBuilder.MethodIr r = IrBuilder.buildMethod(dex, codeOff(dex, 4));
        assertNull(r.error);
        assertEquals(4, r.insns.size());
        assertEquals(3, r.blocks.size());
        IrBuilder.Block b0 = r.blocks.get(0);
        IrBuilder.Block b1 = r.blocks.get(1);
        IrBuilder.Block b2 = r.blocks.get(2);
        assertEquals(0, b0.start);
        assertEquals(2, b0.end);
        assertEquals(Arrays.asList(1, 2), b0.succs);
        assertEquals(2, b1.start);
        assertEquals(4, b1.end);
        assertEquals(Arrays.asList(2), b1.succs);
        assertEquals(4, b2.start);
        assertEquals(5, b2.end);
        assertTrue(b2.succs.isEmpty());
        IrBuilder.Insn i0 = r.insns.get(0);
        assertTrue(i0.isCond);
        assertEquals(4, i0.target);
        assertEquals("if-eqz", i0.name);
        assertTrue(Arrays.equals(new int[]{0}, i0.regs));
        IrBuilder.Insn i1 = r.insns.get(1);
        assertEquals("const/4", i1.name);
        assertTrue(i1.hasLit);
        assertEquals(1, i1.lit);
        IrBuilder.Insn i2 = r.insns.get(2);
        assertTrue(i2.isGoto);
        assertEquals(4, i2.target);
        assertTrue(r.insns.get(3).isReturn);
    }

    @Test
    public void switchSparseSucesores() {
        byte[] dex = SmaliExtractTest.buildTestDex();
        IrBuilder.MethodIr r = IrBuilder.buildMethod(dex, codeOff(dex, 2));
        assertNull(r.error);
        IrBuilder.Insn d = r.insns.get(0);
        assertTrue(d.isSwitch);
        assertEquals(4, d.target);
        assertTrue(Arrays.equals(new int[]{0}, d.regs));
        assertEquals(2, r.blocks.size());
        assertEquals(Arrays.asList(1), r.blocks.get(0).succs);
        assertTrue(r.blocks.get(1).succs.isEmpty());
    }

    @Test
    public void lineaRectaYRef() {
        byte[] dex = SmaliExtractTest.buildTestDex();
        IrBuilder.MethodIr r = IrBuilder.buildMethod(dex, codeOff(dex, 0));
        assertNull(r.error);
        assertEquals(1, r.blocks.size());
        assertEquals(0, r.blocks.get(0).start);
        assertEquals(3, r.blocks.get(0).end);
        assertTrue(r.blocks.get(0).succs.isEmpty());
        IrBuilder.Insn i0 = r.insns.get(0);
        assertEquals("const-string", i0.name);
        assertEquals(SmaliDumper.R_STR, i0.refKind);
        assertEquals(6, i0.refIdx);
    }

    @Test
    public void basuraNoLanza() {
        assertNotNull(IrBuilder.buildMethod(null, 0).error);
        byte[] dex = SmaliExtractTest.buildTestDex();
        assertNotNull(IrBuilder.buildMethod(dex, 99999).error);
        assertNotNull(IrBuilder.build(null, 1, 0).error);
        IrBuilder.MethodIr vacio = IrBuilder.build(new int[0], 0, 0);
        assertNull(vacio.error);
        assertTrue(vacio.blocks.isEmpty());
    }

    @Test
    public void invoke35cNibblesAG() {
        // T1: 35c es A|G|op — A=conteo (bits 12-15), G=5º reg (bits 8-11).
        // A=2, G=0, u2=C|D|E|F con C=0,D=1,E=3,F=4 → regs=[0,1].
        int u0 = (2 << 12) | (0 << 8) | 0x6E;
        int u2 = (4 << 12) | (3 << 8) | (1 << 4) | 0;
        IrBuilder.MethodIr r = IrBuilder.build(new int[]{u0, 7, u2}, 3, 8);
        assertNull(r.error);
        assertEquals(1, r.insns.size());
        assertTrue(Arrays.equals(new int[]{0, 1}, r.insns.get(0).regs));
        // G distinto de 0 con A=5: el 5º es G, no A.
        int u0b = (5 << 12) | (7 << 8) | 0x6E;
        IrBuilder.MethodIr r2 = IrBuilder.build(new int[]{u0b, 7, u2}, 3, 8);
        assertNull(r2.error);
        assertTrue(Arrays.equals(new int[]{0, 1, 3, 4, 7}, r2.insns.get(0).regs));
        // 45cc (invoke-polymorphic) usa el mismo layout A|G (4 units: +proto).
        int u0c = (2 << 12) | (0 << 8) | 0xF2;
        IrBuilder.MethodIr r3 = IrBuilder.build(new int[]{u0c, 7, u2, 0}, 4, 8);
        assertNull(r3.error);
        assertTrue(Arrays.equals(new int[]{0, 1}, r3.insns.get(0).regs));
    }

    /** code_off del método directo N (dex sintético: 1 clase). */
    static int codeOff(byte[] dex, int methodIdx) {
        int classDefsOff = u32(dex, 0x64);
        int p = u32(dex, classDefsOff + 24);
        int[] a = uleb(dex, p);
        p = a[1];
        a = uleb(dex, p);
        p = a[1];
        a = uleb(dex, p);
        int directN = a[0];
        p = a[1];
        a = uleb(dex, p);
        p = a[1];
        int off = -1;
        for (int i = 0; i < directN; i++) {
            a = uleb(dex, p);
            p = a[1];
            a = uleb(dex, p);
            p = a[1];
            a = uleb(dex, p);
            p = a[1];
            if (i == methodIdx) off = a[0];
        }
        return off;
    }

    static int u32(byte[] b, int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8)
                | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }

    static int[] uleb(byte[] b, int p) {
        int v = 0;
        int sh = 0;
        while (true) {
            int c = b[p++] & 0xFF;
            v |= (c & 0x7F) << sh;
            if ((c & 0x80) == 0) break;
            sh += 7;
        }
        return new int[]{v, p};
    }
}
