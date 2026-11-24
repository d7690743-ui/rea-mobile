package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import org.junit.Test;

/** OMEGA E3: SSA pragmático (versiones + phis en joins). */
public class SsaTest {

    @Test
    public void phiEnJoinConEntrada() {
        IrBuilder.MethodIr ir = new IrBuilder.MethodIr();
        ir.regs = 3;
        IrBuilder.Insn c0 = DefUseTest.insn(0, 0x32, 0);
        c0.isCond = true;
        IrBuilder.Insn t = DefUseTest.insn(2, 0x12, 1);
        t.hasLit = true;
        t.lit = 1;
        IrBuilder.Insn g = DefUseTest.insn(3, 0x28);
        g.isGoto = true;
        IrBuilder.Insn ret = DefUseTest.insn(4, 0x0F, 1);
        ret.isReturn = true;
        ir.blocks.add(DefUseTest.block(0, new int[]{1, 2}, c0));
        ir.blocks.add(DefUseTest.block(1, new int[]{2}, t, g));
        ir.blocks.add(DefUseTest.block(2, new int[]{}, ret));
        Ssa.SsaForm f = Ssa.from(ir, null);
        assertEquals("v1_1", f.versions.get(2));
        assertEquals(1, f.phis.size());
        Ssa.Phi p = f.phis.get(0);
        assertEquals(2, p.block);
        assertEquals(1, p.reg);
        assertEquals("v1_2", p.version);
        assertEquals(new HashSet<>(java.util.Arrays.asList("v1_1", Ssa.ENTRY_VER)),
                new HashSet<>(p.sources));
        assertEquals("v1_2", Ssa.versionAt(f, ReachConsts.analyze(ir), 2, 4, 1));
    }

    @Test
    public void sinJoinSinPhi() {
        Ssa.SsaForm f = Ssa.from(DefUseTest.fooIr(), null);
        assertTrue(f.phis.isEmpty());
        assertEquals("v1_1", f.versions.get(3));
        assertEquals("v2_1", f.versions.get(4));
    }

    @Test
    public void basuraNoLanza() {
        assertNotNull(Ssa.from(null, null).versions);
        IrBuilder.MethodIr mala = new IrBuilder.MethodIr();
        mala.error = "x";
        assertTrue(Ssa.from(mala, null).phis.isEmpty());
        assertEquals(Ssa.ENTRY_VER, Ssa.versionAt(null, null, 0, 0, 0));
    }
}
