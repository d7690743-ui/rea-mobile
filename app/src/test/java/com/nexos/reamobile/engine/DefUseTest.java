package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import org.junit.Test;

/** OMEGA E1: def-use intraprocedural sobre IR sintética. */
public class DefUseTest {

    static IrBuilder.Insn insn(int addr, int op, int... regs) {
        IrBuilder.Insn in = new IrBuilder.Insn();
        in.addr = addr;
        in.op = op;
        in.regs = regs;
        return in;
    }

    static IrBuilder.Block block(int id, int[] succs, IrBuilder.Insn... insns) {
        IrBuilder.Block b = new IrBuilder.Block();
        b.id = id;
        b.insns.addAll(Arrays.asList(insns));
        for (int s : succs) b.succs.add(s);
        return b;
    }

    /** invoke → move-result → move → invoke → return. */
    static IrBuilder.MethodIr fooIr() {
        IrBuilder.MethodIr ir = new IrBuilder.MethodIr();
        ir.regs = 6;
        IrBuilder.Insn ret = insn(8, 0x0E);
        ret.isReturn = true;
        ir.blocks.add(block(0, new int[]{}, insn(0, 0x6E, 5), insn(3, 0x0C, 1),
                insn(4, 0x07, 2, 1), insn(5, 0x6E, 2), ret));
        return ir;
    }

    @Test
    public void defsYUsosEncadenados() {
        DefUse.Chains c = DefUse.analyze(fooIr());
        assertEquals(2, c.defs.size());
        assertEquals(3, c.uses.size());
        DefUse.DefSite d1 = c.defByAddr.get(3);
        assertNotNull(d1);
        assertEquals(1, d1.reg);
        assertEquals(0, d1.resultOf);
        assertEquals(Arrays.asList(4), d1.users);
        DefUse.DefSite d2 = c.defByAddr.get(4);
        assertNotNull(d2);
        assertEquals(-1, d2.resultOf);
        assertEquals(Arrays.asList(5), d2.users);
        DefUse.UseSite u = c.useByAddr.get(4);
        assertNotNull(u);
        assertEquals(Arrays.asList(1), u.regs);
        assertEquals(Arrays.asList(3), u.defs);
    }

    @Test
    public void entradaMarcada() {
        DefUse.Chains c = DefUse.analyze(fooIr());
        DefUse.UseSite u = c.useByAddr.get(0);
        assertNotNull(u);
        assertEquals(Arrays.asList(5), u.regs);
        assertEquals(Arrays.asList(DefUse.ENTRY), u.defs);
    }

    @Test
    public void wideMarcaPar() {
        IrBuilder.MethodIr ir = new IrBuilder.MethodIr();
        ir.regs = 4;
        ir.blocks.add(block(0, new int[]{}, insn(0, 0x18, 0), insn(2, 0x0E)));
        DefUse.Chains c = DefUse.analyze(ir);
        assertEquals(1, c.defs.size());
        assertTrue(c.defs.get(0).wide);
        assertNotNull(c.defsByReg.get(1));
    }

    @Test
    public void propagacion() {
        DefUse.Chains c = DefUse.analyze(fooIr());
        assertEquals(new HashSet<>(Arrays.asList(1, 2)),
                DefUse.propagate(c, new HashSet<>(Arrays.asList(1))));
        assertTrue(DefUse.propagate(c, null).isEmpty());
    }

    @Test
    public void basuraNoLanza() {
        assertNotNull(DefUse.analyze(null).defs);
        IrBuilder.MethodIr mala = new IrBuilder.MethodIr();
        mala.error = "x";
        assertTrue(DefUse.analyze(mala).defs.isEmpty());
        assertEquals(-1, DefUse.defReg(0x6E, new int[]{0}));
        assertEquals(0, DefUse.defReg(0x12, new int[]{0}));
        assertTrue(DefUse.useRegs(0x0E, new int[0]).isEmpty());
        assertTrue(DefUse.isInvoke(0x6E));
    }
}
