package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** OMEGA E2: reaching definitions + propagación de constantes. */
public class ReachConstsTest {

    /** const-string v0 + const/4 v1,5 → invoke {v0,v1}. */
    static IrBuilder.MethodIr constIr() {
        IrBuilder.MethodIr ir = new IrBuilder.MethodIr();
        ir.regs = 4;
        IrBuilder.Insn s = DefUseTest.insn(0, 0x1A, 0);
        s.refIdx = 7;
        IrBuilder.Insn l = DefUseTest.insn(2, 0x12, 1);
        l.hasLit = true;
        l.lit = 5;
        IrBuilder.Insn ret = DefUseTest.insn(6, 0x0E);
        ret.isReturn = true;
        ir.blocks.add(DefUseTest.block(0, new int[]{}, s, l,
                DefUseTest.insn(3, 0x6E, 0, 1), ret));
        return ir;
    }

    /** if/else con const distinta por rama → join con invoke. */
    static IrBuilder.MethodIr joinIr(long ramaThen, long ramaElse) {
        IrBuilder.MethodIr ir = new IrBuilder.MethodIr();
        ir.regs = 3;
        IrBuilder.Insn c0 = DefUseTest.insn(0, 0x32, 0);
        c0.isCond = true;
        IrBuilder.Insn t = DefUseTest.insn(2, 0x12, 1);
        t.hasLit = true;
        t.lit = ramaThen;
        IrBuilder.Insn g1 = DefUseTest.insn(3, 0x28);
        g1.isGoto = true;
        IrBuilder.Insn e = DefUseTest.insn(5, 0x12, 1);
        e.hasLit = true;
        e.lit = ramaElse;
        IrBuilder.Insn g2 = DefUseTest.insn(6, 0x28);
        g2.isGoto = true;
        IrBuilder.Insn ret = DefUseTest.insn(9, 0x0E);
        ret.isReturn = true;
        ir.blocks.add(DefUseTest.block(0, new int[]{1, 2}, c0));
        ir.blocks.add(DefUseTest.block(1, new int[]{3}, t, g1));
        ir.blocks.add(DefUseTest.block(2, new int[]{3}, e, g2));
        ir.blocks.add(DefUseTest.block(3, new int[]{}, DefUseTest.insn(8, 0x6E, 1), ret));
        return ir;
    }

    @Test
    public void constantesEnLlamada() {
        ReachConsts.ConstResult r = ReachConsts.analyze(constIr());
        assertEquals(2, r.callConsts.size());
        ReachConsts.CallConst s = r.callConsts.get(0);
        assertEquals(3, s.addr);
        assertEquals(0, s.reg);
        assertEquals(ReachConsts.Kind.STR, s.kind);
        assertEquals(7, s.strRef);
        ReachConsts.CallConst l = r.callConsts.get(1);
        assertEquals(ReachConsts.Kind.LIT, l.kind);
        assertEquals(5, l.lit);
    }

    @Test
    public void joinDistintoEsNac() {
        ReachConsts.ConstResult r = ReachConsts.analyze(joinIr(1, 2));
        assertTrue(r.callConsts.isEmpty());
        assertEquals(2, r.reaching.get(3).get(1).size());
    }

    @Test
    public void joinIgualConserva() {
        ReachConsts.ConstResult r = ReachConsts.analyze(joinIr(1, 1));
        assertEquals(1, r.callConsts.size());
        assertEquals(1, r.callConsts.get(0).lit);
    }

    @Test
    public void pliegaAritmetica() {
        IrBuilder.MethodIr ir = new IrBuilder.MethodIr();
        ir.regs = 3;
        IrBuilder.Insn c = DefUseTest.insn(0, 0x12, 0);
        c.hasLit = true;
        c.lit = 2;
        IrBuilder.Insn add = DefUseTest.insn(1, 0xD0, 1, 0);
        add.hasLit = true;
        add.lit = 3;
        IrBuilder.Insn ret = DefUseTest.insn(4, 0x0E);
        ret.isReturn = true;
        ir.blocks.add(DefUseTest.block(0, new int[]{}, c, add,
                DefUseTest.insn(3, 0x6E, 1), ret));
        ReachConsts.ConstResult r = ReachConsts.analyze(ir);
        assertEquals(1, r.callConsts.size());
        assertEquals(5, r.callConsts.get(0).lit);
    }

    @Test
    public void basuraNoLanza() {
        assertNotNull(ReachConsts.analyze(null).callConsts);
        IrBuilder.MethodIr mala = new IrBuilder.MethodIr();
        mala.error = "x";
        assertTrue(ReachConsts.analyze(mala).entry.isEmpty());
    }
}
