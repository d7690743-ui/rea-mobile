package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Test;

/** PHANTOM flujo-X: multisalto y reflexión por consts. */
public class PhantomTaintTest {

    static IrBuilder.MethodIr forNameIr() {
        IrBuilder.MethodIr ir = new IrBuilder.MethodIr();
        ir.regs = 2;
        IrBuilder.Insn s = DefUseTest.insn(0, 0x1A, 0);
        s.refIdx = 3;
        IrBuilder.Insn inv = DefUseTest.insn(2, 0x6E, 0);
        IrBuilder.Insn ret = DefUseTest.insn(5, 0x0E);
        ret.isReturn = true;
        ir.blocks.add(DefUseTest.block(0, new int[]{}, s, inv, ret));
        return ir;
    }

    @Test
    public void resuelveForName() {
        String m = "Lcom/x/A;->load";
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = m;
        e.callee = "Ljava/lang/Class;->forName";
        e.dex = "classes.dex";
        e.pos = 2;
        RefGraph g = new RefGraph();
        g.add(e);
        Map<String, IrBuilder.MethodIr> irs = new LinkedHashMap<>();
        irs.put(m, forNameIr());
        Map<String, String> dex = new LinkedHashMap<>();
        dex.put(m, "classes.dex");
        Map<String, String> strs = new LinkedHashMap<>();
        strs.put("classes.dex" + ((char) 0) + 3, "com.x.Evil");
        PhantomTaint.TaintXResult r = PhantomTaint.extend(irs, g,
                new LinkedHashMap<String, String>(), dex, strs);
        assertEquals(1, r.reflection.size());
        assertEquals("forName", r.reflection.get(0).call);
        assertEquals("com.x.Evil", r.reflection.get(0).target);
        assertTrue(PhantomTaint.summarize(r).toString().contains("reflexion:"));
    }

    @Test
    public void multisaltoYSinDatos() {
        PhantomTaint.TaintXResult v = PhantomTaint.extend(null, null, null, null, null);
        assertTrue(v.extraFlows.isEmpty());
        assertTrue(PhantomTaint.summarize(null).isEmpty());
        PhantomTaint.TaintXResult r = new PhantomTaint.TaintXResult();
        PhantomTaint.XFlow x = new PhantomTaint.XFlow();
        x.source = "loc";
        x.sink = "net";
        x.chain.add("a");
        x.chain.add("b");
        x.evidence = "ev";
        r.extraFlows.add(x);
        assertTrue(PhantomTaint.summarize(r).toString().contains("multisalto:"));
    }
}
