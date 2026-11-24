package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.Test;

/** OMEGA E5: resúmenes interprocedurales. */
public class InterProcTest {

    static RefGraph grafoFoo() {
        RefGraph g = new RefGraph();
        DexCalls.Edge e1 = new DexCalls.Edge();
        e1.caller = "Lcom/x/A;->foo";
        e1.callee = "Landroid/widget/EditText;->getText";
        e1.pos = 0;
        DexCalls.Edge e2 = new DexCalls.Edge();
        e2.caller = "Lcom/x/A;->foo";
        e2.callee = "Landroid/util/Log;->d";
        e2.pos = 5;
        g.addAll(Arrays.asList(e1, e2));
        return g;
    }

    @Test
    public void resuelveYSitios() {
        RefGraph g = grafoFoo();
        assertEquals(Arrays.asList("Landroid/widget/EditText;->getText"),
                InterProc.calleesAt(g, "Lcom/x/A;->foo", 0));
        assertTrue(InterProc.calleesAt(g, "Lcom/x/A;->foo", 99).isEmpty());
        assertTrue(InterProc.calleesAt(null, "Lcom/x/A;->foo", 0).isEmpty());
    }

    @Test
    public void resumenEntradasYLlamadas() {
        Map<String, IrBuilder.MethodIr> irs = new LinkedHashMap<>();
        irs.put("Lcom/x/A;->foo", DefUseTest.fooIr());
        Map<String, InterProc.Summary> sums = InterProc.summarize(irs, grafoFoo(), null);
        assertEquals(1, sums.size());
        InterProc.Summary s = sums.get("Lcom/x/A;->foo");
        assertNotNull(s);
        assertEquals(new java.util.HashSet<>(Arrays.asList(5)), s.entryRegs);
        assertTrue(!s.retMayCarryEntry);
        assertEquals(2, s.calls.size());
        assertEquals("Landroid/widget/EditText;->getText", s.calls.get(0).callee);
        assertEquals("Landroid/util/Log;->d", s.calls.get(1).callee);
    }

    @Test
    public void retornoDeEntradaYSinks() {
        IrBuilder.MethodIr ir = new IrBuilder.MethodIr();
        ir.regs = 6;
        IrBuilder.Insn ret = DefUseTest.insn(3, 0x0F, 5);
        ret.isReturn = true;
        ir.blocks.add(DefUseTest.block(0, new int[]{}, DefUseTest.insn(0, 0x6E, 5), ret));
        RefGraph g = new RefGraph();
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = "Lcom/x/A;->id";
        e.callee = "Landroid/util/Log;->d";
        e.pos = 0;
        g.add(e);
        Map<String, IrBuilder.MethodIr> irs = new LinkedHashMap<>();
        irs.put("Lcom/x/A;->id", ir);
        InterProc.SinkMatcher m = new InterProc.SinkMatcher() {
            @Override
            public boolean isSink(String cls, String method) {
                return "Landroid/util/Log;".equals(cls) && "d".equals(method);
            }
        };
        Map<String, InterProc.Summary> sums = InterProc.summarize(irs, g, m);
        InterProc.Summary s = sums.get("Lcom/x/A;->id");
        assertTrue(s.retMayCarryEntry);
        assertEquals(1, s.sinksFromEntry.size());
        assertEquals("Landroid/util/Log;->d", s.sinksFromEntry.get(0).sink);
    }

    @Test
    public void basuraNoLanza() {
        assertNotNull(InterProc.summarize(null, null, null));
        assertTrue(InterProc.summarize(null, null, null).isEmpty());
    }
}
