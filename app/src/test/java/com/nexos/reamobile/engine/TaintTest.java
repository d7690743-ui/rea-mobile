package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.Test;

/** OMEGA E4: taint intra + inter de un salto. */
public class TaintTest {

    @Test
    public void tablas() {
        Map<String, String> supers = new LinkedHashMap<>();
        assertTrue(Taint.isSource("Landroid/widget/EditText;", "getText", supers));
        assertTrue(Taint.isSink("Landroid/util/Log;", "d", supers));
        assertTrue(!Taint.isSource("Landroid/util/Log;", "d", supers));
        assertTrue(!Taint.isSink("Landroid/widget/EditText;", "getText", supers));
        assertTrue(!Taint.isSource(null, null, null));
        supers.put("Lcom/x/MiEdit;", "Landroid/widget/EditText;");
        assertTrue(Taint.isSource("Lcom/x/MiEdit;", "getText", supers));
    }

    @Test
    public void flujoIntra() {
        Map<String, IrBuilder.MethodIr> irs = new LinkedHashMap<>();
        irs.put("Lcom/x/A;->foo", DefUseTest.fooIr());
        Taint.TaintResult r = Taint.analyze(irs, InterProcTest.grafoFoo(),
                new LinkedHashMap<String, String>());
        assertEquals(1, r.methods);
        assertEquals(1, r.flows.size());
        Taint.Flow f = r.flows.get(0);
        assertEquals("Landroid/widget/EditText;->getText@+0", f.source);
        assertEquals("Landroid/util/Log;->d@+5", f.sink);
        assertEquals("Lcom/x/A;->foo", f.method);
        assertTrue(!f.inter);
        assertTrue(f.evidence.contains("~>"));
    }

    @Test
    public void sinSumideroSinFlujo() {
        Map<String, IrBuilder.MethodIr> irs = new LinkedHashMap<>();
        irs.put("Lcom/x/A;->foo", DefUseTest.fooIr());
        RefGraph g = new RefGraph();
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = "Lcom/x/A;->foo";
        e.callee = "Landroid/widget/EditText;->getText";
        e.pos = 0;
        g.add(e);
        Taint.TaintResult r = Taint.analyze(irs, g, new LinkedHashMap<String, String>());
        assertTrue(r.flows.isEmpty());
    }

    @Test
    public void flujoInterUnSalto() {
        IrBuilder.MethodIr go = new IrBuilder.MethodIr();
        go.regs = 4;
        IrBuilder.Insn ret = DefUseTest.insn(6, 0x0E);
        ret.isReturn = true;
        go.blocks.add(DefUseTest.block(0, new int[]{}, DefUseTest.insn(0, 0x6E, 0),
                DefUseTest.insn(3, 0x0C, 1), DefUseTest.insn(4, 0x71, 1), ret));
        IrBuilder.MethodIr sink = new IrBuilder.MethodIr();
        sink.regs = 6;
        IrBuilder.Insn ret2 = DefUseTest.insn(3, 0x0E);
        ret2.isReturn = true;
        sink.blocks.add(DefUseTest.block(0, new int[]{},
                DefUseTest.insn(0, 0x6E, 5), ret2));
        Map<String, IrBuilder.MethodIr> irs = new LinkedHashMap<>();
        irs.put("Lcom/x/A;->go", go);
        irs.put("Lcom/x/B;->sink", sink);
        RefGraph g = new RefGraph();
        DexCalls.Edge e1 = new DexCalls.Edge();
        e1.caller = "Lcom/x/A;->go";
        e1.callee = "Landroid/widget/EditText;->getText";
        e1.pos = 0;
        DexCalls.Edge e2 = new DexCalls.Edge();
        e2.caller = "Lcom/x/A;->go";
        e2.callee = "Lcom/x/B;->sink";
        e2.pos = 4;
        DexCalls.Edge e3 = new DexCalls.Edge();
        e3.caller = "Lcom/x/B;->sink";
        e3.callee = "Landroid/util/Log;->d";
        e3.pos = 0;
        g.addAll(Arrays.asList(e1, e2, e3));
        Taint.TaintResult r = Taint.analyze(irs, g, new LinkedHashMap<String, String>());
        assertEquals(1, r.flows.size());
        Taint.Flow f = r.flows.get(0);
        assertTrue(f.inter);
        assertEquals(Arrays.asList("Lcom/x/A;->go", "Lcom/x/B;->sink"), f.chain);
        assertTrue(f.sink.startsWith("Landroid/util/Log;->d"));
    }

    @Test
    public void basuraNoLanza() {
        assertNotNull(Taint.analyze(null, null, null).flows);
        assertTrue(Taint.analyze(null, null, null).flows.isEmpty());
        assertTrue(Taint.matcherFor(null) != null);
    }
}
