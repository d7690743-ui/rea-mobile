package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** OMEGA E0: recolección acotada de IRs sobre el DEX sintético. */
public class FlowScanTest {

    @Test
    public void recolectaMetodosPropios() {
        byte[] dex = SmaliExtractTest.buildTestDex();
        FlowScan.FlowResult r = FlowScan.collect(dex, null, "classes.dex", 400);
        assertNotNull(r);
        assertTrue(r.irs.size() > 0);
        for (String k : r.irs.keySet()) {
            assertTrue(k, k.startsWith("Lcom/x/A;->"));
            assertEquals("classes.dex", r.flowDex.get(k));
        }
        for (IrBuilder.MethodIr ir : r.irs.values()) {
            assertTrue(ir.error == null);
        }
    }

    @Test
    public void respetaBudget() {
        byte[] dex = SmaliExtractTest.buildTestDex();
        FlowScan.FlowResult r = FlowScan.collect(dex, null, "classes.dex", 1);
        assertEquals(1, r.irs.size());
        assertTrue(r.truncated);
        FlowScan.FlowResult vacio = FlowScan.collect(dex, null, "classes.dex", 0);
        assertTrue(vacio.irs.isEmpty());
    }

    @Test
    public void basuraNoLanza() {
        assertTrue(FlowScan.collect(null, null, null, 10).irs.isEmpty());
        assertTrue(FlowScan.collect(new byte[10], null, "x", 10).irs.isEmpty());
        assertTrue(FlowScan.collect(new byte[0x80], null, "x", 10).irs.isEmpty());
    }
}
