package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** F3.2: propagación simple de tipos de registros sobre la CFG. */
public class IrTypesTest {

    static IrTypes.Resolver fake(final String ret) {
        return new IrTypes.Resolver() {
            @Override
            public String methodReturn(int refIdx) {
                return ret;
            }

            @Override
            public String typeName(int refIdx) {
                return "Lcom/x/T;";
            }
        };
    }

    @Test
    public void tiposLineaRecta() {
        int[] units = {0x1012, 0x011a, 0, 0x016e, 7, 0, 0x020c, 0x000e};
        IrBuilder.MethodIr ir = IrBuilder.build(units, units.length, 3);
        assertNotNull(ir);
        String[] t = IrTypes.infer(ir, fake("Landroid/os/Bundle;"));
        assertEquals(3, t.length);
        assertEquals("I", t[0]);
        assertEquals("Ljava/lang/String;", t[1]);
        assertEquals("Landroid/os/Bundle;", t[2]);
    }

    @Test
    public void tiposMergeJoin() {
        int[] diff = {0x0038, 4, 0x1112, 0x0328, 0x011a, 0, 0x000e};
        IrBuilder.MethodIr irD = IrBuilder.build(diff, diff.length, 2);
        String[] td = IrTypes.infer(irD, fake("I"));
        assertEquals(2, td.length);
        assertEquals("?", td[0]);
        assertEquals("?", td[1]);
        int[] same = {0x0038, 3, 0x1112, 0x1112, 0x000e};
        IrBuilder.MethodIr irS = IrBuilder.build(same, same.length, 2);
        String[] ts = IrTypes.infer(irS, fake("I"));
        assertEquals("I", ts[1]);
    }

    @Test
    public void tiposBucleTermina() {
        int[] units = {0x0138, 4, 0x1012, 0xFD28, 0x000e};
        IrBuilder.MethodIr ir = IrBuilder.build(units, units.length, 2);
        String[] t = IrTypes.infer(ir, fake("I"));
        assertEquals(2, t.length);
        assertEquals("?", t[0]);
        assertEquals("?", t[1]);
    }

    @Test
    public void tiposMalosNoLanzan() {
        assertEquals(0, IrTypes.infer(null, fake("I")).length);
        int[] units = {0x1012, 0x000e};
        IrBuilder.MethodIr ir = IrBuilder.build(units, units.length, 1);
        String[] t = IrTypes.infer(ir, null);
        assertEquals(1, t.length);
        assertEquals("I", t[0]);
        IrBuilder.MethodIr bad = IrBuilder.build(null, 1, 0);
        assertEquals(0, IrTypes.infer(bad, fake("I")).length);
    }
}
