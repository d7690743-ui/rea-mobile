package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.LinkedHashSet;
import org.junit.Test;

/** ALFA-2: layouts, entradas verificadas y handlers. */
public class AlfaUiTest {

    static final String LAYOUT = "<LinearLayout>\n"
            + "<TextView android:id=\"@+id/titulo\" />\n"
            + "<Button android:id=\"@+id/ok\" android:onClick=\"enviar\" />\n"
            + "<com.x.MiVista android:id=\"@+id/rara\" />\n"
            + "<include layout=\"@layout/fila\" />\n"
            + "</LinearLayout>\n";

    @Test
    public void parseaLayout() {
        AlfaUi.Screen s = AlfaUi.parseLayout("res/layout/a.xml", LAYOUT);
        assertEquals("res/layout/a.xml", s.layout);
        assertEquals(4, s.views);
        assertEquals(Arrays.asList("titulo", "ok", "rara"), s.ids);
        assertEquals(Arrays.asList("enviar"), s.handlers);
        assertEquals(Arrays.asList("com.x.MiVista"), s.customViews);
        assertEquals(Arrays.asList("fila"), s.includes);
    }

    @Test
    public void entradasVerificadas() {
        RefGraph g = new RefGraph();
        DexCalls.Edge e1 = new DexCalls.Edge();
        e1.caller = "Lcom/x/Main;->onCreate";
        e1.callee = "Ljava/lang/System;->loadLibrary";
        DexCalls.Edge e2 = new DexCalls.Edge();
        e2.caller = "Lcom/x/Help;->run";
        e2.callee = "Ljava/lang/System;->loadLibrary";
        g.addAll(Arrays.asList(e1, e2));
        java.util.Set<String> manifest = new LinkedHashSet<>();
        manifest.add("Lcom/x/Main;");
        assertEquals(Arrays.asList("Lcom/x/Main;->onCreate"),
                AlfaUi.verifiedEntries(g, manifest));
        assertTrue(AlfaUi.verifiedEntries(g, null).isEmpty());
        assertTrue(AlfaUi.verifiedEntries(null, manifest).isEmpty());
    }

    @Test
    public void handlersPorNombre() {
        RefGraph g = new RefGraph();
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = "Lcom/x/Main;->enviar";
        e.callee = "Ljava/lang/System;->loadLibrary";
        g.add(e);
        assertEquals(Arrays.asList("Lcom/x/Main;->enviar"),
                AlfaUi.handlerCallers(g, "enviar"));
        assertTrue(AlfaUi.handlerCallers(g, "otro").isEmpty());
        assertTrue(AlfaUi.handlerCallers(g, null).isEmpty());
    }

    @Test
    public void exportadosADescriptor() {
        java.util.Set<String> out = AlfaUi.exportedDescriptors(
                Arrays.asList("activity:com.x.Main", "receiver:.Boot", "mal"),
                "com.x");
        assertTrue(out.contains("Lcom/x/Main;"));
        assertTrue(out.contains("Lcom/x/Boot;"));
        assertNotNull(AlfaUi.exportedDescriptors(null, null));
    }

    @Test
    public void basuraNoLanza() {
        assertNotNull(AlfaUi.parseLayout(null, null).ids);
        assertTrue(AlfaUi.parseLayout("l", "").views == 0);
        assertTrue(AlfaUi.parseLayout("l", "hola").handlers.isEmpty());
    }
}
