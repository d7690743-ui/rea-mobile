package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

/** PHANTOM agrupador: funciones FN-## con piezas enlazadas. */
public class PhantomGroupTest {

    static RefGraph demoGraph() {
        return RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(
                PhantomNetTest.edge("Lcom/x/Main;->onCreate", "Lcom/x/Api;->fetch"),
                PhantomNetTest.edge("Lcom/x/Api;->fetch", "Lokhttp3/OkHttpClient;->newCall"),
                PhantomNetTest.edge("Lcom/x/Api;->fetch", "Lcom/x/Db;->save"))));
    }

    @Test
    public void agrupaDesdeEntradas() {
        Set<String> manifest = new LinkedHashSet<>(Arrays.asList("Lcom/x/Main;"));
        StringRefs refs = StringRefs.from(new ArrayList<DexCalls.StringRef>(Arrays.asList(
                PhantomNetTest.sref("Lcom/x/Api;->fetch", "https://api.x.test/u"))));
        Map<String, String> callerPerm = new LinkedHashMap<>();
        callerPerm.put("Lcom/x/Api;->fetch", "INTERNET|Lokhttp3/OkHttpClient;->newCall");
        List<PhantomGroup.FuncGroup> gs = PhantomGroup.group(demoGraph(), manifest,
                new ArrayList<String>(Arrays.asList("https://api.x.test/u")),
                refs, callerPerm, null);
        assertEquals(1, gs.size());
        PhantomGroup.FuncGroup g = gs.get(0);
        assertEquals("FN-01", g.id);
        assertEquals("Main", g.name);
        assertTrue(g.methodTotal >= 3);
        assertTrue(g.urls.contains("https://api.x.test/u"));
        assertTrue(g.perms.contains("INTERNET"));
        assertEquals(PhantomGroup.OK, g.states[0]);
        assertEquals(PhantomGroup.OK, g.states[5]);
        assertTrue(PhantomGroup.summarize(gs).toString().contains("FN-01"));
    }

    @Test
    public void cicloDeVidaAntesQueSinteticos() {
        List<String> in = new ArrayList<String>(Arrays.asList(
                "Lcom/x/A;->access$100", "Lcom/x/A;->foo", "Lcom/x/A;->onCreate"));
        List<String> o = PhantomGroup.orderEntries(in);
        assertEquals(Arrays.asList("Lcom/x/A;->onCreate", "Lcom/x/A;->foo",
                "Lcom/x/A;->access$100"), o);
        assertTrue(PhantomGroup.orderEntries(null).isEmpty());
    }

    @Test
    public void pantallaSinIdEsParcial() {
        Set<String> manifest = new LinkedHashSet<>(Arrays.asList("Lcom/x/Main;"));
        PhantomUi.ContentView cv = new PhantomUi.ContentView();
        cv.className = "Lcom/x/Main;";
        cv.layoutId = "";
        List<PhantomUi.ContentView> cvs =
                new ArrayList<PhantomUi.ContentView>(Arrays.asList(cv));
        List<PhantomGroup.FuncGroup> gs = PhantomGroup.group(demoGraph(), manifest,
                null, null, null, cvs);
        assertEquals(1, gs.size());
        assertEquals(PhantomGroup.PARCIAL, gs.get(0).states[1]);
        assertTrue(gs.get(0).screens.get(0).contains("(layout?)"));
    }

    @Test
    public void sinEntradasSinGrupos() {
        List<PhantomGroup.FuncGroup> gs = PhantomGroup.group(demoGraph(),
                new LinkedHashSet<String>(), null, null, null, null);
        assertTrue(gs.isEmpty());
        assertTrue(PhantomGroup.group(null, null, null, null, null, null).isEmpty());
        assertTrue(PhantomGroup.summarize(null).isEmpty());
    }
}
