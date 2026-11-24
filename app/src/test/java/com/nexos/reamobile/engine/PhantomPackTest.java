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

/** PHANTOM orquestador: sección, paquete JSON, intel y prioridad JADX. */
public class PhantomPackTest {

    static ReaEngine.ApkReport demoReport() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.graph = PhantomGroupTest.demoGraph();
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = "Lcom/x/Main;->onCreate";
        e.callee = "Landroid/app/Activity;->setContentView";
        e.dex = "classes.dex";
        e.pos = 9;
        r.graph.add(e);
        r.manifestClasses = new LinkedHashSet<String>(Arrays.asList("Lcom/x/Main;"));
        r.urls = new ArrayList<String>(Arrays.asList("https://api.x.test/u"));
        r.urlOrigin = new LinkedHashMap<String, String>();
        r.urlOrigin.put("https://api.x.test/u", "dex");
        r.manifestPerms = new ArrayList<String>(
                Arrays.asList("android.permission.INTERNET"));
        r.callerPerm = new LinkedHashMap<String, String>();
        r.callerPerm.put("Lcom/x/Api;->fetch", "INTERNET|Lokhttp3/OkHttpClient;->newCall");
        r.stringRefs = StringRefs.from(new ArrayList<DexCalls.StringRef>(Arrays.asList(
                PhantomNetTest.sref("Lcom/x/Api;->fetch", "https://api.x.test/u"),
                PhantomNetTest.sref("Lcom/x/Api;->fetch", "POST"))));
        r.appClasses = new ArrayList<String>(
                Arrays.asList("Lcom/x/Main;", "Lcom/x/Api;", "Lcom/x/UserModel;"));
        return r;
    }

    @Test
    public void orquestadorAgrupaYContrata() {
        ReaEngine.ApkReport r = demoReport();
        Phantom.PhantomResult p = r.phantom();
        assertEquals(1, p.groups.size());
        assertEquals("FN-01", p.groups.get(0).id);
        assertEquals(1, p.contracts.size());
        assertTrue(p.contracts.get(0).verbs.contains("POST"));
        assertEquals(1, p.ui.contentViews.size());
        assertTrue(r.phantom() == p);
    }

    @Test
    public void seccionTextoYBloqueJson() {
        ReaEngine.ApkReport r = demoReport();
        String txt = r.toText();
        assertTrue(txt.contains("=== PHANTOM"));
        assertTrue(txt.contains("FN-01"));
        assertTrue(txt.contains("completitud:"));
        String js = r.toJson();
        assertTrue(js, js.contains("\"phantom\""));
        assertTrue(js, js.contains("FN-01"));
        assertTrue(js, js.contains("\"metric\""));
    }

    @Test
    public void intelRecibeFunciones() {
        ReaEngine.ApkReport r = demoReport();
        ReaEngine.feedIntelPhantom(r);
        boolean fn = false;
        boolean ct = false;
        for (com.nexos.reamobile.intelligence.IntelFinding f : r.intel.all()) {
            if ("funcion".equals(f.category)) fn = true;
            if ("contrato".equals(f.category)) ct = true;
        }
        assertTrue(fn);
        assertTrue(ct);
    }

    @Test
    public void fullReportIncluyePaquete() {
        FullReport.Extras ex = new FullReport.Extras();
        ex.packageJson = "{\"tool\":\"t\"}";
        FullReport.Result r = FullReport.build("com.x", new ArrayList<String>(),
                new ArrayList<String>(), new LinkedHashMap<String, String>(), ex);
        assertTrue(r.packageIncluded);
        assertTrue(r.text.contains("PAQUETE JSON"));
        assertTrue(r.text.contains("{\"tool\":\"t\"}"));
    }

    @Test
    public void prioridadDirigida() {
        ReaEngine.ApkReport r = demoReport();
        List<String> prio = PhantomDecompile.priority(r, 50);
        assertTrue(prio.toString(), prio.contains("Lcom/x/Main;"));
        assertTrue(prio.toString(), prio.contains("Lcom/x/Api;"));
        Set<String> keys = JadxAdapter.priorityKeys(
                new ArrayList<String>(Arrays.asList("Lcom/x/A;", "com.x.B")));
        assertTrue(keys.contains("com.x.A"));
        assertTrue(keys.contains("com.x.B"));
        assertTrue(JadxAdapter.priorityKeys(null).isEmpty());
        assertTrue(PhantomDecompile.priority(null, 10).isEmpty());
    }
}
