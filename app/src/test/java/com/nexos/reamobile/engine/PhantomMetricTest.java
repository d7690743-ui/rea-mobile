package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

/** PHANTOM métrica: completitud por función y distribución. */
public class PhantomMetricTest {

    @Test
    public void scoreYDistribucion() {
        PhantomGroup.FuncGroup g = new PhantomGroup.FuncGroup();
        g.id = "FN-01";
        g.states = new int[]{2, 2, 2, 0, 2, 2, 0, 0};
        assertEquals(5, PhantomMetric.score(g));
        PhantomGroup.FuncGroup h = new PhantomGroup.FuncGroup();
        h.id = "FN-02";
        h.states = new int[]{2, 0, 1, 0, 0, 0, 0, 0};
        assertEquals(1, PhantomMetric.score(h));
        List<PhantomGroup.FuncGroup> gs = new ArrayList<PhantomGroup.FuncGroup>(
                Arrays.asList(g, h));
        assertEquals("2 funciones: 0 ≥6/8, 1 4-5/8, 1 ≤3/8",
                PhantomMetric.distribution(gs));
        assertTrue(PhantomMetric.summarize(gs).toString().contains("entradas=OK"));
        assertEquals(0, PhantomMetric.score(null));
        assertEquals("0 funciones", PhantomMetric.distribution(null));
    }

    @Test
    public void completaDatosYStoreYNativo() {
        Set<String> manifest = new LinkedHashSet<>(Arrays.asList("Lcom/x/Main;"));
        List<PhantomGroup.FuncGroup> gs = PhantomGroup.group(
                PhantomGroupTest.demoGraph(), manifest, null, null, null, null);
        assertEquals(1, gs.size());
        PhantomData.DataHit dh = new PhantomData.DataHit();
        dh.kind = "parcelable";
        dh.detail = "Lcom/x/Api;->writeToParcel";
        dh.evidence = "";
        PhantomStore.StoreHit sh = new PhantomStore.StoreHit();
        sh.kind = "sql";
        sh.detail = "SELECT *";
        sh.evidence = "cargado por com/x/Main;->onCreate";
        AlfaJni.JniLink jl = new AlfaJni.JniLink();
        jl.callers.add("Lcom/x/Api;->fetch");
        PhantomMetric.completeStates(gs,
                new ArrayList<PhantomData.DataHit>(Arrays.asList(dh)),
                new ArrayList<PhantomStore.StoreHit>(Arrays.asList(sh)),
                new ArrayList<AlfaJni.JniLink>(Arrays.asList(jl)), null);
        PhantomGroup.FuncGroup g = gs.get(0);
        assertEquals(PhantomGroup.OK, g.states[7]);
        assertTrue(PhantomMetric.score(g) >= 2);
        PhantomMetric.completeStates(null, null, null, null, null);
    }

    @Test
    public void casaPorClase() {
        PhantomGroup.FuncGroup g = new PhantomGroup.FuncGroup();
        g.id = "FN-01";
        g.methodSample.add("Lcom/x/Main;->onCreate");
        g.classSample.add("Lcom/x/Db;");
        PhantomStore.StoreHit sh = new PhantomStore.StoreHit();
        sh.kind = "sqlite-helper";
        sh.detail = "Lcom/x/Db;";
        sh.evidence = "hereda SQLiteOpenHelper";
        PhantomData.DataHit dh = new PhantomData.DataHit();
        dh.kind = "proto-model";
        dh.detail = "Lcom/x/Db;";
        dh.evidence = "protobuf";
        List<PhantomGroup.FuncGroup> gs = new ArrayList<PhantomGroup.FuncGroup>(
                Arrays.asList(g));
        PhantomMetric.completeStates(gs,
                new ArrayList<PhantomData.DataHit>(Arrays.asList(dh)),
                new ArrayList<PhantomStore.StoreHit>(Arrays.asList(sh)), null, null);
        assertEquals(PhantomGroup.OK, g.states[3]);
        assertEquals(PhantomGroup.OK, g.states[6]);
    }

    @Test
    public void cierreExactoLevantaCampos() {
        String e = "Lcom/x/Main;->onCreate";
        String m = "Lcom/x/Repo;->get";
        String u = "Lcom/x/Repo;->query";
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(
                PhantomNetTest.edge(e, m),
                PhantomNetTest.edge(m, u),
                PhantomNetTest.edge(u, "Lcom/x/Db;->rawQuery"),
                PhantomNetTest.edge(m, "Lcom/x/Msg;->getId"))));
        PhantomGroup.FuncGroup fg = new PhantomGroup.FuncGroup();
        fg.id = "FN-01";
        fg.entries.add(e);
        PhantomMetric.Closure c = PhantomMetric.closureFor(g, fg);
        assertTrue(c.methods.contains(u));
        assertTrue(c.calleeClasses.contains("Lcom/x/Db;"));
        assertTrue(!c.methods.contains("Lcom/x/Otro;->zzz"));
        assertTrue(PhantomMetric.inClosure("Lcom/x/Db;", "hereda X", c));
        assertTrue(!PhantomMetric.inClosure("Lcom/x/Otro;", "", c));
        assertEquals("Lcom/x/A;->a",
                PhantomMetric.evidenceUser("cargado por Lcom/x/A;->a"));
        assertTrue(PhantomMetric.evidenceUser("sin usuario") == null);
        assertEquals("Lcom/x/A;", PhantomMetric.classOf("Lcom/x/A;->a"));
        PhantomStore.StoreHit sh = new PhantomStore.StoreHit();
        sh.kind = "sqlite-helper";
        sh.detail = "Lcom/x/Db;";
        sh.evidence = "hereda SQLiteOpenHelper";
        PhantomData.DataHit dh = new PhantomData.DataHit();
        dh.kind = "proto-model";
        dh.detail = "Lcom/x/Msg;";
        dh.evidence = "protobuf";
        List<PhantomGroup.FuncGroup> gs = new ArrayList<PhantomGroup.FuncGroup>(
                Arrays.asList(fg));
        PhantomMetric.completeStates(gs,
                new ArrayList<PhantomData.DataHit>(Arrays.asList(dh)),
                new ArrayList<PhantomStore.StoreHit>(Arrays.asList(sh)), null, null, g);
        assertEquals(PhantomGroup.OK, fg.states[6]);
        assertEquals(PhantomGroup.OK, fg.states[3]);
    }
}
