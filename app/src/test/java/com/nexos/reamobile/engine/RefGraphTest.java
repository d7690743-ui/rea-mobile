package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.nexos.reamobile.intelligence.IntelFinding;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipOutputStream;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * OMEGA Fase B: índice de llamadas sobre aristas DexCalls.
 * Sintético + DEX reales (invoke a Runtime.exec y métodos iv/ip/q5).
 */
public class RefGraphTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    static DexCalls.Edge mkEdge(String caller, String callee, String dex, int pos) {
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = caller;
        e.callee = callee;
        e.dex = dex;
        e.pos = pos;
        return e;
    }

    @Test
    public void llamadaInternaYConsultas() {
        List<DexCalls.Edge> in = new ArrayList<>();
        in.add(mkEdge("Lcom/x/A;->a", "Lcom/x/A;->b", "classes.dex", 3));
        RefGraph g = RefGraph.from(in);
        assertEquals(1, g.edgeCount());
        assertEquals(2, g.nodeCount());
        assertTrue(g.containsMethod("Lcom/x/A;->a"));
        assertTrue(g.containsMethod("Lcom/x/A;->b"));
        assertEquals(1, g.callersOf("Lcom/x/A;->b").size());
        assertEquals("Lcom/x/A;->a", g.callersOf("Lcom/x/A;->b").get(0));
        assertEquals(1, g.calleesOf("Lcom/x/A;->a").size());
        assertEquals(1, g.edgesFrom("Lcom/x/A;", "a").size());
        RefGraph.RefEdge e = g.edgesFrom("Lcom/x/A;", "a").get(0);
        assertEquals("Lcom/x/A;", e.callerClass);
        assertEquals("a", e.callerMethod);
        assertEquals("Lcom/x/A;", e.calleeClass);
        assertEquals("b", e.calleeMethod);
        assertEquals("classes.dex", e.dex);
        assertEquals(3, e.pos);
        assertTrue(!g.truncated());
    }

    @Test
    public void llamadaExternaYMultiplesCallers() {
        List<DexCalls.Edge> in = new ArrayList<>();
        in.add(mkEdge("Lcom/x/A;->a", "Ljava/lang/Runtime;->exec", "classes.dex", 0));
        in.add(mkEdge("Lcom/x/B;->c", "Ljava/lang/Runtime;->exec", "classes2.dex", 7));
        RefGraph g = RefGraph.from(in);
        List<String> callers = g.callersOf("Ljava/lang/Runtime;->exec");
        assertEquals(2, callers.size());
        assertTrue(callers.contains("Lcom/x/A;->a"));
        assertTrue(callers.contains("Lcom/x/B;->c"));
        assertTrue(g.calleesOf("Ljava/lang/Runtime;->exec").isEmpty());
    }

    @Test
    public void sinLlamadasYDesconocidos() {
        RefGraph g = new RefGraph();
        assertEquals(0, g.edgeCount());
        assertFalse(g.containsMethod("Lcom/x/A;->a"));
        assertTrue(g.callersOf("Lcom/x/A;->a").isEmpty());
        assertTrue(g.calleesOf(null).isEmpty());
        assertTrue(g.callersOf(null).isEmpty());
        assertTrue(g.edgesFrom(null, null).isEmpty());
        assertTrue(g.edgesFrom("Lcom/x/A;", "zzz").isEmpty());
        assertFalse(g.add(null));
        assertTrue(g.truncated());
    }

    @Test
    public void duplicadosMismoSitioColapsan() {
        List<DexCalls.Edge> in = new ArrayList<>();
        in.add(mkEdge("Lcom/x/A;->a", "Lcom/x/A;->b", "classes.dex", 3));
        in.add(mkEdge("Lcom/x/A;->a", "Lcom/x/A;->b", "classes.dex", 3));
        in.add(mkEdge("Lcom/x/A;->a", "Lcom/x/A;->b", "classes.dex", 9));
        RefGraph g = RefGraph.from(in);
        assertEquals(2, g.edgeCount());
        assertEquals(1, g.callersOf("Lcom/x/A;->b").size());
        assertTrue(!g.truncated());
    }

    @Test
    public void topeTruncaYCuenta() {
        List<DexCalls.Edge> in = new ArrayList<>();
        in.add(mkEdge("Lcom/x/A;->a", "Lcom/x/A;->b", "d", 0));
        in.add(mkEdge("Lcom/x/A;->a", "Lcom/x/A;->c", "d", 1));
        in.add(mkEdge("Lcom/x/A;->a", "Lcom/x/A;->e", "d", 2));
        RefGraph g = RefGraph.from(in, 2);
        assertEquals(2, g.edgeCount());
        assertEquals(1, g.dropped());
        assertTrue(g.truncated());
    }

    @Test
    public void topCallersOrdenado() {
        List<DexCalls.Edge> in = new ArrayList<>();
        in.add(mkEdge("Lcom/x/A;->a", "Lcom/x/X;->x", "d", 0));
        in.add(mkEdge("Lcom/x/A;->a", "Lcom/x/Y;->y", "d", 1));
        in.add(mkEdge("Lcom/x/A;->a", "Lcom/x/Z;->z", "d", 2));
        in.add(mkEdge("Lcom/x/B;->b", "Lcom/x/X;->x", "d", 3));
        RefGraph g = RefGraph.from(in);
        List<String> top = g.topCallers(5);
        assertEquals(2, top.size());
        assertEquals("Lcom/x/A;->a", top.get(0));
        assertEquals("Lcom/x/B;->b", top.get(1));
    }

    @Test
    public void dexRealQuienLlamaAExec() {
        byte[] dex = DexCallsTest.buildInvokeDex();
        DexCalls.Result r = DexCalls.collect(dex, null, "classes.dex");
        assertEquals(1, r.edges.size());
        assertEquals("classes.dex", r.edges.get(0).dex);
        assertEquals(0, r.edges.get(0).pos);
        RefGraph g = RefGraph.from(r.edges);
        List<String> callers = g.callersOf("Ljava/lang/Runtime;->exec");
        assertEquals(1, callers.size());
        assertEquals("Lcom/x/A;->foo", callers.get(0));
        assertTrue(g.containsMethod("Lcom/x/A;->foo"));
    }

    @Test
    public void dexRealMultiplesCallers() {
        byte[] dex = SmaliExtractTest.buildTestDex();
        RefGraph g = RefGraph.from(DexCalls.collect(dex, null, "classes.dex").edges);
        List<String> callers = g.callersOf("Lcom/x/A;->foo");
        assertEquals(3, callers.size());
        assertTrue(callers.contains("Lcom/x/A;->iv"));
        assertTrue(callers.contains("Lcom/x/A;->ip"));
        assertTrue(callers.contains("Lcom/x/A;->q5"));
        assertEquals(1, g.calleesOf("Lcom/x/A;->ip").size());
        assertEquals(1, g.edgesFrom("Lcom/x/A;", "ip").size());
        assertEquals("classes.dex", g.edgesFrom("Lcom/x/A;", "ip").get(0).dex);
        // br no llama ni es llamado: fuera del grafo.
        assertFalse(g.containsMethod("Lcom/x/A;->br"));
        assertFalse(g.containsMethod("Lcom/x/A;->nope"));
    }

    @Test
    public void informeYRegistro() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        List<DexCalls.Edge> in = new ArrayList<>();
        in.add(mkEdge("Lcom/x/A;->foo", "Ljava/lang/Runtime;->exec", "classes.dex", 0));
        r.graph.addAll(in);
        ReaEngine.feedIntel(r);
        String txt = r.toText();
        assertTrue(txt, txt.contains("=== GRAFO (nodos=2 aristas=1) ==="));
        assertTrue(txt, txt.contains("exec<=Lcom/x/A;->foo"));
        assertTrue(txt, txt.contains("top=Lcom/x/A;->foo llama 1"));
        List<IntelFinding> gf = r.intel.byCategory("grafo");
        assertEquals(1, gf.size());
        assertEquals("Lcom/x/A;", gf.get(0).className);
        assertEquals("foo", gf.get(0).methodName);
        assertEquals(IntelFinding.Confidence.MEDIUM, gf.get(0).confidence);
        assertTrue(gf.get(0).limitations.contains("no observada"));
        // Vacío: sección explícita sin llamadas.
        ReaEngine.ApkReport v = new ReaEngine.ApkReport();
        assertTrue(v.toText().contains("exec<=(nadie detectado)"));
    }

    @Test
    public void grafoResueltoPorSuperclase() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        List<DexCalls.Edge> in = new ArrayList<>();
        in.add(mkEdge("Lcom/x/A;->cfg", "Lcom/x/W;->addJavascriptInterface", "classes.dex", 0));
        r.graph.addAll(in);
        r.superMap.put("Lcom/x/W;", "Landroid/webkit/WebView;");
        ReaEngine.feedIntel(r);
        assertEquals(1, r.intel.byCategory("grafo").size());
    }

    @Test
    public void endToEndExecEnInforme() throws Exception {
        File apk = new File(tmp.getRoot(), "exec.apk");
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk));
        SmaliExtractTest.put(zos, "AndroidManifest.xml", "no-es-axml".getBytes(StandardCharsets.UTF_8));
        SmaliExtractTest.put(zos, "classes.dex", DexCallsTest.buildInvokeDex());
        zos.close();
        ReaEngine.ApkReport r = ReaEngine.analyze(apk);
        assertEquals(1, r.graph.edgeCount());
        assertEquals("Lcom/x/A;->foo", r.graph.callersOf("Ljava/lang/Runtime;->exec").get(0));
        assertTrue(r.toText().contains("exec<=Lcom/x/A;->foo"));
        assertEquals(1, r.intel.byCategory("grafo").size());
    }
}
