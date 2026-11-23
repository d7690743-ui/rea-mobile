package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.nexos.reamobile.intelligence.IntelFinding;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

/**
 * OMEGA red lógica: entradas, alcanzabilidad y cadenas entrada→API sensible
 * sobre RefGraph. Todo sintético (sin DEX).
 */
public class LogicNetTest {

    static RefGraph grafo(String[]... aristas) {
        List<DexCalls.Edge> in = new ArrayList<>();
        int pos = 0;
        for (String[] a : aristas) {
            in.add(RefGraphTest.mkEdge(a[0], a[1], "classes.dex", pos++));
        }
        return RefGraph.from(in);
    }

    @Test
    public void entradasPorNombre() {
        RefGraph g = grafo(
                new String[]{"Lcom/x/A;->onCreate", "Lcom/x/A;->a"},
                new String[]{"Lcom/x/A;->foo", "Lcom/x/A;->b"},
                new String[]{"Lcom/x/A;->run", "Lcom/x/A;->c"});
        List<String> e = LogicNet.entryPoints(g);
        assertEquals(2, e.size());
        assertEquals("Lcom/x/A;->onCreate", e.get(0));
        assertEquals("Lcom/x/A;->run", e.get(1));
        assertTrue(LogicNet.entryPoints(new RefGraph()).isEmpty());
        assertTrue(LogicNet.entryPoints(null).isEmpty());
    }

    @Test
    public void alcanzableConTopes() {
        RefGraph g = grafo(
                new String[]{"Lcom/x/A;->a", "Lcom/x/A;->b"},
                new String[]{"Lcom/x/A;->b", "Lcom/x/A;->c"},
                new String[]{"Lcom/x/A;->c", "Lcom/x/A;->d"});
        LogicNet.Reach r = LogicNet.reachableFrom(g, "Lcom/x/A;->a", 10, 100);
        assertEquals(Arrays.asList("Lcom/x/A;->b", "Lcom/x/A;->c", "Lcom/x/A;->d"), r.nodes);
        assertTrue(!r.truncated);
        LogicNet.Reach d1 = LogicNet.reachableFrom(g, "Lcom/x/A;->a", 1, 100);
        assertEquals(1, d1.nodes.size());
        assertEquals("Lcom/x/A;->b", d1.nodes.get(0));
        // Ciclo termina y no repite.
        RefGraph cyc = grafo(
                new String[]{"Lcom/x/A;->x", "Lcom/x/A;->y"},
                new String[]{"Lcom/x/A;->y", "Lcom/x/A;->x"});
        LogicNet.Reach rc = LogicNet.reachableFrom(cyc, "Lcom/x/A;->x", 10, 100);
        assertEquals(1, rc.nodes.size());
        assertEquals("Lcom/x/A;->y", rc.nodes.get(0));
        // Tope de nodos recorta y marca.
        LogicNet.Reach cap = LogicNet.reachableFrom(g, "Lcom/x/A;->a", 10, 2);
        assertEquals(2, cap.nodes.size());
        assertTrue(cap.truncated);
        assertTrue(LogicNet.reachableFrom(g, "Lcom/x/A;->zzz", 10, 100).nodes.isEmpty());
    }

    @Test
    public void cadenasAExec() {
        RefGraph g = grafo(
                new String[]{"Lcom/x/A;->onCreate", "Lcom/x/A;->foo"},
                new String[]{"Lcom/x/A;->foo", "Ljava/lang/Runtime;->exec"});
        LogicNet.Chains ch = LogicNet.chainsTo(g, "Ljava/lang/Runtime;->exec", 8, 10);
        assertEquals(1, ch.chains.size());
        assertEquals(Arrays.asList("Lcom/x/A;->onCreate", "Lcom/x/A;->foo",
                "Ljava/lang/Runtime;->exec"), ch.chains.get(0));
        assertTrue(!ch.truncated);
        // Llamador sin entrada: explorado entero, sin cadenas, sin recorte.
        RefGraph sin = grafo(
                new String[]{"Lcom/x/A;->foo", "Ljava/lang/Runtime;->exec"});
        LogicNet.Chains ch2 = LogicNet.chainsTo(sin, "Ljava/lang/Runtime;->exec", 8, 10);
        assertTrue(ch2.chains.isEmpty());
        assertTrue(!ch2.truncated);
        assertTrue(LogicNet.chainsTo(g, "Lcom/x/A;->nadie", 8, 10).chains.isEmpty());
    }

    @Test
    public void objetivoPorClaveExacta() {
        RefGraph g = grafo(
                new String[]{"Lcom/x/A;->onCreate", "Lcom/x/A;->foo"},
                new String[]{"Lcom/x/A;->foo", "Ljava/lang/Runtime;->exec"},
                new String[]{"Lcom/x/B;->onCreate", "Lcom/x/B;->bar"},
                new String[]{"Lcom/x/B;->bar", "Lcom/x/Lib;->exec"});
        // Solo la clave exacta; el homónimo de otra clase no contamina.
        LogicNet.Chains ch = LogicNet.chainsTo(g, "Ljava/lang/Runtime;->exec", 8, 10);
        assertEquals(1, ch.chains.size());
        assertEquals("Lcom/x/A;->onCreate", ch.chains.get(0).get(0));
        // Nombre pelado ya no casa con nada (era el bug del <init>).
        assertTrue(LogicNet.chainsTo(g, "exec", 8, 10).chains.isEmpty());
    }

    @Test
    public void cadenasMultiplesYProfundidad() {
        RefGraph g = grafo(
                new String[]{"Lcom/x/A;->onCreate", "Lcom/x/A;->m"},
                new String[]{"Lcom/x/A;->onClick", "Lcom/x/A;->m"},
                new String[]{"Lcom/x/A;->m", "Ljava/lang/Runtime;->exec"});
        LogicNet.Chains ch = LogicNet.chainsTo(g, "Ljava/lang/Runtime;->exec", 8, 10);
        assertEquals(2, ch.chains.size());
        assertEquals("Lcom/x/A;->onCreate", ch.chains.get(0).get(0));
        assertEquals("Lcom/x/A;->onClick", ch.chains.get(1).get(0));
        assertTrue(!ch.truncated);
        // Tope de cadenas: aborta con ramas pendientes y marca.
        LogicNet.Chains c1 = LogicNet.chainsTo(g, "Ljava/lang/Runtime;->exec", 8, 1);
        assertEquals(1, c1.chains.size());
        assertTrue(c1.truncated);
        // Entrada más allá de la profundidad: sin cadena completa, con recorte.
        RefGraph deep = grafo(
                new String[]{"Lcom/x/A;->onCreate", "Lcom/x/A;->a"},
                new String[]{"Lcom/x/A;->a", "Lcom/x/A;->b"},
                new String[]{"Lcom/x/A;->b", "Ljava/lang/Runtime;->exec"});
        LogicNet.Chains cd = LogicNet.chainsTo(deep, "Ljava/lang/Runtime;->exec", 2, 10);
        assertTrue(cd.chains.isEmpty());
        assertTrue(cd.truncated);
    }

    @Test
    public void topCalleesOrdenado() {
        RefGraph g = grafo(
                new String[]{"Lcom/x/A;->a", "Lcom/x/X;->x"},
                new String[]{"Lcom/x/A;->a", "Lcom/x/Y;->y"},
                new String[]{"Lcom/x/A;->a", "Lcom/x/Z;->z"},
                new String[]{"Lcom/x/B;->b", "Lcom/x/X;->x"});
        List<String> top = LogicNet.topCallees(g, 5);
        assertEquals(3, top.size());
        assertEquals("Lcom/x/X;->x", top.get(0));
        assertEquals("Lcom/x/Y;->y", top.get(1));
        assertEquals("Lcom/x/Z;->z", top.get(2));
        assertTrue(LogicNet.topCallees(new RefGraph(), 5).isEmpty());
        assertTrue(LogicNet.topCallees(null, 5).isEmpty());
    }

    @Test
    public void informeYRegistro() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.graph = grafo(
                new String[]{"Lcom/x/A;->onCreate", "Lcom/x/A;->foo"},
                new String[]{"Lcom/x/A;->foo", "Ljava/lang/Runtime;->exec"});
        ReaEngine.feedIntel(r);
        String txt = r.toText();
        assertTrue(txt, txt.contains("=== RED (entradas=1 cadenas=1) ==="));
        assertTrue(txt, txt.contains("entrada=Lcom/x/A;->onCreate alcanza=2"));
        assertTrue(txt, txt.contains("cadena=Lcom/x/A;->onCreate -> Lcom/x/A;->foo"
                + " -> Ljava/lang/Runtime;->exec"));
        assertTrue(txt, txt.contains("hub=Ljava/lang/Runtime;->exec llamado-por=1"));
        List<IntelFinding> cf = r.intel.byCategory("cadena");
        assertEquals(1, cf.size());
        assertEquals("Lcom/x/A;", cf.get(0).className);
        assertEquals("foo", cf.get(0).methodName);
        assertEquals(IntelFinding.Confidence.MEDIUM, cf.get(0).confidence);
        assertTrue(cf.get(0).limitations.contains("no observada"));
        // Vacío: sección explícita sin entradas.
        ReaEngine.ApkReport v = new ReaEngine.ApkReport();
        assertTrue(v.toText().contains("(sin entradas detectadas)"));
    }

    @Test
    public void agrupaColas() {
        List<List<String>> chains = new ArrayList<>();
        chains.add(Arrays.asList("Lcom/x/A;->e1", "Lcom/x/A;->m", "Ljava/lang/Runtime;->exec"));
        chains.add(Arrays.asList("Lcom/x/A;->e2", "Lcom/x/A;->m", "Ljava/lang/Runtime;->exec"));
        chains.add(Arrays.asList("Lcom/x/A;->e3", "Lcom/x/A;->n", "Ljava/lang/Runtime;->exec"));
        List<LogicNet.TrunkGroup> g = LogicNet.groupByTrunk(chains);
        assertEquals(2, g.size());
        assertEquals(3, g.get(0).first.size());
        assertEquals(Arrays.asList("Lcom/x/A;->e1", "Lcom/x/A;->e2"), g.get(0).entries);
        assertEquals(1, g.get(1).entries.size());
        assertTrue(LogicNet.groupByTrunk(null).isEmpty());
    }

    @Test
    public void colasAgrupadasEnInforme() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.graph = grafo(
                new String[]{"Lcom/x/A;->onCreate", "Lcom/x/A;->m"},
                new String[]{"Lcom/x/A;->onClick", "Lcom/x/A;->m"},
                new String[]{"Lcom/x/A;->m", "Ljava/lang/Runtime;->exec"});
        String txt = r.toText();
        assertTrue(txt, txt.contains("-> Ljava/lang/Runtime;->exec x2"));
        assertTrue(txt, txt.contains("desde=Lcom/x/A;->onClick"));
    }

    @Test
    public void entradaVerificadaMarcada() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.graph = grafo(new String[]{"Lcom/x/A;->onCreate", "Lcom/x/A;->foo"});
        r.manifestClasses.add("Lcom/x/A;");
        String txt = r.toText();
        assertTrue(txt, txt.contains("entrada=Lcom/x/A;->onCreate alcanza=1 [manifest]"));
    }

    @Test
    public void malasNoLanzan() {
        RefGraph g = new RefGraph();
        assertTrue(LogicNet.reachableFrom(null, "Lcom/x/A;->a", 8, 100).nodes.isEmpty());
        assertTrue(LogicNet.reachableFrom(g, null, 8, 100).nodes.isEmpty());
        assertTrue(LogicNet.chainsTo(null, "exec", 8, 10).chains.isEmpty());
        assertTrue(LogicNet.chainsTo(g, null, 8, 10).chains.isEmpty());
        assertTrue(LogicNet.chainsTo(g, "", 8, 10).chains.isEmpty());
        // Topes inválidos usan valores por defecto, sin lanzar.
        assertTrue(LogicNet.reachableFrom(g, "Lcom/x/A;->a", 0, 0).nodes.isEmpty());
        assertTrue(LogicNet.topCallees(g, 0).isEmpty());
    }
}
