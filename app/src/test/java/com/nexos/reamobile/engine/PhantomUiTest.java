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

/** PHANTOM UI: setContentView, handlers y Compose. */
public class PhantomUiTest {

    private static RefGraph graph(String caller, String callee) {
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = caller;
        e.callee = callee;
        e.dex = "classes.dex";
        e.pos = 0;
        return RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(e)));
    }

    @Test
    public void resuelveSetContentView() {
        String act = "Lcom/x/Main;->onCreate";
        RefGraph g = graph(act, "Landroid/app/Activity;->setContentView");
        Set<String> manifest = new LinkedHashSet<>(Arrays.asList("Lcom/x/Main;"));
        PhantomUi.UiResult r = PhantomUi.resolve(g, manifest,
                new ArrayList<AlfaUi.Screen>(), new LinkedHashMap<String, IrBuilder.MethodIr>());
        assertEquals(1, r.contentViews.size());
        assertEquals("Lcom/x/Main;", r.contentViews.get(0).className);
        assertTrue(r.contentViews.get(0).inManifest);
    }

    @Test
    public void idDeLayoutPorIR() {
        String act = "Lcom/x/Main;->onCreate";
        IrBuilder.MethodIr ir = new IrBuilder.MethodIr();
        ir.regs = 2;
        IrBuilder.Insn l = DefUseTest.insn(0, 0x12, 0);
        l.hasLit = true;
        l.lit = 0x7f0b001cL;
        IrBuilder.Insn inv = DefUseTest.insn(2, 0x6E, 0);
        IrBuilder.Insn ret = DefUseTest.insn(5, 0x0E);
        ret.isReturn = true;
        ir.blocks.add(DefUseTest.block(0, new int[]{}, l, inv, ret));
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = act;
        e.callee = "Landroid/app/Activity;->setContentView";
        e.dex = "classes.dex";
        e.pos = 2;
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(e)));
        Map<String, IrBuilder.MethodIr> irs = new LinkedHashMap<>();
        irs.put(act, ir);
        String id = PhantomUi.layoutArg(g, act, RefGraph.split(act), irs);
        assertEquals("0x7f0b001c", id);
    }

    @Test
    public void handlersYCompose() {
        DexCalls.Edge e1 = new DexCalls.Edge();
        e1.caller = "Lcom/x/Main;->onGo";
        e1.callee = "Lcom/x/B;->foo";
        e1.dex = "classes.dex";
        DexCalls.Edge e2 = new DexCalls.Edge();
        e2.caller = "Lcom/x/Ui;->render";
        e2.callee = "Landroidx/compose/runtime/Composer;->start";
        e2.dex = "classes.dex";
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(e1, e2)));
        AlfaUi.Screen s = new AlfaUi.Screen();
        s.layout = "res/layout/main.xml";
        s.handlers.add("onGo");
        PhantomUi.UiResult r = PhantomUi.resolve(g, new LinkedHashSet<String>(),
                new ArrayList<AlfaUi.Screen>(Arrays.asList(s)),
                new LinkedHashMap<String, IrBuilder.MethodIr>());
        assertEquals(1, r.handlers.size());
        assertEquals("onGo", r.handlers.get(0).handler);
        assertEquals(1, r.composeCalls);
        assertTrue(r.composeCallers.contains("Lcom/x/Ui;->render"));
        List<String> lines = PhantomUi.summarize(r);
        assertTrue(lines.toString(), lines.toString().contains("compose: 1 llamadas"));
    }

    @Test
    public void claseLlamadaYAprox() {
        String act = "Lcom/x/Main;->onCreate";
        IrBuilder.MethodIr ir = new IrBuilder.MethodIr();
        ir.regs = 2;
        IrBuilder.Insn l = DefUseTest.insn(0, 0x12, 0);
        l.hasLit = true;
        l.lit = 0x7f0b001cL;
        IrBuilder.Insn inv = DefUseTest.insn(2, 0x6E, 0);
        IrBuilder.Insn ret = DefUseTest.insn(5, 0x0E);
        ret.isReturn = true;
        ir.blocks.add(DefUseTest.block(0, new int[]{}, l, inv, ret));
        assertEquals("0x7f0b001c", PhantomUi.layoutApprox(ir));
        assertEquals("", PhantomUi.layoutApprox(null));
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = act;
        e.callee = "Landroidx/appcompat/app/AppCompatActivity;->setContentView";
        e.dex = "classes.dex";
        e.pos = 99;
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(e)));
        Map<String, IrBuilder.MethodIr> irs = new LinkedHashMap<>();
        irs.put(act, ir);
        PhantomUi.UiResult r = PhantomUi.resolve(g, new LinkedHashSet<String>(),
                new ArrayList<AlfaUi.Screen>(), irs);
        assertEquals(1, r.contentViews.size());
        assertEquals("Landroidx/appcompat/app/AppCompatActivity;",
                r.contentViews.get(0).calleeClass);
        assertTrue(r.contentViews.get(0).layoutApprox);
        assertTrue(PhantomUi.summarize(r).toString().contains("via AppCompatActivity"));
    }

    @Test
    public void vacioSinLanzar() {
        PhantomUi.UiResult r = PhantomUi.resolve(null, null, null, null);
        assertTrue(r.contentViews.isEmpty());
        assertTrue(PhantomUi.summarize(null).isEmpty());
    }
}
