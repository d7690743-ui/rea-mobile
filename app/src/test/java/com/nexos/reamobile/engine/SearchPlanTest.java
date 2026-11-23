package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import org.junit.Test;

/** Fase D: perfil de APK + plan de búsqueda RAG + cobertura honesta. */
public class SearchPlanTest {

    static SearchPlan.Signals sig() {
        SearchPlan.Signals s = new SearchPlan.Signals();
        return s;
    }

    @Test
    public void perfiles() {
        assertEquals(SearchPlan.Profile.SENCILLO, SearchPlan.classify(sig()));
        assertEquals(SearchPlan.Profile.SENCILLO, SearchPlan.classify(null));
        SearchPlan.Signals b = sig();
        b.classes = 2000;
        assertEquals(SearchPlan.Profile.MEDIANO, SearchPlan.classify(b));
        SearchPlan.Signals c = sig();
        c.dexCount = 6;
        c.classes = 37000;
        assertEquals(SearchPlan.Profile.GRANDE, SearchPlan.classify(c));
        SearchPlan.Signals e = sig();
        e.classes = 37000;
        e.ratio = 0.93;
        assertEquals(SearchPlan.Profile.OFUSCADO, SearchPlan.classify(e));
        SearchPlan.Signals p = sig();
        p.classes = 100;
        p.packers = Arrays.asList("jiagu");
        assertEquals(SearchPlan.Profile.OFUSCADO, SearchPlan.classify(p));
        SearchPlan.Signals d = sig();
        d.classes = 5600;
        d.ratio = 0.41;
        d.nativeLibs = Arrays.asList("lib/arm64-v8a/libchrome.so (ARM64)");
        assertEquals(SearchPlan.Profile.FRAMEWORK, SearchPlan.classify(d));
        SearchPlan.Signals u = sig();
        u.classes = 3000;
        u.frameworks = Arrays.asList("Unity");
        assertEquals(SearchPlan.Profile.FRAMEWORK, SearchPlan.classify(u));
    }

    @Test
    public void ordenPlan() {
        assertEquals("identidad", SearchPlan.planFor(SearchPlan.Profile.SENCILLO).get(0).id);
        assertEquals("identidad", SearchPlan.planFor(SearchPlan.Profile.MEDIANO).get(0).id);
        assertEquals("dex", SearchPlan.planFor(SearchPlan.Profile.GRANDE).get(0).id);
        assertEquals("nativas", SearchPlan.planFor(SearchPlan.Profile.FRAMEWORK).get(0).id);
        assertEquals("ofuscacion", SearchPlan.planFor(SearchPlan.Profile.OFUSCADO).get(0).id);
        for (SearchPlan.Profile pr : SearchPlan.Profile.values()) {
            List<SearchPlan.Check> plan = SearchPlan.planFor(pr);
            assertEquals(20, plan.size());
            assertEquals(20, new HashSet<String>(ids(plan)).size());
        }
        assertTrue(SearchPlan.noteFor(SearchPlan.Profile.GRANDE).length() > 0);
        assertTrue(SearchPlan.noteFor(SearchPlan.Profile.FRAMEWORK).length() > 0);
        assertTrue(SearchPlan.noteFor(SearchPlan.Profile.OFUSCADO).length() > 0);
    }

    static List<String> ids(List<SearchPlan.Check> plan) {
        java.util.ArrayList<String> o = new java.util.ArrayList<>();
        for (SearchPlan.Check c : plan) o.add(c.id);
        return o;
    }

    @Test
    public void coberturaVacia() {
        SearchPlan.Plan plan = SearchPlan.build(new ReaEngine.ApkReport());
        assertEquals(SearchPlan.Profile.SENCILLO, plan.profile);
        assertEquals(20, plan.checks.size());
        assertEquals(SearchPlan.State.UNSUPPORTED, estado(plan, "taint"));
        assertEquals(SearchPlan.State.UNSUPPORTED, estado(plan, "dinamico"));
        assertEquals(SearchPlan.State.NOT_EXECUTED, estado(plan, "fuentes"));
        assertEquals(SearchPlan.State.NOT_FOUND_IN_SCOPE, estado(plan, "red"));
        assertEquals(SearchPlan.State.NOT_FOUND_IN_SCOPE, estado(plan, "identidad"));
    }

    @Test
    public void coberturaConDatos() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.packageName = "com.brave.browser";
        r.sha256 = "fa973ab965632ca5d0d93683e9bc5d82dd60f9b82fec8ca9fa3aba1de408ef57";
        r.fileSize = 258961610L;
        r.dexFiles.add("classes.dex (3598564 B)");
        r.totalClasses = 5649;
        r.obfuscatedRatio = 0.41;
        r.nativeLibs.add("lib/arm64-v8a/libchrome.so (ARM64)");
        r.urlTotal = 425;
        r.secretHighTotal = 65;
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = "Lorg/chromium/A;->a";
        e.callee = "Ljavax/crypto/Cipher;->doFinal";
        r.graph.addAll(Arrays.asList(e));
        r.suspiciousApis.add("Ljavax/crypto/Cipher;->doFinal");
        SearchPlan.Plan plan = SearchPlan.build(r);
        assertEquals(SearchPlan.Profile.FRAMEWORK, plan.profile);
        assertEquals(SearchPlan.State.FOUND, estado(plan, "apis"));
        assertEquals("1 apis, 0 llamadas", detalle(plan, "apis"));
        assertEquals("ratio 0.41", detalle(plan, "ofuscacion"));
        assertEquals(SearchPlan.State.FOUND, estado(plan, "identidad"));
        assertEquals(SearchPlan.State.FOUND, estado(plan, "red"));
        assertEquals(SearchPlan.State.FOUND, estado(plan, "secretos"));
        assertEquals(SearchPlan.State.FOUND, estado(plan, "cripto"));
        assertEquals(SearchPlan.State.PARTIAL, estado(plan, "nativas"));
        assertEquals(SearchPlan.State.FOUND, estado(plan, "ofuscacion"));
    }

    @Test
    public void coberturaPackerEsOfuscado() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.totalClasses = 5000;
        r.packers.add("jiagu");
        SearchPlan.Plan plan = SearchPlan.build(r);
        assertEquals(SearchPlan.Profile.OFUSCADO, plan.profile);
        assertEquals(SearchPlan.State.FOUND, estado(plan, "ofuscacion"));
    }

    @Test
    public void malosNoLanzan() {
        SearchPlan.Plan plan = SearchPlan.build(null);
        assertEquals(SearchPlan.Profile.SENCILLO, plan.profile);
        assertEquals(20, plan.checks.size());
        for (SearchPlan.CheckState c : plan.checks) {
            assertEquals(SearchPlan.State.NOT_EXECUTED, c.state);
        }
        assertTrue(SearchPlan.planFor(null).size() == 20);
    }

    static SearchPlan.State estado(SearchPlan.Plan plan, String id) {
        for (SearchPlan.CheckState c : plan.checks) {
            if (id.equals(c.id)) return c.state;
        }
        return null;
    }

    static String detalle(SearchPlan.Plan plan, String id) {
        for (SearchPlan.CheckState c : plan.checks) {
            if (id.equals(c.id)) return c.detail;
        }
        return null;
    }
}
