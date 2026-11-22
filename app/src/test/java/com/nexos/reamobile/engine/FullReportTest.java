package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Informe completo árbol+clases+java en un solo TXT (sin fixtures binarias). */
public class FullReportTest {

    static List<String> tree() {
        List<String> t = new ArrayList<>();
        t.add("AndroidManifest.xml (1234 B)");
        t.add("classes.dex (5678 B)");
        t.add("res/layout/main.xml (90 B)");
        return t;
    }

    static List<String> classes() {
        List<String> c = new ArrayList<>();
        c.add("Lcom/x/A;");
        c.add("Lcom/x/B$1;");
        return c;
    }

    static Map<String, String> java() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("com.x.A", "package com.x;\npublic class A {}\n");
        m.put("com.x.B", "package com.x;\nclass B {}\n");
        m.put("com.x.Nula", null);
        m.put("com.x.Vacia", "   ");
        return m;
    }

    @Test
    public void incluyeArbolClasesYJava() {
        FullReport.Result r = FullReport.build("com.x", tree(), classes(), java());
        assertNotNull(r.text);
        assertTrue(r.text.contains("=== ARBOL"));
        assertTrue(r.text.contains("AndroidManifest.xml (1234 B)"));
        assertTrue(r.text.contains("=== CLASES"));
        assertTrue(r.text.contains("Lcom/x/A;"));
        assertTrue(r.text.contains("=== JAVA"));
        assertTrue(r.text.contains("com.x.A"));
        assertTrue(r.text.contains("public class A {}"));
        assertEquals(3, r.treeLines);
        assertEquals(2, r.classLines);
        assertEquals(2, r.javaFiles);
        assertTrue(!r.treeTruncated && !r.classesTruncated && !r.javaTruncated);
    }

    @Test
    public void recortaConTopes() {
        FullReport.Result r = FullReport.buildFor("com.x", tree(), classes(), java(),
                2, 1, 1, 100000L);
        assertEquals(2, r.treeLines);
        assertEquals(3, r.treeTotal);
        assertTrue(r.treeTruncated);
        assertEquals(1, r.classLines);
        assertTrue(r.classesTruncated);
        assertEquals(1, r.javaFiles);
        assertTrue(r.javaTruncated);
        assertTrue(r.text.contains("recortado"));
    }

    @Test
    public void recortaPorTamanoJava() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("c.A", "0123456789");
        m.put("c.B", "abcdefghij");
        FullReport.Result r = FullReport.buildFor("?", null, null, m, 10, 10, 10, 15L);
        assertEquals(1, r.javaFiles);
        assertTrue(r.javaTruncated);
    }

    @Test
    public void nulosYVaciosNoLanzan() {
        FullReport.Result r = FullReport.build(null, null, null, null);
        assertNotNull(r.text);
        assertTrue(r.text.contains("paquete=?"));
        assertEquals(0, r.treeLines + r.classLines + r.javaFiles);
        FullReport.Result vacio = FullReport.build("?", new ArrayList<String>(),
                new ArrayList<String>(), new LinkedHashMap<String, String>());
        assertTrue(vacio.text.contains("sin Java"));
    }
}
