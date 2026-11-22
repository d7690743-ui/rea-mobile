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
    public void ordenaClasesPorClaseExternaYJavaPorNombre() {
        List<String> c = new ArrayList<>();
        c.add("Lcom/x/B;");
        c.add("Lcom/x/A$2;");
        c.add("Lcom/x/A;");
        c.add("Lcom/x/A$1;");
        Map<String, String> m = new LinkedHashMap<>();
        m.put("com.x.B", "class B {}\n");
        m.put("com.x.A", "class A {}\n");
        FullReport.Result r = FullReport.build("com.x", null, c, m);
        String t = r.text;
        // A, A$1, A$2 juntas y antes de B.
        assertTrue(t.indexOf("Lcom/x/A;") < t.indexOf("Lcom/x/A$1;"));
        assertTrue(t.indexOf("Lcom/x/A$1;") < t.indexOf("Lcom/x/A$2;"));
        assertTrue(t.indexOf("Lcom/x/A$2;") < t.indexOf("Lcom/x/B;"));
        assertTrue(t.indexOf("class A {}") < t.indexOf("class B {}"));
    }

    @Test
    public void quitaComentarioConRutaLocal() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("com.x.A", "package com.x;\n\n"
                + "/* loaded from: /data/user/0/com.nexos.reamobile/cache/dexparts/part1.dex */\n"
                + "/* otro comentario que se conserva */\npublic class A {}\n");
        FullReport.Result r = FullReport.build("com.x", null, null, m);
        assertTrue(!r.text.contains("loaded from"));
        assertTrue(!r.text.contains("/data/user/0"));
        assertTrue(r.text.contains("otro comentario que se conserva"));
        assertTrue(r.text.contains("public class A {}"));
        assertEquals(1, r.javaFiles);
    }

    @Test
    public void incluyeInformeEstaticoYBuildAntesDelArbol() {
        FullReport.Extras x = new FullReport.Extras();
        x.build = "0.4.0 · 1a2b3c4d";
        x.staticReport = "REA Mobile v0.4 — informe estático\n=== MANIFEST ===\n<manifest/>";
        FullReport.Result r = FullReport.build("com.x", tree(), classes(), java(), x);
        assertTrue(r.staticIncluded);
        assertTrue(r.text.contains("(build 0.4.0 · 1a2b3c4d)"));
        assertTrue(r.text.contains("=== INFORME ESTATICO"));
        assertTrue(r.text.contains("<manifest/>"));
        assertTrue(r.text.indexOf("=== INFORME ESTATICO") < r.text.indexOf("=== ARBOL"));
        // Sin extras no aparece nada nuevo.
        FullReport.Result sin = FullReport.build("com.x", tree(), classes(), java());
        assertTrue(!sin.staticIncluded);
        assertTrue(!sin.text.contains("INFORME ESTATICO"));
        assertTrue(!sin.text.contains("(build "));
    }

    @Test
    public void smaliDeRespaldoSoloParaClasesSinJava() {
        List<String> c = new ArrayList<>();
        c.add("Lcom/x/A;");
        c.add("Lcom/x/Z;");
        c.add("Lcom/x/Z$1;");
        Map<String, String> m = new LinkedHashMap<>();
        m.put("com.x.A", "class A {}\n");
        final List<String> pedidas = new ArrayList<>();
        FullReport.Extras x = new FullReport.Extras();
        x.smali = new FullReport.SmaliProvider() {
            @Override
            public String smali(String d) {
                pedidas.add(d);
                return ".class public " + d + "\n";
            }
        };
        FullReport.Result r = FullReport.build("com.x", null, c, m, x);
        assertTrue(r.text.contains("=== SMALI DE RESPALDO (2 clases sin Java)"));
        assertTrue(r.text.contains("===== smali: Lcom/x/Z; ====="));
        assertTrue(r.text.contains("===== smali: Lcom/x/Z$1; ====="));
        assertTrue(!r.text.contains("===== smali: Lcom/x/A; ====="));
        assertEquals(2, r.smaliFiles);
        assertEquals(2, pedidas.size());
        assertTrue(!pedidas.contains("Lcom/x/A;"));
    }

    @Test
    public void smaliRespetaTopeYProveedorQueFalla() {
        List<String> c = new ArrayList<>();
        c.add("Lcom/x/A;");
        c.add("Lcom/x/B;");
        c.add("Lcom/x/C;");
        FullReport.Extras x = new FullReport.Extras();
        x.maxSmaliClasses = 1;
        x.smali = new FullReport.SmaliProvider() {
            @Override
            public String smali(String d) {
                if (d.endsWith("A;")) throw new IllegalStateException("falla");
                return ".class " + d + "\n";
            }
        };
        FullReport.Result r = FullReport.build("com.x", null, c, new LinkedHashMap<String, String>(), x);
        assertEquals(1, r.smaliFiles);
        assertTrue(r.smaliTruncated);
        assertEquals(3, r.smaliTotal);
        assertTrue(r.text.contains("===== smali: Lcom/x/B; ====="));
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
