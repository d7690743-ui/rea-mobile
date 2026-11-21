package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Pruebas de cosecha sobre Java descompilado (sin fixtures binarias). */
public class JavaHarvestTest {

    static Map<String, String> sample() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("com.x.A", "package com.x;\npublic class A {\n"
                + "  String u = \"https://api.ejemplo.com/v1/player\";\n}\n");
        m.put("com.x.B", "package com.x;\n// AKIAIOSFODNN7EXAMPLE aqui\nclass B{}\n");
        m.put("com.x.Nula", null);
        m.put("com.x.Vacia", "   ");
        return m;
    }

    @Test
    public void buscaSubcadenaConLinea() {
        List<JavaHarvest.Hit> h = JavaHarvest.search(sample(), "api.ejemplo", true, 50);
        assertEquals(1, h.size());
        assertEquals("com.x.A", h.get(0).className);
        assertEquals(3, h.get(0).line);
        assertTrue(h.get(0).snippet.contains("api.ejemplo"));
        assertTrue(JavaHarvest.search(sample(), "", true, 50).isEmpty());
        assertTrue(JavaHarvest.search(null, "x", true, 50).isEmpty());
        assertEquals(1, JavaHarvest.search(sample(), "akiaiosfodnn7example", true, 50).size());
        assertEquals(0, JavaHarvest.search(sample(), "akiaiosfodnn7example", false, 50).size());
        Map<String, String> big = new LinkedHashMap<>();
        big.put("c.D", "x\nx\nx\nx\nx\n");
        assertEquals(3, JavaHarvest.search(big, "x", true, 3).size());
    }

    @Test
    public void secretosAltaSenal() {
        List<JavaHarvest.Hit> h = JavaHarvest.findSecrets(sample(), 50);
        assertEquals(1, h.size());
        assertEquals("com.x.B", h.get(0).className);
        assertEquals(2, h.get(0).line);
        Map<String, String> m = new LinkedHashMap<>();
        m.put("c.E", "String api_key = \"abc123\";\nString token = name;\n");
        List<JavaHarvest.Hit> h2 = JavaHarvest.findSecrets(m, 50);
        assertEquals(1, h2.size());
        assertTrue(JavaHarvest.findSecrets(null, 5).isEmpty());
    }

    @Test
    public void zipIdaYVuelta() {
        JavaHarvest.ZipResult r = JavaHarvest.zip(sample());
        assertNotNull(r.zip);
        assertEquals(2, r.files);
        assertTrue(!r.truncated);
        List<String> names = JavaHarvest.zipNames(r.zip);
        assertTrue(names.toString(), names.contains("com/x/A.java"));
        assertTrue(names.toString(), names.contains("com/x/B.java"));
        JavaHarvest.ZipResult vacio = JavaHarvest.zip(null);
        assertNotNull(vacio.zip);
        assertEquals(0, vacio.files);
    }
}
