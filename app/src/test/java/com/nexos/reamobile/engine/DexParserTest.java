package com.nexos.reamobile.engine;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** Pruebas de heurísticas de DexParser (nombres ofuscados). */
public class DexParserTest {

    @Test
    public void nombresCortos() {
        assertTrue(DexParser.isShortName("Lcom/x/A;"));
        assertTrue(DexParser.isShortName("La;"));
        assertTrue(DexParser.isShortName("LX;"));
        assertTrue(DexParser.isShortName("Lcom/x/a$b;"));
        // R8: minúsculas de 3-5 letras.
        assertTrue(DexParser.isShortName("Lcom/x/aftz;"));
        assertTrue(DexParser.isShortName("Laftz;"));
        assertTrue(DexParser.isShortName("Lcom/x/afwj;"));
        // Nombres reales y framework: no.
        assertTrue(!DexParser.isShortName("Lcom/x/RealName;"));
        assertTrue(!DexParser.isShortName("Lcom/x/Abc;"));
        assertTrue(!DexParser.isShortName("Lcom/x/abc12;"));
        assertTrue(!DexParser.isShortName("Landroid/app/Activity;"));
        assertTrue(!DexParser.isShortName("Landroid/aftz;"));
        assertTrue(!DexParser.isShortName("Ljava/lang/String;"));
        assertTrue(!DexParser.isShortName(null));
    }

    @Test
    public void resolucionSuperclase() {
        java.util.Map<String, String> sup = new java.util.HashMap<String, String>();
        sup.put("Lcom/x/W;", "Landroid/webkit/WebView;");
        // Exacto sigue funcionando.
        assertTrue(DexParser.suspiciousLabelWithSupers("Ljava/lang/Runtime;", "exec", sup) != null);
        // Subclase resuelve por la superclase.
        assertTrue(DexParser.suspiciousLabelWithSupers("Lcom/x/W;", "addJavascriptInterface", sup) != null);
        // Sin mapa no resuelve.
        assertTrue(DexParser.suspiciousLabelWithSupers("Lcom/x/W;", "addJavascriptInterface", null) == null);
        assertTrue(DexParser.suspiciousLabelWithSupers("Lcom/x/W;", "otro", sup) == null);
        assertTrue(DexParser.suspiciousLabelWithSupers(null, "exec", sup) == null);
        // Ciclo termina sin colgar.
        sup.put("Lcom/x/A;", "Lcom/x/B;");
        sup.put("Lcom/x/B;", "Lcom/x/A;");
        assertTrue(DexParser.suspiciousLabelWithSupers("Lcom/x/A;", "exec", sup) == null);
    }
}
