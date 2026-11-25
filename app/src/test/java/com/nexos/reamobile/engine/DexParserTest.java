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

    @Test
    public void cabeceraEIntegridad() {
        byte[] dex = SmaliExtractTest.buildTestDex();
        // Íntegro: sin error ni nota.
        DexParser.DexInfo ok = DexParser.parse(dex, "t");
        assertTrue(ok.error == null);
        assertTrue(ok.headerNote == null);
        // header_size corrupto → error.
        byte[] bad = dex.clone();
        bad[36] = 0x71;
        assertTrue(DexParser.parse(bad, "t").error != null);
        // Byte flip cualquiera → nota de integridad (no fatal).
        byte[] flip = dex.clone();
        flip[200] ^= (byte) 0xFF;
        DexParser.DexInfo e2 = DexParser.parse(flip, "t");
        assertTrue(e2.error == null);
        assertTrue(e2.headerNote != null);
        assertTrue(e2.headerNote.contains("checksum"));
    }

    @Test
    public void degradacionParcial() {
        byte[] dex = SmaliExtractTest.buildTestDex();
        // method_ids fuera de rango: esa sección se degrada, las clases salen.
        byte[] cut = dex.clone();
        int off = cut.length - 4;
        cut[92] = (byte) (off & 0xFF);
        cut[93] = (byte) ((off >> 8) & 0xFF);
        cut[94] = (byte) ((off >> 16) & 0xFF);
        cut[95] = (byte) ((off >> 24) & 0xFF);
        DexParser.DexInfo di = DexParser.parse(cut, "t");
        assertTrue(di.error == null);
        assertTrue(di.degradedItems == 8);
        assertTrue(di.classes.size() == 1);
        // Íntegro: cero degradados.
        assertTrue(DexParser.parse(dex, "t").degradedItems == 0);
    }
}
