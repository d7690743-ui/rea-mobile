package com.nexos.reamobile.engine;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** Prueba del adaptador JADX sobre el DEX sintético mantenido. */
public class JadxAdapterTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test(timeout = 180000)
    public void descompilaDexSintetico() throws Exception {
        File dex = new File(tmp.getRoot(), "t.dex");
        Files.write(dex.toPath(), SmaliExtractTest.buildTestDex());
        JadxAdapter.Result r = JadxAdapter.decompile(dex, tmp.getRoot(), 1);
        assertNull(r.error);
        assertTrue("clases=" + r.classes, r.classes >= 1);
        String code = null;
        for (Map.Entry<String, String> e : r.sources.entrySet()) {
            if (e.getKey().contains("com.x.A")) {
                code = e.getValue();
            }
        }
        assertNotNull(code);
        assertTrue(code, code.contains("foo") && code.contains("bar"));
    }

    @Test(timeout = 180000)
    public void filtradoPorPaqueteYTope() throws Exception {
        File dex = new File(tmp.getRoot(), "t.dex");
        Files.write(dex.toPath(), SmaliExtractTest.buildTestDex());
        List<String> pref = new ArrayList<>();
        pref.add("com/x/");
        JadxAdapter.Result r = JadxAdapter.decompileFiltered(dex, tmp.getRoot(), 1, pref, 10, null);
        assertNull(r.error);
        assertEquals(1, r.sources.size());
        List<String> none = new ArrayList<>();
        none.add("zzz/");
        JadxAdapter.Result r2 = JadxAdapter.decompileFiltered(dex, tmp.getRoot(), 1, none, 10, null);
        assertNull(r2.error);
        assertEquals(0, r2.sources.size());
    }

    @Test(timeout = 180000)
    public void entradaInvalidaDevuelveErrorSinLanzar() throws Exception {
        JadxAdapter.Result r = JadxAdapter.decompileFiltered(
                new File(tmp.getRoot(), "noexiste.dex"), tmp.getRoot(), 1,
                new ArrayList<String>(), 10, null);
        assertNotNull(r.error);
        File basura = new File(tmp.getRoot(), "basura.dex");
        Files.write(basura.toPath(), new byte[]{1, 2, 3, 4, 5, 6, 7, 8});
        JadxAdapter.Result r2 = JadxAdapter.decompileFiltered(
                basura, tmp.getRoot(), 1, new ArrayList<String>(), 10, null);
        assertTrue("basura: error o vacío, nunca lanzar",
                r2.error != null || r2.sources.isEmpty());
    }

    @Test(timeout = 180000)
    public void memoriaBajaAbortaSinLanzar() throws Exception {
        File dex = new File(tmp.getRoot(), "t.dex");
        Files.write(dex.toPath(), SmaliExtractTest.buildTestDex());
        JadxAdapter.MemoryPolicy siempreBaja = new JadxAdapter.MemoryPolicy() {
            @Override
            public boolean lowMemory() {
                return true;
            }
        };
        JadxAdapter.Result r = JadxAdapter.decompileFiltered(dex, tmp.getRoot(), 1,
                new ArrayList<String>(), 10, null, siempreBaja);
        assertNotNull(r.error);
        assertTrue(r.error, r.error.contains("memoria"));
        assertTrue(r.memoryAbort);
        assertEquals(0, r.sources.size());
        // Baja a media pasada: trunca con parcial en vez de lanzar.
        final int[] llamadas = {0};
        JadxAdapter.MemoryPolicy aLaSegunda = new JadxAdapter.MemoryPolicy() {
            @Override
            public boolean lowMemory() {
                return (++llamadas[0] >= 2);
            }
        };
        JadxAdapter.Result r2 = JadxAdapter.decompileFiltered(dex, tmp.getRoot(), 1,
                new ArrayList<String>(), 10, null, aLaSegunda);
        assertTrue(r2.truncated);
        assertTrue(r2.memoryAbort);
        assertNotNull(r2.error);
    }

    @Test(timeout = 180000)
    public void apkReintentaPorDexTrasAbortoMemoria() throws Exception {
        File apk = new File(tmp.getRoot(), "t.apk");
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk));
        byte[] dex = SmaliExtractTest.buildTestDex();
        zos.putNextEntry(new ZipEntry("classes.dex"));
        zos.write(dex);
        zos.closeEntry();
        zos.close();
        // Baja solo en la primera consulta: aborta la carga completa,
        // el fallback por dex sí procede.
        final int[] llamadas = {0};
        JadxAdapter.MemoryPolicy bajaUnaVez = new JadxAdapter.MemoryPolicy() {
            @Override
            public boolean lowMemory() {
                return (++llamadas[0] == 1);
            }
        };
        final List<String> fases = new ArrayList<>();
        JadxAdapter.Progress prog = new JadxAdapter.Progress() {
            @Override
            public boolean onClass(int done, int matched) {
                return true;
            }

            @Override
            public void onPhase(String name) {
                fases.add(name);
            }
        };
        JadxAdapter.Result r = JadxAdapter.decompileFiltered(apk, tmp.getRoot(), 1,
                new ArrayList<String>(), 10, prog, bajaUnaVez);
        assertNull("fallback por dex debe rescatar: " + r.error, r.error);
        assertEquals(1, r.sources.size());
        assertTrue(r.sources.containsKey("com.x.A"));
        assertTrue(fases.toString(), fases.contains("cargando APK"));
        assertTrue(fases.toString(), fases.contains("reintentando por dex"));
    }

    @Test(timeout = 180000)
    public void apkPorDexMezclaSinLanzar() throws Exception {
        File apk = new File(tmp.getRoot(), "t.apk");
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk));
        byte[] dex = SmaliExtractTest.buildTestDex();
        zos.putNextEntry(new ZipEntry("classes.dex"));
        zos.write(dex);
        zos.closeEntry();
        zos.putNextEntry(new ZipEntry("classes2.dex"));
        zos.write(dex);
        zos.closeEntry();
        zos.close();
        final List<String> fases = new ArrayList<>();
        JadxAdapter.Progress prog = new JadxAdapter.Progress() {
            @Override
            public boolean onClass(int done, int matched) {
                return true;
            }

            @Override
            public void onPhase(String name) {
                fases.add(name);
            }
        };
        // Aborta la carga completa para forzar el camino por dex.
        final int[] llamadas = {0};
        JadxAdapter.MemoryPolicy bajaUnaVez = new JadxAdapter.MemoryPolicy() {
            @Override
            public boolean lowMemory() {
                return (++llamadas[0] == 1);
            }
        };
        JadxAdapter.Result r = JadxAdapter.decompileFiltered(apk, tmp.getRoot(), 1,
                new ArrayList<String>(), 10, prog, bajaUnaVez);
        assertNull(r.error);
        assertEquals(2, r.classes);
        assertEquals(1, r.sources.size());
        assertTrue(r.sources.containsKey("com.x.A"));
        assertTrue(fases.toString(), fases.contains("reintentando por dex"));
        assertTrue(fases.toString(), fases.contains("dex 1/2"));
        assertTrue(fases.toString(), fases.contains("dex 2/2"));
    }

    @Test
    public void clavesCandidatasInner() {
        assertEquals(java.util.Arrays.asList("com.x.A"),
                JadxAdapter.candidateKeys("Lcom/x/A;"));
        assertEquals(java.util.Arrays.asList("com.x.R$color", "com.x.R.color"),
                JadxAdapter.candidateKeys("Lcom/x/R$color;"));
        assertEquals(
                java.util.Arrays.asList("com.x.A$B$C", "com.x.A$B.C", "com.x.A.B.C"),
                JadxAdapter.candidateKeys("Lcom/x/A$B$C;"));
        assertTrue(JadxAdapter.candidateKeys(null).isEmpty());
    }

    @Test
    public void lookupVisorHasJavaYPrimera() {
        Map<String, String> src = new java.util.LinkedHashMap<>();
        src.put("com.x.A", "class A{}");
        src.put("com.x.R.color", "class color{}");
        src.put("com.x.Vacia", null);
        assertTrue(JadxAdapter.hasJava("Lcom/x/A;", src));
        assertTrue(JadxAdapter.hasJava("Lcom/x/R$color;", src));
        assertTrue(!JadxAdapter.hasJava("Lcom/x/Falta;", src));
        assertTrue(!JadxAdapter.hasJava("Lcom/x/Vacia;", src));
        assertTrue(!JadxAdapter.hasJava(null, src));
        assertTrue(!JadxAdapter.hasJava("Lcom/x/A;", null));
        List<String> descs = java.util.Arrays.asList(
                "Lcom/x/Falta;", "Lcom/x/R$color;", "Lcom/x/A;");
        assertEquals("Lcom/x/R$color;", JadxAdapter.firstWithJava(descs, src));
        assertNull(JadxAdapter.firstWithJava(
                java.util.Arrays.asList("Lcom/x/Falta;"), src));
        assertNull(JadxAdapter.firstWithJava(null, src));
    }

    @Test
    public void topesAdaptativosPorHeap() {
        long m256 = 256L * 1024 * 1024;
        long m512 = 512L * 1024 * 1024;
        assertEquals(1, JadxAdapter.recommendedThreads(m256 - 1));
        assertEquals(2, JadxAdapter.recommendedThreads(m256));
        assertEquals(150, JadxAdapter.recommendedCap(m256 - 1));
        assertEquals(300, JadxAdapter.recommendedCap(m256));
        assertEquals(600, JadxAdapter.recommendedCap(m512));
    }

    @Test
    public void planDexLoadEligeRuta() throws Exception {
        byte[] dex = SmaliExtractTest.buildTestDex();
        File uno = new File(tmp.getRoot(), "uno.apk");
        writeZip(uno, new String[]{"classes.dex"}, new byte[][]{dex});
        JadxAdapter.DexPlan p1 = JadxAdapter.planDexLoad(uno, 1024, null);
        assertTrue(!p1.preferPerDex);
        assertEquals(1, p1.dexCount);
        File dos = new File(tmp.getRoot(), "dos.apk");
        writeZip(dos, new String[]{"classes.dex", "classes2.dex"}, new byte[][]{dex, dex});
        JadxAdapter.DexPlan p2 = JadxAdapter.planDexLoad(dos, 8L * 1024 * 1024 * 1024, null);
        assertTrue(!p2.preferPerDex);
        JadxAdapter.DexPlan p3 = JadxAdapter.planDexLoadFor(dos, 32768, -1, 32768, null);
        assertTrue(p3.preferPerDex);
        assertEquals(2, p3.totalClasses);
        assertTrue(!p3.reason.isEmpty());
        assertNotNull(p3.hits);
        JadxAdapter.DexPlan p4 = JadxAdapter.planDexLoadFor(
                dos, 8L * 1024 * 1024 * 1024, -1, 32768, null);
        assertTrue(!p4.preferPerDex);
        assertTrue(!JadxAdapter.planDexLoad(
                new File(tmp.getRoot(), "no.apk"), 1024, null).preferPerDex);
    }

    @Test
    public void javaVacioRepliegaAExterna() {
        assertEquals(java.util.Arrays.asList("com.x.A$B", "com.x.A"),
                JadxAdapter.outerKeys("com.x.A$B$1"));
        assertTrue(JadxAdapter.outerKeys("com.x.A").isEmpty());
        assertTrue(JadxAdapter.outerKeys(null).isEmpty());
        Map<String, String> src = new java.util.LinkedHashMap<>();
        src.put("com.x.A", "class A{}");
        src.put("com.x.A$1", "");
        src.put("com.x.SoloVacia", "  ");
        assertTrue(JadxAdapter.hasJava("Lcom/x/A$1;", src));
        assertTrue(!JadxAdapter.hasJava("Lcom/x/SoloVacia;", src));
        assertEquals("Lcom/x/A$1;", JadxAdapter.firstWithJava(
                java.util.Arrays.asList("Lcom/x/SoloVacia;", "Lcom/x/A$1;"), src));
    }

    @Test(timeout = 180000)
    public void anonimaResuelvePorNombreRaw() throws Exception {
        File dex = new File(tmp.getRoot(), "t.dex");
        Files.write(dex.toPath(), SmaliExtractTest.buildTestDexWithInner());
        List<String> pref = new ArrayList<>();
        pref.add("com/x/");
        JadxAdapter.Result r = JadxAdapter.decompileFiltered(dex, tmp.getRoot(), 1, pref, 10, null);
        assertNull(r.error);
        assertTrue("claves=" + r.sources.keySet(), r.sources.containsKey("com.x.A$1"));
        // Búsqueda tal como la hace el visor: por descriptor smali.
        for (String desc : new String[]{"Lcom/x/A;", "Lcom/x/A$1;"}) {
            boolean ok = false;
            for (String c : JadxAdapter.candidateKeys(desc)) {
                if (r.sources.containsKey(c)) ok = true;
            }
            assertTrue("lookup visor para " + desc, ok);
        }
    }

    @Test(timeout = 180000)
    public void apkDexCorruptoRescataOtro() throws Exception {
        File apk = new File(tmp.getRoot(), "mix.apk");
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk));
        zos.putNextEntry(new ZipEntry("classes.dex"));
        zos.write(new byte[]{9, 9, 9, 9, 9, 9, 9, 9});
        zos.closeEntry();
        zos.putNextEntry(new ZipEntry("classes2.dex"));
        zos.write(SmaliExtractTest.buildTestDex());
        zos.closeEntry();
        zos.close();
        JadxAdapter.Result r = JadxAdapter.decompileFiltered(apk, tmp.getRoot(), 1,
                new ArrayList<String>(), 10, null);
        assertTrue("rescatada: " + r.error, r.sources.containsKey("com.x.A"));
    }

    @Test
    public void scanDexesLocalizaPaquete() throws Exception {
        File apk = new File(tmp.getRoot(), "s.apk");
        byte[] dex = SmaliExtractTest.buildTestDex();
        writeZip(apk, new String[]{"classes.dex", "classes2.dex"}, new byte[][]{dex, dex});
        List<String> pref = new ArrayList<>();
        pref.add("com/x/");
        List<JadxAdapter.DexHit> hits = JadxAdapter.scanDexes(apk, pref);
        assertEquals(2, hits.size());
        for (JadxAdapter.DexHit h : hits) {
            assertNull(h.error);
            assertEquals(1, h.totalClasses);
            assertEquals(1, h.matched);
        }
        List<String> none = new ArrayList<>();
        none.add("zzz/");
        List<JadxAdapter.DexHit> miss = JadxAdapter.scanDexes(apk, none);
        assertEquals(2, miss.size());
        assertEquals(0, miss.get(0).matched);
        File vacio = new File(tmp.getRoot(), "v.apk");
        writeZip(vacio, new String[]{"a.txt"}, new byte[][]{new byte[]{1}});
        assertTrue(JadxAdapter.scanDexes(vacio, pref).isEmpty());
        File basura = new File(tmp.getRoot(), "b.apk");
        Files.write(basura.toPath(), new byte[]{1, 2, 3});
        assertTrue(JadxAdapter.scanDexes(basura, pref).isEmpty());
        assertTrue(JadxAdapter.scanDexes(null, pref).isEmpty());
    }

    @Test(timeout = 180000)
    public void loteOmiteDexSinCoincidencias() throws Exception {
        File apk = new File(tmp.getRoot(), "s.apk");
        byte[] dex = SmaliExtractTest.buildTestDex();
        writeZip(apk, new String[]{"classes.dex", "classes2.dex"}, new byte[][]{dex, dex});
        List<String> none = new ArrayList<>();
        none.add("zzz/");
        final int[] llamadas = {0};
        JadxAdapter.MemoryPolicy bajaUnaVez = new JadxAdapter.MemoryPolicy() {
            @Override
            public boolean lowMemory() {
                return (++llamadas[0] == 1);
            }
        };
        JadxAdapter.Result r = JadxAdapter.decompileFiltered(apk, tmp.getRoot(), 1,
                none, 10, null, bajaUnaVez);
        assertTrue(r.sources.isEmpty());
        String log = r.log.toString();
        assertTrue(log, log.contains("dex con coincidencias: 0 de 2"));
        assertTrue(log, log.contains("[classes.dex] omitido: sin coincidencias"));
        assertTrue(log, log.contains("[classes2.dex] omitido: sin coincidencias"));
    }

    @Test(timeout = 180000)
    public void logRegistraFalloCarga() throws Exception {
        File apk = new File(tmp.getRoot(), "mix.apk");
        writeZip(apk, new String[]{"classes.dex", "classes2.dex"},
                new byte[][]{new byte[]{9, 9, 9, 9}, SmaliExtractTest.buildTestDex()});
        final int[] llamadas = {0};
        JadxAdapter.MemoryPolicy bajaUnaVez = new JadxAdapter.MemoryPolicy() {
            @Override
            public boolean lowMemory() {
                return (++llamadas[0] == 1);
            }
        };
        JadxAdapter.Result r = JadxAdapter.decompileFiltered(apk, tmp.getRoot(), 1,
                new ArrayList<String>(), 10, null, bajaUnaVez);
        assertTrue(r.sources.containsKey("com.x.A"));
        String log = r.log.toString();
        assertTrue(log, log.contains("[classes.dex]"));
        assertTrue(log, log.contains("[classes2.dex] java=+1"));
    }

    static void writeZip(File out, String[] names, byte[][] datas) throws Exception {
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(out));
        for (int i = 0; i < names.length; i++) {
            zos.putNextEntry(new ZipEntry(names[i]));
            zos.write(datas[i]);
            zos.closeEntry();
        }
        zos.close();
    }

    @Test(timeout = 180000)
    public void apkSinDexVacioSinLanzar() throws Exception {
        File apk = new File(tmp.getRoot(), "vacio.apk");
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk));
        zos.putNextEntry(new ZipEntry("a.txt"));
        zos.write(new byte[]{1});
        zos.closeEntry();
        zos.close();
        JadxAdapter.Result r = JadxAdapter.decompileFiltered(apk, tmp.getRoot(), 1,
                new ArrayList<String>(), 10, null);
        assertTrue(r.sources.isEmpty());
    }
}
