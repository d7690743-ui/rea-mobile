package com.nexos.reamobile.engine;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
}
