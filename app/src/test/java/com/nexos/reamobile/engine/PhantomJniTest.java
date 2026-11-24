package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** PHANTOM nativo: pares nombre+firma y unión con llamadores. */
public class PhantomJniTest {

    private static byte[] bytes(String... parts) {
        try {
            java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
            for (String p : parts) {
                b.write(p.getBytes("UTF-8"));
                b.write(0);
                b.write(1);
                b.write(2);
            }
            return b.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    @Test
    public void detectaParNombreFirma() {
        byte[] head = bytes("nativeInit", "(Ljava/lang/String;)V", "ruido");
        List<String> cands = PhantomJni.scanStrings(head, null);
        assertTrue(cands.toString(), cands.contains("nativeInit|(Ljava/lang/String;)V"));
    }

    @Test
    public void firmasYHeuristicas() {
        assertTrue(PhantomJni.isJniSig("(I)V"));
        assertTrue(PhantomJni.isJniSig("([BLjava/lang/String;)Z"));
        assertTrue(!PhantomJni.isJniSig("hola"));
        assertTrue(!PhantomJni.isJniSig("(xx"));
        assertTrue(PhantomJni.isMethodName("nativeInit"));
        assertTrue(!PhantomJni.isMethodName("com/x/A"));
        assertTrue(!PhantomJni.isMethodName("a b"));
        assertTrue(PhantomJni.scanStrings(null, null).isEmpty());
    }

    @Test
    public void rastreoSoConUrls() {
        byte[] head = bytes("nota https://api.x.test/v1 fin", "nativeGo", "(I)V");
        PhantomJni.SoResult r = PhantomJni.scanSo(head, null);
        assertTrue(r.urls.toString(), r.urls.contains("https://api.x.test/v1"));
        assertTrue(r.jni.toString(), r.jni.contains("nativeGo|(I)V"));
        assertEquals("https://a.test/x", PhantomJni.extractUrl("v https://a.test/x\""));
        assertTrue(PhantomJni.extractUrl("sin nada") == null);
        assertTrue(PhantomJni.extractUrl(null) == null);
    }

    @Test
    public void uneConLlamadoresPropios() {
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = "Lcom/x/A;->nativeInit";
        e.callee = "Lcom/x/B;->foo";
        e.dex = "classes.dex";
        e.pos = 0;
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(e)));
        AlfaElf.ElfInfo elf = new AlfaElf.ElfInfo();
        elf.name = "lib/x.so";
        elf.jniDynamic.add("nativeInit|(I)V");
        List<PhantomJni.DynLink> links = PhantomJni.link(
                new ArrayList<AlfaElf.ElfInfo>(Arrays.asList(elf)), g);
        assertEquals(1, links.size());
        assertEquals("nativeInit", links.get(0).method);
        assertEquals("(I)V", links.get(0).sig);
        assertTrue(links.get(0).callers.contains("Lcom/x/A;->nativeInit"));
        assertTrue(PhantomJni.summarize(links.get(0)).contains("lib/x.so"));
        assertTrue(PhantomJni.link(null, g).isEmpty());
    }
}
