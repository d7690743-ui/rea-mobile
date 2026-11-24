package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

/** PHANTOM red: contratos endpoint+método+payload por llamador. */
public class PhantomNetTest {

    static DexCalls.StringRef sref(String user, String value) {
        DexCalls.StringRef s = new DexCalls.StringRef();
        s.user = user;
        s.value = value;
        s.dex = "classes.dex";
        s.pos = 0;
        return s;
    }

    static DexCalls.Edge edge(String caller, String callee) {
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = caller;
        e.callee = callee;
        e.dex = "classes.dex";
        e.pos = 0;
        return e;
    }

    @Test
    public void contratoConVerboYPermiso() {
        String m = "Lcom/x/Api;->fetch";
        StringRefs refs = StringRefs.from(new ArrayList<DexCalls.StringRef>(Arrays.asList(
                sref(m, "https://api.x.test/v1/u"),
                sref(m, "POST"),
                sref(m, "{\"id\":1}"))));
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(
                edge(m, "Lokhttp3/OkHttpClient;->newCall"))));
        Map<String, String> origin = new LinkedHashMap<>();
        origin.put("https://api.x.test/v1/u", "dex");
        Map<String, String> callerPerm = new LinkedHashMap<>();
        callerPerm.put(m, "INTERNET|Lokhttp3/OkHttpClient;->newCall");
        List<PhantomNet.Contract> cs = PhantomNet.contracts(
                new ArrayList<String>(Arrays.asList("https://api.x.test/v1/u")),
                origin, refs, g,
                new ArrayList<String>(Arrays.asList(
                        "android.permission.INTERNET")), callerPerm);
        assertEquals(1, cs.size());
        PhantomNet.Contract c = cs.get(0);
        assertEquals("api.x.test", c.host);
        assertTrue(c.users.contains(m));
        assertTrue(c.verbs.contains("POST"));
        assertEquals("INTERNET", c.permiso);
        assertTrue(c.permisoDeclarado);
        assertEquals(1, c.payloadHints.size());
        assertTrue(PhantomNet.summarize(c).contains("metodo=POST"));
    }

    @Test
    public void sinEvidenciaDeclaraAusencia() {
        StringRefs refs = StringRefs.from(new ArrayList<DexCalls.StringRef>());
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>());
        List<PhantomNet.Contract> cs = PhantomNet.contracts(
                new ArrayList<String>(Arrays.asList("https://doc.test/x")),
                new LinkedHashMap<String, String>(), refs, g,
                new ArrayList<String>(), new LinkedHashMap<String, String>());
        assertEquals(1, cs.size());
        assertTrue(cs.get(0).users.isEmpty());
        assertTrue(cs.get(0).verbs.isEmpty());
        assertTrue(PhantomNet.summarize(cs.get(0)).contains("[sin llamador]"));
        assertTrue(PhantomNet.contracts(null, null, null, null, null, null).isEmpty());
    }

    @Test
    public void redNativaYToques() {
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(
                edge("Lcom/x/A;->a", "Lorg/chromium/net/CronetEngine;->newUrlRequest"))));
        assertTrue(PhantomNet.touchers(g).contains("Lcom/x/A;->a"));
        assertTrue(PhantomNet.touchers(null).isEmpty());
        AlfaElf.ElfInfo e = new AlfaElf.ElfInfo();
        e.name = "lib/arm64/libcronet.so";
        e.soUrls.add("https://example.test/api");
        List<PhantomNet.Contract> cs = PhantomNet.contracts(null, null, null, g,
                new ArrayList<String>(), new LinkedHashMap<String, String>(),
                new ArrayList<AlfaElf.ElfInfo>(Arrays.asList(e)));
        assertEquals(1, cs.size());
        assertEquals("so:libcronet.so", cs.get(0).origen);
        assertTrue(PhantomNet.summarize(cs.get(0)).contains("[origen nativo]"));
    }

    @Test
    public void indiceInversoYLiterales() {
        String m = "Lcom/x/A;->a";
        StringRefs refs = StringRefs.from(new ArrayList<DexCalls.StringRef>(Arrays.asList(
                sref(m, "uno"), sref(m, "dos"), sref("Lcom/x/B;->b", "tres"))));
        List<String> lits = refs.literalsOf(m, 10);
        assertEquals(2, lits.size());
        assertTrue(lits.contains("uno"));
        List<StringRefs.LitHit> hits = refs.scanContains(new String[]{"o"}, 10);
        assertEquals(2, hits.size());
        assertTrue(refs.literalsOf(null, 10).isEmpty());
        assertTrue(refs.scanContains(null, 10).isEmpty());
    }
}
