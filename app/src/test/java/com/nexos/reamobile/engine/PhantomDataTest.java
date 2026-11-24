package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;

import org.junit.Test;

/** PHANTOM datos: parcelables, json-lib, modelos, literales JSON. */
public class PhantomDataTest {

    @Test
    public void parcelableYJsonLib() {
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(
                PhantomNetTest.edge("Lcom/x/User;->writeToParcel", "Lcom/x/B;->foo"),
                PhantomNetTest.edge("Lcom/x/Api;->parse", "Lcom/google/gson/Gson;->fromJson"))));
        PhantomData.DataResult r = PhantomData.analyze(g, null,
                new ArrayList<String>(Arrays.asList("Lcom/x/UserModel;")));
        assertEquals(3, r.hits.size());
        String s = PhantomData.summarize(r).toString();
        assertTrue(s, s.contains("parcelable:"));
        assertTrue(s, s.contains("json-lib:"));
        assertTrue(s, s.contains("modelo?:"));
    }

    @Test
    public void literalesJson() {
        StringRefs refs = StringRefs.from(new ArrayList<DexCalls.StringRef>(Arrays.asList(
                PhantomNetTest.sref("Lcom/x/A;->a", "{\"name\":\"x\"}"))));
        PhantomData.DataResult r = PhantomData.analyze(null, refs, null);
        assertEquals(1, r.hits.size());
        assertEquals("json-lit", r.hits.get(0).kind);
        PhantomData.DataResult v = PhantomData.analyze(null, null, null);
        assertTrue(v.hits.isEmpty());
        assertTrue(PhantomData.summarize(null).isEmpty());
    }
}
