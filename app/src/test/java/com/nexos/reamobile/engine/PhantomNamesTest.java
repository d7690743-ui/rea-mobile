package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.Test;

/** PHANTOM nombres: cosecha Kotlin, features y comportamiento. */
public class PhantomNamesTest {

    @Test
    public void cosechaKtYDescartaLimpias() {
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(
                PhantomNetTest.edge("Lagr;->run", "Lcom/x/B;->foo"),
                PhantomNetTest.edge("Lcom/x/Clean;->run", "Lcom/x/B;->foo"))));
        StringRefs refs = StringRefs.from(new ArrayList<DexCalls.StringRef>(Arrays.asList(
                PhantomNetTest.sref("Lagr;->run", "MediaSessionShuffleStateAdapter.kt"),
                PhantomNetTest.sref("Lcom/x/Clean;->run", "Other.kt"))));
        Map<String, String> names = PhantomNames.harvest(g, refs);
        assertEquals(1, names.size());
        assertEquals("MediaSessionShuffleStateAdapter", names.get("Lagr;"));
        assertTrue(PhantomNames.summarizeNames(names).toString()
                .contains("Lagr; → MediaSessionShuffleStateAdapter"));
        assertTrue(PhantomNames.harvest(null, refs).isEmpty());
        assertTrue(PhantomNames.harvest(g, null).isEmpty());
        assertTrue(PhantomNames.summarizeNames(null).isEmpty());
    }

    @Test
    public void cosechaPorRuta() {
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(
                PhantomNetTest.edge("Lzz;->a", "Lcom/x/B;->foo"))));
        StringRefs refs = StringRefs.from(new ArrayList<DexCalls.StringRef>(Arrays.asList(
                PhantomNetTest.sref("Lzz;->a",
                        "com/google/android/apps/youtube/music/entities/data/MusicStore"))));
        assertEquals("MusicStore", PhantomNames.harvest(g, refs).get("Lzz;"));
    }

    @Test
    public void features() {
        assertEquals("Music", PhantomNames.featureFor("Lcom/x/MusicActivity;"));
        assertEquals("Bluetooth A2dp",
                PhantomNames.featureFor("Lcom/x/BluetoothA2dpReceiver;"));
        assertEquals("Music Browser",
                PhantomNames.featureFor("Lcom/x/MusicBrowserService;"));
        assertEquals("", PhantomNames.featureFor("Lagr;"));
        assertEquals("", PhantomNames.featureFor(null));
    }

    @Test
    public void comportamientoYDescribe() {
        assertTrue(PhantomNames.isBehavior(
                "attempted to update shuffle state but media session was null: %d"));
        assertTrue(!PhantomNames.isBehavior("corto"));
        assertTrue(!PhantomNames.isBehavior("com/x/y/una/ruta/larga"));
        assertTrue(!PhantomNames.isBehavior(null));
        PhantomGroup.FuncGroup g = new PhantomGroup.FuncGroup();
        g.id = "FN-02";
        g.entries.add("Lcom/x/MusicActivity;->onCreate");
        g.methodSample.add("Lcom/x/MusicActivity;->onCreate");
        g.classSample.add("Lcom/x/MusicActivity;");
        StringRefs refs = StringRefs.from(new ArrayList<DexCalls.StringRef>(Arrays.asList(
                PhantomNetTest.sref("Lcom/x/MusicActivity;->onCreate",
                        "attempted to update shuffle state: %d"))));
        List<String> lines = PhantomNames.describe(
                new ArrayList<PhantomGroup.FuncGroup>(Arrays.asList(g)),
                new java.util.LinkedHashMap<String, String>(), refs);
        assertEquals(1, lines.size());
        assertTrue(lines.get(0), lines.get(0).contains("FN-02 [Music]"));
        assertTrue(lines.get(0), lines.get(0).contains("shuffle state"));
        assertTrue(PhantomNames.describe(null, null, null).isEmpty());
    }

    @Test
    public void ofuscacionSigueB3() {
        assertTrue(PhantomNames.isObfuscated("Lagr;"));
        assertTrue(PhantomNames.isObfuscated("Lcom/x/aftz;"));
        assertTrue(!PhantomNames.isObfuscated("Lcom/x/Clean;"));
        assertTrue(!PhantomNames.isObfuscated("Lcom/x/MusicActivity;"));
        assertTrue(!PhantomNames.isObfuscated(null));
    }
}
