package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.Test;

/** PHANTOM almacenamiento: SQLite, SQL, prefs. */
public class PhantomStoreTest {

    @Test
    public void helperSqlYPrefs() {
        Map<String, String> supers = new LinkedHashMap<>();
        supers.put("Lcom/x/Db;", "Landroid/database/sqlite/SQLiteOpenHelper;");
        StringRefs refs = StringRefs.from(new ArrayList<DexCalls.StringRef>(Arrays.asList(
                PhantomNetTest.sref("Lcom/x/Db;->init", "CREATE TABLE u (id INT)"),
                PhantomNetTest.sref("Lcom/x/Cfg;->load", "mis_prefs"))));
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(
                PhantomNetTest.edge("Lcom/x/Cfg;->load",
                        "Landroid/content/Context;->getSharedPreferences"))));
        PhantomStore.StoreResult r = PhantomStore.analyze(supers, refs, g);
        assertEquals(3, r.hits.size());
        assertTrue(PhantomStore.summarize(r).toString().contains("sqlite-helper"));
        assertTrue(PhantomStore.summarize(r).toString().contains("sql:"));
        assertTrue(PhantomStore.summarize(r).toString().contains("prefs: mis_prefs"));
    }

    @Test
    public void vacioSinLanzar() {
        PhantomStore.StoreResult r = PhantomStore.analyze(null, null, null);
        assertTrue(r.hits.isEmpty());
        assertTrue(PhantomStore.summarize(null).isEmpty());
    }
}
