package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** PHANTOM atribución inversa: amarra hallazgos huérfanos sin añadir. */
public class PhantomAttribTest {

    @Test
    public void protoYHelperAmarrados() {
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(
                PhantomNetTest.edge("Lcom/x/Use;->run", "Lcom/x/Msg;->parse"),
                PhantomNetTest.edge("Lcom/x/Repo;->open", "Lcom/x/Db;->get"))));
        PhantomData.DataHit d = new PhantomData.DataHit();
        d.kind = "proto-model";
        d.detail = "Lcom/x/Msg;";
        d.evidence = "GeneratedMessageLite.dynamicMethod (protobuf)";
        PhantomStore.StoreHit s = new PhantomStore.StoreHit();
        s.kind = "sqlite-helper";
        s.detail = "Lcom/x/Db;";
        s.evidence = "hereda SQLiteOpenHelper";
        List<PhantomData.DataHit> dh = new ArrayList<>(Arrays.asList(d));
        List<PhantomStore.StoreHit> sh = new ArrayList<>(Arrays.asList(s));
        PhantomAttrib.enrich(dh, sh, g);
        assertEquals(1, dh.size());
        assertEquals(1, sh.size());
        assertTrue(d.evidence, d.evidence.contains("referenciado por Lcom/x/Use;->run"));
        assertTrue(s.evidence, s.evidence.contains("referenciado por Lcom/x/Repo;->open"));
    }

    @Test
    public void sqlUnSalto() {
        RefGraph g = RefGraph.from(new ArrayList<DexCalls.Edge>(Arrays.asList(
                PhantomNetTest.edge("Lcom/x/Repo;->load", "Laacb;->q"))));
        PhantomStore.StoreHit s = new PhantomStore.StoreHit();
        s.kind = "sql";
        s.detail = "SELECT * FROM playlist_video";
        s.evidence = "cargado por Laacb;->q";
        List<PhantomStore.StoreHit> sh = new ArrayList<>(Arrays.asList(s));
        PhantomAttrib.enrich(null, sh, g);
        assertTrue(s.evidence, s.evidence.contains("llamado por Lcom/x/Repo;->load"));
    }

    @Test
    public void sinGrafoNoOp() {
        PhantomData.DataHit d = new PhantomData.DataHit();
        d.kind = "proto-model";
        d.detail = "Lcom/x/Msg;";
        d.evidence = "e";
        List<PhantomData.DataHit> dh = new ArrayList<>(Arrays.asList(d));
        PhantomAttrib.enrich(dh, null, null);
        PhantomAttrib.enrich(null, null, null);
        assertEquals("e", d.evidence);
        assertTrue(PhantomAttrib.classCallers(null).isEmpty());
        assertEquals("", PhantomAttrib.classOf(null));
        assertEquals("Lcom/x/M;", PhantomAttrib.classOf("Lcom/x/M;->run"));
    }
}
