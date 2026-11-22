package com.nexos.reamobile.intelligence;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import org.junit.Test;

/** Núcleo intelligence: modelo, registro, topes y filtros (sin fixtures). */
public class IntelTest {

    @Test
    public void fabricaYnulos() {
        IntelFinding f = IntelFinding.create("crypto", "AES/ECB sin IV");
        assertTrue(f.isValid());
        assertEquals(IntelFinding.Confidence.LOW, f.confidence);
        assertEquals(IntelFinding.EvidenceType.STATIC, f.evidenceType);
        assertTrue(!IntelFinding.create(null, null).isValid());
        assertTrue(!IntelFinding.create("", "").isValid());
        f.relate(null);
        f.relate("");
        f.relate("F-0002");
        f.relate("F-0002");
        assertEquals(1, f.relatedIds.size());
    }

    @Test
    public void registroAsignaIdsYFiltra() {
        IntelRegistry r = new IntelRegistry();
        IntelFinding a = IntelFinding.create("network", "URL http");
        a.className = "Lcom/x/Net;";
        IntelFinding b = IntelFinding.create("network", "IP directa");
        b.className = "Lcom/x/Net;";
        IntelFinding c = IntelFinding.create("secret", "token");
        assertTrue(r.add(a));
        assertTrue(r.add(b));
        assertTrue(r.add(c));
        assertEquals("F-0001", a.id);
        assertEquals("F-0003", c.id);
        assertEquals(3, r.size());
        assertEquals(2, r.byCategory("network").size());
        assertEquals(2, r.byClass("Lcom/x/Net;").size());
        assertTrue(r.byCategory("nada").isEmpty());
        List<IntelFinding> all = r.all();
        assertEquals(3, all.size());
        all.clear();
        assertEquals(3, r.size());
    }

    @Test
    public void topeDescartaSinLanzar() {
        IntelRegistry r = new IntelRegistry(2);
        assertTrue(r.add(IntelFinding.create("a", "1")));
        assertTrue(r.add(IntelFinding.create("a", "2")));
        assertFalse(r.add(IntelFinding.create("a", "3")));
        assertFalse(r.add(null));
        assertFalse(r.add(new IntelFinding()));
        assertEquals(2, r.size());
        assertEquals(3, r.dropped());
        assertTrue(r.truncated());
        assertNotNull(r.byCategory(null));
        assertNotNull(r.byClass(null));
    }
}
