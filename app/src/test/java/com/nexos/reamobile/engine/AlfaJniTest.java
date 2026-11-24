package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import org.junit.Test;

/** ALFA-1: decodificación JNI y enlace con el grafo. */
public class AlfaJniTest {

    @Test
    public void decodificaBasico() {
        assertEquals("[Lcom/x/A;, foo]",
                Arrays.toString(AlfaJni.decode("Java_com_x_A_foo")));
    }

    @Test
    public void decodificaEscapesYSobrecarga() {
        assertEquals("[Lcom/x/A;, set_name]",
                Arrays.toString(AlfaJni.decode("Java_com_x_A_set_1name")));
        assertEquals("[Lcom/x/A;, foo]",
                Arrays.toString(AlfaJni.decode("Java_com_x_A_foo__Ljava_lang_String_2")));
        assertEquals("[Lcom/x/A;, mA]",
                Arrays.toString(AlfaJni.decode("Java_com_x_A_m_00041")));
        assertEquals("[Lcom/x/A;, take[I]",
                Arrays.toString(AlfaJni.decode("Java_com_x_A_take_3I")));
    }

    @Test
    public void invalidosNull() {
        assertNull(AlfaJni.decode(null));
        assertNull(AlfaJni.decode("foo"));
        assertNull(AlfaJni.decode("Java_"));
        assertNull(AlfaJni.decode("Java_a"));
        assertNull(AlfaJni.decode("Java_com__"));
    }

    @Test
    public void enlazaConGrafo() {
        RefGraph g = new RefGraph();
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = "Lcom/x/B;->run";
        e.callee = "Lcom/x/A;->foo";
        e.pos = 0;
        g.add(e);
        java.util.List<AlfaJni.JniLink> links = AlfaJni.link(
                Arrays.asList("Java_com_x_A_foo", "Java_com_x_B_bar", "nada"), g);
        assertEquals(2, links.size());
        assertEquals("Lcom/x/A;", links.get(0).javaClass);
        assertEquals("foo", links.get(0).javaMethod);
        assertEquals(1, links.get(0).callers.size());
        assertTrue(links.get(1).callers.isEmpty());
        assertNotNull(AlfaJni.link(null, null));
        assertTrue(AlfaJni.link(null, null).isEmpty());
    }
}
