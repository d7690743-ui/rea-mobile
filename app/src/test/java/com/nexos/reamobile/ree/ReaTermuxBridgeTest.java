package com.nexos.reamobile.ree;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** FASE B: lógica pura del puente REE (sin framework Android, apta para JVM). */
public class ReaTermuxBridgeTest {

    @Test
    public void sqEscapaComillasSimples() {
        assertEquals("'hola'", ReaTermuxBridge.sq("hola"));
        assertEquals("'a'\\''b'", ReaTermuxBridge.sq("a'b"));
        assertEquals("''", ReaTermuxBridge.sq(""));
    }

    @Test
    public void etiquetasValidas() {
        assertTrue(ReaTermuxBridge.validLabel("ree:ping:1"));
        assertTrue(ReaTermuxBridge.validLabel("ree_ping-2.ok:3"));
        assertTrue(ReaTermuxBridge.validLabel("a"));
        assertFalse(ReaTermuxBridge.validLabel(null));
        assertFalse(ReaTermuxBridge.validLabel(""));
        assertFalse(ReaTermuxBridge.validLabel("ree ping"));
        assertFalse(ReaTermuxBridge.validLabel("ree;rm -rf"));
        assertFalse(ReaTermuxBridge.validLabel("../x"));
        assertFalse(ReaTermuxBridge.validLabel(":ree"));
        assertFalse(ReaTermuxBridge.validLabel(rep('a', 65)));
        assertTrue(ReaTermuxBridge.validLabel(rep('a', 64)));
    }

    @Test
    public void constantesRunCommand() {
        assertEquals("com.termux.permission.RUN_COMMAND", ReaTermuxBridge.PERMISSION);
        assertEquals("com.termux.RUN_COMMAND", ReaTermuxBridge.ACTION_RUN);
        assertEquals("com.nexos.reamobile.REE_TERMUX_RESULT", ReaTermuxBridge.ACTION_RESULT);
        assertEquals("ree_label", ReaTermuxBridge.EXTRA_LABEL);
        assertEquals("0", ReaTermuxBridge.SESSION_ACTION);
        assertEquals(65536, ReaTermuxBridge.MAX_SCRIPT_CHARS);
    }

    @Test
    public void receptorAceptaPrefijo() {
        assertTrue(ReaTermuxReceiver.accepts("ree:ping:1", "ree:"));
        assertFalse(ReaTermuxReceiver.accepts("otro:1", "ree:"));
        assertFalse(ReaTermuxReceiver.accepts(null, "ree:"));
        assertFalse(ReaTermuxReceiver.accepts("ree:1", null));
        assertEquals("stdout", ReaTermuxReceiver.RESULT_STDOUT);
        assertEquals("stderr", ReaTermuxReceiver.RESULT_STDERR);
        assertEquals("exitCode", ReaTermuxReceiver.RESULT_EXIT_CODE);
    }

    private static String rep(char c, int n) {
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) sb.append(c);
        return sb.toString();
    }
}
