package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** ALFA-3: correlador permiso→API→método→destino. */
public class AlfaCorrTest {

    static StringRefs refsCon(String literal, String metodo) {
        StringRefs r = new StringRefs();
        DexCalls.StringRef s = new DexCalls.StringRef();
        s.value = literal;
        s.user = metodo;
        r.add(s);
        return r;
    }

    static RefGraph grafoCon(String caller, String callee) {
        RefGraph g = new RefGraph();
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = caller;
        e.callee = callee;
        g.add(e);
        return g;
    }

    @Test
    public void cadenaCompleta() {
        String url = "https://api.x.com/subir";
        StringRefs refs = refsCon(url, "Lcom/x/App;->enviar");
        RefGraph g = grafoCon("Lcom/x/App;->enviar",
                "Landroid/location/LocationManager;->getLastKnownLocation");
        List<AlfaCorr.Chain> cs = AlfaCorr.correlate(Arrays.asList(url), null,
                refs, g, Arrays.asList("android.permission.ACCESS_FINE_LOCATION"), null);
        assertEquals(1, cs.size());
        AlfaCorr.Chain c = cs.get(0);
        assertEquals("ACCESS_FINE_LOCATION", c.permiso);
        assertTrue(c.permisoDeclarado);
        assertTrue(c.permisoRiesgo);
        assertEquals("api.x.com", c.host);
        assertEquals(Arrays.asList("Lcom/x/App;->enviar"), c.metodos);
        String una = AlfaCorr.summarize(c);
        assertTrue(una, una.contains("permiso=ACCESS_FINE_LOCATION[declarado][riesgo]"));
        assertTrue(una, una.contains("destino=" + url));
    }

    @Test
    public void urlDentroDeLiteral() {
        StringRefs refs = refsCon("cfg=https://a.b/c?k=1;", "Lcom/x/C;->run");
        RefGraph g = grafoCon("Lcom/x/C;->run", "Ljava/lang/String;->length");
        List<AlfaCorr.Chain> cs = AlfaCorr.correlate(
                Arrays.asList("https://a.b/c?k=1"), null, refs, g, null, null);
        assertEquals(1, cs.size());
        assertEquals(Arrays.asList("Lcom/x/C;->run"), cs.get(0).metodos);
        assertEquals("?", cs.get(0).permiso);
        assertEquals("a.b", cs.get(0).host);
    }

    @Test
    public void permisoNoDeclarado() {
        StringRefs refs = refsCon("https://h.com/", "Lcom/x/C;->run");
        RefGraph g = grafoCon("Lcom/x/C;->run", "Ljava/net/URL;->openConnection");
        Map<String, String> origin = new LinkedHashMap<>();
        origin.put("https://h.com/", "DEX");
        List<AlfaCorr.Chain> cs = AlfaCorr.correlate(
                Arrays.asList("https://h.com/"), origin, refs, g,
                Arrays.asList("android.permission.CAMERA"), null);
        assertEquals("INTERNET", cs.get(0).permiso);
        assertFalse(cs.get(0).permisoDeclarado);
        assertEquals("DEX", cs.get(0).origen);
    }

    @Test
    public void mapaPrimarioSobreGrafo() {
        StringRefs refs = refsCon("https://m.com/", "Lcom/x/C;->run");
        RefGraph g = new RefGraph();
        Map<String, String> map = new LinkedHashMap<>();
        map.put("Lcom/x/C;->run", "CAMERA|Landroid/hardware/Camera;->open");
        List<AlfaCorr.Chain> cs = AlfaCorr.correlate(
                Arrays.asList("https://m.com/"), null, refs, g,
                Arrays.asList("android.permission.CAMERA"), map);
        assertEquals("CAMERA", cs.get(0).permiso);
        assertTrue(cs.get(0).permisoDeclarado);
        assertTrue(cs.get(0).api.contains("Camera"));
    }

    @Test
    public void unSaltoAAyudante() {
        StringRefs refs = refsCon("https://s.com/", "Lcom/x/C;->onCreate");
        RefGraph g = grafoCon("Lcom/x/C;->onCreate", "Lcom/x/C;->ayuda");
        Map<String, String> map = new LinkedHashMap<>();
        map.put("Lcom/x/C;->ayuda", "INTERNET|Ljava/net/URL;->openConnection");
        List<AlfaCorr.Chain> cs = AlfaCorr.correlate(
                Arrays.asList("https://s.com/"), null, refs, g, null, map);
        assertEquals(1, cs.size());
        assertEquals("INTERNET", cs.get(0).permiso);
        assertEquals("Ljava/net/URL;->openConnection", cs.get(0).api);
        assertEquals("https://s.com/", cs.get(0).destino);
        assertEquals("s.com", cs.get(0).host);
        assertTrue(cs.get(0).metodos.contains("Lcom/x/C;->onCreate"));
    }

    @Test
    public void hostYBasura() {
        assertEquals("h.com:8080".split(":")[0],
                AlfaCorr.hostOf("http://h.com:8080/x"));
        assertEquals("?", AlfaCorr.hostOf("nota-url"));
        assertEquals("?", AlfaCorr.hostOf(null));
        assertEquals("?", AlfaCorr.summarize(null));
        assertTrue(AlfaCorr.correlate(null, null, null, null, null, null).isEmpty());
        assertTrue(AlfaCorr.shortNames(null).isEmpty());
    }
}
