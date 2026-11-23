package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Fase C: roles por clase desde llamadas sensibles del grafo. */
public class ClassRolesTest {

    static DexCalls.Edge edge(String caller, String callee) {
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = caller;
        e.callee = callee;
        e.dex = "classes.dex";
        return e;
    }

    @Test
    public void tablaRoles() {
        assertEquals("red", ClassRoles.roleFor("Ljava/net/HttpURLConnection;"));
        assertEquals("red", ClassRoles.roleFor("Lokhttp3/"));
        assertEquals("red", ClassRoles.roleFor("Ljava/net/URL;"));
        assertEquals("cripto", ClassRoles.roleFor("Ljavax/crypto/"));
        assertEquals("cripto", ClassRoles.roleFor("Ljava/security/"));
        assertEquals("reflexion", ClassRoles.roleFor("Ljava/lang/reflect/"));
        assertEquals("proceso", ClassRoles.roleFor("Ljava/lang/Runtime;"));
        assertEquals("proceso", ClassRoles.roleFor("Ljava/lang/ProcessBuilder;"));
        assertEquals("web", ClassRoles.roleFor("Landroid/webkit/WebView;"));
        assertEquals("telefonia", ClassRoles.roleFor("Landroid/telephony/"));
        assertEquals("ubicacion", ClassRoles.roleFor("Landroid/location/"));
        assertEquals("sistema", ClassRoles.roleFor("Lalgo/desconocido/"));
        assertEquals("sistema", ClassRoles.roleFor(null));
    }

    @Test
    public void asignaPorClase() {
        RefGraph g = RefGraph.from(Arrays.asList(
                edge("Lcom/x/Net;->a", "Ljava/net/HttpURLConnection;->connect"),
                edge("Lcom/x/Net;->b", "Lokhttp3/RealCall;->execute"),
                edge("Lcom/x/Net;->c", "Ljava/lang/String;->length"),
                edge("Lcom/x/Crypto;->k", "Ljavax/crypto/Cipher;->doFinal")));
        Map<String, List<ClassRoles.Role>> r =
                ClassRoles.assign(g, new HashMap<String, String>(), "com/x/");
        assertEquals(2, r.size());
        List<ClassRoles.Role> net = r.get("Lcom/x/Net;");
        assertEquals(1, net.size());
        assertEquals("red", net.get(0).label);
        assertEquals(2, net.get(0).count);
        assertTrue(net.get(0).evidence.get(0).contains("HttpURLConnection"));
        List<ClassRoles.Role> cr = r.get("Lcom/x/Crypto;");
        assertEquals(1, cr.size());
        assertEquals("cripto", cr.get(0).label);
    }

    @Test
    public void herenciaYFiltroPropias() {
        Map<String, String> supers = new HashMap<>();
        supers.put("Lcom/x/W;", "Landroid/webkit/WebView;");
        RefGraph g = RefGraph.from(Arrays.asList(
                edge("Lcom/x/W;->a", "Lcom/x/W;->addJavascriptInterface"),
                edge("La/lib/L;->z", "Ljava/net/URL;->openConnection")));
        Map<String, List<ClassRoles.Role>> r = ClassRoles.assign(g, supers, "com/x/");
        assertEquals(1, r.size());
        assertEquals("web", r.get("Lcom/x/W;").get(0).label);
        Map<String, List<ClassRoles.Role>> all = ClassRoles.assign(g, supers, null);
        assertEquals(2, all.size());
        assertEquals("red", all.get("La/lib/L;").get(0).label);
    }

    @Test
    public void malosNoLanzan() {
        assertTrue(ClassRoles.assign(null, null, null).isEmpty());
        assertTrue(ClassRoles.assign(new RefGraph(), null, "").isEmpty());
        assertTrue(ClassRoles.assign(null, new HashMap<String, String>(), "com/x/").isEmpty());
    }
}
