package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/** Pruebas del informe profundo (ZIP sintético, sin fixtures binarias). */
public class ReaEngineTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void topCountsYHosts() {
        Map<String, Integer> m = new LinkedHashMap<>();
        m.put("com/a", 5);
        m.put("com/b", 9);
        m.put("x", 9);
        assertEquals(Arrays.asList("com/b=9", "x=9"), ReaEngine.topCounts(m, 2));
        assertTrue(ReaEngine.topCounts(null, 3).isEmpty());
        assertEquals("com/a", ReaEngine.prefix2("Lcom/a/B;"));
        assertEquals("otros", ReaEngine.prefix2("LX;"));
        assertEquals("otros", ReaEngine.prefix2(null));
        List<String> urls = Arrays.asList(
                "https://a.com/x", "http://a.com:8080/y?q=1", "https://b.org/", "nota-url", null);
        assertEquals(Arrays.asList("a.com=2", "b.org=1"), ReaEngine.topHosts(urls, 5));
    }

    @Test
    public void resumenUnaLinea() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.frameworks.add("Flutter/Dart");
        r.nativeLibs.add("lib/arm64-v8a/libllama.so (ARM64) [LLM local (llama.cpp)]");
        r.manifestPerms.add("android.permission.INTERNET");
        r.manifestPerms.add("android.permission.RECORD_AUDIO");
        r.secretHighTotal = 2;
        assertEquals("Flutter/Dart + LLM local (llama.cpp) | 2 permisos (1 de riesgo)"
                + " | 2 secreto(s) alta", ReaEngine.buildSummary(r));
        ReaEngine.ApkReport vacio = new ReaEngine.ApkReport();
        assertEquals("? | 0 permisos (0 de riesgo)", ReaEngine.buildSummary(vacio));
    }

    @Test
    public void filtrosScanStrings() {
        Set<String> urls = new LinkedHashSet<>();
        Set<String> ips = new LinkedHashSet<>();
        Set<String> emails = new LinkedHashSet<>();
        Set<String> sec = new LinkedHashSet<>();
        Set<String> high = new LinkedHashSet<>();
        Map<String, String> origin = new LinkedHashMap<>();
        int[] c = new int[5];
        List<String> in = Arrays.asList(
                "ver https://x.test/a ya",
                "oid 1.3.6.1.4.1.311 en cert",
                "solo 2.5.29.37 suelto",
                "ip 10.0.2.2 local",
                "img ytu_promo_dialog_logo@2x.png fin",
                "mail a@b.com ok",
                "Landroid/support/MediaSessionCompat$Token;",
                "token secreto xyz");
        ReaEngine.scanStrings(in, urls, ips, emails, sec, high, c, origin, "dex");
        assertTrue(urls.contains("https://x.test/a"));
        assertEquals("dex", origin.get("https://x.test/a"));
        assertTrue(ips.contains("10.0.2.2"));
        assertTrue(!ips.contains("1.3.6.1"));
        assertTrue(!ips.contains("2.5.29.37"));
        assertTrue(emails.contains("a@b.com"));
        assertTrue(!emails.contains("ytu_promo_dialog_logo@2x.png"));
        assertTrue(!sec.contains("Landroid/support/MediaSessionCompat$Token;"));
        assertTrue(sec.contains("token secreto xyz"));
    }

    @Test
    public void urlsRecortanPuntuacion() {
        Set<String> urls = new LinkedHashSet<>();
        Set<String> ips = new LinkedHashSet<>();
        Set<String> emails = new LinkedHashSet<>();
        Set<String> sec = new LinkedHashSet<>();
        Set<String> high = new LinkedHashSet<>();
        Map<String, String> origin = new LinkedHashMap<>();
        int[] c = new int[5];
        List<String> in = Arrays.asList(
                "ver https://x.test/a.",
                "entre (https://y.test/b) parentesis",
                "wiki https://w.test/c_(d) balanceado",
                "dup https://f.test/e, y https://f.test/e.",
                "regex https://p.test/launch\\?id=([^/]+)? fin");
        ReaEngine.scanStrings(in, urls, ips, emails, sec, high, c, origin, "dex");
        assertTrue(urls.toString(), urls.contains("https://x.test/a"));
        assertTrue(urls.toString(), urls.contains("https://y.test/b"));
        assertTrue(urls.toString(), urls.contains("https://w.test/c_(d)"));
        assertTrue(urls.toString(), urls.contains("https://f.test/e"));
        assertTrue(urls.toString(), urls.contains("https://p.test/launch\\?id=([^/]+)?"));
        assertTrue(!urls.contains("https://x.test/a."));
        assertTrue(!urls.contains("https://y.test/b)"));
        assertTrue(!urls.contains("https://f.test/e,"));
        assertTrue(!urls.contains("https://f.test/e."));
        assertEquals("dex", origin.get("https://x.test/a"));
    }

    @Test
    public void llamadasSinDuplicados() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        ReaEngine.addSuspCall(r, "Lcom/x/A;->a  ->  Ljava/lang/Runtime;->exec");
        ReaEngine.addSuspCall(r, "Lcom/x/A;->a  ->  Ljava/lang/Runtime;->exec");
        ReaEngine.addSuspCall(r, null);
        ReaEngine.addSuspCall(null, "x");
        assertEquals(1, r.suspCalls.size());
    }

    @Test
    public void conservaDefinidoresDeDatosLib() {
        assertTrue(ReaEngine.keepDataLibEdge("Laovr;->dynamicMethod"));
        assertTrue(ReaEngine.keepDataLibEdge("Lcom/x/U;->writeToParcel"));
        assertTrue(!ReaEngine.keepDataLibEdge("Laovr;->foo"));
        assertTrue(!ReaEngine.keepDataLibEdge(null));
    }

    @Test
    public void jsonLlevaRed() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        DexCalls.Edge e = new DexCalls.Edge();
        e.caller = "Lcom/x/A;->onCreate";
        e.callee = "Lcom/x/A;->foo";
        r.graph.addAll(Arrays.asList(e));
        String js = r.toJson();
        assertTrue(js, js.contains("\"graphNodes\":2"));
        assertTrue(js, js.contains("\"graphEdges\":1"));
        assertTrue(js, js.contains("\"graphTruncated\":false"));
        assertTrue(js, js.contains("\"stringValues\":0"));
        assertTrue(js, js.contains("\"redEntries\":[\"Lcom/x/A;->onCreate\"]"));
        assertTrue(js, js.contains("\"redChains\":[]"));
        assertTrue(js, js.contains("\"redTruncated\":false"));
    }

    @Test
    public void pasadaLibreria() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        ReaEngine.collectOwnCalls(r, DexCallsTest.buildOwnPlusLibDex(), "com/x/",
                new LinkedHashSet<String>(), "classes.dex");
        assertEquals(Arrays.asList("Ladrt/L;->bar"),
                r.graph.callersOf("Ljava/lang/Runtime;->exec"));
        assertEquals("Lcom/x/A;", r.superMap.get("Ladrt/L;"));
        assertTrue(r.suspCalls.isEmpty());
        assertTrue(r.dexNotes.isEmpty());
    }

    @Test
    public void rolesInformeYRegistro() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.packageName = "com.x";
        DexCalls.Edge e1 = new DexCalls.Edge();
        e1.caller = "Lcom/x/Net;->a";
        e1.callee = "Ljava/net/HttpURLConnection;->connect";
        DexCalls.Edge e2 = new DexCalls.Edge();
        e2.caller = "Lcom/x/Net;->b";
        e2.callee = "Ljava/net/HttpURLConnection;->getInputStream";
        r.graph.addAll(Arrays.asList(e1, e2));
        String txt = r.toText();
        assertTrue(txt, txt.contains("=== ROLES (1) ==="));
        assertTrue(txt, txt.contains("rol=Lcom/x/Net; red x2"));
        ReaEngine.feedIntel(r);
        String txt2 = r.toText();
        assertTrue(txt2, txt2.contains("[rol]"));
        String js = r.toJson();
        assertTrue(js, js.contains("\"roles\":{"));
        assertTrue(js, js.contains("Lcom/x/Net;"));
    }

    @Test
    public void coberturaInformeYRegistro() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.sha256 = "fa973ab965632ca5d0d93683e9bc5d82dd60f9b82fec8ca9fa3aba1de408ef57";
        r.fileSize = 258961610L;
        r.nativeLibs.add("lib/arm64-v8a/libchrome.so (ARM64)");
        r.totalClasses = 5649;
        r.obfuscatedRatio = 0.41;
        String txt = r.toText();
        assertTrue(txt, txt.contains("=== COBERTURA (perfil=framework) ==="));
        assertTrue(txt, txt.contains("check=taint NOT_EXECUTED"));
        assertTrue(txt, txt.contains("check=nativas PARTIAL"));
        ReaEngine.feedIntel(r);
        String txt2 = r.toText();
        assertTrue(txt2, txt2.contains("[perfil]"));
        String js = r.toJson();
        assertTrue(js, js.contains("\"profile\":\"framework\""));
        assertTrue(js, js.contains("\"coverage\":{"));
    }

    @Test
    public void flujoInformeYRegistro() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.flowIrs.put("Lcom/x/A;->foo", DefUseTest.fooIr());
        DexCalls.Edge e1 = new DexCalls.Edge();
        e1.caller = "Lcom/x/A;->foo";
        e1.callee = "Landroid/widget/EditText;->getText";
        e1.pos = 0;
        DexCalls.Edge e2 = new DexCalls.Edge();
        e2.caller = "Lcom/x/A;->foo";
        e2.callee = "Landroid/util/Log;->d";
        e2.pos = 5;
        r.graph.addAll(Arrays.asList(e1, e2));
        String txt = r.toText();
        assertTrue(txt, txt.contains("=== FLUJO (metodos=1"));
        assertTrue(txt, txt.contains("taint=Landroid/widget/EditText;->getText@+0"
                + " ~> Landroid/util/Log;->d@+5 en Lcom/x/A;->foo"));
        assertTrue(txt, txt.contains("check=taint FOUND"));
        ReaEngine.feedIntel(r);
        assertEquals(1, r.intel.byCategory("taint").size());
        String js = r.toJson();
        assertTrue(js, js.contains("\"flowMethods\":1"));
        assertTrue(js, js.contains("\"taintFlows\":["));
    }

    @Test
    public void nativoInformeYRegistro() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        AlfaElf.ElfInfo e = new AlfaElf.ElfInfo();
        e.name = "lib/arm64-v8a/libx.so";
        e.arch = "ARM64";
        e.elfType = "DYN";
        e.exportCount = 2;
        e.jniExports.add("Java_com_x_A_foo");
        e.hasJniOnLoad = true;
        r.alfaElfs.add(e);
        r.nativeLibs.add("lib/arm64-v8a/libx.so (ARM64)");
        DexCalls.Edge g = new DexCalls.Edge();
        g.caller = "Lcom/x/B;->run";
        g.callee = "Lcom/x/A;->foo";
        g.pos = 0;
        r.graph.add(g);
        String txt = r.toText();
        assertTrue(txt, txt.contains("=== NATIVO (libs=1"));
        assertTrue(txt, txt.contains("jni=Java_com_x_A_foo -> Lcom/x/A;->foo <="));
        assertTrue(txt, txt.contains("check=nativas PARTIAL"));
        ReaEngine.feedIntel(r);
        assertEquals(1, r.intel.byCategory("nativo").size());
        assertEquals(1, r.intel.byCategory("jni").size());
        String js = r.toJson();
        assertTrue(js, js.contains("\"elfParsed\":1"));
        assertTrue(js, js.contains("\"jniLinks\":["));
    }

    @Test
    public void uiInformeYRegistro() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        AlfaUi.Screen s = new AlfaUi.Screen();
        s.layout = "res/layout/a.xml";
        s.views = 2;
        s.handlers.add("enviar");
        r.alfaScreens.add(s);
        DexCalls.Edge g = new DexCalls.Edge();
        g.caller = "Lcom/x/Main;->enviar";
        g.callee = "Ljava/lang/System;->loadLibrary";
        g.pos = 0;
        r.graph.add(g);
        DexCalls.Edge h = new DexCalls.Edge();
        h.caller = "Lcom/x/Main;->onCreate";
        h.callee = "Ljava/lang/System;->loadLibrary";
        h.pos = 0;
        r.graph.add(h);
        r.manifestClasses.add("Lcom/x/Main;");
        r.manifestExported.add("activity:com.x.Main");
        r.packageName = "com.x";
        String txt = r.toText();
        assertTrue(txt, txt.contains("=== UI (pantallas=1"));
        assertTrue(txt, txt.contains("handler=res/layout/a.xml enviar <="));
        assertTrue(txt, txt.contains("entrada=Lcom/x/Main;->onCreate [exportada]"));
        ReaEngine.feedIntel(r);
        assertEquals(2, r.intel.byCategory("entrada").size());
        assertEquals(1, r.intel.byCategory("ui").size());
        String js = r.toJson();
        assertTrue(js, js.contains("\"uiScreens\":1"));
        assertTrue(js, js.contains("\"uiEntries\":["));
    }

    @Test
    public void blueprintInformeYRegistro() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        String url = "https://api.x.com/subir";
        r.urls.add(url);
        r.urlOrigin.put(url, "DEX");
        r.manifestPerms.add("android.permission.ACCESS_FINE_LOCATION");
        DexCalls.StringRef s = new DexCalls.StringRef();
        s.value = url;
        s.user = "Lcom/x/App;->enviar";
        r.stringRefs.add(s);
        DexCalls.Edge g = new DexCalls.Edge();
        g.caller = "Lcom/x/App;->enviar";
        g.callee = "Landroid/location/LocationManager;->getLastKnownLocation";
        g.pos = 0;
        r.graph.add(g);
        String txt = r.toText();
        assertTrue(txt, txt.contains("=== BLUEPRINT (cadenas=1 riesgo=1) ==="));
        assertTrue(txt, txt.contains("permiso=ACCESS_FINE_LOCATION[declarado][riesgo]"));
        ReaEngine.feedIntel(r);
        assertEquals(1, r.intel.byCategory("correlacion").size());
        String js = r.toJson();
        assertTrue(js, js.contains("\"corrChains\":["));
    }

    @Test
    public void recuperacionIndiceYSeccion() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.appClassTotal = 10;
        for (int i = 0; i < 10; i++) r.appClasses.add("Lcom/x/C" + i + ";");
        r.totalStrings = 100;
        r.urlTotal = 4;
        r.urls.add("https://a.com");
        r.urls.add("https://b.com");
        r.secretTotal = 0;
        r.recArscPresent = true;
        r.arscStringCount = 50;
        r.recArscEntries = 20;
        r.recLayoutTotal = 2;
        AlfaUi.Screen s = new AlfaUi.Screen();
        r.alfaScreens.add(s);
        r.recSoTotal = 0;
        r.manifestXml = "<manifest/>";
        r.sigScheme = "v2";
        // 30*1 + 10*0 + 5*.5 + 10*1 + 10*1 + 10*.5 + 10*1 + 5*1 = 72.5/90 ≈ 81
        // (secretos y nativas con total 0 se excluyen del denominador: n/a)
        assertEquals(81, ReaEngine.recoveryIndex(r));
        String txt = r.toText();
        assertTrue(txt, txt.contains("=== RECUPERACIÓN (índice≈81%) ==="));
        assertTrue(txt, txt.contains("clases=10/10"));
        assertTrue(txt, txt.contains("secretos=n/a"));
        assertTrue(txt, txt.contains("arsc-tabla=20 entradas"));
        assertEquals(-1, ReaEngine.recoveryIndex(null));
        String js = r.toJson();
        assertTrue(js, js.contains("\"recIndex\":81"));
    }

    @Test
    public void puenteIntel() {
        ReaEngine.ApkReport r = new ReaEngine.ApkReport();
        r.findings.add(new ReaEngine.Finding("red", "2 URL(s)", "una", "DEX"));
        r.findings.add(new ReaEngine.Finding("firma", "Bloque v2", "moderna", "magia"));
        ReaEngine.feedIntel(r);
        assertEquals(2, r.intel.size());
        // Idempotente: segunda llamada no duplica.
        ReaEngine.feedIntel(r);
        assertEquals(2, r.intel.size());
        String txt = r.toText();
        assertTrue(txt, txt.contains("=== INTELIGENCIA (2) ==="));
        assertTrue(txt, txt.contains("F-0001 [red] 2 URL(s)"));
        assertTrue(txt, txt.contains("F-0002 [firma] Bloque v2"));
        // Sin hallazgos: sección vacía explícita, sin lanzar.
        ReaEngine.ApkReport vacio = new ReaEngine.ApkReport();
        ReaEngine.feedIntel(vacio);
        ReaEngine.feedIntel(null);
        assertTrue(vacio.toText().contains("(sin hallazgos registrados)"));
    }

    @Test
    public void bloqueFirmaV2Detecta() throws Exception {
        File con = new File(tmp.getRoot(), "con.apk");
        writeMiniZip(con, true);
        assertTrue(ReaEngine.hasApkSigBlock(con));
        File sin = new File(tmp.getRoot(), "sin.apk");
        writeMiniZip(sin, false);
        assertTrue(!ReaEngine.hasApkSigBlock(sin));
        assertTrue(!ReaEngine.hasApkSigBlock(new File(tmp.getRoot(), "noexiste.apk")));
        File tiny = new File(tmp.getRoot(), "t.apk");
        FileOutputStream fos = new FileOutputStream(tiny);
        fos.write(new byte[]{1, 2, 3});
        fos.close();
        assertTrue(!ReaEngine.hasApkSigBlock(tiny));
    }

    /** Mini-ZIP válido con o sin bloque de firma simulado. */
    static void writeMiniZip(File out, boolean sig) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] name = "a.txt".getBytes("UTF-8");
        byte[] data = "hi".getBytes("UTF-8");
        le32(b, 0x04034b50);
        le16(b, 20);
        le16(b, 0);
        le16(b, 0);
        le16(b, 0);
        le16(b, 0);
        le32(b, 0);
        le32(b, data.length);
        le32(b, data.length);
        le16(b, name.length);
        le16(b, 0);
        b.write(name);
        b.write(data);
        if (sig) {
            le64(b, 24);
            le64(b, 24);
            b.write("APK Sig Block 42".getBytes("UTF-8"));
        }
        int cdOff = b.size();
        le32(b, 0x02014b50);
        le16(b, 20);
        le16(b, 20);
        le16(b, 0);
        le16(b, 0);
        le16(b, 0);
        le16(b, 0);
        le32(b, 0);
        le32(b, data.length);
        le32(b, data.length);
        le16(b, name.length);
        le16(b, 0);
        le16(b, 0);
        le16(b, 0);
        le16(b, 0);
        le32(b, 0);
        le32(b, 0);
        le32(b, 0);
        b.write(name);
        int cdSize = b.size() - cdOff;
        le32(b, 0x06054b50);
        le16(b, 0);
        le16(b, 0);
        le16(b, 1);
        le16(b, 1);
        le32(b, cdSize);
        le32(b, cdOff);
        le16(b, 0);
        FileOutputStream fos = new FileOutputStream(out);
        fos.write(b.toByteArray());
        fos.close();
    }

    @Test
    public void copiaConTope() throws Exception {
        byte[] data = new byte[1000];
        ByteArrayOutputStream ok = new ByteArrayOutputStream();
        ReaEngine.copyCapped(new ByteArrayInputStream(data), ok, 1000);
        assertEquals(1000, ok.size());
        try {
            ReaEngine.copyCapped(new ByteArrayInputStream(data), new ByteArrayOutputStream(), 999);
            assertTrue("debió lanzar", false);
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("tope"));
        }
    }

    @Test
    public void inventarioAcotado() throws Exception {
        File apk = new File(tmp.getRoot(), "many.zip");
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk));
        for (int i = 0; i < ReaEngine.MAX_ENTRIES + 5; i++) {
            zos.putNextEntry(new ZipEntry("f" + i + ".dat"));
            zos.closeEntry();
        }
        zos.putNextEntry(new ZipEntry("AndroidManifest.xml"));
        zos.write("no-es-axml".getBytes(StandardCharsets.UTF_8));
        zos.closeEntry();
        zos.close();
        ReaEngine.ApkReport r = ReaEngine.analyze(apk);
        assertTrue(r.dexNotes.toString(), r.dexNotes.toString().contains("inventario parcial"));
        assertTrue(r.entryCount <= ReaEngine.MAX_ENTRIES);
    }

    static void le16(ByteArrayOutputStream b, int v) {
        b.write(v & 0xFF);
        b.write((v >> 8) & 0xFF);
    }

    static void le32(ByteArrayOutputStream b, int v) {
        b.write(v & 0xFF);
        b.write((v >> 8) & 0xFF);
        b.write((v >> 16) & 0xFF);
        b.write((v >> 24) & 0xFF);
    }

    static void le64(ByteArrayOutputStream b, long v) {
        for (int i = 0; i < 8; i++) b.write((int) ((v >> (8 * i)) & 0xFF));
    }
}
