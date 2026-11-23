package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
