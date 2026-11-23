package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import org.junit.Test;

/** Pruebas de chequeos de manifest sobre XML sintético. */
public class ManifestChecksTest {

    static final String XML = "<manifest package=\"com.x\">"
            + "<uses-permission android:name=\"android.permission.INTERNET\"/>"
            + "<uses-permission android:name=\"android.permission.MANAGE_EXTERNAL_STORAGE\"/>"
            + "<application android:debuggable=\"true\" android:allowBackup=\"true\""
            + " android:usesCleartextTraffic=\"true\">"
            + "<activity android:name=\"com.x.Main\" android:exported=\"true\"/>"
            + "<activity android:name=\"com.x.In\" android:exported=\"false\"/>"
            + "<receiver android:name=\"com.x.Boot\" android:exported=\"true\">"
            + "<intent-filter><action android:name=\"android.intent.action.BOOT_COMPLETED\"/>"
            + "</intent-filter></receiver>"
            + "<activity android:name=\"com.x.Deep\" android:exported=\"true\">"
            + "<intent-filter><action android:name=\"android.intent.action.VIEW\"/>"
            + "<data android:scheme=\"https\" android:host=\"x.com\"/>"
            + "</intent-filter></activity>"
            + "</application></manifest>";

    @Test
    public void chequeos() {
        ManifestChecks.Result r = ManifestChecks.check(XML,
                Arrays.asList("android.permission.INTERNET",
                        "android.permission.MANAGE_EXTERNAL_STORAGE"));
        assertEquals(1, r.bootReceivers.size());
        assertEquals("com.x.Boot (exportado)", r.bootReceivers.get(0));
        assertEquals(1, r.intrusivePerms.size());
        assertEquals("MANAGE_EXTERNAL_STORAGE — acceso total al almacenamiento",
                r.intrusivePerms.get(0));
        assertEquals(3, r.exported.size());
        assertTrue(r.exported.toString(), r.exported.contains("activity:com.x.Main"));
        assertTrue(r.exported.toString(), r.exported.contains("receiver:com.x.Boot"));
        assertEquals(1, r.deepLinks.size());
        assertEquals("https://x.com", r.deepLinks.get(0));
        assertEquals(3, r.hygiene.size());
    }

    @Test
    public void componentesYResolucion() {
        ManifestChecks.Result r = ManifestChecks.check(XML, null);
        assertEquals(4, r.components.size());
        assertTrue(r.components.contains("com.x.Main"));
        assertTrue(r.components.contains("com.x.In"));
        assertTrue(r.components.contains("com.x.Boot"));
        assertTrue(r.components.contains("com.x.Deep"));
        assertEquals("Lcom/x/Main;", ManifestChecks.resolveDescriptor(".Main", "com.x"));
        assertEquals("Lcom/x/Main;", ManifestChecks.resolveDescriptor("com.x.Main", "com.y"));
        assertEquals("Lcom/x/Main;", ManifestChecks.resolveDescriptor("Main", "com.x"));
        assertTrue(ManifestChecks.resolveDescriptor(null, "com.x") == null);
        assertTrue(ManifestChecks.resolveDescriptor("", "com.x") == null);
    }

    @Test
    public void deeplinksSinDuplicados() {
        String xml = "<manifest><application>"
                + "<activity android:name=\"a\">"
                + "<intent-filter><data android:scheme=\"https\" android:host=\"x.com\"/>"
                + "<data android:scheme=\"https\" android:host=\"x.com\"/>"
                + "</intent-filter></activity></application></manifest>";
        ManifestChecks.Result r = ManifestChecks.check(xml, null);
        assertEquals(1, r.deepLinks.size());
    }

    @Test
    public void vacioNoFalla() {
        ManifestChecks.Result r = ManifestChecks.check("", null);
        assertTrue(r.bootReceivers.isEmpty());
        assertTrue(r.intrusivePerms.isEmpty());
        ManifestChecks.Result n = ManifestChecks.check(null, null);
        assertTrue(n.exported.isEmpty());
    }
}
