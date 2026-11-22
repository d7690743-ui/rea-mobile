package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

/** Pruebas del escaneo ligero de libapp.so. */
public class LibAppScanTest {

    @Test
    public void stringsUrlsYMarcadores() {
        byte[] bin = ("hello\0URL https://a.com/x ok\0Dart SDK 3.0\0ab\0")
                .getBytes(StandardCharsets.UTF_8);
        LibAppScan.Result r = LibAppScan.scan(new ByteArrayInputStream(bin), 0);
        assertEquals(3, r.stringCount);
        assertEquals(1, r.urls.size());
        assertEquals("https://a.com/x", r.urls.get(0));
        assertTrue(r.markers.toString(), r.markers.contains("dart sdk"));
        assertTrue(!r.truncated);
    }

    @Test
    public void topeTrunca() {
        byte[] bin = new byte[100];
        for (int i = 0; i < bin.length; i++) bin[i] = 'A';
        LibAppScan.Result r = LibAppScan.scan(new ByteArrayInputStream(bin), 10);
        assertTrue(r.truncated);
        assertEquals(10, r.bytesRead);
    }

    @Test
    public void nuloVacio() {
        LibAppScan.Result r = LibAppScan.scan(null, 0);
        assertEquals(0, r.stringCount);
        assertTrue(r.urls.isEmpty());
    }
}
