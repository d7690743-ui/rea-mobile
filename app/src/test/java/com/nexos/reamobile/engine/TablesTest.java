package com.nexos.reamobile.engine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** Pruebas de tablas: nativas, trackers, protectores y API→permiso. */
public class TablesTest {

    @Test
    public void nativas() {
        assertEquals("LLM local (llama.cpp)",
                NativeTable.classify("lib/arm64-v8a/libllama.so"));
        assertEquals("código Dart compilado (Flutter AOT)",
                NativeTable.classify("lib/arm64-v8a/libapp.so"));
        assertEquals("framework Flutter", NativeTable.classify("lib/arm64-v8a/libflutter.so"));
        assertEquals("protector Bangcle", NativeTable.classify("lib/arm64-v8a/libDexHelper.so"));
        assertNull(NativeTable.classify("lib/arm64-v8a/libdesconocida.so"));
        assertNull(NativeTable.classify(null));
    }

    @Test
    public void trackers() {
        assertEquals("Meta (Facebook SDK)", TrackerTable.match("com/facebook"));
        assertEquals("AppsFlyer", TrackerTable.match("Lcom/appsflyer/X;"));
        assertEquals("Firebase", TrackerTable.match("com/google/firebase"));
        assertNull(TrackerTable.match("com/ejemplo"));
        assertNull(TrackerTable.match(null));
    }

    @Test
    public void protectores() {
        assertEquals("protector Bangcle",
                PackerMarkers.matchFile("lib/arm64-v8a/libDexHelper.so"));
        assertEquals("instrumentación Frida",
                PackerMarkers.matchFile("lib/arm64-v8a/libfrida-gadget.so"));
        assertEquals("protector SecNeo", PackerMarkers.matchClass("Lcom/secneo/X;"));
        assertNull(PackerMarkers.matchFile("lib/arm64-v8a/libapp.so"));
        assertNull(PackerMarkers.matchClass("Lcom/ejemplo/A;"));
        assertNull(PackerMarkers.matchFile(null));
    }

    @Test
    public void apiPermiso() {
        assertEquals("RECORD_AUDIO",
                PermApiTable.permissionFor("Landroid/media/AudioRecord;->startRecording()V"));
        assertEquals("CAMERA",
                PermApiTable.permissionFor("Landroid/hardware/Camera;->open()V"));
        assertEquals("INTERNET", PermApiTable.permissionFor("Ljava/net/URL;-><init>"));
        assertEquals("INTERNET",
                PermApiTable.permissionFor("Lorg/chromium/net/CronetEngine;->newUrlRequest"));
        assertEquals("INTERNET",
                PermApiTable.permissionFor("Lretrofit2/Retrofit;->create"));
        assertEquals("INTERNET",
                PermApiTable.permissionFor("Lcom/android/volley/RequestQueue;->add"));
        assertEquals("WAKE_LOCK",
                PermApiTable.permissionFor("Landroid/os/PowerManager;->newWakeLock"));
        assertNull(PermApiTable.permissionFor("Ljava/lang/String;->length()I"));
        assertNull(PermApiTable.permissionFor(null));
        assertTrue(PermApiTable.isRisky("android.permission.MANAGE_EXTERNAL_STORAGE"));
        assertTrue(PermApiTable.isRisky("RECORD_AUDIO"));
        assertTrue(!PermApiTable.isRisky("android.permission.INTERNET"));
        assertTrue(!PermApiTable.isRisky(null));
    }
}
