package com.nexos.reamobile.engine;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Escaneo ligero de libapp.so (Flutter AOT): tamaño, nº de strings ASCII,
 * URLs y marcadores Dart/Flutter. Lectura por streaming con tope.
 * Java puro. Nunca lanza.
 */
public final class LibAppScan {
    private LibAppScan() {
    }

    public static final long MAX_BYTES = 32L * 1024 * 1024;
    public static final int MIN_STR = 4;
    public static final int MAX_URLS = 50;

    private static final Pattern URL_RE =
            Pattern.compile("https?://[^\\s\"'<>]{4,200}", Pattern.CASE_INSENSITIVE);

    private static final String[] MARKERS = {
            "dart sdk", "dart:", "dart_", "package:flutter", "flutter/",
            " observatory", "dart_isolate", "flutter engine",
    };

    public static class Result {
        public long bytesRead;
        public int stringCount;
        public List<String> urls = new ArrayList<>();
        public List<String> markers = new ArrayList<>();
        public boolean truncated;
    }

    /** Escanea un stream binario buscando strings ASCII. Nunca lanza. */
    public static Result scan(InputStream in, long maxBytes) {
        Result r = new Result();
        Set<String> urlSet = new LinkedHashSet<>();
        Set<String> markSet = new LinkedHashSet<>();
        try {
            if (in == null) return r;
            long cap = maxBytes <= 0 ? MAX_BYTES : Math.min(maxBytes, MAX_BYTES);
            byte[] buf = new byte[65536];
            StringBuilder cur = new StringBuilder();
            long total = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                for (int i = 0; i < n; i++) {
                    if (total >= cap) {
                        r.truncated = true;
                        break;
                    }
                    total++;
                    int c = buf[i] & 0xFF;
                    if (c >= 32 && c < 127) {
                        if (cur.length() < 512) cur.append((char) c);
                    } else {
                        flush(cur, urlSet, markSet, r);
                    }
                }
                if (total >= cap) {
                    r.truncated = true;
                    break;
                }
            }
            flush(cur, urlSet, markSet, r);
            r.bytesRead = total;
            r.urls.addAll(urlSet);
            r.markers.addAll(markSet);
        } catch (Throwable t) {
            r.truncated = true;
        }
        return r;
    }

    private static void flush(StringBuilder cur, Set<String> urls, Set<String> marks, Result r) {
        try {
            if (cur.length() >= MIN_STR) {
                r.stringCount++;
                String s = cur.toString();
                if (urls.size() < MAX_URLS) {
                    Matcher m = URL_RE.matcher(s);
                    while (m.find() && urls.size() < MAX_URLS) urls.add(m.group());
                }
                String low = s.toLowerCase(Locale.US);
                for (String mk : MARKERS) {
                    if (low.contains(mk)) markSetAdd(marks, mk);
                }
            }
        } catch (Throwable ignored) {
        }
        cur.setLength(0);
    }

    private static void markSetAdd(Set<String> marks, String mk) {
        try {
            if (marks.size() < 10) marks.add(mk.trim());
        } catch (Throwable ignored) {
        }
    }
}
