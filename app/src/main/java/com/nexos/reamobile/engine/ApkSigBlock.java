package com.nexos.reamobile.engine;

import java.io.File;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

/**
 * Lector del bloque de firma APK (v2/v3): extrae el certificado del firmante.
 * Referencia: formato público del APK Signature Scheme (AOSP apksig).
 * Java puro. Nunca lanza.
 */
public final class ApkSigBlock {
    private ApkSigBlock() {
    }

    public static final int ID_V2 = 0x7109871a;
    public static final int ID_V3 = 0xf05368c0;
    public static final int ID_V31 = 0x1b93ad61;
    public static final long MAX_BLOCK = 8L * 1024 * 1024;

    public static class SigInfo {
        public String scheme = "";
        public byte[] cert;
        public String error;
    }

    /** Extrae esquema y primer certificado del bloque de firma. Nunca lanza. */
    public static SigInfo parse(File apk) {
        SigInfo r = new SigInfo();
        RandomAccessFile raf = null;
        try {
            if (apk == null || !apk.isFile()) {
                r.error = "archivo no válido";
                return r;
            }
            raf = new RandomAccessFile(apk, "r");
            long len = raf.length();
            if (len < 64) {
                r.error = "demasiado corto";
                return r;
            }
            long scan = Math.min(len, 65536 + 22);
            byte[] tail = new byte[(int) scan];
            raf.seek(len - scan);
            raf.readFully(tail);
            int eocd = -1;
            for (int i = tail.length - 22; i >= 0; i--) {
                if (tail[i] == 'P' && tail[i + 1] == 'K' && tail[i + 2] == 5 && tail[i + 3] == 6) {
                    eocd = i;
                    break;
                }
            }
            if (eocd < 0) {
                r.error = "sin EOCD";
                return r;
            }
            long cdo = u32(tail, eocd + 16) & 0xFFFFFFFFL;
            if (cdo < 32 || cdo > len) {
                r.error = "directorio inválido";
                return r;
            }
            byte[] foot = new byte[24];
            raf.seek(cdo - 24);
            raf.readFully(foot);
            String magic = "APK Sig Block 42";
            for (int i = 0; i < 16; i++) {
                if (foot[8 + i] != (byte) magic.charAt(i)) {
                    r.error = "sin bloque de firma";
                    return r;
                }
            }
            long blockSize = u64(foot, 0);
            if (blockSize < 32 || blockSize > MAX_BLOCK || blockSize > cdo) {
                r.error = "bloque inválido";
                return r;
            }
            long pairsLen = blockSize - 24;
            if (pairsLen <= 0 || pairsLen > MAX_BLOCK) {
                r.error = "bloque inválido";
                return r;
            }
            byte[] pairs = new byte[(int) pairsLen];
            raf.seek(cdo - 24 - pairsLen);
            raf.readFully(pairs);
            List<Pair> found = splitPairs(pairs);
            for (Pair p : found) {
                String scheme = schemeOf(p.id);
                if (scheme == null) continue;
                byte[] cert = firstCert(p.value);
                if (cert != null) {
                    r.scheme = scheme;
                    r.cert = cert;
                    return r;
                }
            }
            // Hay bloque pero sin firmante legible: se informa esquema vacío.
            r.error = "sin firmante legible";
            return r;
        } catch (Throwable t) {
            r.error = "fallo leyendo bloque";
            return r;
        } finally {
            if (raf != null) {
                try {
                    raf.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static class Pair {
        int id;
        byte[] value;
    }

    private static String schemeOf(int id) {
        if (id == ID_V2) return "v2";
        if (id == ID_V3) return "v3";
        if (id == ID_V31) return "v3.1";
        return null;
    }

    /** Divide el bloque en pares (u64 tamaño, u32 id, valor). */
    static List<Pair> splitPairs(byte[] pairs) {
        List<Pair> out = new ArrayList<>();
        try {
            int p = 0;
            int guard = 0;
            while (p + 12 <= pairs.length && guard++ < 1000) {
                long size = u64(pairs, p);
                if (size < 4 || size > pairs.length - p - 8) break;
                int id = (int) u32(pairs, p + 8);
                int vlen = (int) (size - 4);
                byte[] v = new byte[vlen];
                System.arraycopy(pairs, p + 12, v, 0, vlen);
                Pair pr = new Pair();
                pr.id = id;
                pr.value = v;
                out.add(pr);
                p += 8 + (int) size;
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Primer certificado de un valor v2/v3: secuencia externa → firmantes →
     * signed-data → certificados. Todo con prefijo de longitud u32 LE
     * (formato AOSP: "length-prefixed sequence of length-prefixed signer").
     */
    static byte[] firstCert(byte[] value) {
        try {
            if (value == null || value.length < 4) return null;
            int seqLen = (int) u32(value, 0);
            if (seqLen < 0) return null;
            int seqEnd = Math.min(value.length, 4 + seqLen);
            int p = 4;
            int guard = 0;
            while (p + 4 <= seqEnd && guard++ < 100) {
                int signerLen = (int) u32(value, p);
                if (signerLen <= 0 || signerLen > seqEnd - p - 4) break;
                byte[] cert = certFromSigner(value, p + 4, signerLen);
                if (cert != null) return cert;
                p += 4 + signerLen;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static byte[] certFromSigner(byte[] buf, int off, int len) {
        int end = off + len;
        int p = off;
        // signed-data
        if (p + 4 > end) return null;
        int sdLen = (int) u32(buf, p);
        if (sdLen <= 0 || sdLen > end - p - 4) return null;
        int sdOff = p + 4;
        int sdEnd = sdOff + sdLen;
        // digests (se saltan)
        if (sdOff + 4 > sdEnd) return null;
        int digLen = (int) u32(buf, sdOff);
        if (digLen < 0 || digLen > sdEnd - sdOff - 4) return null;
        int q = sdOff + 4 + digLen;
        // certificates
        if (q + 4 > sdEnd) return null;
        int certsLen = (int) u32(buf, q);
        if (certsLen <= 0 || certsLen > sdEnd - q - 4) return null;
        int cOff = q + 4;
        int cEnd = cOff + certsLen;
        if (cOff + 4 > cEnd) return null;
        int oneLen = (int) u32(buf, cOff);
        if (oneLen <= 0 || oneLen > cEnd - cOff - 4) return null;
        byte[] cert = new byte[oneLen];
        System.arraycopy(buf, cOff + 4, cert, 0, oneLen);
        return cert;
    }

    private static long u32(byte[] b, int p) {
        return ((b[p] & 0xFFL) | ((b[p + 1] & 0xFFL) << 8)
                | ((b[p + 2] & 0xFFL) << 16) | ((b[p + 3] & 0xFFL) << 24));
    }

    private static long u64(byte[] b, int p) {
        return (u32(b, p) & 0xFFFFFFFFL) | ((u32(b, p + 4) & 0xFFFFFFFFL) << 32);
    }
}
