package com.nexos.reamobile.engine;

import java.io.File;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
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

    /** Resultado de la verificación de integridad por digests (S1-real). */
    public static class Verify {
        /** OK | FALLA | sin-bloque | no-comprobable */
        public String integrity = "no-comprobable";
        public String detail = "";
    }

    /**
     * Verifica los digests de contenido v2/v3 sobre las 3 secciones del APK
     * (AOSP apksig). Garantiza integridad del contenido; NO valida la cadena
     * de certificados. Nunca lanza.
     */
    public static Verify verify(File apk) {
        Verify v = new Verify();
        RandomAccessFile raf = null;
        try {
            long[] loc = locate(apk);
            if (loc == null) {
                v.integrity = "sin-bloque";
                v.detail = "sin bloque de firma v2/v3+";
                return v;
            }
            long sbOff = loc[0];
            long blockSize = loc[1];
            long cdOff = loc[2];
            long cdSize = loc[3];
            long eocdOff = loc[4];
            long len = loc[5];
            raf = new RandomAccessFile(apk, "r");
            long pairsLen = blockSize - 24;
            byte[] pairs = new byte[(int) pairsLen];
            raf.seek(sbOff + 8);
            raf.readFully(pairs);
            List<DigestRec> recs = new ArrayList<>();
            for (Pair p : splitPairs(pairs)) {
                if (schemeOf(p.id) == null) continue;
                digestsFromValue(p.value, recs);
            }
            if (recs.isEmpty()) {
                v.detail = "sin digests v2/v3 legibles";
                return v;
            }
            boolean need256 = false;
            boolean need512 = false;
            for (DigestRec dr : recs) {
                String j = jcaForSigAlg(dr.alg);
                if ("SHA-256".equals(j)) need256 = true;
                else if ("SHA-512".equals(j)) need512 = true;
            }
            byte[] d256 = need256
                    ? contentDigest(raf, sbOff, cdOff, cdSize, eocdOff, len, "SHA-256") : null;
            byte[] d512 = need512
                    ? contentDigest(raf, sbOff, cdOff, cdSize, eocdOff, len, "SHA-512") : null;
            int checked = 0;
            for (DigestRec dr : recs) {
                String j = jcaForSigAlg(dr.alg);
                byte[] mine = "SHA-256".equals(j) ? d256
                        : ("SHA-512".equals(j) ? d512 : null);
                if (mine == null) continue;
                checked++;
                if (MessageDigest.isEqual(mine, dr.digest)) {
                    v.integrity = "OK";
                    v.detail = "digest válido (" + j
                            + "); cadena de certificados NO validada";
                    return v;
                }
            }
            if (checked == 0) {
                v.detail = "algoritmos de firma no soportados";
                return v;
            }
            v.integrity = "FALLA";
            v.detail = checked + " digest(s) no coinciden: contenido alterado o firma inválida";
            return v;
        } catch (Throwable t) {
            v.detail = "fallo verificando";
            return v;
        } finally {
            if (raf != null) {
                try {
                    raf.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    /** {sbOff, blockSize, cdOff, cdSize, eocdOff, len} o null. Nunca lanza. */
    static long[] locate(File apk) {
        RandomAccessFile raf = null;
        try {
            if (apk == null || !apk.isFile()) return null;
            raf = new RandomAccessFile(apk, "r");
            long len = raf.length();
            if (len < 64 || len > 0xFFFFFFFFL) return null;
            long scan = Math.min(len, 65536 + 22);
            byte[] tail = new byte[(int) scan];
            raf.seek(len - scan);
            raf.readFully(tail);
            int eocd = -1;
            for (int i = tail.length - 22; i >= 0; i--) {
                if (tail[i] == 'P' && tail[i + 1] == 'K' && tail[i + 2] == 5
                        && tail[i + 3] == 6) {
                    eocd = i;
                    break;
                }
            }
            if (eocd < 0) return null;
            long eocdOff = len - scan + eocd;
            long cdSize = u32(tail, eocd + 12) & 0xFFFFFFFFL;
            long cdo = u32(tail, eocd + 16) & 0xFFFFFFFFL;
            if (cdo < 32 || cdo > len || cdSize > len || cdo + cdSize > len) return null;
            if (eocdOff < cdo + cdSize || eocdOff + 22 > len) return null;
            byte[] foot = new byte[24];
            raf.seek(cdo - 24);
            raf.readFully(foot);
            String magic = "APK Sig Block 42";
            for (int i = 0; i < 16; i++) {
                if (foot[8 + i] != (byte) magic.charAt(i)) return null;
            }
            long blockSize = u64(foot, 0);
            if (blockSize < 32 || blockSize > MAX_BLOCK || blockSize > cdo) return null;
            long sbOff = cdo - blockSize - 8;
            if (sbOff < 0) return null;
            byte[] head = new byte[8];
            raf.seek(sbOff);
            raf.readFully(head);
            if (u64(head, 0) != blockSize) return null;
            return new long[]{sbOff, blockSize, cdo, cdSize, eocdOff, len};
        } catch (Throwable t) {
            return null;
        } finally {
            if (raf != null) {
                try {
                    raf.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    static final int DIGEST_CHUNK = 1024 * 1024;

    /**
     * Digest de contenido v2/v3 (spec AOSP: trozo = 0xA5 + longitud + datos;
     * final = 0x5A + total + concatenación). El EOCD se digiere con el campo
     * offset-directorio = sbOff.
     */
    static byte[] contentDigest(RandomAccessFile raf, long sbOff, long cdOff, long cdSize,
                                long eocdOff, long len, String jca) throws Exception {
        long eocdLen = len - eocdOff;
        if (eocdLen < 22 || eocdLen > 70000) return null;
        byte[] eocd = new byte[(int) eocdLen];
        raf.seek(eocdOff);
        raf.readFully(eocd);
        eocd[16] = (byte) (sbOff & 0xFF);
        eocd[17] = (byte) ((sbOff >> 8) & 0xFF);
        eocd[18] = (byte) ((sbOff >> 16) & 0xFF);
        eocd[19] = (byte) ((sbOff >> 24) & 0xFF);
        long[][] secs = {{0, sbOff}, {cdOff, cdSize}, {-1, eocdLen}};
        long total = 0;
        for (int i = 0; i < 3; i++) total += (secs[i][1] + DIGEST_CHUNK - 1) / DIGEST_CHUNK;
        if (total <= 0 || total > 200000) return null;
        MessageDigest md = MessageDigest.getInstance(jca);
        List<byte[]> chunks = new ArrayList<>();
        byte[] buf = new byte[DIGEST_CHUNK];
        long idx = 0;
        for (int i = 0; i < 3; i++) {
            long off = secs[i][0];
            long left = secs[i][1];
            while (left > 0) {
                int n = (int) Math.min(left, (long) DIGEST_CHUNK);
                if (off < 0) {
                    System.arraycopy(eocd, (int) (eocdLen - left), buf, 0, n);
                } else {
                    raf.seek(off);
                    raf.readFully(buf, 0, n);
                }
                md.reset();
                md.update((byte) 0xA5);
                md.update(le32bytes(n));
                md.update(buf, 0, n);
                chunks.add(md.digest());
                off += n;
                left -= n;
                idx++;
            }
        }
        md.reset();
        md.update((byte) 0x5A);
        md.update(le32bytes(total));
        for (byte[] c : chunks) md.update(c);
        return md.digest();
    }

    private static byte[] le32bytes(long v) {
        return new byte[]{(byte) v, (byte) (v >> 8), (byte) (v >> 16), (byte) (v >> 24)};
    }

    static class DigestRec {
        int alg;
        byte[] digest;
    }

    /** Extrae (sigAlg, digest) del signed-data con el anidado de firstCert. */
    static void digestsFromValue(byte[] value, List<DigestRec> out) {
        try {
            if (value == null || value.length < 4) return;
            int seqLen = (int) u32(value, 0);
            int seqEnd = Math.min(value.length, 4 + seqLen);
            int p = 4;
            int guard = 0;
            while (p + 4 <= seqEnd && guard++ < 100) {
                int signerLen = (int) u32(value, p);
                if (signerLen <= 0 || signerLen > seqEnd - p - 4) break;
                digestsFromSigner(value, p + 4, signerLen, out);
                p += 4 + signerLen;
            }
        } catch (Throwable ignored) {
        }
    }

    private static void digestsFromSigner(byte[] buf, int off, int len,
                                          List<DigestRec> out) {
        int end = off + len;
        int p = off;
        if (p + 4 > end) return;
        int sdLen = (int) u32(buf, p);
        if (sdLen <= 0 || sdLen > end - p - 4) return;
        int sdOff = p + 4;
        int sdEnd = sdOff + sdLen;
        if (sdOff + 4 > sdEnd) return;
        int digLen = (int) u32(buf, sdOff);
        if (digLen < 0 || digLen > sdEnd - sdOff - 4) return;
        int q = sdOff + 4;
        int qEnd = q + digLen;
        int guard = 0;
        // Cada digest es a su vez un registro con prefijo (AOSP apksig).
        while (q + 4 <= qEnd && guard++ < 100) {
            int recLen = (int) u32(buf, q);
            if (recLen < 8 || recLen > qEnd - q - 4) break;
            int r = q + 4;
            int alg = (int) u32(buf, r);
            int dLen = (int) u32(buf, r + 4);
            if (dLen <= 0 || dLen > 128 || dLen > recLen - 8) break;
            byte[] d = new byte[dLen];
            System.arraycopy(buf, r + 8, d, 0, dLen);
            DigestRec dr = new DigestRec();
            dr.alg = alg;
            dr.digest = d;
            out.add(dr);
            q += 4 + recLen;
        }
    }

    /**
     * Algoritmo de contenido JCA para un signature algorithm v2/v3
     * (tabla de la spec AOSP).
     */
    static String jcaForSigAlg(int a) {
        switch (a) {
            case 0x0101:
            case 0x0103:
            case 0x0201:
            case 0x0301:
                return "SHA-256";
            case 0x0102:
            case 0x0104:
            case 0x0202:
                return "SHA-512";
            default:
                return null;
        }
    }

    private static long u32(byte[] b, int p) {
        return ((b[p] & 0xFFL) | ((b[p + 1] & 0xFFL) << 8)
                | ((b[p + 2] & 0xFFL) << 16) | ((b[p + 3] & 0xFFL) << 24));
    }

    private static long u64(byte[] b, int p) {
        return (u32(b, p) & 0xFFFFFFFFL) | ((u32(b, p + 4) & 0xFFFFFFFFL) << 32);
    }
}
