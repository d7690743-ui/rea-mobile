package com.nexos.reamobile.engine;

import java.io.File;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
    /** Bloques de Source Stamp (AOSP SourceStampConstants). */
    public static final int ID_STAMP_V2 = 0x6dff800d;
    public static final int ID_STAMP_V1 = 0x2b09189e;
    /** Atributo proof-of-rotation en signed-data v3/v3.1 (AOSP V3SchemeConstants). */
    public static final int ATTR_ROTATION_V3 = 0x3ba06f8c;
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

    public static class DigestRec {
        public int alg;
        public byte[] digest;
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

    // ------------------------------------------------------------------
    // API pública para el motor de autenticidad (REA APK Authenticity Engine).
    // Solo añade lectura estructurada del bloque; no cambia el código previo.
    // ------------------------------------------------------------------

    /** Un par (id, valor) del bloque de firma. */
    public static class Block {
        public int id;
        public byte[] value;
    }

    /**
     * Todos los pares del bloque de firma (v2/v3/v3.1/sellos/otros).
     * Lista vacía si no hay bloque legible. Nunca lanza.
     */
    public static List<Block> blocks(File apk) {
        List<Block> out = new ArrayList<>();
        RandomAccessFile raf = null;
        try {
            long[] loc = locate(apk);
            if (loc == null) return out;
            long sbOff = loc[0];
            long blockSize = loc[1];
            long pairsLen = blockSize - 24;
            if (pairsLen <= 0 || pairsLen > MAX_BLOCK) return out;
            byte[] pairs = new byte[(int) pairsLen];
            raf = new RandomAccessFile(apk, "r");
            raf.seek(sbOff + 8);
            raf.readFully(pairs);
            for (Pair p : splitPairs(pairs)) {
                Block b = new Block();
                b.id = p.id;
                b.value = p.value;
                out.add(b);
                if (out.size() >= 64) break;
            }
        } catch (Throwable ignored) {
        } finally {
            if (raf != null) {
                try {
                    raf.close();
                } catch (Throwable ignored) {
                }
            }
        }
        return out;
    }

    /**
     * Rango {offset, tamaño} del bloque de firma en el fichero, o null si no
     * hay bloque legible. Nunca lanza.
     */
    public static long[] blockRange(File apk) {
        try {
            long[] loc = locate(apk);
            if (loc == null) return null;
            return new long[]{loc[0], loc[1] + 8};
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** true si hay bloque de Source Stamp (v1 o v2). Nunca lanza. */
    public static boolean hasStampBlock(File apk) {
        try {
            for (Block b : blocks(apk)) {
                if (b.id == ID_STAMP_V2 || b.id == ID_STAMP_V1) return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /** Esquemas v2/v3/v3.1 presentes por ID de bloque. Nunca null. Nunca lanza. */
    public static List<String> schemesPresent(File apk) {
        List<String> out = new ArrayList<>();
        try {
            for (Block b : blocks(apk)) {
                String s = schemeOf(b.id);
                if (s != null && !out.contains(s)) out.add(s);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Una firma (algoritmo + bytes) de un firmante. */
    public static class SigRec {
        public int alg;
        public byte[] sig;
    }

    /** Un firmante de un valor v2/v3/v3.1 con sus piezas para verificar. */
    public static class SignerData {
        /** Bytes exactos de signed-data (lo que cubre la firma asimétrica). */
        public byte[] signedData;
        public List<byte[]> certs = new ArrayList<>();
        public List<SigRec> sigs = new ArrayList<>();
        /** Solo v3/v3.1: cotas SDK del firmante (-1 si ausentes). */
        public int minSdk = -1;
        public int maxSdk = -1;
        /** Valor del atributo proof-of-rotation, null si ausente. */
        public byte[] rotationAttr;
    }

    /**
     * Todos los firmantes de un valor v2/v3/v3.1.
     * v3Layout=true para v3/v3.1 (min/max SDK tras signed-data y en signed-data).
     * Nunca null. Nunca lanza.
     */
    public static List<SignerData> signersOf(byte[] value, boolean v3layout) {
        List<SignerData> out = new ArrayList<>();
        try {
            if (value == null || value.length < 4) return out;
            int seqLen = (int) u32(value, 0);
            int seqEnd = Math.min(value.length, 4 + seqLen);
            int p = 4;
            int guard = 0;
            while (p + 4 <= seqEnd && guard++ < 100 && out.size() < 32) {
                int signerLen = (int) u32(value, p);
                if (signerLen <= 0 || signerLen > seqEnd - p - 4) break;
                SignerData sd = signerAt(value, p + 4, signerLen, v3layout);
                if (sd != null) out.add(sd);
                p += 4 + signerLen;
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static SignerData signerAt(byte[] buf, int off, int len, boolean v3layout) {
        try {
            int end = off + len;
            int p = off;
            if (p + 4 > end) return null;
            int sdLen = (int) u32(buf, p);
            if (sdLen <= 0 || sdLen > end - p - 4) return null;
            byte[] sd = new byte[sdLen];
            System.arraycopy(buf, p + 4, sd, 0, sdLen);
            int q = p + 4 + sdLen;
            SignerData r = new SignerData();
            r.signedData = sd;
            if (v3layout) {
                if (q + 8 > end) return null;
                r.minSdk = (int) u32(buf, q);
                r.maxSdk = (int) u32(buf, q + 4);
                q += 8;
            }
            if (q + 4 > end) return null;
            int sigsLen = (int) u32(buf, q);
            if (sigsLen < 0 || sigsLen > end - q - 4) return null;
            int s = q + 4;
            int sEnd = s + sigsLen;
            int guard = 0;
            while (s + 4 <= sEnd && guard++ < 32) {
                int recLen = (int) u32(buf, s);
                if (recLen < 8 || recLen > sEnd - s - 4) break;
                int t = s + 4;
                int alg = (int) u32(buf, t);
                int sigLen = (int) u32(buf, t + 4);
                if (sigLen <= 0 || sigLen > 8192 || sigLen > recLen - 8) break;
                byte[] sig = new byte[sigLen];
                System.arraycopy(buf, t + 8, sig, 0, sigLen);
                SigRec sr = new SigRec();
                sr.alg = alg;
                sr.sig = sig;
                r.sigs.add(sr);
                s += 4 + recLen;
            }
            r.certs = certsOfSignedData(sd);
            r.rotationAttr = attrValue(sd, ATTR_ROTATION_V3, v3layout);
            return r;
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Todos los certificados del signed-data (v2 y v3 comparten el prefijo
     * digests+certificados). Nunca null. Nunca lanza.
     */
    public static List<byte[]> certsOfSignedData(byte[] sd) {
        List<byte[]> out = new ArrayList<>();
        try {
            if (sd == null || sd.length < 4) return out;
            int digLen = (int) u32(sd, 0);
            if (digLen < 0 || digLen > sd.length - 4) return out;
            int q = 4 + digLen;
            if (q + 4 > sd.length) return out;
            int certsLen = (int) u32(sd, q);
            if (certsLen < 0 || certsLen > sd.length - q - 4) return out;
            int c = q + 4;
            int cEnd = c + certsLen;
            int guard = 0;
            while (c + 4 <= cEnd && guard++ < 32) {
                int oneLen = (int) u32(sd, c);
                if (oneLen <= 0 || oneLen > cEnd - c - 4) break;
                byte[] cert = new byte[oneLen];
                System.arraycopy(sd, c + 4, cert, 0, oneLen);
                out.add(cert);
                c += 4 + oneLen;
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Valor de un atributo adicional del signed-data (null si ausente).
     * v3layout=true: salta min/max SDK u32 antes de los atributos.
     * Nunca lanza.
     */
    public static byte[] attrValue(byte[] sd, int attrId, boolean v3layout) {
        try {
            if (sd == null || sd.length < 4) return null;
            int digLen = (int) u32(sd, 0);
            if (digLen < 0 || digLen > sd.length - 4) return null;
            int q = 4 + digLen;
            if (q + 4 > sd.length) return null;
            int certsLen = (int) u32(sd, q);
            if (certsLen < 0 || certsLen > sd.length - q - 4) return null;
            int a = q + 4 + certsLen;
            if (v3layout) {
                if (a + 8 > sd.length) return null;
                a += 8;
            }
            if (a + 4 > sd.length) return null;
            int attrsLen = (int) u32(sd, a);
            if (attrsLen < 0 || attrsLen > sd.length - a - 4) return null;
            int p = a + 4;
            int end = p + attrsLen;
            int guard = 0;
            while (p + 4 <= end && guard++ < 64) {
                int recLen = (int) u32(sd, p);
                if (recLen < 4 || recLen > end - p - 4) break;
                int id = (int) u32(sd, p + 4);
                int vlen = recLen - 4;
                if (id == attrId) {
                    byte[] v = new byte[vlen];
                    System.arraycopy(sd, p + 8, v, 0, vlen);
                    return v;
                }
                p += 4 + recLen;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** Digests (sigAlg, digest) de un valor v2/v3. Nunca null. Nunca lanza. */
    public static List<DigestRec> digestsOf(byte[] value) {
        List<DigestRec> out = new ArrayList<>();
        try {
            digestsFromValue(value, out);
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Nombre JCA para verificar la firma asimétrica de un signature algorithm
     * v2/v3 (tabla AOSP SignatureAlgorithm). Null si no soportado.
     */
    public static String jcaSigForAlg(int a) {
        switch (a) {
            case 0x0101: return "SHA256withRSA/PSS";
            case 0x0102: return "SHA512withRSA/PSS";
            case 0x0103: return "SHA256withRSA";
            case 0x0104: return "SHA512withRSA";
            case 0x0201: return "SHA256withECDSA";
            case 0x0202: return "SHA512withECDSA";
            case 0x0301: return "SHA256withDSA";
            default: return null;
        }
    }

    /** Verificación de digests agrupada por ID de bloque (una sola pasada). */
    public static class BlockVerify {
        /** Global, misma semántica que {@link #verify(File)}. */
        public Verify all = new Verify();
        /** Por ID de bloque presente (v2/v3/v3.1). */
        public Map<Integer, Verify> byId = new LinkedHashMap<>();
    }

    /**
     * Como {@link #verify(File)} pero con resultado por bloque v2/v3/v3.1,
     * calculando cada digest de contenido una sola vez. Nunca lanza.
     */
    public static BlockVerify verifyByBlock(File apk) {
        BlockVerify r = new BlockVerify();
        RandomAccessFile raf = null;
        try {
            long[] loc = locate(apk);
            if (loc == null) {
                r.all.integrity = "sin-bloque";
                r.all.detail = "sin bloque de firma v2/v3+";
                return r;
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
            Map<Integer, List<DigestRec>> perId = new LinkedHashMap<>();
            for (Pair p : splitPairs(pairs)) {
                if (schemeOf(p.id) == null) continue;
                List<DigestRec> recs = perId.get(p.id);
                if (recs == null) {
                    recs = new ArrayList<>();
                    perId.put(p.id, recs);
                }
                digestsFromValue(p.value, recs);
            }
            boolean anyRec = false;
            boolean need256 = false;
            boolean need512 = false;
            for (List<DigestRec> recs : perId.values()) {
                for (DigestRec dr : recs) {
                    anyRec = true;
                    String j = jcaForSigAlg(dr.alg);
                    if ("SHA-256".equals(j)) need256 = true;
                    else if ("SHA-512".equals(j)) need512 = true;
                }
            }
            if (!anyRec) {
                r.all.detail = "sin digests v2/v3 legibles";
                for (Integer id : perId.keySet()) {
                    Verify v = new Verify();
                    v.detail = "sin digests legibles";
                    r.byId.put(id, v);
                }
                return r;
            }
            byte[] d256 = need256
                    ? contentDigest(raf, sbOff, cdOff, cdSize, eocdOff, len, "SHA-256") : null;
            byte[] d512 = need512
                    ? contentDigest(raf, sbOff, cdOff, cdSize, eocdOff, len, "SHA-512") : null;
            int checkedAll = 0;
            boolean anyOk = false;
            for (Map.Entry<Integer, List<DigestRec>> e : perId.entrySet()) {
                Verify v = new Verify();
                int checked = 0;
                boolean ok = false;
                for (DigestRec dr : e.getValue()) {
                    String j = jcaForSigAlg(dr.alg);
                    byte[] mine = "SHA-256".equals(j) ? d256
                            : ("SHA-512".equals(j) ? d512 : null);
                    if (mine == null) continue;
                    checked++;
                    checkedAll++;
                    if (MessageDigest.isEqual(mine, dr.digest)) ok = true;
                }
                if (ok) {
                    v.integrity = "OK";
                    v.detail = "digest válido; cadena de certificados NO validada";
                    anyOk = true;
                } else if (checked > 0) {
                    v.integrity = "FALLA";
                    v.detail = checked + " digest(s) no coinciden: contenido alterado o firma inválida";
                } else {
                    v.detail = "algoritmos de firma no soportados";
                }
                r.byId.put(e.getKey(), v);
            }
            if (anyOk) {
                r.all.integrity = "OK";
                r.all.detail = "digest válido; cadena de certificados NO validada";
            } else if (checkedAll > 0) {
                r.all.integrity = "FALLA";
                r.all.detail = checkedAll
                        + " digest(s) no coinciden: contenido alterado o firma inválida";
            } else {
                r.all.detail = "algoritmos de firma no soportados";
            }
            return r;
        } catch (Throwable t) {
            r.all.detail = "fallo verificando";
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
}
