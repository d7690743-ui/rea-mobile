package com.nexos.reamobile.engine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Motor de análisis REA Mobile: inventario del ZIP, hashes, firmas, manifest,
 * DEX, recursos, nativas y heurísticas. Todo el análisis es estático y local.
 * Java puro (java.util/java.security/java.util.zip): funciona en la app y en JVM.
 */
public final class ReaEngine {
    private ReaEngine() {
    }

    public static final String VERSION = "0.2";
    private static final long MAX_DEX_BYTES = 160L * 1024 * 1024;
    private static final int MAX_SAMPLE = 50;
    private static final int MANIFEST_TEXT_CAP = 6000;

    private static final Pattern URL_RE = Pattern.compile("https?://[^\\s\"'<>]{4,200}", Pattern.CASE_INSENSITIVE);
    private static final Pattern IP_RE = Pattern.compile("\\b(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\b");
    private static final Pattern EMAIL_RE =
            Pattern.compile("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}");
    private static final Pattern SECRET_WORD_RE = Pattern.compile(
            "api[_-]?key|apikey|secret|passwd|password|token|bearer|private[_-]?key|AKIA[0-9A-Z]{10,}|"
                    + "AIza[0-9A-Za-z_\\-]{10,}|xox[bpas]\\-|ghp_|gho_|sk\\-live|sk\\-test",
            Pattern.CASE_INSENSITIVE);

    public static class Finding {
        public final String section;
        public final String title;
        public final String detail;
        public final String evidence;

        Finding(String section, String title, String detail, String evidence) {
            this.section = section;
            this.title = title;
            this.detail = detail;
            this.evidence = evidence;
        }
    }

    public static class ApkReport {
        public String fileName = "?";
        public long fileSize;
        public String md5 = "-";
        public String sha1 = "-";
        public String sha256 = "-";
        public String packageName = "?";
        public long entryCount;
        public long resCount;
        public long assetCount;
        public List<String> dexFiles = new ArrayList<>();
        public int totalStrings;
        public int totalClasses;
        public int totalMethods;
        public double obfuscatedRatio;
        public Map<String, Integer> apiStats = new LinkedHashMap<>();
        public List<String> nativeLibs = new ArrayList<>();
        public List<String> frameworks = new ArrayList<>();
        public List<String> certFiles = new ArrayList<>();
        public List<String> certSubjects = new ArrayList<>();
        public List<String> manifestPerms = new ArrayList<>();
        public int manifestActivities;
        public int manifestServices;
        public int manifestReceivers;
        public int manifestProviders;
        public int arscStringCount;
        public boolean arscTruncated;
        public List<String> appClasses = new ArrayList<>();
        public int appClassTotal;
        public int urlTotal;
        public int ipTotal;
        public int emailTotal;
        public int secretTotal;
        public List<String> urls = new ArrayList<>();
        public List<String> ips = new ArrayList<>();
        public List<String> emails = new ArrayList<>();
        public List<String> secretHits = new ArrayList<>();
        public List<String> suspiciousApis = new ArrayList<>();
        public String manifestXml = "";
        public String manifestNote = "";
        public List<String> dexNotes = new ArrayList<>();
        public List<Finding> findings = new ArrayList<>();
        public List<String> limitations = new ArrayList<>();
        public List<String> unknowns = new ArrayList<>();
        public String error;

        private void finding(String section, String title, String detail, String evidence) {
            findings.add(new Finding(section, title, detail, evidence));
        }

        /** Informe legible en español. */
        public String toText() {
            StringBuilder sb = new StringBuilder();
            sb.append("REA Mobile v").append(VERSION).append(" — informe estático\n");
            sb.append("archivo=").append(fileName).append(" (").append(fileSize).append(" bytes)\n");
            sb.append("md5=").append(md5).append('\n');
            sb.append("sha1=").append(sha1).append('\n');
            sb.append("sha256=").append(sha256).append('\n');
            sb.append("package=").append(packageName).append('\n');
            if (error != null) sb.append("ERROR=").append(error).append('\n');
            sb.append("\n=== INVENTARIO ===\n");
            sb.append("entradas=").append(entryCount)
                    .append(" res/=").append(resCount).append(" assets/=").append(assetCount).append('\n');
            sb.append("dex=").append(dexFiles).append('\n');
            sb.append("strings=").append(totalStrings).append(" clases=").append(totalClasses)
                    .append(" metodos=").append(totalMethods).append('\n');
            sb.append("ofuscacionRatio=").append(String.format(Locale.US, "%.2f", obfuscatedRatio)).append('\n');
            sb.append("clasesPropias=").append(appClassTotal).append('\n');
            sb.append("api=").append(apiStats).append('\n');
            sb.append("nativas=").append(nativeLibs).append('\n');
            sb.append("frameworks=").append(frameworks).append('\n');
            sb.append("arscStrings=").append(arscStringCount)
                    .append(arscTruncated ? " (muestra)" : "").append('\n');
            for (String n : dexNotes) sb.append("notaDex=").append(n).append('\n');
            sb.append("\n=== FIRMA ===\n");
            sb.append("certificados=").append(certFiles).append('\n');
            for (String s : certSubjects) sb.append("  sujeto=").append(s).append('\n');
            sb.append("\n=== MANIFEST (").append(manifestNote).append(") ===\n");
            sb.append("permisos(").append(manifestPerms.size()).append(")\n");
            for (String p : manifestPerms) sb.append("  - ").append(p).append('\n');
            sb.append("actividades=").append(manifestActivities)
                    .append(" servicios=").append(manifestServices)
                    .append(" receptores=").append(manifestReceivers)
                    .append(" proveedores=").append(manifestProviders).append('\n');
            sb.append("--- xml (extracto) ---\n");
            sb.append(manifestXml.length() > MANIFEST_TEXT_CAP
                    ? manifestXml.substring(0, MANIFEST_TEXT_CAP) + "\n[...recortado...]\n" : manifestXml);
            if (!manifestXml.endsWith("\n")) sb.append('\n');
            sb.append("\n=== INDICIOS ===\n");
            sb.append("urls=").append(urlTotal).append(" ips=").append(ipTotal)
                    .append(" emails=").append(emailTotal).append(" secretos=").append(secretTotal).append('\n');
            dumpList(sb, "url", urls);
            dumpList(sb, "ip", ips);
            dumpList(sb, "email", emails);
            dumpList(sb, "secreto?", secretHits);
            dumpList(sb, "apiSensible", suspiciousApis);
            sb.append("\n=== HALLAZGOS (con evidencia) ===\n");
            for (Finding f : findings) {
                sb.append('[').append(f.section).append("] ").append(f.title).append('\n');
                sb.append("  detalle: ").append(f.detail).append('\n');
                sb.append("  evidencia: ").append(f.evidence).append('\n');
            }
            sb.append("\n=== LIMITACIONES ===\n");
            for (String l : limitations) sb.append("  - ").append(l).append('\n');
            sb.append("\n=== DESCONOCIDOS ===\n");
            for (String u : unknowns) sb.append("  - ").append(u).append('\n');
            return sb.toString();
        }

        private static void dumpList(StringBuilder sb, String label, List<String> items) {
            for (String s : items) {
                String v = s.length() > 160 ? s.substring(0, 160) + "…" : s;
                sb.append("  ").append(label).append('=').append(v).append('\n');
            }
        }

        /** Informe en JSON mínimo. */
        public String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            jsonField(sb, "tool", "REA Mobile v" + VERSION, true);
            jsonField(sb, "file", fileName, false);
            sb.append(",\"size\":").append(fileSize);
            jsonField(sb, "md5", md5, false);
            jsonField(sb, "sha1", sha1, false);
            jsonField(sb, "sha256", sha256, false);
            jsonField(sb, "package", packageName, false);
            sb.append(",\"entries\":").append(entryCount);
            sb.append(",\"strings\":").append(totalStrings);
            sb.append(",\"classes\":").append(totalClasses);
            sb.append(",\"methods\":").append(totalMethods);
            sb.append(",\"obfuscatedRatio\":").append(String.format(Locale.US, "%.3f", obfuscatedRatio));
            jsonStrList(sb, "dexFiles", dexFiles);
            jsonStrList(sb, "nativeLibs", nativeLibs);
            jsonStrList(sb, "frameworks", frameworks);
            jsonStrList(sb, "certSubjects", certSubjects);
            jsonStrList(sb, "permissions", manifestPerms);
            jsonStrList(sb, "urls", urls);
            jsonStrList(sb, "ips", ips);
            jsonStrList(sb, "secretHits", secretHits);
            jsonStrList(sb, "suspiciousApis", suspiciousApis);
            sb.append(",\"apiStats\":{");
            boolean first = true;
            for (Map.Entry<String, Integer> e : apiStats.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                jsonQuoted(sb, e.getKey());
                sb.append(':').append(e.getValue());
            }
            sb.append('}');
            sb.append(",\"findings\":[");
            for (int i = 0; i < findings.size(); i++) {
                Finding f = findings.get(i);
                if (i > 0) sb.append(',');
                sb.append('{');
                jsonField(sb, "section", f.section, true);
                jsonField(sb, "title", f.title, false);
                jsonField(sb, "detail", f.detail, false);
                jsonField(sb, "evidence", f.evidence, false);
                sb.append('}');
            }
            sb.append(']');
            jsonStrList(sb, "limitations", limitations);
            jsonStrList(sb, "unknowns", unknowns);
            sb.append('}');
            return sb.toString();
        }

        private static void jsonField(StringBuilder sb, String k, String v, boolean first) {
            if (!first) sb.append(',');
            jsonQuoted(sb, k);
            sb.append(':');
            jsonQuoted(sb, v == null ? "" : v);
        }

        private static void jsonStrList(StringBuilder sb, String k, List<String> items) {
            sb.append(",\"").append(k).append("\":[");
            for (int i = 0; i < items.size(); i++) {
                if (i > 0) sb.append(',');
                jsonQuoted(sb, items.get(i));
            }
            sb.append(']');
        }

        private static void jsonQuoted(StringBuilder sb, String s) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"':
                        sb.append("\\\"");
                        break;
                    case '\\':
                        sb.append("\\\\");
                        break;
                    case '\n':
                        sb.append("\\n");
                        break;
                    case '\r':
                        sb.append("\\r");
                        break;
                    case '\t':
                        sb.append("\\t");
                        break;
                    default:
                        if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                        else sb.append(c);
                }
            }
            sb.append('"');
        }
    }

    /** Analiza un APK en disco. Nunca lanza: los fallos quedan en error/notas. */
    public static ApkReport analyze(File apk) {
        ApkReport r = new ApkReport();
        try {
            if (apk == null || !apk.isFile()) {
                r.error = "archivo no válido";
                finishStatic(r);
                return r;
            }
            r.fileName = apk.getName();
            r.fileSize = apk.length();
            hashFile(apk, r);

            Set<String> urlSet = new LinkedHashSet<>();
            Set<String> ipSet = new LinkedHashSet<>();
            Set<String> emailSet = new LinkedHashSet<>();
            Set<String> secretSet = new LinkedHashSet<>();
            Set<String> suspSet = new LinkedHashSet<>();
            int[] counters = new int[4]; // url, ip, email, secret
            Set<String> frameworks = new LinkedHashSet<>();
            long obfWeighted = 0;
            long obfTotal = 0;

            ZipFile zip = new ZipFile(apk);
            try {
                byte[] manifestBytes = null;
                byte[] arscBytes = null;
                List<String> dexNames = new ArrayList<>();
                List<String> soNames = new ArrayList<>();
                List<String> certNames = new ArrayList<>();
                Enumeration<? extends ZipEntry> en = zip.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e.isDirectory()) continue;
                    String name = e.getName();
                    r.entryCount++;
                    if (name.equals("AndroidManifest.xml")) manifestBytes = readEntry(zip, e, 20 * 1024 * 1024);
                    else if (name.equals("resources.arsc")) arscBytes = readEntry(zip, e, 100 * 1024 * 1024);
                    else if (name.matches("classes\\d*\\.dex")) dexNames.add(name);
                    else if (name.startsWith("lib/") && name.endsWith(".so")) soNames.add(name);
                    else if (name.startsWith("META-INF/") && name.matches(".*\\.(RSA|DSA|EC|rsa|dsa|ec)$"))
                        certNames.add(name);
                    else if (name.startsWith("res/")) r.resCount++;
                    else if (name.startsWith("assets/")) r.assetCount++;
                    detectFrameworkByName(name, frameworks);
                }

                // Manifest.
                if (manifestBytes != null) {
                    String xml = AxmlDecoder.decode(manifestBytes);
                    r.manifestXml = xml;
                    r.packageName = AxmlDecoder.packageName(xml);
                    r.manifestPerms = AxmlDecoder.usesPermissions(xml);
                    r.manifestActivities = AxmlDecoder.countTag(xml, "activity");
                    r.manifestServices = AxmlDecoder.countTag(xml, "service");
                    r.manifestReceivers = AxmlDecoder.countTag(xml, "receiver");
                    r.manifestProviders = AxmlDecoder.countTag(xml, "provider");
                    r.manifestNote = xml.isEmpty() ? "vacío" : (xml.length() + " caracteres");
                    if (xml.isEmpty()) r.manifestNote = "no decodificado";
                } else {
                    r.manifestNote = "ausente";
                }

                // DEX.
                for (String dexName : dexNames) {
                    ZipEntry e = zip.getEntry(dexName);
                    if (e == null) continue;
                    r.dexFiles.add(dexName + " (" + e.getSize() + " B)");
                    byte[] dexBytes = readEntry(zip, e, MAX_DEX_BYTES);
                    if (dexBytes == null) {
                        r.dexNotes.add(dexName + ": omitido por tamaño");
                        continue;
                    }
                    DexParser.DexInfo di = DexParser.parse(dexBytes, dexName);
                    if (di.error != null) {
                        r.dexNotes.add(dexName + ": " + di.error);
                        continue;
                    }
                    r.totalStrings += di.stringCount;
                    r.totalClasses += di.classCount;
                    r.totalMethods += di.methodCount;
                    obfWeighted += (long) (di.obfuscatedRatio * di.classCount);
                    obfTotal += di.classCount;
                    mergeStats(r.apiStats, di.apiStats);
                    String slash = "L" + r.packageName.replace('.', '/') + "/";
                    for (DexParser.ClassInfo ci : di.classes) {
                        if (ci.name != null && !"?".equals(r.packageName) && ci.name.startsWith(slash)) {
                            r.appClassTotal++;
                            if (r.appClasses.size() < 5000) r.appClasses.add(ci.name);
                        }
                    }
                    if (di.hasKotlin) frameworks.add("Kotlin");
                    if (di.hasAndroidx) frameworks.add("AndroidX/Jetpack");
                    if (di.hasGms) frameworks.add("Google/GMS");
                    if (di.hasUnity) frameworks.add("Unity");
                    scanStrings(di.strings, urlSet, ipSet, emailSet, secretSet, counters);
                    for (String s : di.suspicious) {
                        if (suspSet.size() < MAX_SAMPLE) suspSet.add(s);
                    }
                    if (di.stringsTruncated || di.classesTruncated) {
                        r.dexNotes.add(dexName + ": muestra parcial (topes)");
                    }
                }
                if (obfTotal > 0) r.obfuscatedRatio = (double) obfWeighted / obfTotal;

                // ARSC.
                if (arscBytes != null) {
                    ArscStrings.ArscInfo ai = ArscStrings.parse(arscBytes);
                    if (ai.error != null) {
                        r.dexNotes.add("resources.arsc: " + ai.error);
                    } else {
                        r.arscStringCount = ai.stringCount;
                        r.arscTruncated = ai.truncated;
                        scanStrings(ai.strings, urlSet, ipSet, emailSet, secretSet, counters);
                    }
                }

                // Nativas: inventario + arquitectura por cabecera ELF.
                for (String so : soNames) {
                    ZipEntry e = zip.getEntry(so);
                    byte[] head = e == null ? null : readPrefix(zip, e, 64);
                    r.nativeLibs.add(so + " (" + elfArch(head) + ")");
                    if (r.nativeLibs.size() >= 100) break;
                }

                // Certificados: sujetos X.509.
                for (String cn : certNames) {
                    ZipEntry e = zip.getEntry(cn);
                    if (e == null) continue;
                    r.certFiles.add(cn);
                    byte[] certBytes = readEntry(zip, e, 1024 * 1024);
                    if (certBytes != null) r.certSubjects.addAll(certSubjects(certBytes));
                    if (r.certFiles.size() >= 10) break;
                }

                r.frameworks.addAll(frameworks);
            } finally {
                try {
                    zip.close();
                } catch (Exception ignored) {
                }
            }

            r.urls.addAll(cap(urlSet));
            r.ips.addAll(cap(ipSet));
            r.emails.addAll(cap(emailSet));
            r.secretHits.addAll(cap(secretSet));
            r.suspiciousApis.addAll(suspSet);
            r.urlTotal = counters[0];
            r.ipTotal = counters[1];
            r.emailTotal = counters[2];
            r.secretTotal = counters[3];

            buildFindings(r);
            finishStatic(r);
        } catch (Exception e) {
            r.error = "fallo general: " + e.getMessage();
            finishStatic(r);
        }
        return r;
    }

    private static List<String> cap(Set<String> s) {
        List<String> out = new ArrayList<>();
        for (String v : s) {
            if (out.size() >= MAX_SAMPLE) break;
            out.add(v);
        }
        return out;
    }

    private static void detectFrameworkByName(String name, Set<String> out) {
        String n = name.toLowerCase(Locale.US);
        if (n.contains("libflutter.so") || n.endsWith("libapp.so")) out.add("Flutter/Dart");
        if (n.contains("libreactnativejni.so") || n.contains("libfbjni.so")) out.add("React Native");
        if (n.contains("libunity.so")) out.add("Unity");
        if (n.contains("libmonosgen") || n.contains("libmono")) out.add("Xamarin/.NET");
    }

    private static void scanStrings(Collection<String> strings, Set<String> urls, Set<String> ips,
                                     Set<String> emails, Set<String> secrets, int[] counters) {
        for (String s : strings) {
            if (s == null || s.isEmpty()) continue;
            Matcher mu = URL_RE.matcher(s);
            while (mu.find()) {
                counters[0]++;
                if (urls.size() < MAX_SAMPLE) urls.add(mu.group());
            }
            Matcher mi = IP_RE.matcher(s);
            while (mi.find()) {
                boolean ok = true;
                for (int g = 1; g <= 4; g++) {
                    try {
                        if (Integer.parseInt(mi.group(g)) > 255) ok = false;
                    } catch (NumberFormatException e) {
                        ok = false;
                    }
                }
                if (ok && !"0.0.0.0".equals(mi.group()) && !"255.255.255.255".equals(mi.group())) {
                    counters[1]++;
                    if (ips.size() < MAX_SAMPLE) ips.add(mi.group());
                }
            }
            if (s.length() < 300) {
                Matcher me = EMAIL_RE.matcher(s);
                while (me.find()) {
                    counters[2]++;
                    if (emails.size() < MAX_SAMPLE) emails.add(me.group());
                }
                Matcher ms = SECRET_WORD_RE.matcher(s);
                if (ms.find()) {
                    counters[3]++;
                    if (secrets.size() < MAX_SAMPLE) secrets.add(s.trim());
                }
            }
        }
    }

    private static String elfArch(byte[] head) {
        try {
            if (head == null || head.length < 20) return "?";
            if (head[0] != 0x7F || head[1] != 'E' || head[2] != 'L' || head[3] != 'F') return "no-ELF";
            int machine = (head[18] & 0xFF) | ((head[19] & 0xFF) << 8);
            switch (machine) {
                case 3:
                    return "x86";
                case 40:
                    return "ARM";
                case 62:
                    return "x86-64";
                case 183:
                    return "ARM64";
                default:
                    return "ELF máquina=" + machine;
            }
        } catch (RuntimeException e) {
            return "?";
        }
    }

    private static List<String> certSubjects(byte[] pkcs7) {
        List<String> out = new ArrayList<>();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs =
                    cf.generateCertificates(new ByteArrayInputStream(pkcs7));
            for (Certificate c : certs) {
                if (c instanceof X509Certificate && out.size() < 5) {
                    X509Certificate x = (X509Certificate) c;
                    out.add(x.getSubjectX500Principal().getName() + " | serie=" + x.getSerialNumber());
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    private static void hashFile(File apk, ApkReport r) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            InputStream in = new FileInputStream(apk);
            try {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    md5.update(buf, 0, n);
                    sha1.update(buf, 0, n);
                    sha256.update(buf, 0, n);
                }
            } finally {
                try {
                    in.close();
                } catch (Exception ignored) {
                }
            }
            r.md5 = hex(md5.digest());
            r.sha1 = hex(sha1.digest());
            r.sha256 = hex(sha256.digest());
        } catch (Exception ignored) {
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    private static byte[] readEntry(ZipFile zip, ZipEntry e, long max) {
        try {
            long size = e.getSize();
            if (size > max) return null;
            InputStream in = zip.getInputStream(e);
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[32768];
                int n;
                long total = 0;
                while ((n = in.read(buf)) > 0) {
                    total += n;
                    if (total > max) return null;
                    bos.write(buf, 0, n);
                }
                return bos.toByteArray();
            } finally {
                try {
                    in.close();
                } catch (Exception ignored) {
                }
            }
        } catch (Exception e2) {
            return null;
        }
    }

    /** Lee los primeros n bytes de una entrada (aunque sea grande). */
    private static byte[] readPrefix(ZipFile zip, ZipEntry e, int n) {
        try {
            InputStream in = zip.getInputStream(e);
            try {
                byte[] buf = new byte[n];
                int total = 0;
                int r;
                while (total < n && (r = in.read(buf, total, n - total)) > 0) total += r;
                if (total == 0) return null;
                if (total == n) return buf;
                byte[] out = new byte[total];
                System.arraycopy(buf, 0, out, 0, total);
                return out;
            } finally {
                try {
                    in.close();
                } catch (Exception ignored) {
                }
            }
        } catch (Exception e2) {
            return null;
        }
    }

    public static class ExtractResult {
        public String packageName = "?";
        public int copiedEntries;
        public int smaliClasses;
        public long bytes;
        public List<String> notes = new ArrayList<>();
        public String error;

        public String summary() {
            StringBuilder sb = new StringBuilder();
            sb.append("paquete=").append(packageName).append('\n');
            sb.append("entradasCopiadas=").append(copiedEntries).append('\n');
            sb.append("clasesSmali=").append(smaliClasses).append('\n');
            sb.append("zipBytes=").append(bytes).append('\n');
            for (String n : notes) sb.append("nota=").append(n).append('\n');
            if (error != null) sb.append("ERROR=").append(error).append('\n');
            return sb.toString();
        }
    }

    private static final long MAX_COPY_ENTRY = 80L * 1024 * 1024;
    private static final long MAX_ZIP_TOTAL = 250L * 1024 * 1024;
    private static final int MAX_STRING_LINES = 30000;

    /** Extrae el árbol del APK + smali + informe a un ZIP. Nunca lanza. */
    public static ExtractResult extractToZip(File apk, File outZip) {
        ExtractResult r = new ExtractResult();
        try {
            if (apk == null || !apk.isFile()) {
                r.error = "archivo no válido";
                return r;
            }
            ZipFile zip = new ZipFile(apk);
            try {
                String manifestXml = "";
                String pkg = "?";
                ZipEntry man = zip.getEntry("AndroidManifest.xml");
                if (man != null) {
                    byte[] mb = readEntry(zip, man, 20 * 1024 * 1024);
                    if (mb != null) {
                        manifestXml = AxmlDecoder.decode(mb);
                        pkg = AxmlDecoder.packageName(manifestXml);
                    }
                }
                r.packageName = pkg;
                String pkgSlash = pkg.replace('.', '/') + "/";
                List<String> dexNames = new ArrayList<>();
                Enumeration<? extends ZipEntry> en0 = zip.entries();
                while (en0.hasMoreElements()) {
                    ZipEntry e = en0.nextElement();
                    if (!e.isDirectory() && e.getName().matches("classes\\d*\\.dex")) dexNames.add(e.getName());
                }
                List<byte[]> dexBytes = new ArrayList<>();
                for (String dn : dexNames) {
                    ZipEntry e = zip.getEntry(dn);
                    byte[] b = e == null ? null : readEntry(zip, e, MAX_DEX_BYTES);
                    if (b == null) {
                        r.notes.add(dn + ": omitido por tamaño");
                        continue;
                    }
                    dexBytes.add(b);
                }
                SmaliDumper.DumpResult smali = SmaliDumper.dumpAll(dexBytes, pkgSlash);
                r.smaliClasses = smali.classes.size();
                r.notes.addAll(smali.notes);
                if (smali.truncated) r.notes.add("smali: recortado por topes");
                List<String> dexStrings = new ArrayList<>();
                for (byte[] b : dexBytes) {
                    DexParser.DexInfo di = DexParser.parse(b, "dex");
                    if (di.error == null) {
                        for (String s : di.strings) {
                            if (dexStrings.size() >= MAX_STRING_LINES) break;
                            dexStrings.add(s);
                        }
                    }
                }
                List<String> arscStrings = new ArrayList<>();
                int arscTotal = 0;
                ZipEntry arsc = zip.getEntry("resources.arsc");
                if (arsc != null) {
                    byte[] ab = readEntry(zip, arsc, 100 * 1024 * 1024);
                    if (ab != null) {
                        ArscStrings.ArscInfo ai = ArscStrings.parse(ab);
                        if (ai.error == null) {
                            arscTotal = ai.stringCount;
                            arscStrings.addAll(ai.strings);
                        }
                    }
                }
                ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outZip));
                long total = 0;
                try {
                    StringBuilder tree = new StringBuilder();
                    Enumeration<? extends ZipEntry> en = zip.entries();
                    while (en.hasMoreElements()) {
                        ZipEntry e = en.nextElement();
                        if (e.isDirectory()) continue;
                        String name = e.getName();
                        tree.append(name).append(" (").append(e.getSize()).append(" B)\n");
                        if (e.getSize() > MAX_COPY_ENTRY) {
                            r.notes.add(name + ": no copiado (>80MB)");
                            continue;
                        }
                        byte[] data = readEntry(zip, e, MAX_COPY_ENTRY);
                        if (data == null) {
                            r.notes.add(name + ": no copiado");
                            continue;
                        }
                        if (total + data.length > MAX_ZIP_TOTAL) {
                            r.notes.add("tope total ZIP alcanzado en " + name);
                            break;
                        }
                        zos.putNextEntry(new ZipEntry("apk/" + name));
                        zos.write(data);
                        zos.closeEntry();
                        total += data.length;
                        r.copiedEntries++;
                    }
                    putText(zos, "rea/manifest.xml", manifestXml.isEmpty() ? "(no decodificado)\n" : manifestXml);
                    putText(zos, "rea/ARBOL.txt", tree.toString());
                    StringBuilder cls = new StringBuilder();
                    for (String s : smali.classSummaries) cls.append(s).append('\n');
                    putText(zos, "rea/CLASES_PROPIAS.txt", cls.length() == 0 ? "(sin clases)\n" : cls.toString());
                    for (SmaliDumper.SmaliClass sc : smali.classes) {
                        zos.putNextEntry(new ZipEntry("rea/" + sc.path));
                        zos.write(sc.text.getBytes("UTF-8"));
                        zos.closeEntry();
                    }
                    StringBuilder ds = new StringBuilder();
                    for (String s : dexStrings) ds.append(s.replace('\n', ' ')).append('\n');
                    putText(zos, "rea/INDICIOS_strings_dex.txt", ds.toString());
                    StringBuilder as = new StringBuilder("total=" + arscTotal + "\n");
                    for (String s : arscStrings) as.append(s.replace('\n', ' ')).append('\n');
                    putText(zos, "rea/INDICIOS_strings_arsc.txt", as.toString());
                    List<String> slashes = new ArrayList<>();
                    if (!"?".equals(pkg)) slashes.add(pkgSlash);
                    try {
                        File wd = outZip.getParentFile() != null ? outZip.getParentFile() : new File(".");
                        JadxAdapter.Result jr = JadxAdapter.decompileFiltered(
                                apk, wd, 2, slashes, 300, null);
                        for (Map.Entry<String, String> e : jr.sources.entrySet()) {
                            putText(zos, "rea/JAVA/" + e.getKey().replace('.', '/') + ".java", e.getValue());
                        }
                        r.notes.add("java: " + jr.sources.size() + " clases, errores=" + jr.errors);
                        if (jr.truncated) r.notes.add("java: recortado por topes");
                        if (jr.error != null) r.notes.add("java: " + jr.error);
                    } catch (Exception ex) {
                        r.notes.add("java: no disponible");
                    }
                    ApkReport rep = analyze(apk);
                    putText(zos, "rea/INFORME.txt", rep.toText());
                    StringBuilder xs = new StringBuilder();
                    xs.append("paquete=").append(r.packageName).append('\n');
                    xs.append("entradasCopiadas=").append(r.copiedEntries).append('\n');
                    xs.append("clasesSmali=").append(r.smaliClasses).append('\n');
                    for (String nn : r.notes) xs.append("nota=").append(nn).append('\n');
                    putText(zos, "rea/EXTRACCION.txt", xs.toString());
                } finally {
                    try {
                        zos.close();
                    } catch (Exception ignored) {
                    }
                }
                r.bytes = outZip.length();
            } finally {
                try {
                    zip.close();
                } catch (Exception ignored) {
                }
            }
        } catch (Exception e) {
            r.error = "fallo general: " + e.getMessage();
        }
        return r;
    }

    private static void putText(ZipOutputStream zos, String name, String text) throws Exception {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(text.getBytes("UTF-8"));
        zos.closeEntry();
    }

    private static void mergeStats(Map<String, Integer> acc, Map<String, Integer> one) {
        for (Map.Entry<String, Integer> e : one.entrySet()) {
            acc.put(e.getKey(), acc.containsKey(e.getKey()) ? acc.get(e.getKey()) + e.getValue() : e.getValue());
        }
    }

    private static void buildFindings(ApkReport r) {
        r.finding("identidad", "Paquete " + r.packageName,
                r.entryCount + " entradas, " + r.dexFiles.size() + " dex, "
                        + r.totalClasses + " clases, " + r.totalMethods + " métodos, "
                        + r.totalStrings + " strings.",
                "sha256=" + r.sha256);
        if (!r.certSubjects.isEmpty()) {
            r.finding("firma", r.certSubjects.size() + " certificado(s) en META-INF",
                    r.certSubjects.get(0), "archivos=" + r.certFiles);
        } else {
            r.finding("firma", "Sin certificados X.509 legibles en META-INF",
                    "Puede usar solo firma v2/v3+ (bloque de firma, no extraíble por ZIP).",
                    "archivos=" + r.certFiles);
        }
        if (!r.frameworks.isEmpty()) {
            r.finding("frameworks", "Tecnologías: " + r.frameworks,
                    "Detectadas por librerías y prefijos de clase.", "inventario ZIP + DEX");
        }
        if (r.totalClasses > 50 && r.obfuscatedRatio > 0.30) {
            r.finding("ofuscación", "Ofuscación probable (ratio " + String.format(Locale.US, "%.2f", r.obfuscatedRatio) + ")",
                    "Muchas clases con nombres de 1-2 letras fuera del framework.",
                    r.totalClasses + " clases definidas");
        }
        if (!r.nativeLibs.isEmpty()) {
            r.finding("nativas", r.nativeLibs.size() + " librería(s) .so",
                    r.nativeLibs.size() > 3 ? r.nativeLibs.subList(0, 3) + "…" : r.nativeLibs.toString(),
                    "cabeceras ELF en lib/");
        }
        if (r.urlTotal > 0) {
            r.finding("red", r.urlTotal + " URL(s) en strings",
                    r.urls.isEmpty() ? "-" : r.urls.get(0) + (r.urlTotal > 1 ? " (+" + (r.urlTotal - 1) + ")" : ""),
                    "DEX + ARSC");
        }
        if (r.ipTotal > 0) {
            r.finding("red", r.ipTotal + " IP(s) en strings",
                    r.ips.isEmpty() ? "-" : r.ips.toString(), "DEX + ARSC");
        }
        if (r.secretTotal > 0) {
            r.finding("secretos", r.secretTotal + " posible(s) secreto(s)/clave(s)",
                    "Revisar manualmente: son coincidencias por palabra, no confirmaciones.",
                    "DEX + ARSC");
        }
        if (!r.suspiciousApis.isEmpty()) {
            r.finding("apis", r.suspiciousApis.size() + "+ referencia(s) a API sensible (muestra)",
                    r.suspiciousApis.get(0), "method_ids del DEX");
        }
        if (!r.manifestPerms.isEmpty()) {
            r.finding("permisos", r.manifestPerms.size() + " permiso(s) declarados",
                    r.manifestActivities + " actividades, " + r.manifestServices + " servicios, "
                            + r.manifestReceivers + " receptores, " + r.manifestProviders + " proveedores.",
                    "AndroidManifest.xml decodificado");
        }
    }

    private static void finishStatic(ApkReport r) {
        r.limitations.add("Sin descompilación a Java: requiere JADX con JDK completo, no disponible on-device.");
        r.limitations.add("Sin referencias cruzadas completas (xrefs): solo firmas, conteos y stats por paquete.");
        r.limitations.add("Sin análisis dinámico (Frida/adb): estático únicamente.");
        r.limitations.add("AXML y ARSC decodificados con parser propio (best-effort).");
        r.limitations.add("Nativas: solo inventario y arquitectura ELF, sin desensamblado.");
        r.limitations.add("Muestreo con topes en APKs grandes (ver notas).");
        r.unknowns.add("Comportamiento en ejecución (runtime).");
        r.unknowns.add("Contenido descargado, generado o descifrado en runtime.");
        r.unknowns.add("Código tras ofuscación o empaquetado: nombres y flujo pueden ocultar la lógica.");
    }
}
