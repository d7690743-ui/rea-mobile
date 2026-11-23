package com.nexos.reamobile.engine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
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
import com.nexos.reamobile.intelligence.IntelFinding;
import com.nexos.reamobile.intelligence.IntelRegistry;

/**
 * Motor de análisis REA Mobile: inventario del ZIP, hashes, firmas, manifest,
 * DEX, recursos, nativas y heurísticas. Todo el análisis es estático y local.
 * Java puro (java.util/java.security/java.util.zip): funciona en la app y en JVM.
 */
public final class ReaEngine {
    private ReaEngine() {
    }

    public static final String VERSION = "0.4";
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
        public boolean apkSigBlock;
        public List<String> topPackages = new ArrayList<>();
        public List<String> topHosts = new ArrayList<>();
        public int urlTotal;
        public int ipTotal;
        public int emailTotal;
        public int secretTotal;
        public List<String> urls = new ArrayList<>();
        public Map<String, String> urlOrigin = new LinkedHashMap<>();
        public List<String> ips = new ArrayList<>();
        public List<String> emails = new ArrayList<>();
        public List<String> secretHits = new ArrayList<>();
        public List<String> suspiciousApis = new ArrayList<>();
        public int secretHighTotal;
        public List<String> secretHitsHigh = new ArrayList<>();
        public List<String> suspCalls = new ArrayList<>();
        public List<String> usedPerms = new ArrayList<>();
        public List<String> unusedDangerousPerms = new ArrayList<>();
        public List<String> trackers = new ArrayList<>();
        public List<String> packers = new ArrayList<>();
        public String sigScheme = "";
        public String sigCertSha256 = "";
        public String sigCertSubject = "";
        public long libAppSize;
        public int libAppStrings;
        public List<String> libAppUrls = new ArrayList<>();
        public List<String> libAppMarkers = new ArrayList<>();
        public List<String> manifestBoot = new ArrayList<>();
        public List<String> manifestIntrusive = new ArrayList<>();
        public List<String> manifestExported = new ArrayList<>();
        public List<String> manifestLinks = new ArrayList<>();
        public List<String> manifestHygiene = new ArrayList<>();
        public String summary = "";
        public String manifestXml = "";
        public String manifestNote = "";
        public List<String> dexNotes = new ArrayList<>();
        public List<Finding> findings = new ArrayList<>();
        public IntelRegistry intel = new IntelRegistry();
        public RefGraph graph = new RefGraph();
        public StringRefs stringRefs = new StringRefs();
        public Map<String, String> superMap = new LinkedHashMap<>();
        public Set<String> manifestClasses = new LinkedHashSet<>();
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
            sb.append("resumen=").append(summary).append('\n');
            if (error != null) sb.append("ERROR=").append(error).append('\n');
            sb.append("\n=== INVENTARIO ===\n");
            sb.append("entradas=").append(entryCount)
                    .append(" res/=").append(resCount).append(" assets/=").append(assetCount).append('\n');
            sb.append("dex=").append(dexFiles).append('\n');
            sb.append("strings=").append(totalStrings).append(" clases=").append(totalClasses)
                    .append(" metodos=").append(totalMethods).append('\n');
            sb.append("ofuscacionRatio=").append(String.format(Locale.US, "%.2f", obfuscatedRatio)).append('\n');
            sb.append("clasesPropias=").append(appClassTotal).append('\n');
            sb.append("sigBlockV2=").append(apkSigBlock).append('\n');
            sb.append("topPaquetes=").append(topPackages).append('\n');
            sb.append("hostsTop=").append(topHosts).append('\n');
            sb.append("api=").append(apiStats).append('\n');
            sb.append("nativas=").append(nativeLibs).append('\n');
            sb.append("frameworks=").append(frameworks).append('\n');
            sb.append("trackers=").append(trackers).append('\n');
            sb.append("packers=").append(packers).append('\n');
            if (libAppSize > 0) {
                sb.append("libapp=").append(libAppSize).append(" B, strings=")
                        .append(libAppStrings).append(" marcadores=").append(libAppMarkers).append('\n');
                dumpList(sb, "libappUrl", libAppUrls);
            }
            sb.append("arscStrings=").append(arscStringCount)
                    .append(arscTruncated ? " (muestra)" : "").append('\n');
            for (String n : dexNotes) sb.append("notaDex=").append(n).append('\n');
            sb.append("\n=== FIRMA ===\n");
            sb.append("certificados=").append(certFiles).append('\n');
            for (String s : certSubjects) sb.append("  sujeto=").append(s).append('\n');
            if (!sigScheme.isEmpty()) sb.append("esquema=").append(sigScheme).append('\n');
            if (!sigCertSha256.isEmpty()) sb.append("certSHA256=").append(sigCertSha256).append('\n');
            if (!sigCertSubject.isEmpty()) sb.append("certSujeto=").append(sigCertSubject).append('\n');
            sb.append("\n=== MANIFEST (").append(manifestNote).append(") ===\n");
            sb.append("permisos(").append(manifestPerms.size()).append(")\n");
            for (String p : manifestPerms) sb.append("  - ").append(p).append('\n');
            sb.append("actividades=").append(manifestActivities)
                    .append(" servicios=").append(manifestServices)
                    .append(" receptores=").append(manifestReceivers)
                    .append(" proveedores=").append(manifestProviders).append('\n');
            dumpList(sb, "autoarranque", manifestBoot);
            dumpList(sb, "intrusivo", manifestIntrusive);
            dumpList(sb, "exportado", manifestExported);
            dumpList(sb, "deeplink", manifestLinks);
            dumpList(sb, "higiene", manifestHygiene);
            sb.append("--- xml (extracto) ---\n");
            sb.append(manifestXml.length() > MANIFEST_TEXT_CAP
                    ? manifestXml.substring(0, MANIFEST_TEXT_CAP) + "\n[...recortado...]\n" : manifestXml);
            if (!manifestXml.endsWith("\n")) sb.append('\n');
            sb.append("\n=== INDICIOS ===\n");
            sb.append("urls=").append(urlTotal).append(" ips=").append(ipTotal)
                    .append(" emails=").append(emailTotal).append(" secretos=").append(secretTotal)
                    .append(" secretosAlta=").append(secretHighTotal).append('\n');
            for (String u : urls) {
                if (u == null) continue;
                String v = u.length() > 160 ? u.substring(0, 160) + "…" : u;
                sb.append("  url=").append(v);
                List<String> us = stringRefs.usersOfContaining(u);
                if (!us.isEmpty()) {
                    sb.append(" <= ").append(us.get(0));
                    if (us.size() > 1) sb.append(", ").append(us.get(1));
                    if (us.size() > 2) sb.append(" (+").append(us.size() - 2).append(")");
                } else if ("arsc".equals(urlOrigin.get(u))) {
                    sb.append(" [arsc]");
                }
                sb.append('\n');
            }
            dumpList(sb, "ip", ips);
            dumpList(sb, "email", emails);
            dumpList(sb, "secreto?", secretHits);
            dumpList(sb, "secreto+", secretHitsHigh);
            dumpList(sb, "apiSensible", suspiciousApis);
            sb.append("\n=== LLAMADAS DE CODIGO PROPIO ===\n");
            dumpList(sb, "llama", suspCalls);
            dumpList(sb, "permisoUsado", usedPerms);
            dumpList(sb, "permisoSobrante?", unusedDangerousPerms);
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
            sb.append("\n=== INTELIGENCIA (").append(intel.size()).append(") ===\n");
            if (intel.size() == 0) {
                sb.append("  (sin hallazgos registrados)\n");
            } else {
                int shown = 0;
                for (IntelFinding f : intel.all()) {
                    if (shown >= 60) break;
                    sb.append("  ").append(f.id).append(" [").append(f.category).append("] ")
                            .append(f.description).append('\n');
                    shown++;
                }
                if (intel.size() > shown) sb.append("  [...").append(intel.size() - shown).append(" mas...]\n");
            }
            sb.append("\n=== GRAFO (nodos=").append(graph.nodeCount())
                    .append(" aristas=").append(graph.edgeCount()).append(") ===");
            if (graph.truncated()) sb.append(" [recortado]");
            sb.append('\n');
            List<String> execCallers = graph.callersOf("Ljava/lang/Runtime;->exec");
            if (execCallers.isEmpty()) {
                sb.append("  exec<=(nadie detectado)\n");
            } else {
                for (int i = 0; i < execCallers.size() && i < 20; i++) {
                    sb.append("  exec<=").append(execCallers.get(i)).append('\n');
                }
                if (execCallers.size() > 20) {
                    sb.append("  [...").append(execCallers.size() - 20).append(" mas...]\n");
                }
            }
            for (String top : graph.topCallers(5)) {
                List<String> out = graph.calleesOf(top);
                sb.append("  top=").append(top).append(" llama ").append(out.size());
                int ex = Math.min(3, out.size());
                if (ex > 0) {
                    sb.append(" p.ej. [");
                    for (int i = 0; i < ex; i++) {
                        if (i > 0) sb.append(", ");
                        sb.append(out.get(i));
                    }
                    sb.append("]");
                }
                sb.append('\n');
            }
            RedSummary red = summarizeRed(graph, superMap);
            sb.append("\n=== RED (entradas=").append(red.entries.size())
                    .append(" cadenas=").append(red.chains.size()).append(") ===");
            if (red.truncated) sb.append(" [recortado]");
            sb.append('\n');
            if (red.entries.isEmpty()) {
                sb.append("  (sin entradas detectadas)\n");
            } else {
                for (int i = 0; i < red.reaches.size(); i++) {
                    sb.append("  entrada=").append(red.entries.get(i))
                            .append(" alcanza=").append(red.reaches.get(i).nodes.size());
                    if (red.reaches.get(i).truncated) sb.append(" [+]");
                    if (manifestClasses.contains(RefGraph.split(red.entries.get(i))[0])) {
                        sb.append(" [manifest]");
                    }
                    sb.append('\n');
                }
                if (red.chains.isEmpty()) sb.append("  (sin cadenas a API sensible)\n");
            }
            List<LogicNet.TrunkGroup> groups = LogicNet.groupByTrunk(red.chains);
            for (int i = 0; i < groups.size() && i < 10; i++) {
                LogicNet.TrunkGroup gr = groups.get(i);
                sb.append("  cadena=");
                for (int j = 0; j < gr.first.size(); j++) {
                    if (j > 0) sb.append(" -> ");
                    sb.append(gr.first.get(j));
                }
                if (gr.entries.size() > 1) sb.append(" x").append(gr.entries.size());
                sb.append('\n');
                if (gr.entries.size() > 1) {
                    sb.append("    desde=");
                    int ex = Math.min(5, gr.entries.size() - 1);
                    for (int j = 1; j <= ex; j++) {
                        if (j > 1) sb.append(", ");
                        sb.append(gr.entries.get(j));
                    }
                    if (gr.entries.size() - 1 > ex) {
                        sb.append(" (+").append(gr.entries.size() - 1 - ex).append(")");
                    }
                    sb.append('\n');
                }
            }
            for (String hub : LogicNet.topCallees(graph, 3)) {
                sb.append("  hub=").append(hub).append(" llamado-por=")
                        .append(graph.callersOf(hub).size()).append('\n');
            }
            Map<String, List<ClassRoles.Role>> roles =
                    ClassRoles.assign(graph, superMap, pkgSlashOf(packageName));
            sb.append("\n=== ROLES (").append(roles.size()).append(") ===\n");
            if (roles.isEmpty()) {
                sb.append("  (sin roles detectados)\n");
            } else {
                for (Map.Entry<String, List<ClassRoles.Role>> en : roles.entrySet()) {
                    sb.append("  rol=").append(en.getKey());
                    if (en.getValue() != null) {
                        for (ClassRoles.Role role : en.getValue()) {
                            if (role == null) continue;
                            sb.append(' ').append(role.label).append(" x").append(role.count);
                            if (!role.evidence.isEmpty()) {
                                sb.append(" [");
                                for (int i = 0; i < role.evidence.size(); i++) {
                                    if (i > 0) sb.append(", ");
                                    sb.append(role.evidence.get(i));
                                }
                                sb.append(']');
                            }
                        }
                    }
                    sb.append('\n');
                }
            }
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
            jsonField(sb, "summary", summary, false);
            sb.append(",\"entries\":").append(entryCount);
            sb.append(",\"strings\":").append(totalStrings);
            sb.append(",\"classes\":").append(totalClasses);
            sb.append(",\"methods\":").append(totalMethods);
            sb.append(",\"obfuscatedRatio\":").append(String.format(Locale.US, "%.3f", obfuscatedRatio));
            sb.append(",\"apkSigBlock\":").append(apkSigBlock);
            jsonStrList(sb, "topPackages", topPackages);
            jsonStrList(sb, "topHosts", topHosts);
            jsonStrList(sb, "dexFiles", dexFiles);
            jsonStrList(sb, "nativeLibs", nativeLibs);
            jsonStrList(sb, "frameworks", frameworks);
            jsonStrList(sb, "certSubjects", certSubjects);
            jsonStrList(sb, "permissions", manifestPerms);
            jsonStrList(sb, "urls", urls);
            jsonStrList(sb, "ips", ips);
            jsonStrList(sb, "secretHits", secretHits);
            sb.append(",\"secretHighTotal\":").append(secretHighTotal);
            jsonStrList(sb, "secretHitsHigh", secretHitsHigh);
            jsonStrList(sb, "suspiciousApis", suspiciousApis);
            jsonStrList(sb, "suspCalls", suspCalls);
            jsonStrList(sb, "usedPerms", usedPerms);
            jsonStrList(sb, "unusedDangerousPerms", unusedDangerousPerms);
            jsonStrList(sb, "trackers", trackers);
            jsonStrList(sb, "packers", packers);
            jsonField(sb, "sigScheme", sigScheme, false);
            jsonField(sb, "sigCertSha256", sigCertSha256, false);
            jsonField(sb, "sigCertSubject", sigCertSubject, false);
            sb.append(",\"libAppSize\":").append(libAppSize);
            sb.append(",\"libAppStrings\":").append(libAppStrings);
            jsonStrList(sb, "libAppUrls", libAppUrls);
            jsonStrList(sb, "libAppMarkers", libAppMarkers);
            jsonStrList(sb, "manifestBoot", manifestBoot);
            jsonStrList(sb, "manifestIntrusive", manifestIntrusive);
            jsonStrList(sb, "manifestExported", manifestExported);
            jsonStrList(sb, "manifestLinks", manifestLinks);
            jsonStrList(sb, "manifestHygiene", manifestHygiene);
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
            RedSummary red = summarizeRed(graph, superMap);
            sb.append(",\"graphNodes\":").append(graph.nodeCount());
            sb.append(",\"graphEdges\":").append(graph.edgeCount());
            sb.append(",\"graphTruncated\":").append(graph.truncated());
            sb.append(",\"stringValues\":").append(stringRefs.valueCount());
            sb.append(",\"stringPairs\":").append(stringRefs.pairCount());
            sb.append(",\"stringTruncated\":").append(stringRefs.truncated());
            jsonStrList(sb, "redEntries", red.entries);
            List<String> chainStrs = new ArrayList<>();
            for (List<String> c : red.chains) {
                StringBuilder j = new StringBuilder();
                for (int i = 0; i < c.size(); i++) {
                    if (i > 0) j.append(" -> ");
                    j.append(c.get(i));
                }
                chainStrs.add(j.toString());
            }
            jsonStrList(sb, "redChains", chainStrs);
            sb.append(",\"redTruncated\":").append(red.truncated);
            sb.append(",\"roles\":{");
            Map<String, List<ClassRoles.Role>> roles =
                    ClassRoles.assign(graph, superMap, pkgSlashOf(packageName));
            boolean firstRole = true;
            for (Map.Entry<String, List<ClassRoles.Role>> en : roles.entrySet()) {
                if (en.getKey() == null || en.getValue() == null) continue;
                if (!firstRole) sb.append(',');
                firstRole = false;
                jsonQuoted(sb, en.getKey());
                sb.append(":[");
                boolean firstLbl = true;
                for (ClassRoles.Role role : en.getValue()) {
                    if (role == null) continue;
                    if (!firstLbl) sb.append(',');
                    firstLbl = false;
                    jsonQuoted(sb, role.label);
                }
                sb.append(']');
            }
            sb.append('}');
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
            ApkSigBlock.SigInfo sig = ApkSigBlock.parse(apk);
            if (sig.cert != null) {
                r.apkSigBlock = true;
                r.sigScheme = sig.scheme;
                r.sigCertSha256 = hex(sha256bytes(sig.cert));
                r.sigCertSubject = certSubjectDer(sig.cert);
            } else {
                r.apkSigBlock = hasApkSigBlock(apk);
            }

            Set<String> urlSet = new LinkedHashSet<>();
            Set<String> ipSet = new LinkedHashSet<>();
            Set<String> emailSet = new LinkedHashSet<>();
            Set<String> secretSet = new LinkedHashSet<>();
            Set<String> secretHighSet = new LinkedHashSet<>();
            Set<String> suspSet = new LinkedHashSet<>();
            Set<String> usedPermSet = new LinkedHashSet<>();
            Set<String> packerSet = new LinkedHashSet<>();
            int[] counters = new int[5]; // url, ip, email, secret, secretAlta
            Set<String> frameworks = new LinkedHashSet<>();
            Map<String, Integer> pkgCounts = new LinkedHashMap<>();
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
                    String pkFile = PackerMarkers.matchFile(name);
                    if (pkFile != null && packerSet.size() < 20) packerSet.add(pkFile + " [" + name + "]");
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
                    ManifestChecks.Result mc = ManifestChecks.check(xml, r.manifestPerms);
                    r.manifestBoot.addAll(mc.bootReceivers);
                    r.manifestIntrusive.addAll(mc.intrusivePerms);
                    r.manifestExported.addAll(mc.exported);
                    if (!"?".equals(r.packageName)) {
                        for (String c : mc.components) {
                            String d = ManifestChecks.resolveDescriptor(c, r.packageName);
                            if (d != null) r.manifestClasses.add(d);
                        }
                    }
                    r.manifestLinks.addAll(mc.deepLinks);
                    r.manifestHygiene.addAll(mc.hygiene);
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
                        if (ci.name == null) continue;
                        String px = prefix2(ci.name);
                        pkgCounts.put(px, pkgCounts.containsKey(px) ? pkgCounts.get(px) + 1 : 1);
                        if (!"?".equals(r.packageName) && ci.name.startsWith(slash)) {
                            r.appClassTotal++;
                            if (r.appClasses.size() < 5000) r.appClasses.add(ci.name);
                        }
                        String pkCls = PackerMarkers.matchClass(ci.name);
                        if (pkCls != null && packerSet.size() < 20) packerSet.add(pkCls + " [" + ci.name + "]");
                    }
                    if (di.hasKotlin) frameworks.add("Kotlin");
                    if (di.hasAndroidx) frameworks.add("AndroidX/Jetpack");
                    if (di.hasGms) frameworks.add("Google/GMS");
                    if (di.hasUnity) frameworks.add("Unity");
                    scanStrings(di.strings, urlSet, ipSet, emailSet, secretSet, secretHighSet, counters,
                            r.urlOrigin, "dex");
                    collectOwnCalls(r, dexBytes, "?".equals(r.packageName) ? null
                            : r.packageName.replace('.', '/') + "/", usedPermSet, dexName);
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
                        scanStrings(ai.strings, urlSet, ipSet, emailSet, secretSet, secretHighSet, counters,
                                r.urlOrigin, "arsc");
                    }
                }

                // Nativas: inventario + arquitectura por cabecera ELF + etiqueta conocida.
                for (String so : soNames) {
                    ZipEntry e = zip.getEntry(so);
                    byte[] head = e == null ? null : readPrefix(zip, e, 64);
                    String tag = NativeTable.classify(so);
                    r.nativeLibs.add(so + " (" + elfArch(head) + ")"
                            + (tag == null ? "" : " [" + tag + "]"));
                    if (r.nativeLibs.size() >= 100) break;
                }
                // Flutter AOT: tamaño y strings de libapp.so.
                String libapp = pickLibApp(soNames);
                if (libapp != null) {
                    ZipEntry e = zip.getEntry(libapp);
                    if (e != null) {
                        r.libAppSize = Math.max(0, e.getSize());
                        InputStream lin = null;
                        try {
                            lin = zip.getInputStream(e);
                            LibAppScan.Result lr = LibAppScan.scan(lin, LibAppScan.MAX_BYTES);
                            r.libAppStrings = lr.stringCount;
                            r.libAppUrls.addAll(lr.urls);
                            r.libAppMarkers.addAll(lr.markers);
                            if (lr.truncated) r.dexNotes.add("libapp.so: muestra parcial (tope)");
                        } catch (Throwable ignored) {
                        } finally {
                            if (lin != null) {
                                try {
                                    lin.close();
                                } catch (Throwable ignored) {
                                }
                            }
                        }
                    }
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
            r.secretHitsHigh.addAll(cap(secretHighSet));
            r.suspiciousApis.addAll(suspSet);
            r.urlTotal = counters[0];
            r.ipTotal = counters[1];
            r.emailTotal = counters[2];
            r.secretTotal = counters[3];
            r.secretHighTotal = counters[4];
            r.topPackages = topCounts(pkgCounts, 8);
            r.topHosts = topHosts(urlSet, 8);
            for (String k : pkgCounts.keySet()) {
                String t = TrackerTable.match(k);
                if (t != null && !r.trackers.contains(t) && r.trackers.size() < 20) r.trackers.add(t);
            }
            r.packers.addAll(packerSet);
            r.usedPerms.addAll(usedPermSet);
            for (String p : r.manifestPerms) {
                String s = p;
                int dot = p.lastIndexOf('.');
                if (dot >= 0) s = p.substring(dot + 1);
                if (PermApiTable.isRisky(p) && !usedPermSet.contains(s)
                        && r.unusedDangerousPerms.size() < 20) r.unusedDangerousPerms.add(s);
            }
            r.summary = buildSummary(r);

            buildFindings(r);
            finishStatic(r);
        } catch (OutOfMemoryError oom) {
            r.error = "memoria insuficiente analizando (APK grande)";
            finishStatic(r);
        } catch (Throwable t) {
            r.error = "fallo general: " + t.getMessage();
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

    static void scanStrings(Collection<String> strings, Set<String> urls, Set<String> ips,
                            Set<String> emails, Set<String> secrets, Set<String> secretsHigh,
                            int[] counters, Map<String, String> urlSrc, String src) {
        for (String s : strings) {
            if (s == null || s.isEmpty()) continue;
            Matcher mu = URL_RE.matcher(s);
            while (mu.find()) {
                counters[0]++;
                String u = trimUrl(mu.group());
                if (urls.size() < MAX_SAMPLE) urls.add(u);
                if (urlSrc != null && src != null && !urlSrc.containsKey(u)
                        && urlSrc.size() < MAX_SAMPLE) urlSrc.put(u, src);
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
                String ip = mi.group();
                if (ok && !"0.0.0.0".equals(ip) && !"255.255.255.255".equals(ip)
                        && !isOid(ip) && !isOidPart(s, mi.start(), mi.end())) {
                    counters[1]++;
                    if (ips.size() < MAX_SAMPLE) ips.add(ip);
                }
            }
            if (s.length() < 300) {
                Matcher me = EMAIL_RE.matcher(s);
                while (me.find()) {
                    String em = me.group();
                    if (em.contains("@1x.") || em.contains("@2x.") || em.contains("@3x.")) continue;
                    counters[2]++;
                    if (emails.size() < MAX_SAMPLE) emails.add(em);
                }
                Matcher ms = SECRET_WORD_RE.matcher(s);
                if (ms.find()) {
                    String t = s.trim();
                    if (t.startsWith("L") && t.endsWith(";") && t.contains("/")) continue;
                    counters[3]++;
                    if (secrets.size() < MAX_SAMPLE) secrets.add(t);
                }
                List<String> highIds = SecretRules.match(s);
                if (!highIds.isEmpty()) {
                    counters[4]++;
                    if (secretsHigh.size() < MAX_SAMPLE) secretsHigh.add(highIds.get(0) + ": " + s.trim());
                } else if (SecretRules.isTokenLike(s)) {
                    counters[4]++;
                    if (secretsHigh.size() < MAX_SAMPLE) secretsHigh.add("entropia: " + s.trim());
                }
            }
        }
    }

    /**
     * Recorta puntuación final pegada al citar URLs ("...a.", "...b).",
     * "...e,"): siempre [.,;:!] y cierres )]} desequilibrados (los
     * balanceados tipo wiki_c_(d) se conservan). El "?" final se conserva:
     * puede ser query vacía o parte de un patrón regex. Si el recorte
     * degenera, devuelve el original. Nunca lanza.
     */
    static String trimUrl(String u) {
        try {
            if (u == null || u.isEmpty()) return u;
            String t = u;
            for (int guard = 0; guard < 8; guard++) {
                int n = t.length();
                while (n > 0 && ".,;:!".indexOf(t.charAt(n - 1)) >= 0) n--;
                t = t.substring(0, n);
                if (t.isEmpty()) break;
                char last = t.charAt(t.length() - 1);
                char open = last == ')' ? '(' : last == ']' ? '[' : last == '}' ? '{' : 0;
                if (open == 0) break;
                if (countChar(t, open) < countChar(t, last)) {
                    t = t.substring(0, t.length() - 1);
                    continue;
                }
                break;
            }
            if (t.endsWith("://")) return u;
            return t;
        } catch (Throwable ignored) {
            return u;
        }
    }

    private static int countChar(String s, char c) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == c) n++;
        return n;
    }

    /**
     * Arcos OID X.509 habituales (2.5.29.37 = subjectAltName…): en strings de
     * APK casi siempre son OID, no IPv4 (una IP real 1.2/1.3/2.5.x.y se pierde;
     * se asume por ser raro frente al ruido). Nunca lanza.
     */
    static boolean isOid(String ip) {
        try {
            if (ip == null) return false;
            return ip.startsWith("1.2.") || ip.startsWith("1.3.") || ip.startsWith("2.5.");
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * true si el match numérico forma parte de una secuencia punteada más
     * larga (OID 1.3.6.1.4…), no una IPv4 suelta. Nunca lanza.
     */
    static boolean isOidPart(String s, int start, int end) {
        try {
            if (s == null) return false;
            if (end + 1 < s.length() && s.charAt(end) == '.'
                    && s.charAt(end + 1) >= '0' && s.charAt(end + 1) <= '9') return true;
            if (start - 2 >= 0 && s.charAt(start - 1) == '.'
                    && s.charAt(start - 2) >= '0' && s.charAt(start - 2) <= '9') return true;
        } catch (Throwable ignored) {
        }
        return false;
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

    private static byte[] sha256bytes(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private static String certSubjectDer(byte[] der) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate c = cf.generateCertificate(new ByteArrayInputStream(der));
            if (c instanceof X509Certificate) {
                X509Certificate x = (X509Certificate) c;
                return x.getSubjectX500Principal().getName() + " | serie=" + x.getSerialNumber();
            }
        } catch (Exception ignored) {
        }
        return "";
    }

    private static String pickLibApp(List<String> soNames) {
        try {
            String fallback = null;
            for (String so : soNames) {
                if (so == null || !so.endsWith("libapp.so")) continue;
                if (so.contains("arm64-v8a")) return so;
                if (fallback == null) fallback = so;
            }
            return fallback;
        } catch (Throwable ignored) {
            return null;
        }
    }

    static void collectOwnCalls(ApkReport r, byte[] dexBytes, String pkgSlash, Set<String> usedPermSet,
                                String dexName) {
        try {
            if (r == null || usedPermSet == null) return;
            DexCalls.Result cr = DexCalls.collect(dexBytes, pkgSlash, dexName);
            r.superMap.putAll(cr.supers);
            r.graph.addAll(cr.edges);
            r.stringRefs.addAll(cr.strings);
            for (DexCalls.Edge e : cr.edges) {
                if (e == null || e.callee == null) continue;
                int arrow = e.callee.indexOf("->");
                String cls = arrow < 0 ? e.callee : e.callee.substring(0, arrow);
                String name = arrow < 0 ? "" : e.callee.substring(arrow + 2);
                if (DexParser.suspiciousLabelWithSupers(cls, name, r.superMap) != null) {
                    addSuspCall(r, e.caller + "  ->  " + e.callee);
                }
                String perm = PermApiTable.permissionFor(e.callee);
                if (perm != null && usedPermSet.size() < 60) usedPermSet.add(perm);
            }
            if (cr.truncated) r.dexNotes.add("llamadas: topes alcanzados (muestra parcial)");
            if (cr.stringsTruncated) noteOnce(r, "cadenas: topes alcanzados (muestra parcial)");
            // Segunda pasada: sensibles invocadas desde librerías (adrt…) al grafo.
            // suspCalls queda propio (su sección lo afirma); el grafo es más amplio.
            if (pkgSlash != null) {
                DexCalls.Result lib = DexCalls.collect(dexBytes, null, dexName);
                r.superMap.putAll(lib.supers);
                List<DexCalls.Edge> keep = new ArrayList<>();
                for (DexCalls.Edge e : lib.edges) {
                    if (e == null || e.caller == null || e.callee == null) continue;
                    if (e.caller.startsWith("L" + pkgSlash)) continue;
                    int arrow = e.callee.indexOf("->");
                    String cls = arrow < 0 ? e.callee : e.callee.substring(0, arrow);
                    String name = arrow < 0 ? "" : e.callee.substring(arrow + 2);
                    if (DexParser.suspiciousLabelWithSupers(cls, name, r.superMap) == null) continue;
                    keep.add(e);
                }
                r.graph.addAll(keep);
                r.stringRefs.addAll(lib.strings);
                String tag = dexName == null ? "?" : dexName;
                if (lib.truncated) r.dexNotes.add("librerías " + tag + ": muestra parcial (topes)");
                if (lib.stringsTruncated) noteOnce(r, "cadenas: topes alcanzados (muestra parcial)");
            }
        } catch (Throwable ignored) {
        }
    }

    /** Añade nota de dex una sola vez. Nunca lanza. */
    private static void noteOnce(ApkReport r, String note) {
        try {
            if (r == null || note == null || r.dexNotes.contains(note)) return;
            r.dexNotes.add(note);
        } catch (Throwable ignored) {
        }
    }

    /** Resumen de una línea para la cabecera del informe. Nunca lanza. */
    static String buildSummary(ApkReport r) {
        try {
            StringBuilder sb = new StringBuilder();
            if (r.frameworks.isEmpty()) sb.append("?");
            else {
                for (int i = 0; i < Math.min(3, r.frameworks.size()); i++) {
                    if (i > 0) sb.append(" + ");
                    sb.append(r.frameworks.get(i));
                }
            }
            List<String> tags = new ArrayList<>();
            for (String n : r.nativeLibs) {
                int a = n.indexOf('[');
                int b = n.indexOf(']', a + 1);
                if (a >= 0 && b > a && tags.size() < 2) {
                    String t = n.substring(a + 1, b);
                    if (!tags.contains(t)) tags.add(t);
                }
            }
            for (String t : tags) sb.append(" + ").append(t);
            int risky = 0;
            for (String p : r.manifestPerms) {
                if (PermApiTable.isRisky(p)) risky++;
            }
            sb.append(" | ").append(r.manifestPerms.size()).append(" permisos (")
                    .append(risky).append(" de riesgo)");
            if (r.secretHighTotal > 0) {
                sb.append(" | ").append(r.secretHighTotal).append(" secreto(s) alta");
            }
            if (!r.manifestBoot.isEmpty()) sb.append(" | autoarranque");
            if (!r.manifestIntrusive.isEmpty()) {
                sb.append(" | ").append(r.manifestIntrusive.size()).append(" intrusivo(s)");
            }
            if (!r.sigScheme.isEmpty()) sb.append(" | firma ").append(r.sigScheme);
            if (!r.trackers.isEmpty()) sb.append(" | ").append(r.trackers.size()).append(" tracker(s)");
            if (!r.packers.isEmpty()) sb.append(" | protector");
            if (r.libAppSize > 0) sb.append(" | libapp ").append(r.libAppSize / 1024).append(" KB");
            return sb.toString();
        } catch (Throwable t) {
            return "";
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
                ManifestChecks.Result bootMc = ManifestChecks.check(manifestXml, null);
                for (String b : bootMc.bootReceivers) {
                    String clsName = b.split(" ")[0];
                    String fq = clsName.startsWith(".") && !"?".equals(pkg) ? pkg + clsName : clsName;
                    if (fq.startsWith("?")) continue;
                    String want = "smali/" + fq.replace('.', '/') + ".smali";
                    for (SmaliDumper.SmaliClass sc : smali.classes) {
                        if (want.equals(sc.path) && (sc.text.contains("startActivity")
                                || sc.text.contains("getLaunchIntentForPackage"))) {
                            r.notes.add("autoarranque: " + fq + " lanza actividad (smali)");
                            break;
                        }
                    }
                }
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
                    // Libera dex/strings ya volcados antes de cargar JADX.
                    dexBytes.clear();
                    dexStrings.clear();
                    arscStrings.clear();
                    System.gc();
                    try {
                        File wd = outZip.getParentFile() != null ? outZip.getParentFile() : new File(".");
                        long heap = 256L * 1024 * 1024;
                        try {
                            heap = Runtime.getRuntime().maxMemory();
                        } catch (Throwable ignored) {
                        }
                        JadxAdapter.Result jr = JadxAdapter.decompileFiltered(
                                apk, wd, JadxAdapter.recommendedThreads(heap), slashes,
                                JadxAdapter.recommendedCap(heap), null);
                        for (Map.Entry<String, String> e : jr.sources.entrySet()) {
                            putText(zos, "rea/JAVA/" + e.getKey().replace('.', '/') + ".java", e.getValue());
                        }
                        r.notes.add("java: " + jr.sources.size() + " clases, errores=" + jr.errors);
                        if (jr.truncated) r.notes.add("java: recortado por topes");
                        if (jr.error != null) r.notes.add("java: " + jr.error);
                        int nl = 0;
                        for (String l : jr.log) {
                            if (nl++ >= 25) break;
                            r.notes.add("java-log: " + l);
                        }
                    } catch (OutOfMemoryError oom) {
                        r.notes.add("java: memoria insuficiente");
                    } catch (Throwable t) {
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
        } catch (OutOfMemoryError oom) {
            r.error = "memoria insuficiente extrayendo (APK grande)";
        } catch (Throwable t) {
            String msg = t.getMessage();
            r.error = "fallo general: " + (msg == null ? t.toString() : msg);
        }
        return r;
    }

    private static void putText(ZipOutputStream zos, String name, String text) throws Exception {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(text.getBytes("UTF-8"));
        zos.closeEntry();
    }

    /** true si el APK trae bloque de firma v2/v3+ (magia antes del directorio). Nunca lanza. */
    static boolean hasApkSigBlock(File apk) {
        RandomAccessFile raf = null;
        try {
            if (apk == null || !apk.isFile()) return false;
            raf = new RandomAccessFile(apk, "r");
            long len = raf.length();
            if (len < 64) return false;
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
            if (eocd < 0) return false;
            int cdo = (tail[eocd + 16] & 0xFF) | ((tail[eocd + 17] & 0xFF) << 8)
                    | ((tail[eocd + 18] & 0xFF) << 16) | ((tail[eocd + 19] & 0xFF) << 24);
            if (cdo < 32 || (long) cdo > len) return false;
            byte[] foot = new byte[24];
            raf.seek((long) cdo - 24);
            raf.readFully(foot);
            String magic = "APK Sig Block 42";
            for (int i = 0; i < 16; i++) {
                if (foot[8 + i] != (byte) magic.charAt(i)) return false;
            }
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            if (raf != null) {
                try {
                    raf.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    /** Prefijo de 2 segmentos ("Lcom/a/b/C;" a "com/a") u "otros". Nunca lanza. */
    static String prefix2(String desc) {
        try {
            if (desc == null || !desc.startsWith("L")) return "otros";
            int a = desc.indexOf('/', 1);
            if (a < 0) return "otros";
            int b = desc.indexOf('/', a + 1);
            if (b < 0) return "otros";
            return desc.substring(1, b);
        } catch (Throwable t) {
            return "otros";
        }
    }

    /** Top N "k=v" ordenado por valor desc (empates por clave). Nunca lanza. */
    static List<String> topCounts(Map<String, Integer> counts, int n) {
        List<String> out = new ArrayList<>();
        try {
            if (counts == null || counts.isEmpty() || n <= 0) return out;
            List<Map.Entry<String, Integer>> es = new ArrayList<>(counts.entrySet());
            Collections.sort(es, new Comparator<Map.Entry<String, Integer>>() {
                @Override
                public int compare(Map.Entry<String, Integer> a, Map.Entry<String, Integer> b) {
                    int c = b.getValue().compareTo(a.getValue());
                    if (c != 0) return c;
                    return a.getKey().compareTo(b.getKey());
                }
            });
            for (int i = 0; i < Math.min(n, es.size()); i++) {
                out.add(es.get(i).getKey() + "=" + es.get(i).getValue());
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Top N hosts "h=c" de una colección de URLs. Nunca lanza. */
    static List<String> topHosts(Collection<String> urls, int n) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        try {
            if (urls != null) {
                for (String u : urls) {
                    String h = hostOf(u);
                    if (h == null) continue;
                    counts.put(h, counts.containsKey(h) ? counts.get(h) + 1 : 1);
                }
            }
        } catch (Throwable ignored) {
        }
        return topCounts(counts, n);
    }

    private static String hostOf(String url) {
        try {
            if (url == null) return null;
            int s = url.indexOf("://");
            if (s < 0) return null;
            int e = url.indexOf('/', s + 3);
            String h = e < 0 ? url.substring(s + 3) : url.substring(s + 3, e);
            int q = h.indexOf('?');
            if (q >= 0) h = h.substring(0, q);
            int at = h.lastIndexOf('@');
            if (at >= 0) h = h.substring(at + 1);
            int c = h.indexOf(':');
            if (c >= 0) h = h.substring(0, c);
            h = h.toLowerCase(Locale.US);
            return h.isEmpty() ? null : h;
        } catch (Throwable t) {
            return null;
        }
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
        } else if (!r.apkSigBlock) {
            r.finding("firma", "Sin firma detectable",
                    "Ni certificados v1 en META-INF ni bloque v2/v3+.",
                    "archivos=" + r.certFiles);
        }
        if (r.apkSigBlock) {
            String det = "Firma moderna fuera del ZIP visible.";
            if (!r.sigScheme.isEmpty()) {
                det = "Esquema " + r.sigScheme
                        + (r.sigCertSubject.isEmpty() ? "" : "; " + r.sigCertSubject);
            }
            r.finding("firma", "Bloque de firma APK v2/v3+ presente",
                    det, "magia \"APK Sig Block 42\""
                            + (r.sigCertSha256.isEmpty() ? "" : "; sha256=" + r.sigCertSha256));
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
        if (r.secretHighTotal > 0) {
            r.finding("secretos", r.secretHighTotal + " secreto(s) de ALTA confianza",
                    r.secretHitsHigh.isEmpty() ? "-" : r.secretHitsHigh.get(0),
                    "formato de clave o entropía (DEX + ARSC)");
        }
        if (!r.suspiciousApis.isEmpty()) {
            r.finding("apis", r.suspiciousApis.size() + "+ referencia(s) a API sensible (muestra)",
                    r.suspiciousApis.get(0), "method_ids del DEX");
        }
        if (!r.suspCalls.isEmpty()) {
            r.finding("apis", r.suspCalls.size() + " llamada(s) sensible(s) desde código propio",
                    r.suspCalls.get(0), "code_item del DEX (DexCalls)");
        }
        if (!r.manifestPerms.isEmpty()) {
            r.finding("permisos", r.manifestPerms.size() + " permiso(s) declarados",
                    r.manifestActivities + " actividades, " + r.manifestServices + " servicios, "
                            + r.manifestReceivers + " receptores, " + r.manifestProviders + " proveedores.",
                    "AndroidManifest.xml decodificado");
        }
        if (!r.unusedDangerousPerms.isEmpty()) {
            r.finding("permisos", "Posibles permisos sobrantes: " + r.unusedDangerousPerms,
                    "De riesgo y sin llamada detectada que los ampare.",
                    "manifest + llamadas propias");
        }
        if (!r.manifestBoot.isEmpty()) {
            r.finding("persistencia", "Autoarranque tras reinicio: " + r.manifestBoot,
                    "Receptor con BOOT_COMPLETED; revisar si lanza actividad o servicio.",
                    "AndroidManifest.xml decodificado");
        }
        if (!r.manifestIntrusive.isEmpty()) {
            r.finding("privacidad", r.manifestIntrusive.size() + " permiso(s)/componente(s) intrusivo(s)",
                    r.manifestIntrusive.size() > 3
                            ? r.manifestIntrusive.subList(0, 3) + "…" : r.manifestIntrusive.toString(),
                    "AndroidManifest.xml decodificado");
        }
        if (!r.manifestHygiene.isEmpty()) {
            r.finding("higiene", "Avisos de manifest: " + r.manifestHygiene,
                    "Banderas de application a revisar.", "AndroidManifest.xml decodificado");
        }
        if (!r.manifestLinks.isEmpty()) {
            r.finding("superficie", r.manifestLinks.size() + " deep link(s)",
                    r.manifestLinks.size() > 3
                            ? r.manifestLinks.subList(0, 3) + "…" : r.manifestLinks.toString(),
                    "etiquetas <data> del manifest");
        }
        if (!r.trackers.isEmpty()) {
            r.finding("trackers", r.trackers.size() + " SDK/tracker(s): " + r.trackers,
                    "Detectados por prefijo de paquete.", "clases del DEX");
        }
        if (!r.packers.isEmpty()) {
            r.finding("protector", "Marcadores: " + r.packers,
                    "Posible protector, empaquetador o instrumentación.",
                    "nombres de fichero/clase");
        }
        if (r.libAppSize > 0) {
            r.finding("flutter", "libapp.so: " + r.libAppSize + " bytes, " + r.libAppStrings + " strings",
                    r.libAppUrls.isEmpty() ? "marcadores=" + r.libAppMarkers
                            : r.libAppUrls.get(0) + (r.libAppUrls.size() > 1
                            ? " (+" + (r.libAppUrls.size() - 1) + ")" : ""),
                    "escaneo de strings en libapp.so");
        }
    }

    /**
     * Puente OMEGA: vuelca los hallazgos clásicos al núcleo intelligence.
     * Idempotente (no duplica si ya se alimentó) y nunca lanza.
     */
    static void feedIntel(ApkReport r) {
        try {
            if (r == null || r.findings == null || r.intel == null) return;
            if (r.intel.size() > 0) return;
            for (Finding f : r.findings) {
                if (f == null) continue;
                IntelFinding inf = IntelFinding.create(f.section, f.title);
                String det = f.detail == null ? "" : f.detail;
                String ev = f.evidence == null ? "" : f.evidence;
                inf.evidence = det.isEmpty() ? ev : (ev.isEmpty() ? det : det + " // " + ev);
                inf.limitations = "convertido de Finding v0.4 (estático)";
                r.intel.add(inf);
            }
            feedIntelGraph(r);
            feedIntelRed(r);
            feedIntelRoles(r);
        } catch (Throwable ignored) {
        }
    }

    /** pkg "com.x" → "com/x/" para filtros de propias; null si "?". Nunca lanza. */
    static String pkgSlashOf(String pkg) {
        try {
            if (pkg == null || pkg.isEmpty() || "?".equals(pkg)) return null;
            return pkg.replace('.', '/') + "/";
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Añade llamada sensible sin duplicados (tope MAX_SAMPLE). Nunca lanza.
     */
    static void addSuspCall(ApkReport r, String line) {
        try {
            if (r == null || line == null || line.isEmpty()) return;
            if (r.suspCalls.contains(line)) return;
            if (r.suspCalls.size() < MAX_SAMPLE) r.suspCalls.add(line);
        } catch (Throwable ignored) {
        }
    }

    /** Resumen RED precomputado (lo usan toText y toJson). Nunca lanza. */
    private static class RedSummary {
        List<String> entries = new ArrayList<>();
        List<LogicNet.Reach> reaches = new ArrayList<>();
        List<List<String>> chains = new ArrayList<>();
        boolean truncated;
    }

    private static RedSummary summarizeRed(RefGraph g, Map<String, String> supers) {
        RedSummary s = new RedSummary();
        try {
            if (g == null) return s;
            s.entries = LogicNet.entryPoints(g);
            for (int i = 0; i < s.entries.size() && i < 20; i++) {
                LogicNet.Reach reach = LogicNet.reachableFrom(g, s.entries.get(i), 6, 2000);
                if (reach.truncated) s.truncated = true;
                s.reaches.add(reach);
            }
            for (String t : sensitiveTargets(g, 5, supers)) {
                if (s.chains.size() >= 10) {
                    s.truncated = true;
                    break;
                }
                LogicNet.Chains ch = LogicNet.chainsTo(g, t, 8, 10 - s.chains.size());
                if (ch.truncated) s.truncated = true;
                s.chains.addAll(ch.chains);
            }
        } catch (Throwable ignored) {
        }
        return s;
    }

    /**
     * Claves completas de API sensible invocada (orden de aparición, cap).
     * Clave completa (no nombre) para no mezclar homónimos (<init>, run…).
     * Nunca lanza.
     */
    private static List<String> sensitiveTargets(RefGraph g, int cap, Map<String, String> supers) {
        List<String> out = new ArrayList<>();
        try {
            if (g == null || cap <= 0) return out;
            Set<String> seen = new LinkedHashSet<>();
            for (RefGraph.RefEdge e : g.edges()) {
                if (e == null) continue;
                if (out.size() >= cap) break;
                if (e.callee == null || e.calleeMethod == null) continue;
                if (DexParser.suspiciousLabelWithSupers(e.calleeClass, e.calleeMethod, supers) == null) {
                    continue;
                }
                if (seen.add(e.callee)) out.add(e.callee);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * OMEGA red lógica: cada cadena entrada→API sensible pasa al registro con
     * el llamador directo. Confianza MEDIA (instrucciones reales) y nunca se
     * afirma ejecución. Tope 20. Nunca lanza.
     */
    static void feedIntelRed(ApkReport r) {
        try {
            if (r == null || r.graph == null || r.intel == null) return;
            int added = 0;
            for (String t : sensitiveTargets(r.graph, 5, r.superMap)) {
                if (added >= 20) break;
                LogicNet.Chains ch = LogicNet.chainsTo(r.graph, t, 8, 20 - added);
                for (List<String> c : ch.chains) {
                    if (added >= 20 || c == null || c.isEmpty()) break;
                    String hop = c.size() >= 2 ? c.get(c.size() - 2) : c.get(0);
                    String[] parts = RefGraph.split(hop);
                    StringBuilder desc = new StringBuilder();
                    for (int i = 0; i < c.size(); i++) {
                        if (i > 0) desc.append(" -> ");
                        desc.append(c.get(i));
                    }
                    IntelFinding inf = IntelFinding.create("cadena", desc.toString());
                    inf.className = parts[0];
                    inf.methodName = parts[1];
                    inf.evidence = "invoke(s) DEX; entradas por nombre";
                    inf.confidence = IntelFinding.Confidence.MEDIUM;
                    inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                    inf.limitations = "cadena estática respaldada por instrucciones invoke;"
                            + " ejecución no observada";
                    if (r.intel.add(inf)) added++;
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * OMEGA Fase B: cada llamada a API sensible pasa al registro con clase y
     * método del llamador. Confianza MEDIA (instrucción real) y nunca se afirma
     * ejecución. Tope 100. Nunca lanza.
     */
    static void feedIntelGraph(ApkReport r) {
        try {
            if (r == null || r.graph == null || r.intel == null) return;
            Set<String> seen = new LinkedHashSet<>();
            int added = 0;
            for (RefGraph.RefEdge e : r.graph.edges()) {
                if (added >= 100) break;
                if (e == null) continue;
                if (DexParser.suspiciousLabelWithSupers(e.calleeClass, e.calleeMethod, r.superMap) == null) {
                    continue;
                }
                String key = e.caller + "\u0000" + e.callee;
                if (!seen.add(key)) continue;
                IntelFinding inf = IntelFinding.create("grafo", e.caller + " llama a " + e.callee);
                inf.className = e.callerClass;
                inf.methodName = e.callerMethod;
                inf.evidence = "invoke " + e.dex + "@+" + e.pos;
                inf.confidence = IntelFinding.Confidence.MEDIUM;
                inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                inf.limitations = "llamada estática respaldada por instrucción DEX; ejecución no observada";
                if (r.intel.add(inf)) added++;
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * OMEGA roles: cada (clase, rol) pasa al registro con su primera
     * evidencia. Confianza MEDIA y nunca se afirma ejecución. Tope 20.
     * Nunca lanza.
     */
    static void feedIntelRoles(ApkReport r) {
        try {
            if (r == null || r.graph == null || r.intel == null) return;
            int added = 0;
            Map<String, List<ClassRoles.Role>> roles =
                    ClassRoles.assign(r.graph, r.superMap, pkgSlashOf(r.packageName));
            for (Map.Entry<String, List<ClassRoles.Role>> en : roles.entrySet()) {
                if (added >= 20) break;
                if (en.getKey() == null || en.getValue() == null) continue;
                for (ClassRoles.Role role : en.getValue()) {
                    if (added >= 20 || role == null) break;
                    IntelFinding inf = IntelFinding.create("rol",
                            en.getKey() + " actúa como " + role.label + " x" + role.count);
                    inf.className = en.getKey();
                    inf.evidence = role.evidence.isEmpty() ? "-" : role.evidence.get(0);
                    inf.confidence = IntelFinding.Confidence.MEDIUM;
                    inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                    inf.limitations = "llamada estática respaldada por instrucción DEX; ejecución no observada";
                    if (r.intel.add(inf)) added++;
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void finishStatic(ApkReport r) {
        feedIntel(r);
        r.limitations.add("Java bajo demanda en el visor (JADX on-device con topes); el informe base no incluye fuentes.");
        r.limitations.add("Xrefs parciales: llamadas de código propio (DexCalls) sin flujo inter-procedural completo.");
        r.limitations.add("Sin análisis dinámico (Frida/adb): estático únicamente.");
        r.limitations.add("AXML y ARSC decodificados con parser propio (best-effort).");
        r.limitations.add("Nativas: solo inventario y arquitectura ELF, sin desensamblado.");
        r.limitations.add("Muestreo con topes en APKs grandes (ver notas).");
        r.unknowns.add("Comportamiento en ejecución (runtime).");
        r.unknowns.add("Contenido descargado, generado o descifrado en runtime.");
        r.unknowns.add("Código tras ofuscación o empaquetado: nombres y flujo pueden ocultar la lógica.");
    }
}
