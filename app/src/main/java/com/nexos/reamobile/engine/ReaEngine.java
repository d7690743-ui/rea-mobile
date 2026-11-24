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
    private static final int MAX_ELF_LIBS = 30;
    private static final int ELF_HEAD_CAP = 4 * 1024 * 1024;
    private static final int ELF_TAIL_CAP = 2 * 1024 * 1024;
    private static final long MAX_SO_SCAN = 150L * 1024 * 1024;
    private static final int MAX_LAYOUTS = 200;
    private static final int MAX_LAYOUT_BYTES = 1024 * 1024;
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
        public Map<String, IrBuilder.MethodIr> flowIrs = new LinkedHashMap<>();
        public Map<String, String> flowDex = new LinkedHashMap<>();
        public Map<String, String> flowStrings = new LinkedHashMap<>();
        public boolean flowTruncated;
        public List<AlfaElf.ElfInfo> alfaElfs = new ArrayList<>();
        public List<AlfaUi.Screen> alfaScreens = new ArrayList<>();
        /** ALFA-3: primer "permiso|api" por llamador propio (tope 4000). */
        public Map<String, String> callerPerm = new LinkedHashMap<>();
        public Map<String, String> superMap = new LinkedHashMap<>();
        public Set<String> manifestClasses = new LinkedHashSet<>();
        public List<String> limitations = new ArrayList<>();
        public List<String> unknowns = new ArrayList<>();
        /** RECUPERACIÓN: totales para el índice (0 = no aplica). */
        public int recLayoutTotal;
        public int recSoTotal;
        public int recArscTypes;
        public int recArscEntries;
        public boolean recArscPresent;
        public String error;
        /** PHANTOM (caché perezosa, estilo summarizeFlow). Nunca null ni lanza. */
        private Phantom.PhantomResult phantomCache;

        public Phantom.PhantomResult phantom() {
            try {
                if (phantomCache == null) phantomCache = Phantom.summarize(this);
                if (phantomCache == null) phantomCache = new Phantom.PhantomResult();
            } catch (Throwable ignored) {
                phantomCache = new Phantom.PhantomResult();
            }
            return phantomCache;
        }

        /** Flujo OMEGA memoizado (def-use+consts+taint una sola vez). Nunca null. */
        private FlowSummary flowCache;

        public FlowSummary flow() {
            try {
                if (flowCache == null) flowCache = computeFlow(this);
                if (flowCache == null) flowCache = new FlowSummary();
            } catch (Throwable ignored) {
                flowCache = new FlowSummary();
            }
            return flowCache;
        }

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
            FlowSummary flow = summarizeFlow(this);
            sb.append("\n=== FLUJO (metodos=").append(flow.methods)
                    .append(" defs=").append(flow.defs)
                    .append(" consts=").append(flow.consts.size())
                    .append(" taint=").append(flow.flows.size()).append(") ===");
            if (flow.truncated) sb.append(" [recortado]");
            sb.append('\n');
            if (flow.methods == 0) {
                sb.append("  (sin flujo analizado)\n");
            } else {
                for (int i = 0; i < flow.consts.size() && i < 10; i++) {
                    ResolvedConst k = flow.consts.get(i);
                    sb.append("  const=").append(k.caller).append("@+").append(k.addr)
                            .append(" v").append(k.reg).append('=').append(k.text).append('\n');
                }
                for (int i = 0; i < flow.flows.size() && i < 10; i++) {
                    Taint.Flow f = flow.flows.get(i);
                    sb.append("  taint=").append(f.source).append(" ~> ").append(f.sink)
                            .append(" en ").append(f.method);
                    if (f.inter) sb.append(" [inter]");
                    sb.append('\n');
                }
                if (flow.consts.isEmpty() && flow.flows.isEmpty()) {
                    sb.append("  (sin constantes ni flujos en llamadas)\n");
                }
            }
            SearchPlan.Plan plan = SearchPlan.build(this);
            sb.append("\n=== COBERTURA (perfil=").append(plan.profile.label).append(") ===\n");
            if (plan.note != null && !plan.note.isEmpty()) {
                sb.append("  nota=").append(plan.note).append('\n');
            }
            for (SearchPlan.CheckState c : plan.checks) {
                if (c == null) continue;
                sb.append("  check=").append(c.id).append(' ').append(c.state)
                        .append(' ').append(c.detail).append('\n');
            }
            List<AlfaJni.JniLink> jni = summarizeAlfaJni(this);
            sb.append("\n=== NATIVO (libs=").append(alfaElfs.size())
                    .append(" jni=").append(jni.size()).append(") ===\n");
            if (alfaElfs.isEmpty()) {
                sb.append("  (sin ELF parseados)\n");
            } else {
                for (AlfaElf.ElfInfo e : alfaElfs) {
                    if (e == null) continue;
                    sb.append("  nativo=").append(e.name).append(' ').append(e.arch)
                            .append(' ').append(e.elfType)
                            .append(" imp=").append(e.importCount)
                            .append(" exp=").append(e.exportCount)
                            .append(" jni=").append(e.jniExports.size());
                    if (!e.needed.isEmpty()) {
                        sb.append(" necesita=[");
                        for (int i = 0; i < Math.min(3, e.needed.size()); i++) {
                            if (i > 0) sb.append(", ");
                            sb.append(e.needed.get(i));
                        }
                        sb.append(']');
                    }
                    if (e.hasJniOnLoad) sb.append(" [JNI_OnLoad]");
                    if (e.partial) sb.append(" [parcial]");
                    sb.append('\n');
                }
                for (int i = 0; i < jni.size() && i < 20; i++) {
                    AlfaJni.JniLink l = jni.get(i);
                    sb.append("  jni=").append(l.symbol).append(" -> ")
                            .append(l.javaClass).append("->").append(l.javaMethod);
                    if (l.callers.isEmpty()) sb.append(" [sin llamadas]");
                    else sb.append(" <= ").append(l.callers.get(0));
                    sb.append('\n');
                }
            }
            List<String> alfaEntries = summarizeAlfaEntries(this);
            Set<String> exportedDescs = AlfaUi.exportedDescriptors(manifestExported, packageName);
            int handlerTotal = 0;
            for (AlfaUi.Screen s : alfaScreens) {
                if (s != null && s.handlers != null) handlerTotal += s.handlers.size();
            }
            sb.append("\n=== UI (pantallas=").append(alfaScreens.size())
                    .append(" handlers=").append(handlerTotal)
                    .append(" entradas=").append(alfaEntries.size()).append(") ===\n");
            if (alfaScreens.isEmpty() && alfaEntries.isEmpty()) {
                sb.append("  (sin UI analizada)\n");
            } else {
                for (int i = 0; i < alfaScreens.size() && i < 10; i++) {
                    AlfaUi.Screen s = alfaScreens.get(i);
                    if (s == null) continue;
                    sb.append("  pantalla=").append(s.layout).append(" vistas=").append(s.views);
                    if (!s.handlers.isEmpty()) sb.append(" handlers=").append(s.handlers);
                    if (!s.customViews.isEmpty()) {
                        sb.append(" custom=").append(s.customViews.size());
                    }
                    sb.append('\n');
                }
                int shownH = 0;
                for (AlfaUi.Screen s : alfaScreens) {
                    if (s == null || s.handlers == null) continue;
                    for (String h : s.handlers) {
                        if (shownH >= 10) break;
                        List<String> cs = AlfaUi.handlerCallers(graph, h);
                        sb.append("  handler=").append(s.layout).append(' ').append(h);
                        if (cs.isEmpty()) sb.append(" [sin código]");
                        else sb.append(" <= ").append(cs.get(0));
                        sb.append('\n');
                        shownH++;
                    }
                    if (shownH >= 10) break;
                }
                for (int i = 0; i < alfaEntries.size() && i < 20; i++) {
                    String en = alfaEntries.get(i);
                    sb.append("  entrada=").append(en);
                    if (exportedDescs.contains(RefGraph.split(en)[0])) {
                        sb.append(" [exportada]");
                    }
                    sb.append('\n');
                }
            }
            List<AlfaCorr.Chain> chains = null;
            try {
                chains = AlfaCorr.correlate(urls, urlOrigin, stringRefs, graph,
                        manifestPerms, callerPerm);
            } catch (Throwable ignored) {
                chains = new ArrayList<>();
            }
            int riskyChains = 0;
            for (AlfaCorr.Chain c : chains) {
                if (c != null && c.permisoRiesgo && c.permisoDeclarado) riskyChains++;
            }
            sb.append("\n=== BLUEPRINT (cadenas=").append(chains.size())
                    .append(" riesgo=").append(riskyChains).append(") ===\n");
            sb.append("  mapa: permiso→API→método→destino (").append(urls.size())
                    .append(" urls, ").append(manifestPerms.size()).append(" permisos, ")
                    .append(alfaScreens.size()).append(" pantallas, ")
                    .append(alfaElfs.size()).append(" .so)\n");
            if (chains.isEmpty()) {
                sb.append("  (sin cadenas: no hay URLs o no se ligaron a código)\n");
            } else {
                for (int i = 0; i < chains.size() && i < 10; i++) {
                    sb.append("  ").append(AlfaCorr.summarize(chains.get(i))).append('\n');
                }
            }
            int recIdx = -1;
            try {
                recIdx = recoveryIndex(this);
            } catch (Throwable ignored) {
            }
            sb.append("\n=== RECUPERACIÓN (índice≈")
                    .append(recIdx < 0 ? "?" : recIdx + "%").append(") ===\n");
            if (recIdx < 0) {
                sb.append("  (sin datos)\n");
            } else {
                appendRecLine(sb, "clases", appClasses.size(), appClassTotal);
                int pairs = 0;
                try {
                    pairs = stringRefs.pairCount();
                } catch (Throwable ignored) {
                }
                appendRecLine(sb, "strings", pairs, totalStrings);
                appendRecLine(sb, "urls", urls.size(), urlTotal);
                appendRecLine(sb, "secretos", secretHits.size(), secretTotal);
                if (recArscPresent) {
                    int kept = arscTruncated ? ArscStrings.MAX_STRINGS : arscStringCount;
                    appendRecLine(sb, "arsc-str", kept, arscStringCount);
                    sb.append("  arsc-tabla=").append(recArscEntries).append(" entradas, ")
                            .append(recArscTypes).append(" tipos\n");
                }
                appendRecLine(sb, "layouts", alfaScreens.size(), recLayoutTotal);
                appendRecLine(sb, "nativas", alfaElfs.size(), recSoTotal);
                sb.append("  manifest=").append(manifestXml.isEmpty() ? "no" : "sí")
                        .append(" firma=")
                        .append((!sigScheme.isEmpty() || !certSubjects.isEmpty() || apkSigBlock)
                                ? "sí" : "no").append('\n');
            }
            Phantom.PhantomResult ph = null;
            try {
                ph = phantom();
            } catch (Throwable ignored) {
                ph = null;
            }
            sb.append("\n=== PHANTOM (funciones=")
                    .append(ph == null ? 0 : ph.groups.size()).append(") ===\n");
            if (ph == null) {
                sb.append("  (no disponible)\n");
            } else {
                for (String line : Phantom.summarizeText(ph)) {
                    if (line == null) continue;
                    sb.append("  ").append(line).append('\n');
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
            FlowSummary flow = summarizeFlow(this);
            sb.append(",\"flowMethods\":").append(flow.methods);
            sb.append(",\"flowDefs\":").append(flow.defs);
            sb.append(",\"flowTruncated\":").append(flow.truncated);
            List<String> flowConstStrs = new ArrayList<>();
            for (ResolvedConst k : flow.consts) {
                flowConstStrs.add(k.caller + "@+" + k.addr + " v" + k.reg + "=" + k.text);
            }
            jsonStrList(sb, "flowConsts", flowConstStrs);
            List<String> taintStrs = new ArrayList<>();
            for (Taint.Flow f : flow.flows) {
                taintStrs.add(f.source + " ~> " + f.sink + " @ " + f.method
                        + (f.inter ? " [inter]" : ""));
            }
            jsonStrList(sb, "taintFlows", taintStrs);
            sb.append(",\"elfParsed\":").append(alfaElfs.size());
            List<String> jniStrs = new ArrayList<>();
            for (AlfaJni.JniLink l : summarizeAlfaJni(this)) {
                jniStrs.add(l.symbol + " -> " + l.javaClass + "->" + l.javaMethod
                        + (l.callers.isEmpty() ? "" : " <= " + l.callers.get(0)));
            }
            jsonStrList(sb, "jniLinks", jniStrs);
            sb.append(",\"uiScreens\":").append(alfaScreens.size());
            jsonStrList(sb, "uiEntries", summarizeAlfaEntries(this));
            List<String> uiHandlers = new ArrayList<>();
            for (AlfaUi.Screen s : alfaScreens) {
                if (s == null || s.handlers == null) continue;
                for (String h : s.handlers) uiHandlers.add(s.layout + ":" + h);
            }
            jsonStrList(sb, "uiHandlers", uiHandlers);
            List<String> corrStrs = new ArrayList<>();
            try {
                List<AlfaCorr.Chain> cs =
                        AlfaCorr.correlate(urls, urlOrigin, stringRefs, graph,
                                manifestPerms, callerPerm);
                for (AlfaCorr.Chain c : cs) corrStrs.add(AlfaCorr.summarize(c));
            } catch (Throwable ignored) {
            }
            jsonStrList(sb, "corrChains", corrStrs);
            int recIdx = -1;
            try {
                recIdx = recoveryIndex(this);
            } catch (Throwable ignored) {
            }
            sb.append(",\"recIndex\":").append(recIdx);
            SearchPlan.Plan plan = SearchPlan.build(this);
            jsonField(sb, "profile", plan.profile.label, false);
            sb.append(",\"coverage\":{");
            boolean firstCov = true;
            for (SearchPlan.CheckState c : plan.checks) {
                if (c == null) continue;
                if (!firstCov) sb.append(',');
                firstCov = false;
                jsonQuoted(sb, c.id);
                sb.append(':');
                jsonQuoted(sb, c.state == null ? "?" : c.state.name());
            }
            sb.append('}');
            try {
                jsonPhantom(sb, phantom());
            } catch (Throwable ignored) {
            }
            sb.append('}');
            return sb.toString();
        }

        /** Bloque PHANTOM del paquete JSON (acotado). Nunca lanza. */
        private static void jsonPhantom(StringBuilder sb, Phantom.PhantomResult p) {
            try {
                if (p == null) return;
                sb.append(",\"phantom\":{");
                jsonField(sb, "metric", PhantomMetric.distribution(p.groups), true);
                List<String> funcs = new ArrayList<>();
                if (p.groups != null) {
                    for (PhantomGroup.FuncGroup g : p.groups) {
                        if (g == null || funcs.size() >= 60) break;
                        StringBuilder f = new StringBuilder();
                        f.append(g.id).append(' ').append(g.name);
                        f.append(" [").append(PhantomMetric.score(g)).append("/8]");
                        f.append(" met=").append(g.methodTotal);
                        if (!g.entries.isEmpty()) f.append(' ').append(g.entries.get(0));
                        funcs.add(f.toString());
                    }
                }
                jsonStrList(sb, "functions", funcs);
                List<String> nets = new ArrayList<>();
                if (p.contracts != null) {
                    for (PhantomNet.Contract c : p.contracts) {
                        if (c == null || nets.size() >= 30) break;
                        nets.add(PhantomNet.summarize(c));
                    }
                }
                jsonStrList(sb, "netContracts", nets);
                List<String> uis = new ArrayList<>();
                if (p.ui != null) uis.addAll(PhantomUi.summarize(p.ui));
                jsonStrList(sb, "screens", uis.size() > 70 ? uis.subList(0, 70) : uis);
                List<String> jd = new ArrayList<>();
                if (p.dynJni != null) {
                    for (PhantomJni.DynLink l : p.dynJni) {
                        if (l == null || jd.size() >= 30) break;
                        jd.add(PhantomJni.summarize(l));
                    }
                }
                jsonStrList(sb, "dynJni", jd);
                List<String> tx = new ArrayList<>();
                if (p.taintX != null) tx.addAll(PhantomTaint.summarize(p.taintX));
                jsonStrList(sb, "flowX", tx.size() > 30 ? tx.subList(0, 30) : tx);
                sb.append('}');
            } catch (Throwable ignored) {
            }
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
                List<String> layoutNames = new ArrayList<>();
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
                    else if (name.startsWith("res/")) {
                        r.resCount++;
                        if (name.startsWith("res/layout") && name.endsWith(".xml")) {
                            r.recLayoutTotal++;
                            if (layoutNames.size() < MAX_LAYOUTS) layoutNames.add(name);
                        }
                    }
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

                // Layouts UI.
                for (String ln : layoutNames) {
                    ZipEntry e = zip.getEntry(ln);
                    byte[] lb = e == null ? null : readEntry(zip, e, MAX_LAYOUT_BYTES);
                    if (lb == null) continue;
                    String xml = AxmlDecoder.decode(lb);
                    if (xml == null || xml.isEmpty()) continue;
                    r.alfaScreens.add(AlfaUi.parseLayout(ln, xml));
                    if (r.alfaScreens.size() >= MAX_LAYOUTS) break;
                }

                // ARSC.
                if (arscBytes != null) {
                    r.recArscPresent = true;
                    ArscStrings.ArscInfo ai = ArscStrings.parse(arscBytes);
                    if (ai.error != null) {
                        r.dexNotes.add("resources.arsc: " + ai.error);
                    } else {
                        r.arscStringCount = ai.stringCount;
                        r.arscTruncated = ai.truncated;
                        scanStrings(ai.strings, urlSet, ipSet, emailSet, secretSet, secretHighSet, counters,
                                r.urlOrigin, "arsc");
                    }
                    try {
                        ArscTable.TableInfo ti = ArscTable.parse(arscBytes, 0);
                        if (ti.error == null) {
                            r.recArscTypes = ti.typeCount;
                            r.recArscEntries = ti.entryTotal;
                        }
                    } catch (Throwable ignored) {
                    }
                }

                // Nativas: inventario + arquitectura por cabecera ELF + etiqueta conocida.
                r.recSoTotal = soNames.size();
                int elfParsed = 0;
                for (String so : soNames) {
                    ZipEntry e = zip.getEntry(so);
                    byte[] head = e == null ? null : readPrefix(zip, e, 64);
                    String tag = NativeTable.classify(so);
                    r.nativeLibs.add(so + " (" + elfArch(head) + ")"
                            + (tag == null ? "" : " [" + tag + "]"));
                    if (e != null && elfParsed < MAX_ELF_LIBS) {
                        HeadTail ht = readHeadTail(zip, e, ELF_HEAD_CAP, ELF_TAIL_CAP);
                        if (ht == null) {
                            r.dexNotes.add("elf " + so + ": omitido por tamaño");
                        } else {
                            AlfaElf.ElfInfo ei = AlfaElf.parse(so, ht.head, ht.tail,
                                    ht.tailStart, ht.fileSize);
                            if (ei.error == null) {
                                try {
                                    PhantomJni.SoResult soScan = PhantomJni.scanSo(
                                            ht.head, ht.tail);
                                    if (soScan != null) {
                                        if (!soScan.jni.isEmpty()) {
                                            ei.jniDynamic = soScan.jni;
                                        }
                                        if (!soScan.urls.isEmpty()) {
                                            ei.soUrls = soScan.urls;
                                        }
                                    }
                                } catch (Throwable ignored) {
                                }
                                r.alfaElfs.add(ei);
                            } else {
                                r.dexNotes.add("elf " + so + ": " + ei.error);
                            }
                            elfParsed++;
                        }
                    }
                    if (r.nativeLibs.size() >= 100) break;
                }
                if (soNames.size() > MAX_ELF_LIBS) {
                    r.dexNotes.add("elf: parseados " + MAX_ELF_LIBS + " de " + soNames.size());
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
            DexCalls.Result cr = DexCalls.collect(dexBytes, pkgSlash, dexName, pkgSlash != null);
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
                if (perm != null && e.caller != null && r.callerPerm.size() < 4000
                        && !r.callerPerm.containsKey(e.caller)) {
                    r.callerPerm.put(e.caller, perm + "|" + e.callee);
                }
            }
            if (cr.truncated) r.dexNotes.add("llamadas: topes alcanzados (muestra parcial)");
            if (cr.stringsTruncated) noteOnce(r, "cadenas: topes alcanzados (muestra parcial)");
            collectFlow(r, dexBytes, cr, dexName);
            // Sensibles invocadas desde librerías (adrt…) al grafo.
            // suspCalls queda propio (su sección lo afirma); el grafo es más amplio.
            if (pkgSlash != null) {
                List<DexCalls.Edge> keep = new ArrayList<>();
                int dataKept = 0;
                for (DexCalls.Edge e : cr.libEdges) {
                    if (e == null || e.caller == null || e.callee == null) continue;
                    int arrow = e.callee.indexOf("->");
                    String cls = arrow < 0 ? e.callee : e.callee.substring(0, arrow);
                    String name = arrow < 0 ? "" : e.callee.substring(arrow + 2);
                    if (DexParser.suspiciousLabelWithSupers(cls, name, r.superMap) == null) {
                        if (!keepDataLibEdge(e.caller) || dataKept >= 500) continue;
                        dataKept++;
                    }
                    keep.add(e);
                }
                r.graph.addAll(keep);
                r.stringRefs.addAll(cr.libStrings);
                String tag = dexName == null ? "?" : dexName;
                if (cr.libTruncated) r.dexNotes.add("librerías " + tag + ": muestra parcial (topes)");
                if (cr.libStringsTruncated) {
                    noteOnce(r, "cadenas: topes alcanzados (muestra parcial)");
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * OMEGA flujo: construye IRs sobre los métodos que DexCalls ya recorrió
     * (sin re-recorrer el DEX ni re-decodificar strings). Nunca lanza.
     */
    static void collectFlow(ApkReport r, byte[] dexBytes, DexCalls.Result cr, String dexName) {
        try {
            if (r == null) return;
            int budget = FlowScan.MAX_FLOW_METHODS - r.flowIrs.size();
            if (budget <= 0) {
                r.flowTruncated = true;
                return;
            }
            FlowScan.FlowResult fr = FlowScan.buildFrom(dexBytes,
                    cr == null ? null : cr.codeOffs, cr == null ? null : cr.table,
                    dexName, budget);
            for (Map.Entry<String, IrBuilder.MethodIr> en : fr.irs.entrySet()) {
                if (en.getKey() == null || en.getValue() == null) continue;
                if (r.flowIrs.containsKey(en.getKey())) continue;
                r.flowIrs.put(en.getKey(), en.getValue());
                String dx = fr.flowDex.get(en.getKey());
                r.flowDex.put(en.getKey(), dx == null ? "?" : dx);
            }
            if (fr.strings != null) r.flowStrings.putAll(fr.strings);
            if (fr.truncated) r.flowTruncated = true;
            if (fr.skipped > 0) {
                noteOnce(r, "flujo: " + fr.skipped + " método(s) grande(s) omitidos");
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * true si un llamador lib define datos (proto/parcel): sus aristas se
     * conservan (tope 500) para que PHANTOM vea modelos ofuscados.
     * Nunca lanza.
     */
    static boolean keepDataLibEdge(String caller) {
        try {
            if (caller == null) return false;
            return caller.endsWith("->dynamicMethod")
                    || caller.endsWith("->writeToParcel");
        } catch (Throwable ignored) {
            return false;
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

    /** Ventanas cabeza+cola de una entrada grande. Nunca lanza. */
    static class HeadTail {
        byte[] head = new byte[0];
        byte[] tail = new byte[0];
        long tailStart;
        long fileSize;
    }

    /**
     * Lee una entrada en una pasada reteniendo cabeza (headCap) y cola
     * (tailCap). Null si supera MAX_SO_SCAN o falla. Nunca lanza.
     */
    static HeadTail readHeadTail(ZipFile zip, ZipEntry e, int headCap, int tailCap) {
        try {
            if (zip == null || e == null || headCap <= 0 || tailCap <= 0) return null;
            long size = e.getSize();
            if (size > MAX_SO_SCAN) return null;
            InputStream in = zip.getInputStream(e);
            try {
                byte[] head = new byte[headCap];
                int headLen = 0;
                byte[] ring = new byte[tailCap];
                int ringPos = 0;
                long total = 0;
                byte[] buf = new byte[65536];
                int r;
                while ((r = in.read(buf)) > 0) {
                    if (total + r > MAX_SO_SCAN) return null;
                    for (int i = 0; i < r; i++) {
                        byte v = buf[i];
                        if (headLen < headCap) head[headLen++] = v;
                        ring[ringPos] = v;
                        ringPos = (ringPos + 1) % tailCap;
                    }
                    total += r;
                }
                if (total == 0) return null;
                HeadTail ht = new HeadTail();
                ht.fileSize = total;
                if (total <= headCap) {
                    byte[] h = new byte[(int) total];
                    System.arraycopy(head, 0, h, 0, (int) total);
                    ht.head = h;
                    ht.tail = new byte[0];
                    ht.tailStart = total;
                } else {
                    byte[] h = new byte[headCap];
                    System.arraycopy(head, 0, h, 0, headCap);
                    ht.head = h;
                    int tailLen = (int) Math.min(total, (long) tailCap);
                    byte[] t = new byte[tailLen];
                    int start = (int) ((ringPos - tailLen + tailCap) % tailCap);
                    for (int i = 0; i < tailLen; i++) {
                        t[i] = ring[(start + i) % tailCap];
                    }
                    ht.tail = t;
                    ht.tailStart = total - tailLen;
                }
                return ht;
            } finally {
                try {
                    in.close();
                } catch (Exception ignored) {
                }
            }
        } catch (Throwable ignored) {
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
    private static final long MAX_SMALI_STREAM = 150L * 1024 * 1024;

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
                // Pasada 1 (barata): prefijos para elegir paquete propio + strings.
                Map<String, Integer> prefixCounts = new LinkedHashMap<>();
                List<String> dexStrings = new ArrayList<>();
                for (String dn : dexNames) {
                    ZipEntry e = zip.getEntry(dn);
                    byte[] b = e == null ? null : readEntry(zip, e, MAX_DEX_BYTES);
                    if (b == null) {
                        r.notes.add(dn + ": omitido por tamaño");
                        continue;
                    }
                    SmaliDumper.countPrefixes(b, prefixCounts);
                    DexParser.DexInfo di = DexParser.parse(b, "dex");
                    if (di.error == null) {
                        for (String s : di.strings) {
                            if (dexStrings.size() >= MAX_STRING_LINES) break;
                            dexStrings.add(s);
                        }
                    }
                    b = null;
                }
                String ownSlash = SmaliDumper.pickOwnPrefix(prefixCounts, pkgSlash);
                if (!ownSlash.equals(pkgSlash) && !ownSlash.isEmpty()) {
                    r.notes.add("smali: sin clases bajo " + pkgSlash + "; resúmenes con "
                            + ownSlash);
                }
                final Set<String> bootWant = new LinkedHashSet<>();
                ManifestChecks.Result bootMc = ManifestChecks.check(manifestXml, null);
                for (String b : bootMc.bootReceivers) {
                    String clsName = b.split(" ")[0];
                    String fq = clsName.startsWith(".") && !"?".equals(pkg) ? pkg + clsName : clsName;
                    if (fq.startsWith("?")) continue;
                    bootWant.add("smali/" + fq.replace('.', '/') + ".smali");
                }
                List<String> arscStrings = new ArrayList<>();
                int arscTotal = 0;
                ArscTable.TableInfo arscTable = null;
                ZipEntry arsc = zip.getEntry("resources.arsc");
                if (arsc != null) {
                    byte[] ab = readEntry(zip, arsc, 100 * 1024 * 1024);
                    if (ab != null) {
                        ArscStrings.ArscInfo ai = ArscStrings.parse(ab);
                        if (ai.error == null) {
                            arscTotal = ai.stringCount;
                            arscStrings.addAll(ai.strings);
                        }
                        try {
                            arscTable = ArscTable.parse(ab, 30000);
                        } catch (Throwable ignored) {
                            arscTable = null;
                        }
                    }
                }
                ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outZip));
                long total = 0;
                int layoutTotal = 0;
                int layoutOk = 0;
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
                        if (isLayoutXml(name)) {
                            layoutTotal++;
                            if (layoutOk < MAX_LAYOUTS && data.length <= MAX_LAYOUT_BYTES) {
                                try {
                                    String xml = AxmlDecoder.decode(data);
                                    if (xml != null && !xml.isEmpty()) {
                                        putText(zos, "rea/layouts/" + name, xml);
                                        layoutOk++;
                                    }
                                } catch (Throwable ignored) {
                                }
                            }
                        }
                    }
                    if (layoutTotal > 0) {
                        r.notes.add("layouts: " + layoutOk + "/" + layoutTotal
                                + " decodificados");
                    }
                    putText(zos, "rea/manifest.xml", manifestXml.isEmpty() ? "(no decodificado)\n" : manifestXml);
                    putText(zos, "rea/ARBOL.txt", tree.toString());
                    // Pasada 2: volcado TOTAL al ZIP en streaming (sin retener).
                    final ZipOutputStream zosF = zos;
                    final long[] smaliBytes = new long[1];
                    SmaliDumper.ClassSink sink = new SmaliDumper.ClassSink() {
                        public void accept(String path, String text) {
                            try {
                                if (smaliBytes[0] + text.length() > MAX_SMALI_STREAM) {
                                    throw new SmaliDumper.Stop("tope 150MB en ZIP");
                                }
                                byte[] data = text.getBytes("UTF-8");
                                zosF.putNextEntry(new ZipEntry("rea/" + path));
                                zosF.write(data);
                                zosF.closeEntry();
                                smaliBytes[0] += text.length();
                                if (bootWant.contains(path)
                                        && (text.contains("startActivity")
                                        || text.contains("getLaunchIntentForPackage"))) {
                                    r.notes.add("autoarranque: "
                                            + path.replace('/', '.').replace("smali.", "")
                                            .replace(".smali", "")
                                            + " lanza actividad (smali)");
                                }
                            } catch (SmaliDumper.Stop s) {
                                throw s;
                            } catch (Exception e) {
                                throw new SmaliDumper.Stop("zip: " + e.getMessage());
                            }
                        }
                    };
                    SmaliDumper.FullDump full = new SmaliDumper.FullDump(ownSlash, sink);
                    for (String dn : dexNames) {
                        ZipEntry de = zip.getEntry(dn);
                        byte[] db = de == null ? null : readEntry(zip, de, MAX_DEX_BYTES);
                        if (db == null) continue;
                        full.addDex(db);
                        db = null;
                        if (full.r.truncated) break;
                    }
                    StringBuilder cls = new StringBuilder();
                    for (String s : full.r.classSummaries) cls.append(s).append('\n');
                    putText(zos, "rea/CLASES_PROPIAS.txt", cls.length() == 0 ? "(sin clases)\n" : cls.toString());
                    r.smaliClasses = full.r.dumped;
                    r.notes.add("smali: " + full.r.dumped + "/" + full.r.scanned
                            + " clases, propias=" + full.r.ownMatched);
                    r.notes.addAll(full.r.notes);
                    full.r.classSummaries.clear();
                    StringBuilder ds = new StringBuilder();
                    for (String s : dexStrings) ds.append(s.replace('\n', ' ')).append('\n');
                    putText(zos, "rea/INDICIOS_strings_dex.txt", ds.toString());
                    StringBuilder as = new StringBuilder("total=" + arscTotal + "\n");
                    for (String s : arscStrings) as.append(s.replace('\n', ' ')).append('\n');
                    putText(zos, "rea/INDICIOS_strings_arsc.txt", as.toString());
                    if (arscTable != null && arscTable.error == null) {
                        StringBuilder tb = new StringBuilder();
                        tb.append("paquetes=").append(arscTable.packageCount).append('\n');
                        tb.append("tipos=").append(arscTable.typeCount).append('\n');
                        tb.append("configs=").append(arscTable.configChunks).append('\n');
                        tb.append("entradas=").append(arscTable.entryTotal).append('\n');
                        for (Map.Entry<String, String> me : arscTable.idToName.entrySet()) {
                            tb.append(me.getKey()).append(" = ").append(me.getValue())
                                    .append('\n');
                        }
                        putText(zos, "rea/RECURSOS_ids.txt", tb.toString());
                        r.notes.add("recursos: " + arscTable.idToName.size() + "/"
                                + arscTable.entryTotal + " ids, tipos="
                                + arscTable.typeCount);
                        if (arscTable.truncated) r.notes.add("recursos: mapa recortado");
                    } else if (arsc != null) {
                        r.notes.add("recursos: tabla no decodificada");
                    }
                    List<String> slashes = new ArrayList<>();
                    if (!"?".equals(pkg)) slashes.add(pkgSlash);
                    // Libera strings ya volcados antes de cargar JADX.
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
                    try {
                        putText(zos, "rea/paquete.json", rep.toJson());
                        r.notes.add("paquete: rea/paquete.json incluido");
                    } catch (Throwable ignored) {
                        r.notes.add("paquete: no se pudo emitir el JSON");
                    }
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

    /** true si es un XML de recurso decodificable (layout, xml, navigation...). */
    private static boolean isLayoutXml(String name) {
        try {
            if (name == null || !name.endsWith(".xml")) return false;
            return name.startsWith("res/layout") || name.startsWith("res/xml")
                    || name.startsWith("res/navigation") || name.startsWith("res/menu")
                    || name.startsWith("res/drawable/") || name.startsWith("res/values/");
        } catch (Throwable ignored) {
            return false;
        }
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

    /** Fracción 0..1 (0 si total<=0). Nunca lanza. */
    private static double recFrac(int kept, int total) {
        try {
            if (total <= 0 || kept <= 0) return 0;
            double f = kept / (double) total;
            return f > 1 ? 1 : f;
        } catch (Throwable ignored) {
            return 0;
        }
    }

    /**
     * Índice de recuperación 0..100 (-1 sin datos): media ponderada de lo
     * retenido frente al total por artefacto; lo no aplicable no pondera.
     * Pesos en docs/RECUPERACION.md. Nunca lanza.
     */
    static int recoveryIndex(ApkReport r) {
        try {
            if (r == null) return -1;
            double num = 0;
            double den = 0;
            if (r.appClassTotal > 0) {
                num += 30 * recFrac(r.appClasses.size(), r.appClassTotal);
                den += 30;
            }
            if (r.totalStrings > 0) {
                int pairs = 0;
                try {
                    pairs = r.stringRefs.pairCount();
                } catch (Throwable ignored) {
                }
                num += 10 * recFrac(pairs, r.totalStrings);
                den += 10;
            }
            if (r.urlTotal > 0) {
                num += 5 * recFrac(r.urls.size(), r.urlTotal);
                den += 5;
            }
            if (r.secretTotal > 0) {
                num += 5 * recFrac(r.secretHits.size(), r.secretTotal);
                den += 5;
            }
            if (r.recArscPresent) {
                int kept = r.arscTruncated ? ArscStrings.MAX_STRINGS : r.arscStringCount;
                num += 10 * recFrac(kept, Math.max(1, r.arscStringCount));
                den += 10;
                num += 10 * (r.recArscEntries > 0 ? 1 : 0);
                den += 10;
            }
            if (r.recLayoutTotal > 0) {
                num += 10 * recFrac(r.alfaScreens.size(), r.recLayoutTotal);
                den += 10;
            }
            if (r.recSoTotal > 0) {
                num += 5 * recFrac(r.alfaElfs.size(), r.recSoTotal);
                den += 5;
            }
            num += 10 * (r.manifestXml.isEmpty() ? 0 : 1);
            den += 10;
            boolean firma = !r.sigScheme.isEmpty() || !r.certSubjects.isEmpty() || r.apkSigBlock;
            num += 5 * (firma ? 1 : 0);
            den += 5;
            if (den <= 0) return -1;
            return (int) Math.round(100 * num / den);
        } catch (Throwable ignored) {
            return -1;
        }
    }

    /** Línea "  nombre=kept/total" (o "n/a"). Nunca lanza. */
    private static void appendRecLine(StringBuilder sb, String name, int kept, int total) {
        try {
            sb.append("  ").append(name).append('=');
            if (total <= 0) sb.append("n/a");
            else sb.append(kept).append('/').append(total);
            sb.append('\n');
        } catch (Throwable ignored) {
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
            feedIntelFlow(r);
            feedIntelAlfa(r);
            feedIntelPlan(r);
            feedIntelPhantom(r);
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

    /** Constante resuelta en un sitio de llamada. Nunca lanza. */
    static class ResolvedConst {
        String caller = "?";
        int addr = -1;
        int reg = -1;
        String text = "?";
    }

    /** Resumen FLUJO precomputado (lo usan toText, toJson y SearchPlan). Nunca lanza. */
    static class FlowSummary {
        int methods;
        int defs;
        int uses;
        List<ResolvedConst> consts = new ArrayList<>();
        List<Taint.Flow> flows = new ArrayList<>();
        boolean truncated;
    }

    /**
     * Analiza el flujo sobre las IRs recolectadas (def-use, constantes en
     * llamadas, taint). Vacío si no hay IRs. Nunca null ni lanza.
     */
    static FlowSummary summarizeFlow(ApkReport r) {
        try {
            if (r != null) return r.flow();
        } catch (Throwable ignored) {
        }
        return computeFlow(r);
    }

    /**
     * Cómputo real del resumen de flujo (ver {@link #summarizeFlow}).
     * Nunca null ni lanza.
     */
    private static FlowSummary computeFlow(ApkReport r) {
        FlowSummary s = new FlowSummary();
        try {
            if (r == null || r.flowIrs == null || r.flowIrs.isEmpty()) return s;
            s.methods = r.flowIrs.size();
            if (r.flowTruncated) s.truncated = true;
            for (Map.Entry<String, IrBuilder.MethodIr> en : r.flowIrs.entrySet()) {
                if (en.getKey() == null || en.getValue() == null) continue;
                try {
                    DefUse.Chains chains = DefUse.analyze(en.getValue());
                    s.defs += chains.defs.size();
                    s.uses += chains.uses.size();
                    if (chains.truncated) s.truncated = true;
                    ReachConsts.ConstResult cr = ReachConsts.analyze(en.getValue());
                    if (cr.truncated) s.truncated = true;
                    for (ReachConsts.CallConst cc : cr.callConsts) {
                        if (cc == null || s.consts.size() >= 50) {
                            if (cc != null) s.truncated = true;
                            break;
                        }
                        ResolvedConst k = new ResolvedConst();
                        k.caller = en.getKey();
                        k.addr = cc.addr;
                        k.reg = cc.reg;
                        k.text = constText(r, en.getKey(), cc);
                        s.consts.add(k);
                    }
                } catch (Throwable ignored) {
                }
            }
            Taint.TaintResult tr = Taint.analyze(r.flowIrs, r.graph, r.superMap);
            s.flows.addAll(tr.flows);
            if (tr.truncated) s.truncated = true;
        } catch (Throwable ignored) {
        }
        return s;
    }

    /** Texto legible de una constante (literal o string resuelto). Nunca lanza. */
    private static String constText(ApkReport r, String caller, ReachConsts.CallConst cc) {
        try {
            if (cc.kind == ReachConsts.Kind.LIT) return "lit " + cc.lit;
            if (cc.kind == ReachConsts.Kind.STR) {
                String dex = r.flowDex == null ? null : r.flowDex.get(caller);
                String v = (r.flowStrings == null || dex == null) ? null
                        : r.flowStrings.get(dex + "\u0000" + cc.strRef);
                if (v == null) return "str#" + cc.strRef;
                if (v.length() > 80) v = v.substring(0, 80) + "…";
                return "\"" + v + "\"";
            }
        } catch (Throwable ignored) {
        }
        return "?";
    }

    /**
     * Enlaces JNI de los ELF parseados con el grafo (perezoso: lo usan
     * toText, toJson y feedIntel). Nunca null ni lanza.
     */
    static List<AlfaJni.JniLink> summarizeAlfaJni(ApkReport r) {
        List<AlfaJni.JniLink> out = new ArrayList<>();
        try {
            if (r == null || r.alfaElfs == null || r.alfaElfs.isEmpty()) return out;
            List<String> syms = new ArrayList<>();
            for (AlfaElf.ElfInfo e : r.alfaElfs) {
                if (e == null || e.jniExports == null) continue;
                for (String s : e.jniExports) {
                    if (s != null && !syms.contains(s)) syms.add(s);
                }
            }
            out = AlfaJni.link(syms, r.graph);
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Entradas UI verificadas (perezoso). Nunca null ni lanza.
     */
    static List<String> summarizeAlfaEntries(ApkReport r) {
        try {
            if (r == null) return new ArrayList<>();
            return AlfaUi.verifiedEntries(r.graph, r.manifestClasses);
        } catch (Throwable ignored) {
            return new ArrayList<>();
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

    /**
     * OMEGA flujo: cada taint origen→sumidero pasa al registro, más las
     * constantes resueltas en llamadas sensibles. Confianza MEDIA
     * (instrucciones reales) y nunca se afirma ejecución. Topes 20+10.
     * Nunca lanza.
     */
    static void feedIntelFlow(ApkReport r) {
        try {
            if (r == null || r.intel == null) return;
            FlowSummary flow = summarizeFlow(r);
            int added = 0;
            for (Taint.Flow f : flow.flows) {
                if (added >= 20 || f == null) break;
                String[] parts = RefGraph.split(f.method);
                IntelFinding inf = IntelFinding.create("taint",
                        f.source + " ~> " + f.sink);
                inf.className = parts[0];
                inf.methodName = parts[1];
                inf.evidence = f.evidence == null || f.evidence.isEmpty() ? "-" : f.evidence;
                inf.confidence = IntelFinding.Confidence.MEDIUM;
                inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                inf.limitations = "flujo estático best-effort (intra exacto, inter un salto);"
                        + " ejecución no observada";
                if (r.intel.add(inf)) added++;
            }
            int addedC = 0;
            for (ResolvedConst k : flow.consts) {
                if (addedC >= 10 || k == null) break;
                boolean sensitive = false;
                String callee = "?";
                for (String c : InterProc.calleesAt(r.graph, k.caller, k.addr)) {
                    String[] parts = RefGraph.split(c);
                    if (DexParser.suspiciousLabelWithSupers(parts[0], parts[1], r.superMap)
                            != null) {
                        sensitive = true;
                        callee = c;
                        break;
                    }
                }
                if (!sensitive) continue;
                String[] parts = RefGraph.split(k.caller);
                IntelFinding inf = IntelFinding.create("flujo",
                        k.caller + " arg v" + k.reg + " = " + k.text);
                inf.className = parts[0];
                inf.methodName = parts[1];
                inf.evidence = "invoke @+" + k.addr + " -> " + callee;
                inf.confidence = IntelFinding.Confidence.MEDIUM;
                inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                inf.limitations = "constante estática en sitio de llamada; ejecución no observada";
                if (r.intel.add(inf)) addedC++;
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * ALFA: librerías con JNI, enlaces JNI con llamadas, entradas
     * exportadas, handlers UI y cadenas permiso→destino pasan al registro.
     * Confianza MEDIA/LOW según evidencia y nunca se afirma ejecución.
     * Topes 10+20+20+10+10. Nunca lanza.
     */
    static void feedIntelAlfa(ApkReport r) {
        try {
            if (r == null || r.intel == null) return;
            int added = 0;
            if (r.alfaElfs != null) {
                for (AlfaElf.ElfInfo e : r.alfaElfs) {
                    if (added >= 10 || e == null) break;
                    if (e.jniExports == null || e.jniExports.isEmpty()) continue;
                    IntelFinding inf = IntelFinding.create("nativo",
                            e.name + ": " + e.jniExports.size() + " JNI (" + e.arch + ")");
                    inf.evidence = "exports ELF" + (e.hasJniOnLoad ? " + JNI_OnLoad" : "");
                    inf.confidence = IntelFinding.Confidence.MEDIUM;
                    inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                    inf.limitations = "símbolos dinámicos; registro dinámico"
                            + " (RegisterNatives) no visible";
                    if (r.intel.add(inf)) added++;
                }
            }
            int addedJ = 0;
            for (AlfaJni.JniLink l : summarizeAlfaJni(r)) {
                if (addedJ >= 20 || l == null) break;
                if (l.callers.isEmpty()) continue;
                IntelFinding inf = IntelFinding.create("jni",
                        l.javaClass + "->" + l.javaMethod + " implementado en nativo");
                inf.className = l.javaClass;
                inf.methodName = l.javaMethod;
                inf.evidence = l.symbol + " <= " + l.callers.get(0);
                inf.confidence = IntelFinding.Confidence.MEDIUM;
                inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                inf.limitations = "llamada estática respaldada por instrucción DEX;"
                        + " ejecución no observada";
                if (r.intel.add(inf)) addedJ++;
            }
            Set<String> exportedDescs =
                    AlfaUi.exportedDescriptors(r.manifestExported, r.packageName);
            int addedE = 0;
            for (String en : summarizeAlfaEntries(r)) {
                if (addedE >= 20 || en == null) break;
                String[] parts = RefGraph.split(en);
                if (!exportedDescs.contains(parts[0])) continue;
                IntelFinding inf = IntelFinding.create("entrada",
                        "entry point exportado: " + en);
                inf.className = parts[0];
                inf.methodName = parts[1];
                inf.evidence = "componente exportado + llamador en grafo";
                inf.confidence = IntelFinding.Confidence.MEDIUM;
                inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                inf.limitations = "alcanzabilidad externa no demostrada;"
                        + " ejecución no observada";
                if (r.intel.add(inf)) addedE++;
            }
            int addedU = 0;
            if (r.alfaScreens != null) {
                for (AlfaUi.Screen s : r.alfaScreens) {
                    if (addedU >= 10 || s == null || s.handlers == null) break;
                    for (String h : s.handlers) {
                        if (addedU >= 10 || h == null) break;
                        List<String> cs = AlfaUi.handlerCallers(r.graph, h);
                        if (cs.isEmpty()) continue;
                        IntelFinding inf = IntelFinding.create("ui",
                                "handler onClick " + h + " en " + s.layout);
                        inf.evidence = "unión por nombre: " + cs.get(0);
                        inf.confidence = IntelFinding.Confidence.LOW;
                        inf.evidenceType = IntelFinding.EvidenceType.INFERRED;
                        inf.limitations = "layout↔actividad no resuelto;"
                                + " ejecución no observada";
                        if (r.intel.add(inf)) addedU++;
                    }
                }
            }
            int addedC = 0;
            List<AlfaCorr.Chain> chains = AlfaCorr.correlate(
                    r.urls, r.urlOrigin, r.stringRefs, r.graph, r.manifestPerms,
                    r.callerPerm);
            for (AlfaCorr.Chain c : chains) {
                if (addedC >= 10 || c == null) break;
                if (c.metodos.isEmpty()) continue;
                IntelFinding inf = IntelFinding.create("correlacion",
                        "cadena " + c.permiso + " → " + c.host);
                inf.evidence = AlfaCorr.summarize(c);
                if (c.permisoDeclarado && !"?".equals(c.permiso)) {
                    inf.confidence = IntelFinding.Confidence.MEDIUM;
                    inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                } else {
                    inf.confidence = IntelFinding.Confidence.LOW;
                    inf.evidenceType = IntelFinding.EvidenceType.INFERRED;
                }
                inf.limitations = "correlación estática por literal compartido;"
                        + " ejecución no observada";
                if (r.intel.add(inf)) addedC++;
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * OMEGA plan RAG: un hallazgo con el perfil y el recuento de estados.
     * Nunca lanza.
     */
    static void feedIntelPlan(ApkReport r) {
        try {
            if (r == null || r.intel == null) return;
            if (r.fileSize <= 0 && (r.sha256 == null || r.sha256.length() < 32)) return;
            SearchPlan.Plan plan = SearchPlan.build(r);
            int found = 0;
            int partial = 0;
            int missing = 0;
            int unsupported = 0;
            for (SearchPlan.CheckState c : plan.checks) {
                if (c == null || c.state == null) continue;
                switch (c.state) {
                    case FOUND:
                        found++;
                        break;
                    case PARTIAL:
                        partial++;
                        break;
                    case NOT_FOUND_IN_SCOPE:
                        missing++;
                        break;
                    case UNSUPPORTED:
                    case NOT_EXECUTED:
                        unsupported++;
                        break;
                    default:
                        break;
                }
            }
            IntelFinding inf = IntelFinding.create("perfil",
                    "Perfil de análisis: " + plan.profile.label);
            inf.evidence = plan.checks.size() + " checks: " + found + " FOUND, " + partial
                    + " PARTIAL, " + missing + " NOT_FOUND, " + unsupported + " NO-EJECUTADO";
            inf.confidence = IntelFinding.Confidence.HIGH;
            inf.evidenceType = IntelFinding.EvidenceType.STATIC;
            inf.limitations = "cobertura declarada por el propio analizador";
            r.intel.add(inf);
        } catch (Throwable ignored) {
        }
    }

    /**
     * PHANTOM: funciones, contratos, pantallas, JNI dinámico y multisalto
     * al registro (perezoso con caché). Nunca lanza.
     */
    static void feedIntelPhantom(ApkReport r) {
        try {
            if (r == null || r.intel == null) return;
            Phantom.PhantomResult p = null;
            try {
                p = r.phantom();
            } catch (Throwable ignored) {
                p = null;
            }
            Phantom.feedIntel(r, p);
        } catch (Throwable ignored) {
        }
    }

    private static void finishStatic(ApkReport r) {
        feedIntel(r);
        r.limitations.add("Java bajo demanda en el visor (JADX on-device con topes); el informe base no incluye fuentes.");
        r.limitations.add("Flujo de datos parcial: def-use/taint best-effort con topes (inter de un salto, sin heap ni reflexión).");
        r.limitations.add("Sin análisis dinámico (Frida/adb): estático únicamente.");
        r.limitations.add("AXML y ARSC decodificados con parser propio (best-effort).");
        r.limitations.add("Nativas: ELF parseado (símbolos/JNI), sin desensamblado; RegisterNatives best-effort (PHANTOM).");
        r.limitations.add("UI: setContentView resuelto best-effort (PHANTOM, id sin nombre); handlers verificados en grafo.");
        r.limitations.add("Blueprint: correlación por literal compartido, no flujo verificado.");
        r.limitations.add("Muestreo con topes en APKs grandes (ver notas).");
        r.unknowns.add("Comportamiento en ejecución (runtime).");
        r.unknowns.add("Contenido descargado, generado o descifrado en runtime.");
        r.unknowns.add("Código tras ofuscación o empaquetado: nombres y flujo pueden ocultar la lógica.");
    }
}
