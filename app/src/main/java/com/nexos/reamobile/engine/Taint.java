package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OMEGA Fase E4: taint analysis. Rastrea datos desde orígenes sensibles
 * (texto, ubicación, contactos, identificadores…) hasta sumideros (red,
 * SMS, exec, logs…) dentro de cada método (intra, exacto sobre DefUse) y
 * a través de una llamada (inter de un salto, vía resúmenes InterProc).
 * Utilidad estática sin estado. Java puro. Nunca lanza.
 *
 * <p>Límites honestos: matching por nombre (la ofuscación lo degrada),
 * inter de un solo salto, retorno con taint sobre-aproximado (si el
 * callee puede devolver su entrada y recibe un arg marcado, el resultado
 * se marca), sin heap ni reflexión.</p>
 */
public final class Taint {
    private Taint() {
    }

    public static final int MAX_METHODS = 200;
    public static final int MAX_FLOWS = 50;

    /** Orígenes: {prefijo de clase, método exacto}. */
    private static final String[][] SOURCES = {
            {"Landroid/widget/EditText;", "getText"},
            {"Landroid/widget/TextView;", "getText"},
            {"Landroid/widget/AutoCompleteTextView;", "getText"},
            {"Landroid/location/LocationManager;", "getLastKnownLocation"},
            {"Landroid/location/LocationManager;", "requestLocationUpdates"},
            {"Landroid/location/LocationManager;", "requestSingleUpdate"},
            {"Landroid/location/Location;", "getLatitude"},
            {"Landroid/location/Location;", "getLongitude"},
            {"Landroid/telephony/TelephonyManager;", "getDeviceId"},
            {"Landroid/telephony/TelephonyManager;", "getImei"},
            {"Landroid/telephony/TelephonyManager;", "getMeid"},
            {"Landroid/telephony/TelephonyManager;", "getSubscriberId"},
            {"Landroid/telephony/TelephonyManager;", "getLine1Number"},
            {"Landroid/telephony/TelephonyManager;", "getSimSerialNumber"},
            {"Landroid/content/ContentResolver;", "query"},
            {"Landroid/content/ClipboardManager;", "getPrimaryClip"},
            {"Landroid/content/ClipboardManager;", "getText"},
            {"Landroid/accounts/AccountManager;", "getAccounts"},
            {"Landroid/accounts/AccountManager;", "getAccountsByType"},
            {"Landroid/provider/Settings$Secure;", "getString"},
            {"Landroid/net/wifi/WifiInfo;", "getMacAddress"},
            {"Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;", "getAdvertisingIdInfo"},
    };

    /** Sumideros: {prefijo de clase, método exacto}. */
    private static final String[][] SINKS = {
            {"Ljava/net/URL;", "openConnection"},
            {"Ljava/net/URL;", "openStream"},
            {"Ljava/net/HttpURLConnection;", "connect"},
            {"Ljava/net/HttpURLConnection;", "getOutputStream"},
            {"Lokhttp3/OkHttpClient;", "newCall"},
            {"Lokhttp3/Request$Builder;", "build"},
            {"Lorg/apache/http/client/HttpClient;", "execute"},
            {"Ljava/net/Socket;", "connect"},
            {"Ljava/net/Socket;", "getOutputStream"},
            {"Landroid/telephony/SmsManager;", "sendTextMessage"},
            {"Landroid/telephony/SmsManager;", "sendMultipartTextMessage"},
            {"Ljava/lang/Runtime;", "exec"},
            {"Ljava/lang/ProcessBuilder;", "start"},
            {"Ljava/lang/ProcessBuilder;", "command"},
            {"Landroid/webkit/WebView;", "loadUrl"},
            {"Landroid/webkit/WebView;", "evaluateJavascript"},
            {"Landroid/webkit/WebView;", "postUrl"},
            {"Landroid/util/Log;", "d"},
            {"Landroid/util/Log;", "i"},
            {"Landroid/util/Log;", "v"},
            {"Landroid/util/Log;", "w"},
            {"Landroid/util/Log;", "e"},
            {"Landroid/util/Log;", "wtf"},
            {"Landroid/util/Log;", "println"},
            {"Ljava/io/FileOutputStream;", "write"},
            {"Landroid/content/SharedPreferences$Editor;", "putString"},
            {"Landroid/content/ContentResolver;", "insert"},
    };

    /** Flujo origen → sumidero con evidencia. Nunca lanza. */
    public static class Flow {
        public String source = "?";
        public String sink = "?";
        public String method = "?";
        public List<String> chain = new ArrayList<>();
        public String evidence = "";
        public boolean inter;
    }

    /** Resultado del análisis. Nunca lanza. */
    public static class TaintResult {
        public List<Flow> flows = new ArrayList<>();
        public int methods;
        public boolean truncated;
    }

    /** true si (cls, método) es origen (con herencia por supers). Nunca lanza. */
    public static boolean isSource(String cls, String method, Map<String, String> supers) {
        return match(SOURCES, cls, method, supers);
    }

    /** true si (cls, método) es sumidero (con herencia por supers). Nunca lanza. */
    public static boolean isSink(String cls, String method, Map<String, String> supers) {
        return match(SINKS, cls, method, supers);
    }

    /** Matcher para InterProc con supers fijos. Nunca null ni lanza. */
    public static InterProc.SinkMatcher matcherFor(final Map<String, String> supers) {
        return new InterProc.SinkMatcher() {
            @Override
            public boolean isSink(String cls, String method) {
                return Taint.isSink(cls, method, supers);
            }
        };
    }

    private static boolean match(String[][] table, String cls, String method,
            Map<String, String> supers) {
        try {
            if (cls == null || method == null) return false;
            if (hit(table, cls, method)) return true;
            if (supers == null) return false;
            String c = cls;
            Set<String> seen = new LinkedHashSet<>();
            seen.add(c);
            for (int i = 0; i < 8; i++) {
                String sup = supers.get(c);
                if (sup == null || sup.isEmpty() || "?".equals(sup) || !seen.add(sup)) return false;
                if (hit(table, sup, method)) return true;
                c = sup;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static boolean hit(String[][] table, String cls, String method) {
        for (String[] e : table) {
            if (cls.startsWith(e[0]) && method.equals(e[1])) return true;
        }
        return false;
    }

    /**
     * Analiza métodos (tope MAX_METHODS). Nunca null ni lanza.
     */
    public static TaintResult analyze(Map<String, IrBuilder.MethodIr> irs,
            RefGraph graph, Map<String, String> supers) {
        TaintResult r = new TaintResult();
        try {
            if (irs == null || irs.isEmpty()) return r;
            Map<String, IrBuilder.MethodIr> capped = new LinkedHashMap<>();
            for (Map.Entry<String, IrBuilder.MethodIr> en : irs.entrySet()) {
                if (capped.size() >= MAX_METHODS) {
                    r.truncated = true;
                    break;
                }
                if (en.getKey() == null || en.getValue() == null) continue;
                capped.put(en.getKey(), en.getValue());
            }
            Map<String, Map<Integer, String>> tainted = new LinkedHashMap<>();
            Map<String, DefUse.Chains> chainsMap = new LinkedHashMap<>();
            for (Map.Entry<String, IrBuilder.MethodIr> en : capped.entrySet()) {
                DefUse.Chains chains = DefUse.analyze(en.getValue());
                chainsMap.put(en.getKey(), chains);
                Map<Integer, String> seeds = seedSources(en.getKey(), en.getValue(),
                        chains, graph, supers);
                Map<Integer, String> t = propagateWithSrc(chains, seeds);
                tainted.put(en.getKey(), t);
                r.methods++;
                checkSinks(en.getKey(), en.getValue(), t, graph, supers, r, false);
                if (r.flows.size() >= MAX_FLOWS) {
                    r.truncated = true;
                    return r;
                }
            }
            interPass(capped, chainsMap, tainted, graph, supers, r);
        } catch (Throwable ignored) {
        }
        return r;
    }

    /** Semillas: regs que recogen (move-result) el retorno de un origen. */
    private static Map<Integer, String> seedSources(String method, IrBuilder.MethodIr ir,
            DefUse.Chains chains, RefGraph graph, Map<String, String> supers) {
        Map<Integer, String> seeds = new LinkedHashMap<>();
        try {
            if (chains == null) return seeds;
            for (DefUse.DefSite d : chains.defs) {
                if (d == null || d.resultOf < 0) continue;
                for (String callee : InterProc.calleesAt(graph, method, d.resultOf)) {
                    String[] parts = RefGraph.split(callee);
                    if (isSource(parts[0], parts[1], supers)) {
                        seeds.put(d.reg, callee + "@+" + d.resultOf);
                        break;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return seeds;
    }

    /** Propaga taint con procedencia (reg → descripción del origen). */
    private static Map<Integer, String> propagateWithSrc(DefUse.Chains chains,
            Map<Integer, String> seeds) {
        Map<Integer, String> t = new LinkedHashMap<>();
        try {
            if (chains == null || seeds == null) return t;
            t.putAll(seeds);
            for (int pass = 0; pass < 32; pass++) {
                boolean changed = false;
                for (DefUse.DefSite d : chains.defs) {
                    if (d == null || t.containsKey(d.reg)) continue;
                    for (int s : d.srcRegs) {
                        String src = t.get(s);
                        if (src != null) {
                            t.put(d.reg, src);
                            changed = true;
                            break;
                        }
                    }
                }
                if (!changed) break;
            }
        } catch (Throwable ignored) {
        }
        return t;
    }

    private static void checkSinks(String method, IrBuilder.MethodIr ir,
            Map<Integer, String> tainted, RefGraph graph, Map<String, String> supers,
            TaintResult r, boolean inter) {
        try {
            if (tainted.isEmpty()) return;
            for (IrBuilder.Block b : ir.blocks) {
                if (b == null) continue;
                for (IrBuilder.Insn in : b.insns) {
                    if (in == null || !DefUse.isInvoke(in.op)) continue;
                    int[] regs = in.regs == null ? new int[0] : in.regs;
                    String src = null;
                    for (int a : regs) {
                        src = tainted.get(a);
                        if (src != null) break;
                    }
                    if (src == null) continue;
                    for (String callee : InterProc.calleesAt(graph, method, in.addr)) {
                        String[] parts = RefGraph.split(callee);
                        if (isSink(parts[0], parts[1], supers)) {
                            addFlow(r, src, callee + "@+" + in.addr, method, inter);
                            if (r.flows.size() >= MAX_FLOWS) return;
                            break;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Pasada inter de un salto: si el llamador pasa un arg marcado a un
     * callee con sinks desde entrada, flujo encadenado; si el callee puede
     * devolver su entrada, su resultado se marca en el llamador y se
     * re-inspeccionan los sinks del llamador. Nunca lanza.
     */
    private static void interPass(Map<String, IrBuilder.MethodIr> capped,
            Map<String, DefUse.Chains> chainsMap, Map<String, Map<Integer, String>> tainted,
            RefGraph graph, Map<String, String> supers, TaintResult r) {
        try {
            if (graph == null) return;
            Map<String, InterProc.Summary> sums =
                    InterProc.summarize(capped, graph, matcherFor(supers));
            Set<String> recheck = new LinkedHashSet<>();
            for (RefGraph.RefEdge e : graph.edges()) {
                if (r.flows.size() >= MAX_FLOWS) {
                    r.truncated = true;
                    return;
                }
                if (e == null || e.caller == null || e.callee == null) continue;
                IrBuilder.MethodIr callerIr = capped.get(e.caller);
                InterProc.Summary calleeSum = sums.get(e.callee);
                if (callerIr == null || calleeSum == null) continue;
                Map<Integer, String> callerT = tainted.get(e.caller);
                if (callerT == null || callerT.isEmpty()) continue;
                int[] args = invokeArgsAt(callerIr, e.pos);
                if (args == null) continue;
                String src = null;
                for (int a : args) {
                    src = callerT.get(a);
                    if (src != null) break;
                }
                if (src == null) continue;
                for (InterProc.SinkHit h : calleeSum.sinksFromEntry) {
                    if (h == null) continue;
                    Flow f = new Flow();
                    f.source = src;
                    f.sink = h.sink + "@+" + h.addr;
                    f.method = e.caller;
                    f.chain.add(e.caller);
                    f.chain.add(e.callee);
                    f.evidence = "arg marcado en " + e.caller + "@+" + e.pos
                            + " ~> " + h.sink + " en " + e.callee + "@+" + h.addr;
                    f.inter = true;
                    addFlowObj(r, f);
                }
                if (calleeSum.retMayCarryEntry) {
                    DefUse.Chains chains = chainsMap.get(e.caller);
                    if (chains == null) continue;
                    boolean added = false;
                    for (DefUse.DefSite d : chains.defs) {
                        if (d != null && d.resultOf == e.pos && !callerT.containsKey(d.reg)) {
                            callerT.put(d.reg, src + " ~> " + e.callee);
                            added = true;
                        }
                    }
                    if (added) {
                        Map<Integer, String> grown = propagateWithSrc(chains, callerT);
                        callerT.clear();
                        callerT.putAll(grown);
                        recheck.add(e.caller);
                    }
                }
            }
            for (String m : recheck) {
                IrBuilder.MethodIr ir = capped.get(m);
                Map<Integer, String> t = tainted.get(m);
                if (ir == null || t == null) continue;
                int before = r.flows.size();
                checkSinks(m, ir, t, graph, supers, r, true);
                if (r.flows.size() >= MAX_FLOWS) {
                    r.truncated = true;
                    return;
                }
                if (r.flows.size() == before) {
                    // sin flujos nuevos: nada que marcar
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static int[] invokeArgsAt(IrBuilder.MethodIr ir, int pos) {
        try {
            for (IrBuilder.Block b : ir.blocks) {
                if (b == null) continue;
                for (IrBuilder.Insn in : b.insns) {
                    if (in != null && in.addr == pos && DefUse.isInvoke(in.op)) {
                        return in.regs == null ? new int[0] : in.regs;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static void addFlow(TaintResult r, String src, String sink, String method,
            boolean inter) {
        Flow f = new Flow();
        f.source = src;
        f.sink = sink;
        f.method = method;
        f.chain.add(method);
        f.evidence = src + " ~> " + sink + " en " + method;
        f.inter = inter;
        addFlowObj(r, f);
    }

    private static void addFlowObj(TaintResult r, Flow f) {
        try {
            if (r.flows.size() >= MAX_FLOWS) {
                r.truncated = true;
                return;
            }
            String key = f.source + "\u0000" + f.sink + "\u0000" + f.method;
            for (Flow e : r.flows) {
                if (e != null && key.equals(e.source + "\u0000" + e.sink + "\u0000" + e.method)) {
                    return;
                }
            }
            r.flows.add(f);
        } catch (Throwable ignored) {
        }
    }
}
