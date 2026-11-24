package com.nexos.reamobile.engine;

import com.nexos.reamobile.intelligence.IntelFinding;

import java.util.ArrayList;
import java.util.List;

/**
 * Motor PHANTOM: paquete de conocimiento reconstructivo. Trabaja EN CONJUNTO
 * con OMEGA (grafo, strings, flujo, taint, roles, plan) y ALFA (ELF/JNI, UI,
 * Blueprint) consumiendo sus salidas del ApkReport, sin re-parsear el APK.
 *
 * <p>Submódulos: Group (FN-##), Metric (completitud), Net (contratos),
 * Ui (pantallas), Store (almacenamiento), Data (modelos), Jni (dinámico),
 * Taint (multi-salto+reflexión), Decompile (prioridad JADX). El paquete
 * JSON sale del teléfono vía extractToZip (rea/paquete.json) y FullReport.
 *
 * <p>Perezoso con caché en ApkReport (estilo summarizeFlow): coste una sola
 * vez por informe. Nunca lanza.
 */
public final class Phantom {
    private Phantom() {
    }

    /** Resultado completo PHANTOM para un informe. Nunca lanza. */
    public static class PhantomResult {
        public List<PhantomNet.Contract> contracts = new ArrayList<>();
        public PhantomUi.UiResult ui = new PhantomUi.UiResult();
        public PhantomStore.StoreResult store = new PhantomStore.StoreResult();
        public PhantomData.DataResult data = new PhantomData.DataResult();
        public List<PhantomJni.DynLink> dynJni = new ArrayList<>();
        public List<PhantomGroup.FuncGroup> groups = new ArrayList<>();
        public PhantomTaint.TaintXResult taintX = new PhantomTaint.TaintXResult();
        public boolean truncated;
    }

    /**
     * Ejecuta PHANTOM sobre un informe ya analizado. Nunca null ni lanza.
     */
    public static PhantomResult summarize(ReaEngine.ApkReport r) {
        PhantomResult p = new PhantomResult();
        try {
            if (r == null) return p;
            List<AlfaJni.JniLink> jniLinks = ReaEngine.summarizeAlfaJni(r);
            p.contracts = PhantomNet.contracts(r.urls, r.urlOrigin, r.stringRefs,
                    r.graph, r.manifestPerms, r.callerPerm);
            p.ui = PhantomUi.resolve(r.graph, r.manifestClasses, r.alfaScreens, r.flowIrs);
            p.store = PhantomStore.analyze(r.superMap, r.stringRefs, r.graph);
            p.data = PhantomData.analyze(r.graph, r.stringRefs, r.appClasses);
            p.dynJni = PhantomJni.link(r.alfaElfs, r.graph);
            List<PhantomUi.ContentView> cvs = p.ui == null ? null : p.ui.contentViews;
            p.groups = PhantomGroup.group(r.graph, r.manifestClasses, r.urls,
                    r.stringRefs, r.callerPerm, cvs);
            List<PhantomData.DataHit> dh = p.data == null ? null : p.data.hits;
            List<PhantomStore.StoreHit> sh = p.store == null ? null : p.store.hits;
            PhantomMetric.completeStates(p.groups, dh, sh, jniLinks, p.dynJni);
            List<Taint.Flow> base = null;
            try {
                ReaEngine.FlowSummary fs = r.flow();
                base = fs == null ? null : fs.flows;
            } catch (Throwable ignored) {
                base = null;
            }
            p.taintX = PhantomTaint.extend(r.flowIrs, r.graph, r.superMap,
                    r.flowDex, r.flowStrings, base);
            p.truncated = (p.ui != null && p.ui.truncated)
                    || (p.store != null && p.store.truncated)
                    || (p.data != null && p.data.truncated)
                    || (p.taintX != null && p.taintX.truncated);
        } catch (Throwable ignored) {
        }
        return p;
    }

    /**
     * Hallazgos PHANTOM al registro (funciones, contratos, pantallas, JNI
     * dinámico, multisalto). Topes 10+5+5+5+5. Nunca lanza.
     */
    static void feedIntel(ReaEngine.ApkReport r, PhantomResult p) {
        try {
            if (r == null || r.intel == null || p == null) return;
            int n = 0;
            if (p.groups != null) {
                for (PhantomGroup.FuncGroup g : p.groups) {
                    if (g == null || n >= 10) break;
                    if (PhantomMetric.score(g) < 4) continue;
                    IntelFinding inf = IntelFinding.create("funcion",
                            g.id + " " + g.name + " [" + PhantomMetric.score(g) + "/8]");
                    inf.evidence = g.entries.isEmpty() ? "sin entrada"
                            : g.entries.get(0) + " +" + g.methodTotal + " métodos";
                    inf.confidence = IntelFinding.Confidence.MEDIUM;
                    inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                    inf.limitations = "agrupación estática best-effort;"
                            + " ejecución no observada";
                    if (r.intel.add(inf)) n++;
                }
            }
            int c = 0;
            if (p.contracts != null) {
                for (PhantomNet.Contract ct : p.contracts) {
                    if (ct == null || c >= 5) break;
                    if (ct.users.isEmpty()) continue;
                    IntelFinding inf = IntelFinding.create("contrato",
                            "red " + ct.host + " verbo="
                                    + (ct.verbs.isEmpty() ? "?" : ct.verbs.get(0)));
                    inf.evidence = PhantomNet.summarize(ct);
                    inf.confidence = IntelFinding.Confidence.MEDIUM;
                    inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                    inf.limitations = "verbo/payload observados como literales;"
                            + " ejecución no observada";
                    if (r.intel.add(inf)) c++;
                }
            }
            int u = 0;
            if (p.ui != null && p.ui.contentViews != null) {
                for (PhantomUi.ContentView cv : p.ui.contentViews) {
                    if (cv == null || u >= 5) break;
                    IntelFinding inf = IntelFinding.create("pantalla",
                            cv.className + " setContentView("
                                    + (cv.layoutId.isEmpty() ? "?" : cv.layoutId) + ")");
                    inf.className = cv.className;
                    inf.evidence = "llamador en grafo" + (cv.inManifest ? " + manifest" : "");
                    inf.confidence = IntelFinding.Confidence.MEDIUM;
                    inf.evidenceType = IntelFinding.EvidenceType.STATIC;
                    inf.limitations = "id sin traducir a nombre (sin mapa ARSC);"
                            + " ejecución no observada";
                    if (r.intel.add(inf)) u++;
                }
            }
            int j = 0;
            if (p.dynJni != null) {
                for (PhantomJni.DynLink l : p.dynJni) {
                    if (l == null || j >= 5) break;
                    IntelFinding inf = IntelFinding.create("jni-dinamico",
                            l.method + " en " + l.lib);
                    inf.evidence = PhantomJni.summarize(l);
                    inf.confidence = IntelFinding.Confidence.LOW;
                    inf.evidenceType = IntelFinding.EvidenceType.INFERRED;
                    inf.limitations = "par nombre+firma best-effort;"
                            + " registro no verificado en ejecución";
                    if (r.intel.add(inf)) j++;
                }
            }
            int t = 0;
            if (p.taintX != null && p.taintX.extraFlows != null) {
                for (PhantomTaint.XFlow x : p.taintX.extraFlows) {
                    if (x == null || t >= 5) break;
                    IntelFinding inf = IntelFinding.create("multisalto",
                            x.source + " →…→ " + x.sink);
                    inf.evidence = x.chain.size() + " saltos: " + x.evidence;
                    inf.confidence = IntelFinding.Confidence.LOW;
                    inf.evidenceType = IntelFinding.EvidenceType.INFERRED;
                    inf.limitations = "encadenado por grafo, no por flujo de datos;"
                            + " ejecución no observada";
                    if (r.intel.add(inf)) t++;
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /** Líneas de la sección PHANTOM del informe. Nunca lanza. */
    public static List<String> summarizeText(PhantomResult p) {
        List<String> out = new ArrayList<>();
        try {
            if (p == null) return out;
            out.add("-- funciones (" + p.groups.size() + ") --");
            out.addAll(PhantomGroup.summarize(p.groups));
            out.add("-- completitud --");
            out.addAll(PhantomMetric.summarize(p.groups));
            out.add("-- contratos red (" + p.contracts.size() + ") --");
            for (PhantomNet.Contract ct : p.contracts) {
                out.add(PhantomNet.summarize(ct));
            }
            out.add("-- pantallas (" + p.ui.contentViews.size() + ") --");
            out.addAll(PhantomUi.summarize(p.ui));
            out.add("-- almacenamiento (" + p.store.hits.size() + ") --");
            out.addAll(PhantomStore.summarize(p.store));
            out.add("-- datos (" + p.data.hits.size() + ") --");
            out.addAll(PhantomData.summarize(p.data));
            out.add("-- jni dinámico (" + p.dynJni.size() + ") --");
            for (PhantomJni.DynLink l : p.dynJni) {
                out.add(PhantomJni.summarize(l));
            }
            out.add("-- flujo-X --");
            out.addAll(PhantomTaint.summarize(p.taintX));
            if (p.truncated) out.add("(phantom recortado por topes)");
        } catch (Throwable ignored) {
        }
        return out;
    }
}
