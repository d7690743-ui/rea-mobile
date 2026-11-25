package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OMEGA Fase E5: análisis interprocedural. Resume cada método (qué registros
 * de entrada lee, si el retorno puede llevar valor de entrada, a quién
 * llama y con qué argumentos constantes) y resuelve cada sitio de llamada
 * contra el RefGraph. El taint interprocedural consume estos resúmenes.
 * Utilidad estática sin estado. Java puro. Nunca lanza.
 *
 * <p>Límites: sin firmas de método (nº de parámetros desconocido), la
 * "entrada" se aproxima como registros leídos antes de definirse; resolución
 * de callee por (llamador, posición) contra aristas reales del grafo.</p>
 */
public final class InterProc {
    private InterProc() {
    }

    public static final int MAX_METHODS = 300;
    public static final int MAX_CALLS_PER_METHOD = 200;

    /** Clasificador de sumideros (lo implementa Taint). Nunca lanza. */
    public interface SinkMatcher {
        boolean isSink(String cls, String method);
    }

    /** Llamada con sus argumentos y constantes conocidas. Nunca lanza. */
    public static class Call {
        public String callee = "?";
        public int addr = -1;
        public List<Integer> args = new ArrayList<>();
        public Map<Integer, ReachConsts.Const> constArgs = new LinkedHashMap<>();
    }

    /** Sumidero alcanzable desde la entrada del método. Nunca lanza. */
    public static class SinkHit {
        public String sink = "?";
        public int addr = -1;
    }

    /** Resumen de un método. Nunca lanza. */
    public static class Summary {
        public String method = "?";
        /** Registros leídos antes de definirse (posibles parámetros). */
        public Set<Integer> entryRegs = new LinkedHashSet<>();
        /** true si un return puede devolver valor de entrada. */
        public boolean retMayCarryEntry;
        public List<Call> calls = new ArrayList<>();
        public List<SinkHit> sinksFromEntry = new ArrayList<>();
        public boolean truncated;
    }

    /**
     * Callees conocidos en un sitio de llamada (llamador + posición en
     * units, la misma que Insn.addr). Vacío si grafo nulo o sin arista.
     * Nunca null ni lanza.
     */
    public static List<String> calleesAt(RefGraph graph, String caller, int pos) {
        List<String> out = new ArrayList<>();
        try {
            if (graph == null || caller == null) return out;
            for (RefGraph.RefEdge e : graph.edgesFromKey(caller)) {
                if (e != null && e.pos == pos && e.callee != null && !"?".equals(e.callee)) {
                    if (!out.contains(e.callee)) out.add(e.callee);
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /**
     * Resume métodos (tope MAX_METHODS, orden del mapa). matcher null =
     * sin sinksFromEntry. Nunca null ni lanza.
     */
    public static Map<String, Summary> summarize(Map<String, IrBuilder.MethodIr> irs,
            RefGraph graph, SinkMatcher matcher) {
        Map<String, Summary> out = new LinkedHashMap<>();
        try {
            if (irs == null) return out;
            for (Map.Entry<String, IrBuilder.MethodIr> en : irs.entrySet()) {
                if (out.size() >= MAX_METHODS) break;
                if (en.getKey() == null || en.getValue() == null) continue;
                out.put(en.getKey(), summarizeOne(en.getKey(), en.getValue(), graph, matcher));
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static Summary summarizeOne(String method, IrBuilder.MethodIr ir,
            RefGraph graph, SinkMatcher matcher) {
        Summary s = new Summary();
        s.method = method;
        try {
            if (ir.error != null || ir.blocks.isEmpty() || ir.regs <= 0) return s;
            ReachConsts.ConstResult consts = ReachConsts.analyze(ir);
            DefUse.Chains chains = DefUse.analyze(ir);
            collectEntries(ir, consts, s);
            collectCalls(ir, consts, graph, s);
            if (matcher != null) collectSinkHits(ir, chains, graph, matcher, s);
        } catch (Throwable ignored) {
        }
        return s;
    }

    private static void collectEntries(IrBuilder.MethodIr ir, ReachConsts.ConstResult consts,
            Summary s) {
        for (int i = 0; i < ir.blocks.size(); i++) {
            IrBuilder.Block b = ir.blocks.get(i);
            if (b == null) continue;
            Map<Integer, Set<Integer>> enR = i < consts.reaching.size()
                    ? consts.reaching.get(i) : null;
            Set<Integer> definedHere = new LinkedHashSet<>();
            for (IrBuilder.Insn in : b.insns) {
                if (in == null) continue;
                int[] regs = in.regs == null ? new int[0] : in.regs;
                for (int u : DefUse.useRegs(in.op, regs)) {
                    if (u < 0 || u >= ir.regs || definedHere.contains(u)) continue;
                    Set<Integer> reach = enR == null ? null : enR.get(u);
                    if (reach == null || reach.isEmpty() || reach.contains(DefUse.ENTRY)) {
                        s.entryRegs.add(u);
                        if (in.isReturn) s.retMayCarryEntry = true;
                    }
                }
                int def = DefUse.defReg(in.op, regs);
                if (def >= 0 && def < ir.regs) definedHere.add(def);
            }
        }
    }

    private static void collectCalls(IrBuilder.MethodIr ir, ReachConsts.ConstResult consts,
            RefGraph graph, Summary s) {
        Map<Integer, List<ReachConsts.CallConst>> byAddr = new LinkedHashMap<>();
        for (ReachConsts.CallConst cc : consts.callConsts) {
            if (cc == null) continue;
            List<ReachConsts.CallConst> l = byAddr.get(cc.addr);
            if (l == null) {
                l = new ArrayList<>();
                byAddr.put(cc.addr, l);
            }
            l.add(cc);
        }
        for (IrBuilder.Block b : ir.blocks) {
            if (b == null) continue;
            for (IrBuilder.Insn in : b.insns) {
                if (in == null || !DefUse.isInvoke(in.op)) continue;
                if (s.calls.size() >= MAX_CALLS_PER_METHOD) {
                    s.truncated = true;
                    return;
                }
                Call c = new Call();
                c.addr = in.addr;
                int[] regs = in.regs == null ? new int[0] : in.regs;
                for (int a : regs) c.args.add(a);
                List<String> cal = calleesAt(graph, s.method, in.addr);
                if (!cal.isEmpty()) c.callee = cal.get(0);
                List<ReachConsts.CallConst> k = byAddr.get(in.addr);
                if (k != null) {
                    for (ReachConsts.CallConst cc : k) {
                        ReachConsts.Const v = new ReachConsts.Const();
                        v.kind = cc.kind;
                        v.lit = cc.lit;
                        v.strRef = cc.strRef;
                        c.constArgs.put(cc.reg, v);
                    }
                }
                s.calls.add(c);
            }
        }
    }

    private static void collectSinkHits(IrBuilder.MethodIr ir, DefUse.Chains chains,
            RefGraph graph, SinkMatcher matcher, Summary s) {
        if (s.entryRegs.isEmpty()) return;
        Set<Integer> tainted = DefUse.propagate(chains, s.entryRegs);
        for (Call c : s.calls) {
            boolean hit = false;
            for (int a : c.args) {
                if (tainted.contains(a)) {
                    hit = true;
                    break;
                }
            }
            if (!hit || "?".equals(c.callee)) continue;
            String[] parts = RefGraph.split(c.callee);
            boolean sink = false;
            try {
                sink = matcher.isSink(parts[0], parts[1]);
            } catch (Throwable ignored) {
            }
            if (sink) {
                SinkHit h = new SinkHit();
                h.sink = c.callee;
                h.addr = c.addr;
                s.sinksFromEntry.add(h);
            }
        }
    }
}
