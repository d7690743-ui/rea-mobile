package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OMEGA Fase E2: reaching definitions + propagación de constantes sobre la
 * CFG de IrBuilder. Responde qué definiciones alcanzan cada punto y qué
 * registros llevan un valor constante conocido (literales y const-string)
 * en cada sitio de llamada. Base de Ssa, InterProc y Taint.
 * Utilidad estática sin estado. Java puro. Nunca lanza.
 *
 * <p>Modelo: lattice UNDEF/CONST/NAC por registro con meet en joins;
 * reaching con gen/kill y unión acotada. Solo se pliegan operaciones
 * enteras con operandos constantes; heap, floats no triviales y wide
 * pares se marcan NAC (no se inventan valores).</p>
 */
public final class ReachConsts {
    private ReachConsts() {
    }

    public static final int MAX_REACH_PER_REG = 8;
    public static final int MAX_CALLCONSTS = 500;

    /** Estado de constante de un registro. Nunca lanza. */
    public enum Kind {
        NONE, LIT, STR, NAC
    }

    /** Constante conocida (LIT: lit; STR: strRef). Nunca lanza. */
    public static class Const {
        public Kind kind = Kind.NONE;
        public long lit;
        public int strRef = -1;

        static Const none() {
            return new Const();
        }

        static Const lit(long v) {
            Const c = new Const();
            c.kind = Kind.LIT;
            c.lit = v;
            return c;
        }

        static Const str(int refIdx) {
            Const c = new Const();
            c.kind = Kind.STR;
            c.strRef = refIdx;
            return c;
        }

        static Const nac() {
            Const c = new Const();
            c.kind = Kind.NAC;
            return c;
        }

        /** Meet del lattice. Nunca null ni lanza. */
        static Const meet(Const a, Const b) {
            try {
                if (a == null || a.kind == Kind.NONE) return copy(b);
                if (b == null || b.kind == Kind.NONE) return copy(a);
                if (a.kind == Kind.NAC || b.kind == Kind.NAC) return nac();
                if (a.kind == Kind.LIT && b.kind == Kind.LIT && a.lit == b.lit) {
                    return lit(a.lit);
                }
                if (a.kind == Kind.STR && b.kind == Kind.STR && a.strRef == b.strRef) {
                    return str(a.strRef);
                }
                return nac();
            } catch (Throwable ignored) {
                return nac();
            }
        }

        static Const copy(Const c) {
            Const o = new Const();
            if (c == null) return o;
            o.kind = c.kind == null ? Kind.NONE : c.kind;
            o.lit = c.lit;
            o.strRef = c.strRef;
            return o;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Const)) return false;
            Const c = (Const) o;
            return kind == c.kind && lit == c.lit && strRef == c.strRef;
        }
    }

    /** Argumento constante en un sitio de llamada. Nunca lanza. */
    public static class CallConst {
        public int addr = -1;
        public int block = -1;
        public int reg = -1;
        public Kind kind = Kind.NONE;
        public long lit;
        public int strRef = -1;
    }

    /** Resultado del análisis de un método. Nunca lanza. */
    public static class ConstResult {
        /** Constantes a la entrada de cada bloque (índice = id). */
        public List<Const[]> entry = new ArrayList<>();
        /**
         * Reaching a la entrada de cada bloque: reg → addrs de def.
         * Ausente o vacío = solo llega la entrada; si algún camino del
         * join no define el registro se añade DefUse.ENTRY (-1).
         */
        public List<Map<Integer, Set<Integer>>> reaching = new ArrayList<>();
        public List<CallConst> callConsts = new ArrayList<>();
        public boolean truncated;
    }

    /**
     * Analiza un método. IR nula, con error o sin bloques → vacío.
     * Nunca null ni lanza.
     */
    public static ConstResult analyze(IrBuilder.MethodIr ir) {
        ConstResult r = new ConstResult();
        try {
            if (ir == null || ir.error != null || ir.blocks.isEmpty() || ir.regs <= 0) return r;
            int nregs = ir.regs;
            int nb = ir.blocks.size();
            List<List<Integer>> preds = new ArrayList<>(nb);
            for (int i = 0; i < nb; i++) preds.add(new ArrayList<Integer>());
            for (IrBuilder.Block b : ir.blocks) {
                if (b == null) continue;
                for (int s : b.succs) {
                    if (s < 0 || s >= nb) continue;
                    if (!preds.get(s).contains(b.id)) preds.get(s).add(b.id);
                }
            }
            for (int i = 0; i < nb; i++) {
                r.entry.add(newState(nregs));
                r.reaching.add(new LinkedHashMap<Integer, Set<Integer>>());
            }
            List<Const[]> exit = new ArrayList<>(nb);
            List<Map<Integer, Set<Integer>>> exitR = new ArrayList<>(nb);
            for (int i = 0; i < nb; i++) {
                exit.add(newState(nregs));
                exitR.add(new LinkedHashMap<Integer, Set<Integer>>());
            }
            int maxPasses = Math.min(32, 4 + nb * 2);
            for (int pass = 0; pass < maxPasses; pass++) {
                boolean changed = false;
                for (int i = 0; i < nb; i++) {
                    IrBuilder.Block b = ir.blocks.get(i);
                    if (b == null) continue;
                    Const[] en = mergeConsts(preds.get(i), exit, nregs);
                    Map<Integer, Set<Integer>> enR = mergeReach(preds.get(i), exitR, r);
                    r.entry.set(i, en);
                    r.reaching.set(i, enR);
                    Const[] st = copyState(en);
                    Map<Integer, Set<Integer>> reach = copyReach(enR);
                    simulate(b, st, reach, r, i, null);
                    if (!statesEqual(exit.get(i), st) || !reachEqual(exitR.get(i), reach)) {
                        exit.set(i, st);
                        exitR.set(i, reach);
                        changed = true;
                    }
                }
                if (!changed) break;
            }
            for (int i = 0; i < nb; i++) {
                IrBuilder.Block b = ir.blocks.get(i);
                if (b == null) continue;
                Const[] st = copyState(r.entry.get(i));
                Map<Integer, Set<Integer>> reach = copyReach(r.reaching.get(i));
                List<CallConst> found = new ArrayList<>();
                simulate(b, st, reach, r, i, found);
                for (CallConst cc : found) {
                    if (r.callConsts.size() < MAX_CALLCONSTS) r.callConsts.add(cc);
                    else r.truncated = true;
                }
            }
        } catch (Throwable ignored) {
        }
        return r;
    }

    private static Const[] newState(int nregs) {
        Const[] s = new Const[nregs];
        for (int i = 0; i < nregs; i++) s[i] = Const.none();
        return s;
    }

    private static Const[] copyState(Const[] s) {
        Const[] o = new Const[s.length];
        for (int i = 0; i < s.length; i++) o[i] = Const.copy(s[i]);
        return o;
    }

    private static Map<Integer, Set<Integer>> copyReach(Map<Integer, Set<Integer>> m) {
        Map<Integer, Set<Integer>> o = new LinkedHashMap<>();
        for (Map.Entry<Integer, Set<Integer>> e : m.entrySet()) {
            o.put(e.getKey(), new LinkedHashSet<>(e.getValue()));
        }
        return o;
    }

    private static boolean statesEqual(Const[] a, Const[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
            if (!a[i].equals(b[i])) return false;
        }
        return true;
    }

    private static boolean reachEqual(Map<Integer, Set<Integer>> a, Map<Integer, Set<Integer>> b) {
        if (a == null || b == null || a.size() != b.size()) return false;
        for (Map.Entry<Integer, Set<Integer>> e : a.entrySet()) {
            Set<Integer> o = b.get(e.getKey());
            if (o == null || !o.equals(e.getValue())) return false;
        }
        return true;
    }

    private static Const[] mergeConsts(List<Integer> preds, List<Const[]> exit, int nregs) {
        Const[] en = newState(nregs);
        boolean first = true;
        for (int p : preds) {
            if (p < 0 || p >= exit.size()) continue;
            Const[] pe = exit.get(p);
            if (pe == null || pe.length != nregs) continue;
            if (first) {
                en = copyState(pe);
                first = false;
            } else {
                for (int i = 0; i < nregs; i++) en[i] = Const.meet(en[i], pe[i]);
            }
        }
        return en;
    }

    private static Map<Integer, Set<Integer>> mergeReach(List<Integer> preds,
            List<Map<Integer, Set<Integer>>> exitR, ConstResult r) {
        Map<Integer, Set<Integer>> en = new LinkedHashMap<>();
        List<Integer> valid = new ArrayList<>();
        for (int p : preds) {
            if (p < 0 || p >= exitR.size()) continue;
            if (exitR.get(p) == null) continue;
            valid.add(p);
        }
        Map<Integer, Integer> contributors = new LinkedHashMap<>();
        for (int p : valid) {
            Map<Integer, Set<Integer>> pe = exitR.get(p);
            for (Map.Entry<Integer, Set<Integer>> e : pe.entrySet()) {
                if (e.getValue() == null || e.getValue().isEmpty()) continue;
                Set<Integer> s = en.get(e.getKey());
                if (s == null) {
                    s = new LinkedHashSet<>();
                    en.put(e.getKey(), s);
                }
                for (int a : e.getValue()) {
                    if (s.size() < MAX_REACH_PER_REG) s.add(a);
                    else r.truncated = true;
                }
                contributors.put(e.getKey(),
                        contributors.containsKey(e.getKey()) ? contributors.get(e.getKey()) + 1 : 1);
            }
        }
        for (Map.Entry<Integer, Set<Integer>> e : en.entrySet()) {
            int c = contributors.containsKey(e.getKey()) ? contributors.get(e.getKey()) : 0;
            if (c < valid.size() && e.getValue().size() < MAX_REACH_PER_REG) {
                e.getValue().add(DefUse.ENTRY);
            }
        }
        return en;
    }

    private static void simulate(IrBuilder.Block b, Const[] st,
            Map<Integer, Set<Integer>> reach, ConstResult r, int blockId,
            List<CallConst> found) {
        for (IrBuilder.Insn in : b.insns) {
            if (in == null) continue;
            int op = in.op & 0xFF;
            int[] regs = in.regs == null ? new int[0] : in.regs;
            if (DefUse.isInvoke(op)) {
                if (found != null) {
                    for (int arg : regs) {
                        Const c = get(st, arg);
                        if (c.kind == Kind.LIT || c.kind == Kind.STR) {
                            CallConst cc = new CallConst();
                            cc.addr = in.addr;
                            cc.block = blockId;
                            cc.reg = arg;
                            cc.kind = c.kind;
                            cc.lit = c.lit;
                            cc.strRef = c.strRef;
                            found.add(cc);
                        }
                    }
                }
                continue;
            }
            int def = DefUse.defReg(op, regs);
            if (def < 0 || def >= st.length) continue;
            Const v = transfer(op, in, regs, st);
            st[def] = v;
            Set<Integer> s = new LinkedHashSet<>();
            s.add(in.addr);
            reach.put(def, s);
        }
    }

    private static Const get(Const[] st, int reg) {
        if (reg < 0 || reg >= st.length || st[reg] == null) {
            Const c = new Const();
            c.kind = Kind.NAC;
            return c;
        }
        return st[reg];
    }

    /** Valor que define la instrucción. Nunca null ni lanza. */
    private static Const transfer(int op, IrBuilder.Insn in, int[] regs, Const[] st) {
        try {
            if (op >= 0x12 && op <= 0x19) {
                return in.hasLit ? Const.lit(in.lit) : Const.nac();
            }
            if (op == 0x1A || op == 0x1B) return Const.str(in.refIdx);
            if (op >= 0x01 && op <= 0x09) {
                return regs.length >= 2 ? Const.copy(get(st, regs[1])) : Const.nac();
            }
            if (op == 0x1F) {
                return regs.length >= 1 ? Const.copy(get(st, regs[0])) : Const.nac();
            }
            if (op >= 0x0A && op <= 0x0C) return Const.nac();
            if (op >= 0x90 && op <= 0xAF) return foldBinop(op, regs, st);
            if (op >= 0xB0 && op <= 0xCF) return foldBinop2addr(op, regs, st);
            if (op >= 0xD0 && op <= 0xE2) return foldBinopLit(op, regs, st, in);
            if (op >= 0x7B && op <= 0x8F) return foldUnop(op, regs, st);
            return Const.nac();
        } catch (Throwable ignored) {
            return Const.nac();
        }
    }

    private static Const foldBinop(int op, int[] regs, Const[] st) {
        if (regs.length < 3) return Const.nac();
        Const a = get(st, regs[1]);
        Const b = get(st, regs[2]);
        if (a.kind != Kind.LIT || b.kind != Kind.LIT) return Const.nac();
        Long v = intBinop(op, a.lit, b.lit);
        return v == null ? Const.nac() : Const.lit(v);
    }

    private static Const foldBinop2addr(int op, int[] regs, Const[] st) {
        if (regs.length < 2) return Const.nac();
        Const a = get(st, regs[0]);
        Const b = get(st, regs[1]);
        if (a.kind != Kind.LIT || b.kind != Kind.LIT) return Const.nac();
        Long v = intBinop(op - 0x20, a.lit, b.lit);
        return v == null ? Const.nac() : Const.lit(v);
    }

    private static Const foldBinopLit(int op, int[] regs, Const[] st, IrBuilder.Insn in) {
        if (regs.length < 2 || !in.hasLit) return Const.nac();
        Const a = get(st, regs[1]);
        if (a.kind != Kind.LIT) return Const.nac();
        Long v = intBinop(op - 0x40, a.lit, in.lit);
        return v == null ? Const.nac() : Const.lit(v);
    }

    /** Pliegue entero (semántica Java int). null si no plegable. Nunca lanza. */
    private static Long intBinop(int op, long a, long b) {
        try {
            int x = (int) a;
            int y = (int) b;
            switch (op) {
                case 0x90:
                    return (long) (x + y);
                case 0x91:
                    return (long) (x - y);
                case 0x92:
                    return (long) (x * y);
                case 0x93:
                    return y == 0 ? null : (long) (x / y);
                case 0x94:
                    return y == 0 ? null : (long) (x % y);
                case 0x95:
                    return (long) (x & y);
                case 0x96:
                    return (long) (x | y);
                case 0x97:
                    return (long) (x ^ y);
                case 0x98:
                    return (long) (x << y);
                case 0x99:
                    return (long) (x >> y);
                case 0x9A:
                    return (long) (x >>> y);
                default:
                    return null;
            }
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Const foldUnop(int op, int[] regs, Const[] st) {
        if (regs.length < 2) return Const.nac();
        Const a = get(st, regs[1]);
        if (a.kind != Kind.LIT) return Const.nac();
        int x = (int) a.lit;
        switch (op) {
            case 0x7B:
                return Const.lit(-x);
            case 0x7C:
                return Const.lit(~x);
            default:
                return Const.nac();
        }
    }
}
