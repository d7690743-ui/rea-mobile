package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OMEGA Fase E3: forma SSA pragmática sobre DefUse + ReachConsts. Cada
 * definición recibe una versión única (v0_1, v0_2…) y en la entrada de los
 * bloques join se inserta una phi por registro con varias definiciones
 * alcanzantes. Utilidad estática sin estado. Java puro. Nunca lanza.
 *
 * <p>Honestidad: no se calcula frontera de dominancia; la phi es
 * conservadora (puede sobrar donde un análisis de dominadores la
 * eliminaría) y nunca falta donde dos valores distintos confluyen.
 * Pensada para lectura (visor/informe), no como IR de optimización.</p>
 */
public final class Ssa {
    private Ssa() {
    }

    public static final int MAX_PHIS = 200;
    public static final int MAX_PHI_SRC = 8;
    public static final String ENTRY_VER = "entry";

    /** Phi en la entrada de un bloque. Nunca lanza. */
    public static class Phi {
        public int block = -1;
        public int reg = -1;
        public String version = "";
        public List<String> sources = new ArrayList<>();
    }

    /** Forma SSA de un método. Nunca lanza. */
    public static class SsaForm {
        /** addr de def → versión ("v3_2"). */
        public Map<Integer, String> versions = new LinkedHashMap<>();
        public List<Phi> phis = new ArrayList<>();
        public boolean truncated;
    }

    /**
     * Construye la forma SSA. Si consts es null se calcula aquí.
     * IR nula, con error o sin bloques → forma vacía. Nunca null ni lanza.
     */
    public static SsaForm from(IrBuilder.MethodIr ir, ReachConsts.ConstResult consts) {
        SsaForm f = new SsaForm();
        try {
            if (ir == null || ir.error != null || ir.blocks.isEmpty() || ir.regs <= 0) return f;
            if (consts == null) consts = ReachConsts.analyze(ir);
            versionDefs(ir, f);
            insertPhis(ir, consts, f);
        } catch (Throwable ignored) {
        }
        return f;
    }

    private static void versionDefs(IrBuilder.MethodIr ir, SsaForm f) {
        Map<Integer, Integer> counter = new LinkedHashMap<>();
        for (IrBuilder.Block b : ir.blocks) {
            if (b == null) continue;
            for (IrBuilder.Insn in : b.insns) {
                if (in == null) continue;
                int[] regs = in.regs == null ? new int[0] : in.regs;
                int def = DefUse.defReg(in.op, regs);
                if (def < 0 || def >= ir.regs) continue;
                int k = counter.containsKey(def) ? counter.get(def) + 1 : 1;
                counter.put(def, k);
                f.versions.put(in.addr, "v" + def + "_" + k);
            }
        }
    }

    private static void insertPhis(IrBuilder.MethodIr ir, ReachConsts.ConstResult consts,
            SsaForm f) {
        if (consts.reaching.size() != ir.blocks.size()) return;
        Map<Integer, Integer> counter = new LinkedHashMap<>();
        for (int i = 0; i < ir.blocks.size(); i++) {
            IrBuilder.Block b = ir.blocks.get(i);
            if (b == null) continue;
            Map<Integer, Set<Integer>> reach = consts.reaching.get(i);
            if (reach == null) continue;
            for (Map.Entry<Integer, Set<Integer>> e : reach.entrySet()) {
                int reg = e.getKey();
                Set<Integer> defs = e.getValue();
                if (reg < 0 || reg >= ir.regs || defs == null || defs.size() < 2) continue;
                if (f.phis.size() >= MAX_PHIS) {
                    f.truncated = true;
                    return;
                }
                int k = counter.containsKey(reg) ? counter.get(reg) + 1 : versionMax(f, reg) + 1;
                counter.put(reg, k);
                Phi p = new Phi();
                p.block = b.id;
                p.reg = reg;
                p.version = "v" + reg + "_" + k;
                for (int a : defs) {
                    if (p.sources.size() >= MAX_PHI_SRC) {
                        f.truncated = true;
                        break;
                    }
                    String v = f.versions.get(a);
                    p.sources.add(v == null ? ENTRY_VER : v);
                }
                f.phis.add(p);
            }
        }
    }

    private static int versionMax(SsaForm f, int reg) {
        int m = 0;
        String prefix = "v" + reg + "_";
        for (String v : f.versions.values()) {
            if (v != null && v.startsWith(prefix)) {
                try {
                    int k = Integer.parseInt(v.substring(prefix.length()));
                    if (k > m) m = k;
                } catch (RuntimeException ignored) {
                }
            }
        }
        return m;
    }

    /**
     * Versión del valor usado en (bloque, addr): la phi del bloque si el
     * registro la tiene, si no la versión de su def alcanzante, si no
     * "entry". Nunca null ni lanza.
     */
    public static String versionAt(SsaForm f, ReachConsts.ConstResult consts,
            int blockId, int addr, int reg) {
        try {
            if (f == null) return ENTRY_VER;
            for (Phi p : f.phis) {
                if (p != null && p.block == blockId && p.reg == reg) return p.version;
            }
            if (consts != null && blockId >= 0 && blockId < consts.reaching.size()) {
                Map<Integer, Set<Integer>> reach = consts.reaching.get(blockId);
                if (reach != null) {
                    Set<Integer> defs = reach.get(reg);
                    if (defs != null && defs.size() == 1) {
                        String v = f.versions.get(defs.iterator().next());
                        if (v != null) return v;
                    }
                }
            }
            return ENTRY_VER;
        } catch (Throwable ignored) {
            return ENTRY_VER;
        }
    }
}
