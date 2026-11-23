package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * F3.2: propagación simple de tipos de registros sobre la CFG de IrBuilder.
 * Dominios: "I" (int/boolean/byte/short/char), "J" (long), descriptores
 * ("Ljava/lang/String;", "[I"…) y "?" (desconocido). Sensible al flujo con
 * mezcla en joins (igual conserva, distinto colapsa a "?") y punto fijo
 * acotado. Solo resultados de invoke (vía Resolver) y const; parámetros
 * de entrada quedan "?". Nunca lanza.
 */
public final class IrTypes {
    private IrTypes() {
    }

    /** Tipos que IrBuilder no resuelve solo. Nunca lanza (contrato). */
    public interface Resolver {
        /** Descriptor de retorno del método refIdx, o null. */
        String methodReturn(int refIdx);

        /** Descriptor del tipo refIdx, o null. */
        String typeName(int refIdx);
    }

    /**
     * Tipo final por registro (merge de salidas de bloques con return; si no
     * hay, merge de todas). Vacío si IR nula, con error o sin bloques.
     * Nunca null ni lanza.
     */
    public static String[] infer(IrBuilder.MethodIr ir, Resolver r) {
        try {
            if (ir == null || ir.error != null || ir.blocks.isEmpty() || ir.regs <= 0) {
                return new String[0];
            }
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
            String[][] entry = new String[nb][];
            String[][] exit = new String[nb][];
            for (int i = 0; i < nb; i++) {
                entry[i] = newState(nregs);
                exit[i] = newState(nregs);
            }
            int maxPasses = Math.min(64, 4 + nb * 2);
            for (int pass = 0; pass < maxPasses; pass++) {
                boolean changed = false;
                for (int i = 0; i < nb; i++) {
                    IrBuilder.Block b = ir.blocks.get(i);
                    if (b == null) continue;
                    String[] en;
                    if (i == 0) {
                        en = newState(nregs);
                        for (int p : preds.get(0)) en = merge(en, exit[p]);
                    } else {
                        en = null;
                        for (int p : preds.get(i)) {
                            en = en == null ? Arrays.copyOf(exit[p], nregs) : merge(en, exit[p]);
                        }
                        if (en == null) en = newState(nregs);
                    }
                    entry[i] = en;
                    String[] st = Arrays.copyOf(en, nregs);
                    changed |= simulate(b, st, r);
                    if (!Arrays.equals(exit[i], st)) {
                        exit[i] = st;
                        changed = true;
                    }
                }
                if (!changed) break;
            }
            String[] fin = null;
            for (int i = 0; i < nb; i++) {
                IrBuilder.Block b = ir.blocks.get(i);
                if (b == null || b.insns.isEmpty()) continue;
                if (b.insns.get(b.insns.size() - 1).isReturn) {
                    fin = fin == null ? Arrays.copyOf(exit[i], nregs) : merge(fin, exit[i]);
                }
            }
            if (fin == null) {
                for (int i = 0; i < nb; i++) {
                    fin = fin == null ? Arrays.copyOf(exit[i], nregs) : merge(fin, exit[i]);
                }
            }
            return fin == null ? new String[0] : fin;
        } catch (Throwable ignored) {
            return new String[0];
        }
    }

    private static String[] newState(int nregs) {
        String[] s = new String[nregs];
        Arrays.fill(s, "?");
        return s;
    }

    private static String[] merge(String[] a, String[] b) {
        String[] o = new String[a.length];
        for (int i = 0; i < a.length; i++) {
            o[i] = a[i].equals(b[i]) ? a[i] : "?";
        }
        return o;
    }

    /**
     * Simula un bloque sobre st (move-result consume el último invoke del
     * bloque). true si st cambió. Nunca lanza.
     */
    private static boolean simulate(IrBuilder.Block b, String[] st, Resolver r) {
        boolean changed = false;
        try {
            String pending = "?";
            for (IrBuilder.Insn in : b.insns) {
                if (in == null) continue;
                int op = in.op & 0xFF;
                int[] regs = in.regs == null ? new int[0] : in.regs;
                if (op >= 0x12 && op <= 0x15) {
                    changed |= set(st, regs, 0, "I");
                } else if (op >= 0x16 && op <= 0x19) {
                    changed |= set(st, regs, 0, "J");
                    changed |= setNextUnknown(st, regs);
                } else if (op == 0x1a || op == 0x1b) {
                    changed |= set(st, regs, 0, "Ljava/lang/String;");
                } else if (op == 0x1c) {
                    changed |= set(st, regs, 0, "Ljava/lang/Class;");
                } else if (op == 0x01 || op == 0x07) {
                    if (regs.length >= 2) changed |= set(st, regs, 0, get(st, regs[1]));
                } else if (op == 0x04) {
                    if (regs.length >= 2) changed |= set(st, regs, 0, get(st, regs[1]));
                    changed |= setNextUnknown(st, regs);
                } else if (op == 0x0a || op == 0x0b || op == 0x0c) {
                    changed |= set(st, regs, 0, pending);
                    if (op == 0x0b) changed |= setNextUnknown(st, regs);
                    pending = "?";
                } else if (op == 0x1f || op == 0x22) {
                    changed |= set(st, regs, 0, safeType(r, in.refIdx));
                } else if (op == 0x20 || op == 0x21) {
                    changed |= set(st, regs, 0, "I");
                } else if ((op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)) {
                    pending = safeReturn(r, in.refIdx);
                }
            }
        } catch (Throwable ignored) {
        }
        return changed;
    }

    private static String get(String[] st, int reg) {
        if (reg < 0 || reg >= st.length) return "?";
        return st[reg] == null ? "?" : st[reg];
    }

    private static boolean set(String[] st, int[] regs, int i, String t) {
        if (regs == null || i >= regs.length) return false;
        int reg = regs[i];
        if (reg < 0 || reg >= st.length) return false;
        if (t == null) t = "?";
        if (t.equals(st[reg])) return false;
        st[reg] = t;
        return true;
    }

    private static boolean setNextUnknown(String[] st, int[] regs) {
        if (regs == null || regs.length == 0) return false;
        int reg = regs[0] + 1;
        if (reg < 0 || reg >= st.length) return false;
        if ("?".equals(st[reg])) return false;
        st[reg] = "?";
        return true;
    }

    private static String safeReturn(Resolver r, int refIdx) {
        try {
            if (r == null) return "?";
            String t = r.methodReturn(refIdx);
            return t == null || t.isEmpty() ? "?" : t;
        } catch (Throwable ignored) {
            return "?";
        }
    }

    private static String safeType(Resolver r, int refIdx) {
        try {
            if (r == null) return "?";
            String t = r.typeName(refIdx);
            return t == null || t.isEmpty() ? "?" : t;
        } catch (Throwable ignored) {
            return "?";
        }
    }
}
