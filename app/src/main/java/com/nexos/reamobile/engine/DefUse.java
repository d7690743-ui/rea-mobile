package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * OMEGA Fase E1: cadenas def-use intraprocedurales sobre la IR de IrBuilder.
 * Dice qué instrucción define cada registro y qué instrucciones lo usan, con
 * encadenado exacto dentro de cada bloque. Entre bloques solo se marca
 * "entrada/desconocido" (-1): el flujo inter-bloque lo resuelve ReachConsts.
 * Utilidad estática sin estado. Java puro. Nunca lanza.
 *
 * <p>Límites honestos: los pares wide (long/double) se aproximan al primer
 * registro salvo move-wide/const-wide/move-result-wide/cmp-long, donde se
 * registra también el segundo; heap (iget/iput/aget/aput/sget/sput de
 * objetos) y excepciones no se modelan.</p>
 */
public final class DefUse {
    private DefUse() {
    }

    /** -1 = el valor puede venir de la entrada (parámetro) o de otro bloque. */
    public static final int ENTRY = -1;

    public static final int MAX_REFS_PER_REG = 4096;

    /** Sitio donde se define un registro. Nunca lanza. */
    public static class DefSite {
        public int addr = -1;
        public int block = -1;
        public int reg = -1;
        /** true si también define reg+1 (par wide). */
        public boolean wide;
        /** addr del invoke cuyo resultado recoge (move-result), o -1. */
        public int resultOf = -1;
        /** Registros leídos para calcular el valor (puede estar vacío). */
        public List<Integer> srcRegs = new ArrayList<>();
        /** Usos intra-bloque encadenados (addrs). */
        public List<Integer> users = new ArrayList<>();
    }

    /** Sitio donde se usa al menos un registro. Nunca lanza. */
    public static class UseSite {
        public int addr = -1;
        public int block = -1;
        public List<Integer> regs = new ArrayList<>();
        /**
         * Defs intra-bloque que alcanzan (addrs; ENTRY si pudo venir de
         * fuera del bloque). Exacto en línea recta.
         */
        public List<Integer> defs = new ArrayList<>();
    }

    /** Cadenas de un método. Nunca lanza. */
    public static class Chains {
        public int regs;
        public List<DefSite> defs = new ArrayList<>();
        public List<UseSite> uses = new ArrayList<>();
        public Map<Integer, List<DefSite>> defsByReg = new LinkedHashMap<>();
        public Map<Integer, UseSite> useByAddr = new LinkedHashMap<>();
        public Map<Integer, DefSite> defByAddr = new LinkedHashMap<>();
        public boolean truncated;
    }

    /**
     * Analiza un método. IR nula, con error o sin bloques → cadenas vacías.
     * Nunca null ni lanza.
     */
    public static Chains analyze(IrBuilder.MethodIr ir) {
        Chains c = new Chains();
        try {
            if (ir == null || ir.error != null || ir.blocks.isEmpty() || ir.regs <= 0) return c;
            c.regs = ir.regs;
            for (IrBuilder.Block b : ir.blocks) {
                if (b == null) continue;
                analyzeBlock(b, c);
            }
        } catch (Throwable ignored) {
        }
        return c;
    }

    private static void analyzeBlock(IrBuilder.Block b, Chains c) {
        Map<Integer, Integer> lastDef = new LinkedHashMap<>();
        Map<Integer, DefSite> lastSite = new LinkedHashMap<>();
        int pendingInvoke = -1;
        for (IrBuilder.Insn in : b.insns) {
            if (in == null) continue;
            int op = in.op & 0xFF;
            int[] regs = in.regs == null ? new int[0] : in.regs;
            if (isInvoke(op)) pendingInvoke = in.addr;
            int def = defReg(op, regs);
            List<Integer> uses = useRegs(op, regs);
            if (def >= 0 && def < c.regs) {
                DefSite d = new DefSite();
                d.addr = in.addr;
                d.block = b.id;
                d.reg = def;
                d.wide = isWideDef(op) && def + 1 < c.regs;
                if (op >= 0x0A && op <= 0x0C) d.resultOf = pendingInvoke;
                d.srcRegs.addAll(uses);
                addDef(c, d);
                lastDef.put(def, in.addr);
                lastSite.put(def, d);
                if (d.wide) {
                    lastDef.put(def + 1, in.addr);
                    lastSite.put(def + 1, d);
                }
            }
            if (!uses.isEmpty()) {
                UseSite u = new UseSite();
                u.addr = in.addr;
                u.block = b.id;
                Set<Integer> seen = new LinkedHashSet<>();
                for (int r : uses) {
                    if (r < 0 || r >= c.regs || !seen.add(r)) continue;
                    u.regs.add(r);
                    Integer ld = lastDef.get(r);
                    int da = ld == null ? ENTRY : ld;
                    if (!u.defs.contains(da)) u.defs.add(da);
                    if (ld != null) {
                        DefSite ds = lastSite.get(r);
                        if (ds != null && !ds.users.contains(in.addr)) ds.users.add(in.addr);
                    }
                }
                if (!u.regs.isEmpty()) {
                    c.uses.add(u);
                    c.useByAddr.put(u.addr, u);
                }
            }
            if (!isInvoke(op) && (op < 0x0A || op > 0x0C)) pendingInvoke = -1;
        }
    }

    private static void addDef(Chains c, DefSite d) {
        c.defs.add(d);
        if (!c.defByAddr.containsKey(d.addr)) c.defByAddr.put(d.addr, d);
        List<DefSite> l = c.defsByReg.get(d.reg);
        if (l == null) {
            l = new ArrayList<>();
            c.defsByReg.put(d.reg, l);
        }
        if (l.size() < MAX_REFS_PER_REG) {
            l.add(d);
        } else {
            c.truncated = true;
        }
        if (d.wide) {
            List<DefSite> l2 = c.defsByReg.get(d.reg + 1);
            if (l2 == null) {
                l2 = new ArrayList<>();
                c.defsByReg.put(d.reg + 1, l2);
            }
            if (l2.size() < MAX_REFS_PER_REG) {
                l2.add(d);
            } else {
                c.truncated = true;
            }
        }
    }

    /**
     * Propaga un conjunto de registros "marcados" (taint) por las defs:
     * una def queda marcada si alguno de sus srcRegs lo está. Punto fijo
     * acotado. Vacío si cadenas nulas. Nunca null ni lanza.
     */
    public static Set<Integer> propagate(Chains c, Set<Integer> seeds) {
        Set<Integer> out = new LinkedHashSet<>();
        try {
            if (c == null || seeds == null || seeds.isEmpty()) return out;
            for (int s : seeds) {
                if (s >= 0 && s < c.regs) out.add(s);
            }
            for (int pass = 0; pass < 32; pass++) {
                boolean changed = false;
                for (DefSite d : c.defs) {
                    if (d == null || out.contains(d.reg)) continue;
                    for (int s : d.srcRegs) {
                        if (out.contains(s)) {
                            out.add(d.reg);
                            if (d.wide && d.reg + 1 < c.regs) out.add(d.reg + 1);
                            changed = true;
                            break;
                        }
                    }
                }
                if (!changed) break;
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** true si el opcode es invoke-*. Nunca lanza. */
    public static boolean isInvoke(int op) {
        try {
            int o = op & 0xFF;
            return (o >= 0x6E && o <= 0x72) || (o >= 0x74 && o <= 0x78);
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Registro definido por el opcode, o -1 si no define. Nunca lanza.
     */
    public static int defReg(int op, int[] regs) {
        try {
            if (regs == null || regs.length == 0) return -1;
            int o = op & 0xFF;
            int r0 = regs[0];
            if (o >= 0x01 && o <= 0x0D) return r0;
            if (o >= 0x12 && o <= 0x1C) return r0;
            if (o == 0x1F || o == 0x20 || o == 0x21 || o == 0x22 || o == 0x23) return r0;
            if (o >= 0x2D && o <= 0x31) return r0;
            if (o >= 0x44 && o <= 0x4A) return r0;
            if (o >= 0x52 && o <= 0x58) return r0;
            if (o >= 0x60 && o <= 0x66) return r0;
            if (o >= 0x7B && o <= 0xE2) return r0;
            return -1;
        } catch (Throwable ignored) {
            return -1;
        }
    }

    private static boolean isWideDef(int op) {
        int o = op & 0xFF;
        return o == 0x04 || o == 0x05 || o == 0x06 || o == 0x0B
                || (o >= 0x16 && o <= 0x19);
    }

    /**
     * Registros usados por el opcode (puede estar vacío). Nunca null ni lanza.
     */
    public static List<Integer> useRegs(int op, int[] regs) {
        List<Integer> out = new ArrayList<>();
        try {
            if (regs == null) return out;
            int o = op & 0xFF;
            if (o >= 0x01 && o <= 0x09) {
                add(out, regs, 1);
                if (o >= 0x04 && o <= 0x06) addPlusOne(out, regs, 1);
            } else if (o >= 0x0F && o <= 0x11) {
                add(out, regs, 0);
            } else if (o == 0x1D || o == 0x1E || o == 0x26 || o == 0x27
                    || o == 0x2B || o == 0x2C) {
                add(out, regs, 0);
            } else if (o == 0x1F) {
                add(out, regs, 0);
            } else if (o == 0x20 || o == 0x21 || o == 0x23) {
                add(out, regs, 1);
            } else if (o == 0x24 || o == 0x25) {
                addAll(out, regs);
            } else if (o >= 0x2D && o <= 0x31) {
                add(out, regs, 1);
                add(out, regs, 2);
                if (o == 0x31) {
                    addPlusOne(out, regs, 1);
                    addPlusOne(out, regs, 2);
                }
            } else if (o >= 0x32 && o <= 0x3D) {
                addAll(out, regs);
            } else if (o >= 0x44 && o <= 0x4A) {
                add(out, regs, 1);
                add(out, regs, 2);
            } else if (o >= 0x4B && o <= 0x51) {
                add(out, regs, 0);
                add(out, regs, 1);
                add(out, regs, 2);
            } else if (o >= 0x52 && o <= 0x58) {
                add(out, regs, 1);
            } else if (o >= 0x59 && o <= 0x5F) {
                add(out, regs, 0);
                add(out, regs, 1);
            } else if (o >= 0x67 && o <= 0x6D) {
                add(out, regs, 0);
            } else if ((o >= 0x6E && o <= 0x72) || (o >= 0x74 && o <= 0x78)) {
                addAll(out, regs);
            } else if (o >= 0x7B && o <= 0x8F) {
                add(out, regs, 1);
            } else if (o >= 0x90 && o <= 0xAF) {
                add(out, regs, 1);
                add(out, regs, 2);
            } else if (o >= 0xB0 && o <= 0xCF) {
                add(out, regs, 0);
                add(out, regs, 1);
            } else if (o >= 0xD0 && o <= 0xE2) {
                add(out, regs, 1);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static void add(List<Integer> out, int[] regs, int i) {
        if (i < regs.length) out.add(regs[i]);
    }

    private static void addPlusOne(List<Integer> out, int[] regs, int i) {
        if (i < regs.length) out.add(regs[i] + 1);
    }

    private static void addAll(List<Integer> out, int[] regs) {
        for (int r : regs) out.add(r);
    }
}
