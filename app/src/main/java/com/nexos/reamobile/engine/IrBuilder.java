package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * F3.1: representación intermedia + bloques básicos + sucesores (CFG).
 * Java puro. Reutiliza las tablas de SmaliDumper (una sola fuente).
 * Los targets de payload switch son relativos al dispatch (verificado
 * contra baksmali). Nunca lanza: devuelve error/truncado.
 */
public final class IrBuilder {
    private IrBuilder() {
    }

    public static final int MAX_INSNS = 20000;

    public static class Insn {
        public int addr;
        public int op;
        public int fmt;
        public int size;
        public String name = "";
        public int[] regs = new int[0];
        public boolean hasLit;
        public long lit;
        public int target = -1;
        public int refKind;
        public int refIdx;
        public boolean isGoto, isCond, isSwitch, isFillArray, isReturn, isThrow, isPayload;
    }

    public static class Block {
        public int id;
        public int start;
        public int end;
        public List<Insn> insns = new ArrayList<>();
        public List<Integer> succs = new ArrayList<>();
    }

    public static class MethodIr {
        public int regs;
        public List<Insn> insns = new ArrayList<>();
        public List<Block> blocks = new ArrayList<>();
        public boolean truncated;
        public String error;
    }

    /** IR de un code_item en codeOff. Nunca lanza. */
    public static MethodIr buildMethod(byte[] dex, int codeOff) {
        MethodIr r = new MethodIr();
        try {
            if (dex == null || codeOff < 0 || codeOff + 16 > dex.length) {
                r.error = "codeOff inválido";
                return r;
            }
            int regs = u16(dex, codeOff);
            int insnsSize = u32(dex, codeOff + 12);
            if (insnsSize < 0 || insnsSize > 200000
                    || codeOff + 16 + insnsSize * 2 > dex.length) {
                r.error = "insnsSize inválido";
                return r;
            }
            int[] units = new int[insnsSize];
            for (int i = 0; i < insnsSize; i++) units[i] = u16(dex, codeOff + 16 + i * 2);
            r = build(units, insnsSize, regs);
        } catch (Throwable t) {
            r.error = "ir: " + t.getMessage();
        }
        return r;
    }

    /** IR desde units crudos. Nunca lanza. */
    public static MethodIr build(int[] units, int n, int regs) {
        MethodIr r = new MethodIr();
        r.regs = regs;
        try {
            if (units == null || n < 0 || n > units.length) {
                r.error = "units inválidos";
                return r;
            }
            List<Insn> insns = new ArrayList<>();
            int p = 0;
            while (p < n) {
                if (insns.size() >= MAX_INSNS) {
                    r.truncated = true;
                    break;
                }
                int op = units[p] & 0xFF;
                int fmt = SmaliDumper.FORMATS[op];
                int size = SmaliDumper.insnSize(fmt, units, p, n);
                if (size <= 0 || p + size > n) {
                    r.truncated = true;
                    break;
                }
                insns.add(decode(units, p, n, op, fmt, size));
                p += size;
            }
            r.insns = insns;
            splitBlocks(r, units, n);
        } catch (Throwable t) {
            r.error = "ir: " + t.getMessage();
        }
        return r;
    }

    private static Insn decode(int[] units, int p, int n, int op, int fmt, int size) {
        Insn in = new Insn();
        in.addr = p;
        in.op = op;
        in.fmt = fmt;
        in.size = size;
        int u0 = units[p];
        if (fmt == SmaliDumper.F00) {
            if (u0 == 0x0100) in.name = "packed-switch-payload";
            else if (u0 == 0x0200) in.name = "sparse-switch-payload";
            else if (u0 == 0x0300) in.name = "fill-array-payload";
            else in.name = "nop";
            in.isPayload = !in.name.equals("nop");
            return in;
        }
        in.name = SmaliDumper.NAMES[op];
        in.refKind = SmaliDumper.REFS[op];
        switch (fmt) {
            case SmaliDumper.F12x:
                in.regs = new int[]{(u0 >> 8) & 15, (u0 >> 12) & 15};
                break;
            case SmaliDumper.F11n: {
                in.regs = new int[]{(u0 >> 8) & 15};
                int v = (u0 >> 12) & 15;
                in.hasLit = true;
                in.lit = v >= 8 ? v - 16 : v;
                break;
            }
            case SmaliDumper.F11x:
                in.regs = new int[]{(u0 >> 8) & 15};
                break;
            case SmaliDumper.F10t:
                in.target = p + (byte) (u0 >> 8);
                in.isGoto = true;
                break;
            case SmaliDumper.F20t:
            case SmaliDumper.F30t:
                in.target = SmaliDumper.branchTarget(fmt, units, p, op);
                in.isGoto = true;
                break;
            case SmaliDumper.F22x:
                in.regs = new int[]{(u0 >> 8) & 255, units[p + 1]};
                break;
            case SmaliDumper.F21t:
                in.regs = new int[]{(u0 >> 8) & 255};
                in.target = p + (short) units[p + 1];
                in.isCond = true;
                break;
            case SmaliDumper.F22t:
                in.regs = new int[]{(u0 >> 8) & 15, (u0 >> 12) & 15};
                in.target = p + (short) units[p + 1];
                in.isCond = true;
                break;
            case SmaliDumper.F21s:
            case SmaliDumper.F22s:
                in.regs = fmt == SmaliDumper.F21s
                        ? new int[]{(u0 >> 8) & 255}
                        : new int[]{(u0 >> 8) & 15, (u0 >> 12) & 15};
                in.hasLit = true;
                in.lit = (short) units[p + 1];
                break;
            case SmaliDumper.F21h:
                in.regs = new int[]{(u0 >> 8) & 255};
                in.hasLit = true;
                in.lit = (long) units[p + 1] << 16;
                break;
            case SmaliDumper.F21lh:
                in.regs = new int[]{(u0 >> 8) & 255};
                in.hasLit = true;
                in.lit = (long) units[p + 1] << 48;
                break;
            case SmaliDumper.F21c:
                in.regs = new int[]{(u0 >> 8) & 255};
                in.refIdx = units[p + 1];
                break;
            case SmaliDumper.F22b:
                in.regs = new int[]{(u0 >> 8) & 15, (u0 >> 12) & 15};
                in.hasLit = true;
                in.lit = (byte) (units[p + 1] & 0xFF);
                break;
            case SmaliDumper.F23x:
                in.regs = new int[]{(u0 >> 8) & 255, units[p + 1] & 255, (units[p + 1] >> 8) & 255};
                break;
            case SmaliDumper.F22c:
                in.regs = new int[]{(u0 >> 8) & 15, (u0 >> 12) & 15};
                in.refIdx = units[p + 1];
                break;
            case SmaliDumper.F32x:
                in.regs = new int[]{units[p + 1], units[p + 2]};
                break;
            case SmaliDumper.F31i:
                in.regs = new int[]{(u0 >> 8) & 255};
                in.hasLit = true;
                in.lit = (units[p + 1] | (units[p + 2] << 16));
                break;
            case SmaliDumper.F31t:
                in.regs = new int[]{(u0 >> 8) & 255};
                in.target = p + (units[p + 1] | (units[p + 2] << 16));
                if (op == 0x2b || op == 0x2c) in.isSwitch = true;
                else in.isFillArray = true;
                break;
            case SmaliDumper.F31c:
                in.regs = new int[]{(u0 >> 8) & 255};
                in.refIdx = units[p + 1] | (units[p + 2] << 16);
                break;
            case SmaliDumper.F35c:
            case SmaliDumper.F45cc: {
                int u2 = units[p + 2];
                int a = (u0 >> 8) & 15;
                int[] all = {u2 & 15, (u2 >> 4) & 15, (u2 >> 8) & 15, (u2 >> 12) & 15,
                        (u0 >> 12) & 15};
                int k = Math.max(0, Math.min(a, 5));
                in.regs = new int[k];
                System.arraycopy(all, 0, in.regs, 0, k);
                in.refIdx = units[p + 1];
                break;
            }
            case SmaliDumper.F3rc:
            case SmaliDumper.F4rcc: {
                int a = (u0 >> 8) & 255;
                int first = units[p + 2];
                int k = Math.max(0, Math.min(a, 256));
                in.regs = new int[k];
                for (int i = 0; i < k; i++) in.regs[i] = first + i;
                in.refIdx = units[p + 1];
                break;
            }
            case SmaliDumper.F51l: {
                in.regs = new int[]{(u0 >> 8) & 255};
                in.hasLit = true;
                in.lit = ((long) units[p + 1]) | ((long) units[p + 2] << 16)
                        | ((long) units[p + 3] << 32) | ((long) units[p + 4] << 48);
                break;
            }
            default:
                break;
        }
        if (op >= 0x0e && op <= 0x11) in.isReturn = true;
        if (op == 0x27) in.isThrow = true;
        return in;
    }

    /** Parte en bloques básicos y calcula sucesores. */
    private static void splitBlocks(MethodIr r, int[] units, int n) {
        List<Insn> code = new ArrayList<>();
        for (Insn in : r.insns) {
            if (!in.isPayload) code.add(in);
        }
        if (code.isEmpty()) return;
        Map<Integer, Boolean> leaders = new LinkedHashMap<>();
        leaders.put(code.get(0).addr, Boolean.TRUE);
        for (int i = 0; i < code.size(); i++) {
            Insn in = code.get(i);
            int next = in.addr + in.size;
            if (in.isGoto || in.isCond || in.isSwitch || in.isFillArray) {
                if (in.target >= 0 && in.target < n) leaders.put(in.target, Boolean.TRUE);
            }
            boolean endsBlock = in.isGoto || in.isCond || in.isSwitch
                    || in.isReturn || in.isThrow;
            if (endsBlock && next < n) leaders.put(next, Boolean.TRUE);
        }
        Map<Integer, Insn> byAddr = new LinkedHashMap<>();
        for (Insn in : code) byAddr.put(in.addr, in);
        List<Integer> bounds = new ArrayList<>();
        for (int a : leaders.keySet()) {
            if (byAddr.containsKey(a)) bounds.add(a);
        }
        bounds.sort(null);
        Map<Integer, Integer> blockOf = new LinkedHashMap<>();
        for (int b = 0; b < bounds.size(); b++) {
            Block bl = new Block();
            bl.start = bounds.get(b);
            bl.end = (b + 1 < bounds.size()) ? bounds.get(b + 1) : n;
            for (Insn in : code) {
                if (in.addr >= bl.start && in.addr < bl.end) bl.insns.add(in);
            }
            if (!bl.insns.isEmpty()) {
                bl.id = r.blocks.size();
                bl.end = bl.insns.get(bl.insns.size() - 1).addr
                        + bl.insns.get(bl.insns.size() - 1).size;
                for (Insn in : bl.insns) blockOf.put(in.addr, bl.id);
                r.blocks.add(bl);
            }
        }
        for (Block bl : r.blocks) {
            Insn last = bl.insns.get(bl.insns.size() - 1);
            List<Integer> succAddrs = new ArrayList<>();
            if (last.isGoto) {
                succAddrs.add(last.target);
            } else if (last.isCond) {
                succAddrs.add(last.addr + last.size);
                succAddrs.add(last.target);
            } else if (last.isSwitch) {
                succAddrs.add(last.addr + last.size);
                succAddrs.addAll(caseTargets(units, n, last));
            } else if (!(last.isReturn || last.isThrow)) {
                succAddrs.add(last.addr + last.size);
            }
            for (int a : succAddrs) {
                Integer b = blockOf.get(a);
                if (b != null && !bl.succs.contains(b)) bl.succs.add(b);
            }
        }
    }

    /** Targets case del payload (relativos al dispatch). Vacío si inválido. */
    private static List<Integer> caseTargets(int[] units, int n, Insn dispatch) {
        List<Integer> out = new ArrayList<>();
        try {
            int t = dispatch.target;
            if (t < 0 || t + 2 > n) return out;
            int u0 = units[t];
            int size = units[t + 1];
            if (size <= 0 || size > 100000) return out;
            if (u0 == 0x0100) {
                if (t + 4 + size * 2 > n) return out;
                for (int i = 0; i < size; i++) {
                    int off = units[t + 4 + i * 2] | (units[t + 5 + i * 2] << 16);
                    int a = dispatch.addr + off;
                    if (a >= 0 && a < n) out.add(a);
                }
            } else if (u0 == 0x0200) {
                if (t + 2 + size * 4 > n) return out;
                for (int i = 0; i < size; i++) {
                    int tp = t + 2 + size * 2 + i * 2;
                    int off = units[tp] | (units[tp + 1] << 16);
                    int a = dispatch.addr + off;
                    if (a >= 0 && a < n) out.add(a);
                }
            }
        } catch (RuntimeException e) {
            // payload inválido: sin cases
        }
        return out;
    }

    private static int u16(byte[] b, int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8);
    }

    private static int u32(byte[] b, int p) {
        return (b[p] & 0xFF) | ((b[p + 1] & 0xFF) << 8)
                | ((b[p + 2] & 0xFF) << 16) | ((b[p + 3] & 0xFF) << 24);
    }
}
