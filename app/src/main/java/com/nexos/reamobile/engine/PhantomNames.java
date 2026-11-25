package com.nexos.reamobile.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PHANTOM nombres: contexto semántico bajo ofuscación. Las clases YTM
 * ofuscadas (Lagr;) conservan const-strings Kotlin con el fichero real
 * ("MediaSessionShuffleStateAdapter.kt") y rutas ("com/.../Music...Impl"):
 * aquí se cosechan como etiquetas. Además deriva el feature de cada
 * clase del manifest (MusicActivity → "Music") y resume 1-2 strings de
 * comportamiento por función. Todo best-effort declarado. Nunca lanza.
 */
public final class PhantomNames {
    private PhantomNames() {
    }

    public static final int MAX_CLASSES = 500;
    public static final int MAX_CALLERS_SCAN = 6000;
    public static final int MAX_LITS_PER_METHOD = 15;
    public static final int MAX_BEHAVIOR = 2;

    private static final Pattern KT_FILE =
            Pattern.compile("([A-Za-z0-9_$]{3,64})\\.(kt|java)$");
    private static final Pattern CLASS_PATH =
            Pattern.compile("(?:^|[/.])([A-Z][A-Za-z0-9_$]{2,63})$");

    /**
     * Cosecha etiquetas para clases ofuscadas: llamador → literales →
     * fichero .kt/.java o ruta de clase. Una pasada acotada. Nunca null.
     */
    public static Map<String, String> harvest(RefGraph graph, StringRefs refs) {
        Map<String, String> out = new LinkedHashMap<>();
        try {
            if (graph == null || refs == null) return out;
            Set<String> seen = new LinkedHashSet<>();
            int scanned = 0;
            for (RefGraph.RefEdge e : graph.edges()) {
                if (e == null || e.caller == null) continue;
                if (!seen.add(e.caller)) continue;
                if (scanned++ >= MAX_CALLERS_SCAN
                        || out.size() >= MAX_CLASSES) break;
                String cls = RefGraph.split(e.caller)[0];
                if (!isObfuscated(cls) || out.containsKey(cls)) continue;
                String label = labelForMethod(refs, e.caller);
                if (!label.isEmpty()) out.put(cls, label);
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static String labelForMethod(StringRefs refs, String method) {
        try {
            String pathHit = "";
            for (String lit : refs.literalsOf(method, MAX_LITS_PER_METHOD)) {
                if (lit == null) continue;
                String t = lit.trim();
                if (t.length() > 160) continue;
                Matcher mk = KT_FILE.matcher(t);
                if (mk.find()) return clean(mk.group(1));
                if (pathHit.isEmpty() && t.indexOf('/') >= 0) {
                    Matcher mp = CLASS_PATH.matcher(t);
                    if (mp.find()) pathHit = clean(mp.group(1));
                }
            }
            return pathHit;
        } catch (Throwable ignored) {
            return "";
        }
    }

    /** Clase ofuscada probable: delega en DexParser.isShortName (B3, única fuente). */
    static boolean isObfuscated(String cls) {
        try {
            return DexParser.isShortName(cls);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String clean(String s) {
        try {
            if (s == null) return "";
            int d = s.indexOf('$');
            String t = d < 0 ? s : s.substring(0, d);
            return t.length() < 3 ? "" : t;
        } catch (Throwable ignored) {
            return "";
        }
    }

    /**
     * Feature de una clase del manifest ("Lcom/..;/MusicActivity;"
     * → "Music"). "" si no se deriva. Nunca lanza.
     */
    public static String featureFor(String cls) {
        try {
            if (cls == null || isObfuscated(cls)) return "";
            int s = cls.lastIndexOf('/');
            int e = cls.endsWith(";") ? cls.length() - 1 : cls.length();
            String tail = s < 0 ? cls : cls.substring(s + 1, e);
            if (tail.startsWith("L")) tail = tail.substring(1);
            for (String suf : new String[]{"Activity", "Service", "Receiver",
                    "Provider", "Fragment", "Dialog"}) {
                if (tail.endsWith(suf) && tail.length() > suf.length()) {
                    tail = tail.substring(0, tail.length() - suf.length());
                    break;
                }
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < tail.length(); i++) {
                char c = tail.charAt(i);
                if (i > 0 && c >= 'A' && c <= 'Z'
                        && tail.charAt(i - 1) >= 'a'
                        && tail.charAt(i - 1) <= 'z') sb.append(' ');
                sb.append(c);
            }
            String f = sb.toString().trim();
            return f.length() < 2 ? "" : f;
        } catch (Throwable ignored) {
            return "";
        }
    }

    /**
     * Strings de comportamiento de un grupo: format-strings o frases
     * con espacios (no rutas ni URLs). Tope MAX_BEHAVIOR. Nunca null.
     */
    public static List<String> behaviorFor(PhantomGroup.FuncGroup g,
                                           StringRefs refs) {
        List<String> out = new ArrayList<>();
        try {
            if (g == null || g.methodSample == null || refs == null) return out;
            for (String m : g.methodSample) {
                if (m == null || out.size() >= MAX_BEHAVIOR) break;
                for (String lit : refs.literalsOf(m, 10)) {
                    if (out.size() >= MAX_BEHAVIOR) break;
                    if (isBehavior(lit) && !out.contains(lit.trim())) {
                        out.add(trim(lit));
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    static boolean isBehavior(String lit) {
        try {
            if (lit == null) return false;
            String t = lit.trim();
            if (t.length() < 15 || t.length() > 140) return false;
            if (t.indexOf('\n') >= 0 || t.indexOf('/') >= 0
                    || t.indexOf(';') >= 0) return false;
            if (t.startsWith("http") || t.startsWith("L")) return false;
            if (t.contains("%s") || t.contains("%d") || t.contains("%1$")
                    || t.contains("%i")) return true;
            int spaces = 0;
            for (int i = 0; i < t.length(); i++) {
                if (t.charAt(i) == ' ') spaces++;
            }
            return spaces >= 3;
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Una línea semántica por grupo con contenido: feature, etiqueta
     * de-obfuscada y primer comportamiento. Nunca null ni lanza.
     */
    public static List<String> describe(List<PhantomGroup.FuncGroup> groups,
                                        Map<String, String> names,
                                        StringRefs refs) {
        List<String> out = new ArrayList<>();
        try {
            if (groups == null) return out;
            for (PhantomGroup.FuncGroup g : groups) {
                if (g == null) continue;
                String entry = g.entries.isEmpty() ? "" : g.entries.get(0);
                String cls = entry.isEmpty() ? "" : RefGraph.split(entry)[0];
                String feat = featureFor(cls);
                String deob = "";
                if (names != null && g.classSample != null) {
                    for (String c : g.classSample) {
                        String l = names.get(c);
                        if (l != null && !l.isEmpty()) {
                            deob = shortCls(c) + "→" + l;
                            break;
                        }
                    }
                }
                List<String> beh = behaviorFor(g, refs);
                if (feat.isEmpty() && deob.isEmpty() && beh.isEmpty()) continue;
                StringBuilder sb = new StringBuilder();
                sb.append(g.id);
                if (!feat.isEmpty()) sb.append(" [").append(feat).append(']');
                if (!deob.isEmpty()) sb.append(' ').append(deob);
                if (!beh.isEmpty()) sb.append(": \"").append(beh.get(0)).append('"');
                out.add(sb.toString());
                if (out.size() >= 60) break;
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    /** Líneas "Lagr; → MediaSessionShuffleStateAdapter". Nunca lanza. */
    public static List<String> summarizeNames(Map<String, String> names) {
        List<String> out = new ArrayList<>();
        try {
            if (names == null) return out;
            for (Map.Entry<String, String> e : names.entrySet()) {
                if (e == null || e.getValue() == null) continue;
                out.add(e.getKey() + " → " + e.getValue());
                if (out.size() >= 20) {
                    int rest = names.size() - 20;
                    if (rest > 0) out.add("(+" + rest + " más)");
                    break;
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static String shortCls(String desc) {
        try {
            if (desc == null) return "?";
            int s = desc.lastIndexOf('/');
            int e = desc.endsWith(";") ? desc.length() - 1 : desc.length();
            String t = s < 0 ? desc.substring(0, e) : desc.substring(s + 1, e);
            return t.isEmpty() ? "?" : t;
        } catch (Throwable ignored) {
            return "?";
        }
    }

    private static String trim(String s) {
        try {
            if (s == null) return "";
            String t = s.replace('\n', ' ').trim();
            return t.length() > 100 ? t.substring(0, 100) + "…" : t;
        } catch (Throwable ignored) {
            return "";
        }
    }
}
