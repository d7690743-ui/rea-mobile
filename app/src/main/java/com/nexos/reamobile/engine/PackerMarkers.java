package com.nexos.reamobile.engine;

/**
 * Marcadores de protectores/empaquetadores e instrumentación por nombre de
 * fichero o prefijo de clase. Tabla propia. Java puro. Nunca lanza.
 */
public final class PackerMarkers {
    private PackerMarkers() {
    }

    private static final String[][] FILES = {
            {"libdexhelper.so", "protector Bangcle"},
            {"libjiagu", "protector 360 Jiagu"},
            {"ijiami", "protector Ijiami"},
            {"libtosprotection", "protector Tencent"},
            {"secneo", "protector SecNeo"},
            {"libapkprotect", "protector APKProtect"},
            {"libnqshield", "protector NQ Shield"},
            {"leggen", "protector Leggu"},
            {"libdxprotect", "protector DxProtect"},
            {"libfrida", "instrumentación Frida"},
            {"libxposed", "Xposed"},
            {"substrate", "Cydia Substrate"},
    };

    private static final String[][] CLASSES = {
            {"com/secneo", "protector SecNeo"},
            {"com/bangcle", "protector Bangcle"},
            {"com/qihoo", "protector 360"},
            {"com/tencent/stub", "protector Tencent"},
            {"de/robv/android/xposed", "Xposed"},
            {"com/saurik/substrate", "Cydia Substrate"},
            {"com/frida", "instrumentación Frida"},
    };

    /** Etiqueta para un nombre de entrada del ZIP, o null. Nunca lanza. */
    public static String matchFile(String entryName) {
        try {
            if (entryName == null) return null;
            String n = entryName.toLowerCase(java.util.Locale.US);
            for (String[] e : FILES) {
                if (n.contains(e[0])) return e[1];
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** Etiqueta para un descriptor de clase, o null. Nunca lanza. */
    public static String matchClass(String desc) {
        try {
            if (desc == null) return null;
            String p = desc.startsWith("L") ? desc.substring(1) : desc;
            for (String[] e : CLASSES) {
                if (p.startsWith(e[0])) return e[1];
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
