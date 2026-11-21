package com.nexos.reamobile.engine;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.plugins.input.dex.DexInputPlugin;
import java.io.File;
import java.util.List;

/**
 * Diagnóstico on-device vía app_process (la app no lo usa):
 * CLASSPATH=app.apk app_process / com.nexos.reamobile.engine.ArtDiag &lt;apk&gt;
 * Imprime traza COMPLETA (con causas) del descompilado directo en ART.
 */
public final class ArtDiag {
    private ArtDiag() {
    }

    public static void main(String[] argv) {
        try {
            File apk = new File(argv[0]);
            System.out.println("APK=" + apk + " size=" + apk.length());
            JadxArgs args = new JadxArgs();
            args.setInputFile(apk);
            args.setOutDir(new File("/tmp/artdiag-wd"));
            args.setSkipResources(true);
            args.setThreadsCount(1);
            JadxDecompiler jadx = new JadxDecompiler(args);
            jadx.registerPlugin(new DexInputPlugin());
            jadx.load();
            List<JavaClass> classes = jadx.getClassesWithInners();
            System.out.println("CLASSES=" + classes.size());
            int n = 0;
            for (JavaClass c : classes) {
                try {
                    c.getCode();
                    n++;
                } catch (Throwable t) {
                    System.out.println("CLASS-ERR " + safeName(c));
                    t.printStackTrace(System.out);
                    break;
                }
                if (n >= 3) break;
            }
            System.out.println("CODE_OK=" + n);
            jadx.close();
        } catch (Throwable t) {
            System.out.println("FALLO:");
            t.printStackTrace(System.out);
        }
    }

    private static String safeName(JavaClass c) {
        try {
            return c.getFullName();
        } catch (Throwable t) {
            return "?";
        }
    }
}
