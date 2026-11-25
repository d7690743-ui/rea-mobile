package com.nexos.reamobile.ree;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * REE Fase B: puente RUN_COMMAND hacia Termux.
 *
 * <p>Portado de NEXUS Agents ({@code mx.nexus.agents.TermuxBridge}, probado en
 * producción) con adaptaciones: package {@code com.nexos.reamobile},
 * PendingIntent inmutable (target 35), validación de etiqueta y tope de
 * script. Solo ejecuta scripts construidos por REA; nunca datos procedentes
 * del APK analizado.
 */
public final class ReaTermuxBridge {
    public static final String TERMUX_PKG = "com.termux";
    public static final String PERMISSION = "com.termux.permission.RUN_COMMAND";
    public static final String TERMUX_HOME = "/data/data/com.termux/files/home";
    public static final String TERMUX_PREFIX = "/data/data/com.termux/files/usr";
    public static final String ACTION_RUN = "com.termux.RUN_COMMAND";
    public static final String ACTION_RESULT = "com.nexos.reamobile.REE_TERMUX_RESULT";
    public static final String EXTRA_LABEL = "ree_label";
    public static final String EXTRA_PATH = "com.termux.RUN_COMMAND_PATH";
    public static final String EXTRA_ARGUMENTS = "com.termux.RUN_COMMAND_ARGUMENTS";
    public static final String EXTRA_WORKDIR = "com.termux.RUN_COMMAND_WORKDIR";
    public static final String EXTRA_BACKGROUND = "com.termux.RUN_COMMAND_BACKGROUND";
    public static final String EXTRA_SESSION_ACTION = "com.termux.RUN_COMMAND_SESSION_ACTION";
    public static final String EXTRA_COMMAND_LABEL = "com.termux.RUN_COMMAND_COMMAND_LABEL";
    public static final String EXTRA_PENDING_INTENT = "com.termux.RUN_COMMAND_PENDING_INTENT";
    /** Acción de sesión heredada de NEXUS (String "0", probada en producción). */
    public static final String SESSION_ACTION = "0";
    /** Tope de script para no acercarse al límite de Binder (~1 MB). */
    public static final int MAX_SCRIPT_CHARS = 65536;
    /** Longitud máxima de etiqueta (formato ree:&lt;op&gt;:&lt;id&gt;). */
    public static final int MAX_LABEL_CHARS = 64;

    private static final AtomicInteger counter = new AtomicInteger(100);

    private ReaTermuxBridge() {
    }

    /** Etiqueta válida: [A-Za-z0-9][A-Za-z0-9_.:-]* de 1 a 64 caracteres. */
    public static boolean validLabel(String label) {
        return label != null && label.length() <= MAX_LABEL_CHARS
                && label.matches("[A-Za-z0-9][A-Za-z0-9_.:-]*");
    }

    @SuppressWarnings("deprecation")
    public static boolean isInstalled(Context c) {
        try {
            c.getPackageManager().getPackageInfo(TERMUX_PKG, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    public static boolean hasPermission(Context c) {
        return c.checkSelfPermission(PERMISSION) == PackageManager.PERMISSION_GRANTED;
    }

    public static void requestPermission(Activity a) {
        a.requestPermissions(new String[] { PERMISSION }, 1);
    }

    /**
     * Ejecuta un script en bash de Termux.
     *
     * @param background true = sin terminal, devuelve stdout/stderr por broadcast;
     *                   false = abre sesión visible en Termux.
     * @return null si se envió correctamente, o un mensaje de error en español.
     */
    public static String run(Context c, String label, String script, boolean background) {
        if (c == null) return "Sin contexto Android.";
        if (!validLabel(label)) return "Etiqueta REE inválida.";
        if (script == null || script.isEmpty()) return "Script vacío.";
        if (script.length() > MAX_SCRIPT_CHARS) return "Script mayor de 64 KB.";
        try {
            Intent i = new Intent(ACTION_RUN);
            i.setClassName(TERMUX_PKG, "com.termux.app.RunCommandService");
            i.putExtra(EXTRA_PATH, TERMUX_PREFIX + "/bin/bash");
            i.putExtra(EXTRA_ARGUMENTS, new String[] { "-c", script });
            i.putExtra(EXTRA_WORKDIR, TERMUX_HOME);
            i.putExtra(EXTRA_BACKGROUND, background);
            i.putExtra(EXTRA_SESSION_ACTION, SESSION_ACTION);
            i.putExtra(EXTRA_COMMAND_LABEL, label);

            Intent cb = new Intent(ACTION_RESULT);
            cb.setPackage(c.getPackageName());
            cb.putExtra(EXTRA_LABEL, label);
            int flags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;
            PendingIntent pi = PendingIntent.getBroadcast(c, counter.getAndIncrement(), cb, flags);
            i.putExtra(EXTRA_PENDING_INTENT, pi);

            c.startService(i);
            return null;
        } catch (SecurityException e) {
            return "Permiso denegado. Concede RUN_COMMAND a REA y activa allow-external-apps en Termux. (" + e.getMessage() + ")";
        } catch (Exception e) {
            return "No se pudo contactar con Termux: " + e;
        }
    }

    /** Escapa un texto para ponerlo entre comillas simples en bash. */
    public static String sq(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }
}
