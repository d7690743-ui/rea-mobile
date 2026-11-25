package com.nexos.reamobile.ree;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;

/**
 * REE Fase B: receptor dinámico de resultados RUN_COMMAND.
 *
 * <p>Generaliza el patrón de NEXUS Agents (MainActivity/ChatActivity):
 * filtrado por prefijo de etiqueta y lectura de stdout/stderr/exitCode más
 * err/errmsg. Registrar solo mientras se espera una respuesta y retirar
 * después; no depende de que una Activity siga abierta en FASE E.
 */
public class ReaTermuxReceiver extends BroadcastReceiver {

    public static final String RESULT_STDOUT = "stdout";
    public static final String RESULT_STDERR = "stderr";
    public static final String RESULT_EXIT_CODE = "exitCode";
    public static final String RESULT_ERR = "err";
    public static final String RESULT_ERRMSG = "errmsg";

    /** Resultado inmutable de una ejecución externa (cadenas tal cual las envía Termux). */
    public static final class Result {
        public final String label;
        public final String stdout;
        public final String stderr;
        public final int exitCode;
        public final String err;
        public final String errmsg;

        public Result(String label, String stdout, String stderr, int exitCode,
                String err, String errmsg) {
            this.label = label;
            this.stdout = stdout;
            this.stderr = stderr;
            this.exitCode = exitCode;
            this.err = err;
            this.errmsg = errmsg;
        }
    }

    public interface Listener {
        void onResult(Result r);
    }

    private final String prefix;
    private final Listener listener;

    public ReaTermuxReceiver(String prefix, Listener listener) {
        this.prefix = prefix;
        this.listener = listener;
    }

    /** Filtro puro (probable en JVM): acepta etiquetas con el prefijo esperado. */
    public static boolean accepts(String label, String prefix) {
        return label != null && prefix != null && label.startsWith(prefix);
    }

    @Override
    public void onReceive(Context c, Intent intent) {
        if (intent == null || listener == null) return;
        String label = intent.getStringExtra(ReaTermuxBridge.EXTRA_LABEL);
        if (!accepts(label, prefix)) return;
        listener.onResult(new Result(label,
                intent.getStringExtra(RESULT_STDOUT),
                intent.getStringExtra(RESULT_STDERR),
                intent.getIntExtra(RESULT_EXIT_CODE, -1),
                intent.getStringExtra(RESULT_ERR),
                intent.getStringExtra(RESULT_ERRMSG)));
    }

    /** Registra el receptor como no exportado (la respuesta va dirigida a este package). */
    @SuppressWarnings("deprecation")
    public static ReaTermuxReceiver register(Context c, String prefix, Listener l) {
        ReaTermuxReceiver r = new ReaTermuxReceiver(prefix, l);
        IntentFilter f = new IntentFilter(ReaTermuxBridge.ACTION_RESULT);
        if (Build.VERSION.SDK_INT >= 33) {
            c.registerReceiver(r, f, Context.RECEIVER_NOT_EXPORTED);
        } else {
            c.registerReceiver(r, f);
        }
        return r;
    }

    /** Retira el receptor; tolera doble retirada. */
    public static void unregister(Context c, ReaTermuxReceiver r) {
        if (c == null || r == null) return;
        try {
            c.unregisterReceiver(r);
        } catch (IllegalArgumentException e) {
            // Ya retirado: sin efecto.
        }
    }
}
