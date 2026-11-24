package com.nexos.reamobile.engine;

/**
 * Mapeo reducido API→permiso (estilo PScout) + lista de permisos de riesgo.
 * Java puro. Nunca lanza.
 */
public final class PermApiTable {
    private PermApiTable() {
    }

    private static final String[][] TABLE = {
            {"Landroid/media/AudioRecord;", "RECORD_AUDIO"},
            {"Landroid/media/MediaRecorder;", "RECORD_AUDIO"},
            {"Landroid/speech/SpeechRecognizer;", "RECORD_AUDIO"},
            {"Landroid/hardware/Camera;", "CAMERA"},
            {"Landroid/hardware/camera2/CameraManager;", "CAMERA"},
            {"Landroid/location/", "ACCESS_FINE_LOCATION"},
            {"Lcom/google/android/gms/location/", "ACCESS_FINE_LOCATION"},
            {"Lcom/google/android/gms/maps/", "ACCESS_FINE_LOCATION"},
            {"Landroid/telephony/SmsManager;", "SEND_SMS"},
            {"Landroid/telephony/TelephonyManager;", "READ_PHONE_STATE"},
            {"Landroid/telephony/SubscriptionManager;", "READ_PHONE_STATE"},
            {"Landroid/provider/ContactsContract;", "READ_CONTACTS"},
            {"Landroid/provider/CallLog;", "READ_CALL_LOG"},
            {"Landroid/provider/Telephony;", "READ_SMS"},
            {"Landroid/accounts/AccountManager;", "GET_ACCOUNTS"},
            {"Landroid/bluetooth/BluetoothAdapter;", "BLUETOOTH"},
            {"Landroid/bluetooth/le/BluetoothLeScanner;", "BLUETOOTH_SCAN"},
            {"Landroid/net/wifi/WifiManager;", "ACCESS_WIFI_STATE"},
            {"Landroid/net/wifi/WifiScanner;", "ACCESS_WIFI_STATE"},
            {"Landroid/hardware/SensorManager;", "BODY_SENSORS"},
            {"Ljava/net/", "INTERNET"},
            {"Ljavax/net/", "INTERNET"},
            {"Landroid/webkit/WebView;", "INTERNET"},
            {"Lokhttp3/", "INTERNET"},
            {"Lcom/squareup/okhttp/", "INTERNET"},
            {"Lcom/android/volley/", "INTERNET"},
            {"Lretrofit2/", "INTERNET"},
            {"Lorg/chromium/net/", "INTERNET"},
            {"Lorg/apache/http/", "INTERNET"},
            {"Landroid/os/PowerManager;", "WAKE_LOCK"},
            {"Landroid/app/admin/DevicePolicyManager;", "BIND_DEVICE_ADMIN"},
            {"Landroid/accessibilityservice/", "BIND_ACCESSIBILITY_SERVICE"},
            {"Landroid/os/Vibrator;", "VIBRATE"},
            {"Landroid/app/NotificationManager;", "POST_NOTIFICATIONS"},
            {"Landroid/provider/MediaStore;", "READ_EXTERNAL_STORAGE"},
            {"Landroid/media/MediaScannerConnection;", "READ_EXTERNAL_STORAGE"},
            {"Landroid/app/WallpaperManager;", "SET_WALLPAPER"},
    };

    /** Permisos que marcan riesgo/privacidad al declararse. */
    public static final String[] RISKY = {
            "MANAGE_EXTERNAL_STORAGE",
            "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "SYSTEM_ALERT_WINDOW",
            "BIND_ACCESSIBILITY_SERVICE",
            "REQUEST_INSTALL_PACKAGES",
            "READ_SMS",
            "SEND_SMS",
            "RECEIVE_SMS",
            "READ_CALL_LOG",
            "PROCESS_OUTGOING_CALLS",
            "READ_PHONE_NUMBERS",
            "ACCESS_BACKGROUND_LOCATION",
            "QUERY_ALL_PACKAGES",
            "BIND_DEVICE_ADMIN",
            "RECORD_AUDIO",
            "CAMERA",
            "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION",
            "READ_CONTACTS",
            "WRITE_CONTACTS",
            "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE",
            "ACTIVITY_RECOGNITION",
            "BODY_SENSORS",
    };

    /** Permiso que ampara una llamada "Lclase;->metodo", o null. Nunca lanza. */
    public static String permissionFor(String callee) {
        try {
            if (callee == null) return null;
            for (String[] e : TABLE) {
                if (callee.startsWith(e[0])) return e[1];
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** true si el nombre corto de permiso está en la lista de riesgo. Nunca lanza. */
    public static boolean isRisky(String perm) {
        try {
            if (perm == null) return false;
            String shortName = perm;
            int dot = perm.lastIndexOf('.');
            if (dot >= 0) shortName = perm.substring(dot + 1);
            for (String r : RISKY) {
                if (r.equals(shortName)) return true;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }
}
