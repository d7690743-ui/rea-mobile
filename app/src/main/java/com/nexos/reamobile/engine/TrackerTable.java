package com.nexos.reamobile.engine;

/**
 * Tabla reducida de SDK/trackers por prefijo de paquete (estilo Exodus).
 * Java puro. Nunca lanza.
 */
public final class TrackerTable {
    private TrackerTable() {
    }

    private static final String[][] TABLE = {
            {"com/facebook", "Meta (Facebook SDK)"},
            {"com/appsflyer", "AppsFlyer"},
            {"com/adjust", "Adjust"},
            {"com/google/firebase", "Firebase"},
            {"com/google/android/gms", "Google Play Services"},
            {"com/google/ads", "Google Ads"},
            {"com/google/analytics", "Google Analytics"},
            {"com/mixpanel", "Mixpanel"},
            {"com/amplitude", "Amplitude"},
            {"com/segment", "Segment"},
            {"com/branch", "Branch"},
            {"io/branch", "Branch"},
            {"com/uxcam", "UXCam"},
            {"com/tealium", "Tealium"},
            {"com/kochava", "Kochava"},
            {"com/singular", "Singular"},
            {"com/tenjin", "Tenjin"},
            {"com/ironsource", "ironSource"},
            {"com/applovin", "AppLovin"},
            {"com/mopub", "MoPub"},
            {"com/inmobi", "InMobi"},
            {"com/chartboost", "Chartboost"},
            {"com/vungle", "Vungle"},
            {"com/startapp", "StartApp"},
            {"com/moengage", "MoEngage"},
            {"com/clevertap", "CleverTap"},
            {"com/onesignal", "OneSignal"},
            {"com/urbanairship", "Airship"},
            {"com/braze", "Braze"},
            {"com/leanplum", "Leanplum"},
            {"com/sentry", "Sentry"},
            {"io/sentry", "Sentry"},
            {"com/bugsnag", "BugSnag"},
            {"com/crashlytics", "Crashlytics"},
            {"ly/count", "Countly"},
            {"com/flurry", "Flurry"},
            {"com/localytics", "Localytics"},
            {"com/tapjoy", "Tapjoy"},
            {"com/fyber", "Fyber"},
            {"com/adcolony", "AdColony"},
            {"com/smaato", "Smaato"},
            {"com/millennialmedia", "Millennial Media"},
            {"com/tune", "TUNE"},
            {"com/kahuna", "Kahuna"},
            {"com/supersonic", "Supersonic"},
            {"com/appboy", "Appboy (Braze)"},
            {"com/unity3d/ads", "Unity Ads"},
    };

    /** Nombre del tracker para un prefijo ("com/facebook") o descriptor, o null. Nunca lanza. */
    public static String match(String prefixOrDesc) {
        try {
            if (prefixOrDesc == null) return null;
            String p = prefixOrDesc;
            if (p.startsWith("L")) p = p.substring(1);
            for (String[] e : TABLE) {
                if (p.startsWith(e[0])) return e[1];
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
