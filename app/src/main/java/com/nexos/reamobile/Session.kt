package com.nexos.reamobile

import java.io.File
import java.util.Collections
import java.util.LinkedHashMap

/** Caché de sesión entre pantallas (se libera al re-analizar o salir del visor). */
object Session {
    var apk: File? = null
    var pkg: String = "?"
    var appClasses: List<String> = emptyList()
    var appClassTotal: Int = 0
    var dexBytes: List<ByteArray> = emptyList()
    /** Tope de clases por caché (H6): LRU, sincronizado, con instantáneas. */
    const val MAX_CACHE_CLASSES = 400
    /** Tope de caracteres por caché (P1-4): 400 entradas × 2 MB era teórico. */
    const val MAX_CACHE_CHARS = 20_000_000
    private fun <K, V> lru(): MutableMap<K, V> = Collections.synchronizedMap(
        object : LinkedHashMap<K, V>(64, 0.75f, true) {
            override fun removeEldestEntry(e: Map.Entry<K, V>): Boolean =
                size > MAX_CACHE_CLASSES
        })
    val smaliCache: MutableMap<String, String> = lru()
    var smaliTruncated = false
    val jadxCache: MutableMap<String, String> = lru()
    /** Inserta recortando por bytes además de por entradas (P1-4). */
    fun putSmali(key: String, value: String) {
        smaliCache[key] = value
        trimCache(smaliCache)
    }
    fun putJadx(key: String, value: String) {
        jadxCache[key] = value
        trimCache(jadxCache)
    }
    /** Recorta las entradas más antiguas hasta el tope de caracteres. */
    fun trimCache(map: MutableMap<String, String>) {
        synchronized(map) {
            var total = 0
            for (v in map.values) total += v.length
            if (total <= MAX_CACHE_CHARS) return
            val it = map.entries.iterator()
            while (total > MAX_CACHE_CHARS && it.hasNext()) {
                val e = it.next()
                total -= e.value.length
                try {
                    it.remove()
                } catch (t: Throwable) {
                    return
                }
            }
        }
    }
    /** Recorta ambas cachés (tras putAll masivos). */
    fun trimCaches() {
        trimCache(smaliCache)
        trimCache(jadxCache)
    }
    /** Instantáneas para iterar sin ConcurrentModificationException. */
    fun smaliSnapshot(): LinkedHashMap<String, String> =
        synchronized(smaliCache) { LinkedHashMap(smaliCache) }
    fun jadxSnapshot(): LinkedHashMap<String, String> =
        synchronized(jadxCache) { LinkedHashMap(jadxCache) }
    var jadxErrors = 0
    var jadxTruncated = false
    var jadxDone = false
    var jadxError: String? = null
    var jadxLog: List<String> = emptyList()
    /** Generación de resultados JADX: ++ por cada descompilación terminada. */
    var jadxSeq = 0
    /** Hay una descompilación en curso (quizá de otra instancia del visor). */
    @Volatile var jadxRunning = false
    /** Último mensaje de progreso publicado por el hilo de fondo. */
    @Volatile var jadxProgressMsg = ""
    /** Secretos de alta señal hallados en el Java descompilado. */
    var jadxSecrets = 0
    /** Análisis/extracción en curso (globales: impiden doble trabajo entre instancias). */
    @Volatile var analyzing = false
    @Volatile var extracting = false
    /** Informe completo cacheado (H8): se reutiliza si el APK no cambió. */
    var lastFullReport: String? = null
    var lastFullReportKey: String = ""
    /** Resultado de autenticidad del último análisis (pantalla Autenticidad). */
    var auth: com.nexos.reamobile.engine.auth.AuthResult.Report? = null

    /** Tope de caracteres por vista de texto (H5): el dato completo sigue en caché. */
    const val MAX_VIEW_CHARS = 500000

    /** Recorta para TextView con marcador; el original queda intacto. */
    fun capForView(s: String): String {
        if (s.length <= MAX_VIEW_CHARS) return s
        return s.substring(0, MAX_VIEW_CHARS) + "\n\n[…vista recortada: " + s.length +
            " caracteres en total…]"
    }

    fun pkgSlash(): String = if (pkg == "?") "?/" else pkg.replace('.', '/') + "/"

    fun resetCache() {
        dexBytes = emptyList()
        smaliCache.clear()
        smaliTruncated = false
        jadxCache.clear()
        jadxErrors = 0
        jadxTruncated = false
        jadxDone = false
        jadxError = null
        jadxLog = emptyList()
        jadxSeq = 0
        jadxRunning = false
        jadxProgressMsg = ""
        jadxSecrets = 0
        lastFullReport = null
        lastFullReportKey = ""
    }
}
