package com.nexos.reamobile

import java.io.File

/** Caché de sesión entre pantallas (se libera al re-analizar o salir del visor). */
object Session {
    var apk: File? = null
    var pkg: String = "?"
    var appClasses: List<String> = emptyList()
    var appClassTotal: Int = 0
    var dexBytes: List<ByteArray> = emptyList()
    val smaliCache = LinkedHashMap<String, String>()
    var smaliTruncated = false
    val jadxCache = LinkedHashMap<String, String>()
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
    }
}
