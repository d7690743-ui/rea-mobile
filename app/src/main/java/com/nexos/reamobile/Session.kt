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

    fun pkgSlash(): String = if (pkg == "?") "?/" else pkg.replace('.', '/') + "/"

    fun resetCache() {
        dexBytes = emptyList()
        smaliCache.clear()
        smaliTruncated = false
        jadxCache.clear()
        jadxErrors = 0
        jadxTruncated = false
        jadxDone = false
    }
}
