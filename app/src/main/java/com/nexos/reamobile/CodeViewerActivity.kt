package com.nexos.reamobile

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ContentValues
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.provider.MediaStore
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import com.nexos.reamobile.engine.JadxAdapter
import com.nexos.reamobile.engine.SmaliDumper
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipFile

/** Visor Fase 4: clases propias con pestañas Smali/Java, búsqueda y exportación. */
class CodeViewerActivity : Activity() {

    private lateinit var list: ListView
    private lateinit var adapter: ArrayAdapter<String>
    private lateinit var code: TextView
    private lateinit var status: TextView
    private lateinit var hits: TextView
    private lateinit var search: EditText
    private lateinit var codeSearch: EditText
    private lateinit var btnSmali: Button
    private lateinit var btnJava: Button
    private lateinit var btnDecompile: Button
    private lateinit var btnStop: Button
    private lateinit var btnExport: Button
    private lateinit var progress: ProgressBar
    private var filtered: List<String> = emptyList()
    private var selected: String? = null
    private var modeSmali = true
    private var working = false
    @Volatile private var stopRequested = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val apk = Session.apk
        if (apk == null || !apk.isFile()) {
            finish()
            return
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 16, 16, 16)
        }
        val title = TextView(this).apply {
            text = "Código — " + Session.pkg
            textSize = 18f
        }
        search = EditText(this).apply { hint = "filtrar clases…" }
        val btnFilter = Button(this).apply { text = "Filtrar" }
        val rowSearch = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(search, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnFilter)
        }
        list = ListView(this)
        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, mutableListOf<String>())
        list.adapter = adapter
        status = TextView(this).apply { textSize = 12f }
        hits = TextView(this).apply { textSize = 12f }
        btnSmali = Button(this).apply { text = "Smali" }
        btnJava = Button(this).apply { text = "Java" }
        btnDecompile = Button(this).apply { text = "Descompilar" }
        btnStop = Button(this).apply { text = "Detener"; isEnabled = false }
        val rowTabs = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(btnSmali, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnJava, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnDecompile, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnStop, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        }
        codeSearch = EditText(this).apply { hint = "buscar en código…" }
        val btnFind = Button(this).apply { text = "Buscar" }
        btnExport = Button(this).apply { text = "Exportar" }
        val rowFind = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(codeSearch, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnFind)
            addView(btnExport)
        }
        progress = ProgressBar(this).apply { visibility = View.GONE }
        val scroll = ScrollView(this)
        code = TextView(this).apply {
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        scroll.addView(code)

        root.addView(title)
        root.addView(rowSearch)
        root.addView(list, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        root.addView(status)
        root.addView(rowTabs)
        root.addView(rowFind)
        root.addView(hits)
        root.addView(progress)
        root.addView(scroll, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 2f))
        setContentView(root)

        btnFilter.setOnClickListener { applyFilter() }
        btnFind.setOnClickListener { findInCode() }
        btnSmali.setOnClickListener { modeSmali = true; showCode() }
        btnJava.setOnClickListener { modeSmali = false; showCode() }
        btnDecompile.setOnClickListener { decompile(apk) }
        btnStop.setOnClickListener { stopRequested = true }
        btnExport.setOnClickListener { exportCurrent() }
        list.onItemClickListener =
            AdapterView.OnItemClickListener { _, _, pos, _ ->
                if (pos in filtered.indices) selectClass(filtered[pos])
            }

        refreshList(Session.appClasses)
        updateStatus("Cargando dex…")
        loadDex(apk)
    }

    override fun onDestroy() {
        Session.dexBytes = emptyList()
        super.onDestroy()
    }

    /** Estado de trabajo + botón Descompilar bloqueado mientras hay tarea. */
    private fun markWorking(on: Boolean) {
        working = on
        btnDecompile.isEnabled = !on
    }

    private fun refreshList(items: List<String>) {
        filtered = items
        adapter.clear()
        adapter.addAll(items.map { shortName(it) })
        adapter.notifyDataSetChanged()
    }

    private fun shortName(desc: String): String =
        desc.removePrefix("L").removeSuffix(";")

    private fun applyFilter() {
        val q = search.text.toString().trim()
        val base = if (Session.appClasses.isNotEmpty()) Session.appClasses
            else Session.smaliCache.keys.sorted()
        refreshList(if (q.isEmpty()) base else base.filter { it.contains(q, ignoreCase = true) })
        updateStatus()
    }

    private fun selectClass(desc: String) {
        selected = desc
        showCode()
    }

    private fun showCode() {
        val sel = selected
        if (sel == null) {
            code.text = "(elige una clase)"
            return
        }
        if (modeSmali) {
            val smali = Session.smaliCache[sel]
            if (smali != null) {
                code.text = smali
            } else {
                code.text = "(dump smali parcial…)"
                dumpSingle(sel)
            }
        } else {
            val text = JadxAdapter.candidateKeys(sel)
                .asSequence()
                .mapNotNull { Session.jadxCache[it] }
                .firstOrNull()
            code.text = text ?: ("(sin Java para ${shortName(sel)}"
                + " — caché: ${Session.jadxCache.size}"
                + (Session.jadxError?.let { " — error: $it" } ?: "") + ")")
        }
    }

    private fun dumpSingle(desc: String) {
        if (working) return
        markWorking(true)
        progress.visibility = View.VISIBLE
        Thread {
            if (Session.dexBytes.isEmpty()) ensureDex()
            val text = try {
                if (Session.dexBytes.isEmpty()) null
                else SmaliDumper.dumpSingleClass(Session.dexBytes, desc)
            } catch (e: Throwable) {
                null
            }
            if (text != null) Session.smaliCache[desc] = text
            runOnUiThread {
                markWorking(false)
                progress.visibility = View.GONE
                if (selected == desc && modeSmali) code.text = text ?: "(sin smali)"
            }
        }.start()
    }

    private fun loadDex(apk: File) {
        if (Session.dexBytes.isNotEmpty()) {
            preloadSmali()
            return
        }
        markWorking(true)
        progress.visibility = View.VISIBLE
        Thread {
            ensureDex()
            runOnUiThread { preloadSmali() }
        }.start()
    }

    /** Lee los dex del APK a memoria si la caché está vacía (hilo de fondo). */
    private fun ensureDex() {
        if (Session.dexBytes.isNotEmpty()) return
        val apk = Session.apk
        if (apk == null || !apk.isFile()) return
        val dexes = mutableListOf<ByteArray>()
        try {
            ZipFile(apk).use { zip ->
                val en = zip.entries()
                while (en.hasMoreElements()) {
                    val e = en.nextElement()
                    if (!e.isDirectory && e.name.matches(Regex("classes\\d*\\.dex"))) {
                        readCapped(zip, e, 160L * 1024 * 1024)?.let { dexes.add(it) }
                    }
                }
            }
        } catch (e: Throwable) {
            // se informa en estado
        }
        Session.dexBytes = dexes
    }

    private fun readCapped(zip: ZipFile, e: java.util.zip.ZipEntry, max: Long): ByteArray? {
        return try {
            zip.getInputStream(e).use { inp ->
                val bos = ByteArrayOutputStream()
                val buf = ByteArray(32768)
                var total = 0L
                while (true) {
                    val n = inp.read(buf)
                    if (n <= 0) break
                    total += n
                    if (total > max) return null
                    bos.write(buf, 0, n)
                }
                bos.toByteArray()
            }
        } catch (ex: Exception) {
            null
        }
    }

    private fun preloadSmali() {
        if (Session.smaliCache.isNotEmpty()) {
            markWorking(false)
            progress.visibility = View.GONE
            if (Session.appClasses.isEmpty()) refreshList(Session.smaliCache.keys.sorted())
            autoSelect()
            updateStatus()
            return
        }
        Thread {
            try {
                val res = SmaliDumper.dumpAll(Session.dexBytes, Session.pkgSlash())
                for (sc in res.classes) {
                    val desc = "L" + sc.path.removePrefix("smali/").removeSuffix(".smali") + ";"
                    Session.smaliCache[desc] = sc.text
                }
                Session.smaliTruncated = res.truncated
            } catch (t: Throwable) {
                // estado lo refleja
            }
            runOnUiThread {
                markWorking(false)
                progress.visibility = View.GONE
                if (Session.appClasses.isEmpty()) refreshList(Session.smaliCache.keys.sorted())
                autoSelect()
                updateStatus()
            }
        }.start()
    }

    private fun autoSelect() {
        if (selected == null && filtered.isNotEmpty()) selectClass(filtered[0])
        else showCode()
    }

    private fun decompile(apk: File) {
        if (working) return
        val memMsg = systemMemoryGate()
        if (memMsg != null) {
            updateStatus(memMsg)
            return
        }
        markWorking(true)
        stopRequested = false
        btnStop.isEnabled = true
        progress.visibility = View.VISIBLE
        updateStatus("Descompilando con JADX…")
        Thread {
            val prefixes = if (Session.pkg == "?") emptyList() else listOf(Session.pkgSlash())
            var fail: String? = null
            var res: JadxAdapter.Result? = null
            try {
                // Libera el mayor bloque (dex en RAM) antes de cargar JADX;
                // dumpSingle los recarga bajo demanda con ensureDex().
                Session.dexBytes = emptyList()
                System.gc()
                res = JadxAdapter.decompileFiltered(apk, cacheDir, 2, prefixes, 300,
                    object : JadxAdapter.Progress {
                        override fun onClass(done: Int, matched: Int): Boolean {
                            runOnUiThread { updateStatus("JADX $done clases…") }
                            return !stopRequested
                        }

                        override fun onPhase(name: String) {
                            runOnUiThread { updateStatus("JADX $name…") }
                        }
                    })
                if (res.error == null) {
                    Session.jadxCache.putAll(res.sources)
                    Session.jadxErrors = res.errors
                    Session.jadxTruncated = res.truncated
                } else if (res.sources.isNotEmpty()) {
                    Session.jadxCache.putAll(res.sources)
                    Session.jadxTruncated = true
                }
                Session.jadxDone = true
            } catch (t: OutOfMemoryError) {
                fail = "Memoria insuficiente: prueba con un APK más pequeño o cierra apps."
                Session.jadxDone = true
            } catch (t: Throwable) {
                fail = t.message
                Session.jadxDone = true
            } finally {
                Session.jadxError = res?.error ?: fail
                runOnUiThread {
                    markWorking(false)
                    btnStop.isEnabled = false
                    progress.visibility = View.GONE
                    modeSmali = false
                    showCode()
                    updateStatus(res?.error ?: fail)
                }
            }
        }.start()
    }

    /** Barrera previa: si el sistema está en memoria baja, ni se intenta. */
    private fun systemMemoryGate(): String? {
        return try {
            val am = getSystemService(ACTIVITY_SERVICE) as android.app.ActivityManager
            val info = android.app.ActivityManager.MemoryInfo()
            am.getMemoryInfo(info)
            if (info.lowMemory || info.availMem < 60L * 1024 * 1024) {
                "Memoria del sistema baja: cierra apps e inténtalo de nuevo."
            } else null
        } catch (t: Throwable) {
            null
        }
    }

    private fun updateStatus(extra: String? = null) {
        val sb = StringBuilder()
        sb.append("clases: ").append(filtered.size)
        if (Session.appClassTotal > 0) sb.append(" (total ").append(Session.appClassTotal).append(")")
        sb.append(" | smali: ").append(Session.smaliCache.size)
        if (Session.smaliTruncated) sb.append("+recorte")
        sb.append(" | java: ").append(Session.jadxCache.size)
        if (Session.jadxDone) sb.append(" err=").append(Session.jadxErrors)
        if (Session.jadxTruncated) sb.append("+recorte")
        if (!Session.jadxDone) sb.append(" (sin descompilar)")
        if (extra != null && extra.isNotEmpty()) sb.append("\n").append(extra)
        status.text = sb.toString()
    }

    private fun findInCode() {
        val q = codeSearch.text.toString()
        if (q.isEmpty()) {
            hits.text = ""
            return
        }
        val text = code.text.toString()
        var count = 0
        val lines = mutableListOf<Int>()
        var idx = text.indexOf(q)
        while (idx >= 0 && count < 1000) {
            count++
            if (lines.size < 5) lines.add(text.substring(0, idx).count { it == '\n' } + 1)
            idx = text.indexOf(q, idx + 1)
        }
        hits.text = if (count == 0) "sin coincidencias"
            else "$count coincidencias (líneas ${lines.joinToString()})"
    }

    private fun exportCurrent() {
        val sel = selected
        val text = code.text.toString()
        if (sel == null || text.isEmpty()) return
        val ext = if (modeSmali) "smali" else "java"
        val simple = sel.removePrefix("L").removeSuffix(";").substringAfterLast('/').replace('$', '_')
        try {
            val dest = saveTextToDownloads(text, "$simple.$ext")
            hits.text = "Guardado: $dest"
        } catch (e: Exception) {
            hits.text = "Error exportando: ${e.message}"
        }
    }

    @SuppressLint("NewApi")
    private fun saveTextToDownloads(text: String, name: String): String {
        val safePkg = if (Session.pkg == "?") "apk" else Session.pkg.replace('.', '_')
        if (Build.VERSION.SDK_INT >= 29) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                put(MediaStore.Downloads.RELATIVE_PATH, "Download/REA-Mobile/$safePkg")
            }
            val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw IllegalStateException("MediaStore rechazó la inserción")
            contentResolver.openOutputStream(uri)?.use { out ->
                out.write(text.toByteArray())
            } ?: throw IllegalStateException("sin stream de salida")
            return "Descargas/REA-Mobile/$safePkg/$name"
        } else {
            val dir = getExternalFilesDir(null)
                ?: throw IllegalStateException("sin almacenamiento externo")
            val dest = File(dir, name)
            FileOutputStream(dest).use { it.write(text.toByteArray()) }
            return dest.absolutePath
        }
    }
}
