package com.nexos.reamobile

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ContentValues
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
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
import com.nexos.reamobile.engine.FullReport
import com.nexos.reamobile.engine.JadxAdapter
import com.nexos.reamobile.engine.JavaHarvest
import com.nexos.reamobile.engine.PhantomDecompile
import com.nexos.reamobile.engine.ReaEngine
import com.nexos.reamobile.engine.SmaliDumper
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
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
    private lateinit var btnLog: Button
    private lateinit var btnZip: Button
    private lateinit var btnReport: Button
    private var lastFindQuery = ""
    private var lastFindMatches: List<JavaHarvest.Hit> = emptyList()
    private var lastFindIdx = -1
    private lateinit var progress: ProgressBar
    private var filtered: List<String> = emptyList()
    private var selected: String? = null
    private var modeSmali = true
    private var showingLog = false
    private var working = false
    @Volatile private var stopRequested = false
    private var seenSeq = 0
    private val tickHandler = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() {
            tickForeign()
            tickHandler.postDelayed(this, 500)
        }
    }

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
        btnLog = Button(this).apply { text = "Log" }
        val rowTabs = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(btnSmali, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnJava, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnDecompile, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnStop, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnLog, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        }
        codeSearch = EditText(this).apply { hint = "buscar en código…" }
        val btnFind = Button(this).apply { text = "Buscar" }
        btnExport = Button(this).apply { text = "Exportar" }
        btnZip = Button(this).apply { text = "Zip" }
        btnReport = Button(this).apply { text = "Informe" }
        val rowFind = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(codeSearch, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(btnFind)
            addView(btnExport)
            addView(btnZip)
        }
        val rowReport = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(btnReport, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT))
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
        root.addView(rowReport)
        root.addView(hits)
        root.addView(progress)
        root.addView(scroll, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 2f))
        setContentView(root)

        btnFilter.setOnClickListener { applyFilter() }
        btnFind.setOnClickListener { findInCode() }
        btnSmali.setOnClickListener { modeSmali = true; showingLog = false; showCode() }
        btnJava.setOnClickListener { modeSmali = false; showingLog = false; showCode() }
        btnDecompile.setOnClickListener { decompile(apk) }
        btnStop.setOnClickListener { stopRequested = true }
        btnLog.setOnClickListener { toggleLog() }
        btnExport.setOnClickListener { exportCurrent() }
        btnZip.setOnClickListener { exportJavaZip() }
        btnReport.setOnClickListener { generateFullReport() }
        list.onItemClickListener =
            AdapterView.OnItemClickListener { _, _, pos, _ ->
                if (pos in filtered.indices) selectClass(filtered[pos])
            }

        refreshList(Session.appClasses)
        updateStatus("Cargando dex…")
        loadDex(apk)
        seenSeq = Session.jadxSeq
    }

    override fun onResume() {
        super.onResume()
        tickHandler.post(ticker)
    }

    override fun onPause() {
        tickHandler.removeCallbacks(ticker)
        super.onPause()
    }

    /** Sincroniza con descompilaciones de otra instancia: progreso vivo y refresco final. */
    private fun tickForeign() {
        if (working) return
        if (Session.jadxRunning) updateStatus(Session.jadxProgressMsg.ifEmpty { "descompilando…" })
        if (Session.jadxSeq == seenSeq) return
        seenSeq = Session.jadxSeq
        refreshList(filtered)
        if (!showingLog && !modeSmali) {
            selectFirstWithJava()
            showCode()
        }
        updateStatus()
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
        val mark = Session.jadxDone
        adapter.addAll(items.map {
            (if (mark) (if (JadxAdapter.hasJava(it, Session.jadxCache)) "● " else "○ ") else "") +
                shortName(it)
        })
        adapter.notifyDataSetChanged()
    }

    /** Si la selección actual no tiene Java, salta a la primera que sí. */
    private fun selectFirstWithJava() {
        val sel = selected
        if (sel != null && JadxAdapter.hasJava(sel, Session.jadxCache)) return
        JadxAdapter.firstWithJava(filtered, Session.jadxCache)?.let { selected = it }
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
        showingLog = false
        showCode()
    }

    private fun toggleLog() {
        showingLog = !showingLog
        if (!showingLog) {
            showCode()
            return
        }
        val log = Session.jadxLog
        code.text = if (log.isEmpty()) "(log vacío: aún no se descompila)"
        else log.joinToString("\n")
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
            var text = JadxAdapter.candidateKeys(sel)
                .asSequence()
                .mapNotNull { Session.jadxCache[it] }
                .firstOrNull()
            // Inners vacías (lambdas, R$*): van incluidas en la externa.
            var viaOuter: String? = null
            if (text.isNullOrBlank()) {
                outer@ for (k in JadxAdapter.candidateKeys(sel)) {
                    for (ok in JadxAdapter.outerKeys(k)) {
                        val t = Session.jadxCache[ok]
                        if (!t.isNullOrBlank()) {
                            text = t
                            viaOuter = ok
                            break@outer
                        }
                    }
                }
            }
            if (!text.isNullOrBlank()) {
                code.text = (if (viaOuter != null) "// (esta clase va incluida en $viaOuter)\n\n" else "") + text
            } else if (working || Session.jadxRunning) {
                val prog = Session.jadxProgressMsg.ifEmpty { "descompilando…" }
                code.text = "(descompilando… $prog — la vista se actualizará sola)"
            } else {
                code.text = ("(sin Java para ${shortName(sel)}"
                    + " — caché: ${Session.jadxCache.size}"
                    + (Session.jadxError?.let { " — error: $it" } ?: "") + ")")
            }
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
        Session.jadxRunning = true
        Session.jadxProgressMsg = "iniciando…"
        Thread {
            val prefixes = if (Session.pkg == "?") emptyList() else listOf(Session.pkgSlash())
            var fail: String? = null
            var res: JadxAdapter.Result? = null
            try {
                // Libera el mayor bloque (dex en RAM) antes de cargar JADX;
                // dumpSingle los recarga bajo demanda con ensureDex().
                Session.dexBytes = emptyList()
                System.gc()
                val heap = try {
                    Runtime.getRuntime().maxMemory()
                } catch (t: Throwable) {
                    256L * 1024 * 1024
                }
                // PHANTOM: prioridad dirigida (entradas+pantallas+grupos); si falla,
                // lista vacía = orden de carga de siempre.
                val prio: List<String> = try {
                    val rep = ReaEngine.analyze(apk)
                    val p = PhantomDecompile.priority(rep,
                        JadxAdapter.recommendedCap(heap))
                    System.gc()
                    p
                } catch (t: Throwable) {
                    emptyList()
                }
                res = JadxAdapter.decompileFiltered(apk, cacheDir,
                    JadxAdapter.recommendedThreads(heap), prefixes,
                    JadxAdapter.recommendedCap(heap),
                    object : JadxAdapter.Progress {
                        override fun onClass(done: Int, matched: Int): Boolean {
                            Session.jadxProgressMsg = "JADX $done clases…"
                            runOnUiThread { updateStatus("JADX $done clases…") }
                            return !stopRequested
                        }

                        override fun onPhase(name: String) {
                            Session.jadxProgressMsg = "JADX $name…"
                            runOnUiThread { updateStatus("JADX $name…") }
                        }
                    }, prio)
                if (res.error == null) {
                    Session.jadxCache.putAll(res.sources)
                    Session.jadxErrors = res.errors
                    Session.jadxTruncated = res.truncated
                } else if (res.sources.isNotEmpty()) {
                    Session.jadxCache.putAll(res.sources)
                    Session.jadxErrors = res.errors
                    Session.jadxTruncated = true
                }
                val secs = try {
                    JavaHarvest.findSecrets(Session.jadxCache, 200)
                } catch (t: Throwable) {
                    emptyList<JavaHarvest.Hit>()
                }
                Session.jadxSecrets = secs.size
                val logPlus = res.log.toMutableList()
                for (h in secs.take(10)) logPlus.add("[sec] ${h.className}:${h.line} ${h.snippet}")
                Session.jadxLog = logPlus.toList()
                Session.jadxDone = true
            } catch (t: OutOfMemoryError) {
                fail = "Memoria insuficiente: prueba con un APK más pequeño o cierra apps."
                Session.jadxDone = true
            } catch (t: Throwable) {
                fail = t.message
                Session.jadxDone = true
            } finally {
                Session.jadxError = res?.error ?: fail
                Session.jadxRunning = false
                Session.jadxProgressMsg = ""
                Session.jadxSeq++
                runOnUiThread {
                    markWorking(false)
                    btnStop.isEnabled = false
                    progress.visibility = View.GONE
                    seenSeq = Session.jadxSeq
                    refreshList(filtered)
                    modeSmali = false
                    showingLog = false
                    selectFirstWithJava()
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
            .append(" sec=").append(Session.jadxSecrets)
        if (Session.jadxTruncated) sb.append("+recorte")
        if (!Session.jadxDone) sb.append(" (sin descompilar)")
        if (extra != null && extra.isNotEmpty()) sb.append("\n").append(extra)
        status.text = sb.toString()
    }

    private fun findInCode() {
        val q = codeSearch.text.toString()
        if (q.isEmpty()) {
            hits.text = ""
            lastFindQuery = ""
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
        var msg = if (count == 0) "sin coincidencias"
            else "$count coincidencias (líneas ${lines.joinToString()})"
        // Búsqueda global en el Java: repetir Buscar avanza al siguiente hit.
        if (Session.jadxCache.isNotEmpty()) {
            if (q != lastFindQuery) {
                lastFindMatches = try {
                    JavaHarvest.search(Session.jadxCache, q, true, 200)
                } catch (t: Throwable) {
                    emptyList()
                }
                lastFindIdx = -1
                lastFindQuery = q
            }
            if (lastFindMatches.isNotEmpty()) {
                lastFindIdx = (lastFindIdx + 1) % lastFindMatches.size
                val h = lastFindMatches[lastFindIdx]
                modeSmali = false
                showingLog = false
                val desc = filtered.firstOrNull { d ->
                    JadxAdapter.candidateKeys(d).contains(h.className)
                }
                if (desc != null) selected = desc
                code.text = Session.jadxCache[h.className] ?: code.text.toString()
                msg += "; java ${lastFindIdx + 1}/${lastFindMatches.size} ${h.className}:${h.line}"
            } else {
                msg += "; java-global: 0"
            }
        }
        hits.text = msg
    }

    private fun exportCurrent() {
        val sel = selected
        val text = code.text.toString()
        if (sel == null || text.isEmpty()) return
        val ext = if (showingLog) "log" else if (modeSmali) "smali" else "java"
        val simple = if (showingLog) "jadx-log"
            else sel.removePrefix("L").removeSuffix(";").substringAfterLast('/').replace('$', '_')
        try {
            val dest = saveTextToDownloads(text, "$simple.$ext")
            hits.text = "Guardado: $dest"
        } catch (e: Exception) {
            hits.text = "Error exportando: ${e.message}"
        }
    }

    private fun exportJavaZip() {
        if (Session.jadxCache.isEmpty() || working) return
        markWorking(true)
        progress.visibility = View.VISIBLE
        hits.text = "Comprimiendo Java…"
        Thread {
            var dest: String? = null
            var fail: String? = null
            var n = 0
            var trunc = false
            try {
                val snap = LinkedHashMap(Session.jadxCache)
                val zr = JavaHarvest.zip(snap)
                val bytes = zr?.zip
                if (bytes == null) {
                    fail = "sin datos"
                } else {
                    n = zr.files
                    trunc = zr.truncated
                    dest = saveBytesToDownloads(bytes, "java.zip", "application/zip")
                }
            } catch (t: Throwable) {
                fail = t.message
            }
            runOnUiThread {
                markWorking(false)
                progress.visibility = View.GONE
                hits.text = if (dest != null)
                    "Guardado: $dest ($n clases${if (trunc) ", recortado" else ""})"
                    else "Error exportando: $fail"
            }
        }.start()
    }

    /** Informe completo en un TXT: árbol del APK + clases + Java descompilado. */
    private fun generateFullReport() {
        val apk = Session.apk
        if (apk == null || !apk.isFile() || working) return
        markWorking(true)
        progress.visibility = View.VISIBLE
        hits.text = "Generando informe…"
        Thread {
            var dest: String? = null
            var fail: String? = null
            var stats = ""
            try {
                val tree = mutableListOf<String>()
                try {
                    ZipFile(apk).use { zip ->
                        val en = zip.entries()
                        while (en.hasMoreElements()) {
                            val e = en.nextElement()
                            if (!e.isDirectory) tree.add(e.name + " (" + e.size + " B)")
                        }
                    }
                    tree.sort()
                } catch (t: Throwable) {
                    tree.add("(arbol no disponible: ${t.message})")
                }
                val classes = when {
                    Session.appClasses.isNotEmpty() -> Session.appClasses
                    Session.smaliCache.isNotEmpty() -> Session.smaliCache.keys.sorted()
                    else -> filtered
                }
                val snap = LinkedHashMap(Session.jadxCache)
                val extras = FullReport.Extras()
                extras.build = buildId()
                // Informe estático + paquete JSON (un solo analyze, PHANTOM incluido).
                try {
                    val rep = ReaEngine.analyze(apk)
                    extras.staticReport = rep.toText()
                    extras.packageJson = rep.toJson()
                } catch (t: Throwable) {
                    extras.staticReport = ""
                    extras.packageJson = ""
                }
                // Smali de respaldo para las clases sin Java.
                try {
                    ensureDex()
                } catch (t: Throwable) {
                }
                extras.smali = FullReport.SmaliProvider { desc ->
                    Session.smaliCache[desc] ?: try {
                        SmaliDumper.dumpSingleClass(Session.dexBytes, desc)
                    } catch (t: Throwable) {
                        null
                    }
                }
                val rep = FullReport.build(Session.pkg, tree, classes, snap, extras)
                dest = saveTextToDownloads(rep.text, "informe_completo.txt")
                stats = "arbol=${rep.treeLines} clases=${rep.classLines} java=${rep.javaFiles}" +
                    (if (rep.smaliFiles > 0) " smali=${rep.smaliFiles}" else "") +
                    (if (rep.treeTruncated || rep.classesTruncated || rep.javaTruncated ||
                        rep.smaliTruncated) " (recortado)" else "")
            } catch (e: OutOfMemoryError) {
                fail = "memoria insuficiente"
            } catch (t: Throwable) {
                fail = t.message
            }
            runOnUiThread {
                markWorking(false)
                progress.visibility = View.GONE
                hits.text = if (dest != null) "Guardado: $dest ($stats)"
                else "Error generando informe: $fail"
            }
        }.start()
    }

    /** "0.4.0 · 1a2b3c4d": versionName + 8 primeros hex del SHA-256 del APK de REA. */
    private fun buildId(): String = try {
        val v = packageManager.getPackageInfo(packageName, 0).versionName ?: "?"
        val md = MessageDigest.getInstance("SHA-256")
        File(packageCodePath).inputStream().use { ins ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = ins.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        val hex = md.digest().joinToString("") { "%02x".format(it) }
        "$v · ${hex.substring(0, 8)}"
    } catch (t: Throwable) {
        ""
    }

    private fun saveTextToDownloads(text: String, name: String): String =
        saveBytesToDownloads(text.toByteArray(), name, "text/plain")

    @SuppressLint("NewApi")
    private fun saveBytesToDownloads(data: ByteArray, name: String, mime: String): String {
        val safePkg = if (Session.pkg == "?") "apk" else Session.pkg.replace('.', '_')
        if (Build.VERSION.SDK_INT >= 29) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, mime)
                put(MediaStore.Downloads.RELATIVE_PATH, "Download/REA-Mobile/$safePkg")
            }
            val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw IllegalStateException("MediaStore rechazó la inserción")
            contentResolver.openOutputStream(uri)?.use { out ->
                out.write(data)
            } ?: throw IllegalStateException("sin stream de salida")
            return "Descargas/REA-Mobile/$safePkg/$name"
        } else {
            val dir = getExternalFilesDir(null)
                ?: throw IllegalStateException("sin almacenamiento externo")
            val dest = File(dir, name)
            FileOutputStream(dest).use { it.write(data) }
            return dest.absolutePath
        }
    }
}
