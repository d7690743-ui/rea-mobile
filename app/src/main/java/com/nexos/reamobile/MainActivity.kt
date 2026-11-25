package com.nexos.reamobile

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.ContentValues
import android.content.Intent
import android.content.pm.ComponentInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.MediaStore
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.nexos.reamobile.engine.ReaEngine
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest

/** Pantalla única: abrir APK por SAF, analizar, extraer ZIP y compartir informe. */
class MainActivity : Activity() {

    private lateinit var txt: TextView
    private lateinit var btnPick: Button
    private lateinit var btnShare: Button
    private lateinit var btnExtract: Button
    private lateinit var btnShareZip: Button
    private lateinit var btnView: Button
    private lateinit var progress: ProgressBar
    private var lastReport: String = ""
    private var lastApk: File? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
        }
        val title = TextView(this).apply {
            text = "REA Mobile " + appVersion() + " — análisis de APK"
            textSize = 20f
        }
        btnPick = Button(this).apply { text = "Abrir APK…" }
        btnShare = Button(this).apply {
            text = "Compartir informe"
            isEnabled = false
        }
        btnExtract = Button(this).apply {
            text = "Extraer ZIP (árbol + smali)"
            isEnabled = false
        }
        btnShareZip = Button(this).apply {
            text = "Compartir ZIP"
            isEnabled = false
        }
        btnView = Button(this).apply {
            text = "Ver código"
            isEnabled = false
        }
        progress = ProgressBar(this).apply { visibility = View.GONE }
        val scroll = ScrollView(this)
        txt = TextView(this).apply {
            text = "Elige un APK para empezar.\n\nAnálisis estático local: manifest, " +
                    "componentes, permisos, firmas, dex, recursos, nativas y heurísticas. " +
                    "El botón Extraer genera un ZIP con el árbol completo y el smali. " +
                    "Sin red, sin nube."
            textSize = 13f
            setTextIsSelectable(true)
        }
        scroll.addView(txt)
        root.addView(title)
        root.addView(btnPick)
        root.addView(btnShare)
        root.addView(btnExtract)
        root.addView(btnShareZip)
        root.addView(btnView)
        root.addView(progress)
        root.addView(
            scroll,
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
        )
        setContentView(root)

        btnPick.setOnClickListener { if (!Session.analyzing && !Session.extracting) openPicker() }
        btnShare.setOnClickListener { shareReport() }
        btnExtract.setOnClickListener { extractZip() }
        btnShareZip.setOnClickListener { shareZip() }
        btnView.setOnClickListener { openViewer() }
        showDisclaimerOnce()
    }

    private fun appVersion(): String {
        return try {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, 0).versionName ?: "?"
        } catch (t: Throwable) {
            "?"
        }
    }

    private fun showDisclaimerOnce() {
        val prefs = getPreferences(MODE_PRIVATE)
        if (prefs.getBoolean("disclaimer_ok", false)) return
        AlertDialog.Builder(this)
            .setTitle("Uso responsable")
            .setMessage(
                "Analiza solo APKs que te pertenecen o para los que tienes autorización " +
                        "expresa (tus apps, apps de prueba, código abierto). " +
                        "Respeta licencias y leyes aplicables."
            )
            .setPositiveButton("Entendido") { _, _ ->
                prefs.edit().putBoolean("disclaimer_ok", true).apply()
            }
            .setCancelable(false)
            .show()
    }

    private fun openPicker() {
        try {
            val i = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
                putExtra(
                    Intent.EXTRA_MIME_TYPES,
                    arrayOf("application/vnd.android.package-archive", "application/zip")
                )
            }
            @Suppress("DEPRECATION")
            startActivityForResult(i, 1001)
        } catch (e: Exception) {
            txt.text = "No se pudo abrir el selector: ${e.message}"
        }
    }

    @Deprecated("Selector SAF clásico, sin AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1001 && resultCode == RESULT_OK) {
            val uri: Uri = data?.data ?: return
            analyzeUri(uri)
        }
    }

    private fun analyzeUri(uri: Uri) {
        if (Session.analyzing || Session.extracting) return
        Session.analyzing = true
        btnShare.isEnabled = false
        btnExtract.isEnabled = false
        btnShareZip.isEnabled = false
        btnView.isEnabled = false
        progress.visibility = View.VISIBLE
        txt.text = "Analizando…"
        Thread {
            try {
                val input = contentResolver.openInputStream(uri)
                    ?: throw IllegalStateException("sin acceso al archivo")
                val tmp = File(cacheDir, "rea_input_" + System.currentTimeMillis() + ".apk")
                cleanStaleTemps(tmp)
                try {
                    FileOutputStream(tmp).use { out ->
                        input.use { ReaEngine.copyCapped(it, out, 512L * 1024 * 1024) }
                    }
                } catch (e: IOException) {
                    try {
                        tmp.delete()
                    } catch (t: Throwable) {
                    }
                    throw IllegalStateException("APK mayor de 512 MB o ilegible")
                }
                val report = ReaEngine.analyze(tmp)
                val pmSection = packageManagerSection(tmp.absolutePath)
                lastReport = report.toText() + "\n" + pmSection
                runOnUiThread {
                    lastApk = tmp
                    Session.apk = tmp
                    Session.pkg = report.packageName
                    Session.appClasses = report.appClasses
                    Session.appClassTotal = report.appClassTotal
                    Session.resetCache()
                    txt.text = Session.capForView(lastReport)
                    btnShare.isEnabled = true
                    btnExtract.isEnabled = true
                    btnView.isEnabled = true
                    progress.visibility = View.GONE
                }
            } catch (t: OutOfMemoryError) {
                runOnUiThread {
                    txt.text = "Memoria insuficiente analizando: prueba con un APK más pequeño."
                    progress.visibility = View.GONE
                }
            } catch (t: Throwable) {
                runOnUiThread {
                    txt.text = "Error analizando: ${t.message}"
                    progress.visibility = View.GONE
                }
            } finally {
                Session.analyzing = false
            }
        }.start()
    }

    private fun extractZip() {
        val apk = lastApk
        if (Session.analyzing || Session.extracting || apk == null || !apk.isFile()) return
        Session.extracting = true
        btnPick.isEnabled = false
        btnShare.isEnabled = false
        btnExtract.isEnabled = false
        btnShareZip.isEnabled = false
        progress.visibility = View.VISIBLE
        txt.text = "Extrayendo…"
        Thread {
            try {
                val tmpZip = File(cacheDir, "rea_extraccion_" + System.currentTimeMillis() + ".zip")
                cleanStaleTemps(tmpZip)
                val res = ReaEngine.extractToZip(apk, tmpZip)
                val out = File(cacheDir, ZipShareProvider.FILE_NAME)
                if (out.exists()) out.delete()
                if (!tmpZip.renameTo(out)) throw IllegalStateException("no se pudo publicar el ZIP")
                if (res.error != null) throw IllegalStateException(res.error)
                val dest = saveZipToDownloads(out, res.packageName)
                val summary = "ZIP guardado: " + dest + "\n\n" + res.summary()
                runOnUiThread {
                    txt.text = Session.capForView(summary + "\n" + lastReport)
                    btnShareZip.isEnabled = true
                    progress.visibility = View.GONE
                }
            } catch (t: OutOfMemoryError) {
                runOnUiThread {
                    txt.text = "Memoria insuficiente extrayendo: prueba con un APK más pequeño."
                    progress.visibility = View.GONE
                }
            } catch (t: Throwable) {
                runOnUiThread {
                    txt.text = "Error extrayendo: ${t.message}"
                    progress.visibility = View.GONE
                }
            } finally {
                Session.extracting = false
                runOnUiThread {
                    btnPick.isEnabled = true
                    btnShare.isEnabled = lastReport.isNotEmpty()
                    btnExtract.isEnabled = lastApk != null
                    btnView.isEnabled = lastApk != null
                }
            }
        }.start()
    }

    @SuppressLint("NewApi")
    private fun saveZipToDownloads(zip: File, pkg: String): String {
        val safePkg = if (pkg == "?" || pkg.isEmpty()) "apk" else pkg.replace('.', '_')
        val name = safePkg + "_rea_mobile.zip"
        if (Build.VERSION.SDK_INT >= 29) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "application/zip")
                put(MediaStore.Downloads.RELATIVE_PATH, "Download/REA-Mobile")
            }
            val uri: Uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw IllegalStateException("MediaStore rechazó la inserción")
            contentResolver.openOutputStream(uri)?.use { out ->
                FileInputStream(zip).use { inp -> inp.copyTo(out) }
            } ?: throw IllegalStateException("sin stream de salida")
            return "Descargas/REA-Mobile/$name"
        } else {
            val dir = getExternalFilesDir(null)
                ?: throw IllegalStateException("sin almacenamiento externo")
            val dest = File(dir, name)
            FileInputStream(zip).use { inp -> FileOutputStream(dest).use { inp.copyTo(it) } }
            return dest.absolutePath
        }
    }

    @Suppress("DEPRECATION")
    private fun packageManagerSection(path: String): String {
        val sb = StringBuilder()
        sb.append("=== FICHA PackageManager (Android) ===\n")
        try {
            val flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
                    PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or
                    PackageManager.GET_PERMISSIONS or PackageManager.GET_META_DATA or
                    PackageManager.GET_CONFIGURATIONS or
                    (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES
                    else PackageManager.GET_SIGNATURES)
            val info = packageManager.getPackageArchiveInfo(path, flags)
            if (info == null) {
                sb.append("sin info (null)\n")
                return sb.toString()
            }
            sb.append("package=").append(info.packageName).append('\n')
            sb.append("versionName=").append(info.versionName).append('\n')
            val vCode = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
            sb.append("versionCode=").append(vCode).append('\n')
            val appInfo = info.applicationInfo
            sb.append("minSdk=").append(appInfo?.minSdkVersion ?: "?").append('\n')
            sb.append("targetSdk=").append(appInfo?.targetSdkVersion ?: "?").append('\n')
            val perms = info.requestedPermissions
            sb.append("permisos(").append(perms?.size ?: 0).append("):\n")
            perms?.take(200)?.forEach { sb.append("  - ").append(it).append('\n') }
            dumpComponents(sb, "actividades", info.activities)
            dumpComponents(sb, "servicios", info.services)
            dumpComponents(sb, "receptores", info.receivers)
            dumpComponents(sb, "proveedores", info.providers)
            val digests = mutableListOf<String>()
            if (Build.VERSION.SDK_INT >= 28) {
                val sc = info.signingInfo
                if (sc != null) {
                    val sigs = if (sc.hasMultipleSigners()) sc.apkContentsSigners
                    else sc.signingCertificateHistory
                    sb.append("firmantes=").append(sigs.size).append('\n')
                    for (s in sigs) digests.add(sha256(s.toByteArray()))
                }
            } else {
                for (s in info.signatures ?: emptyArray()) digests.add(sha256(s.toByteArray()))
            }
            digests.take(5).forEach { sb.append("firmaSHA256=").append(it).append('\n') }
        } catch (e: Exception) {
            sb.append("error: ").append(e.message).append('\n')
        }
        return sb.toString()
    }

    private fun dumpComponents(sb: StringBuilder, label: String, arr: Array<out ComponentInfo>?) {
        sb.append(label).append('(').append(arr?.size ?: 0).append("):\n")
        arr?.take(200)?.forEach { sb.append("  - ").append(it.name).append('\n') }
    }

    private fun sha256(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256").digest(bytes)
        return md.joinToString("") { "%02X".format(it) }
    }

    private fun openViewer() {
        if (Session.analyzing || Session.extracting || lastApk == null) return
        startActivity(Intent(this, CodeViewerActivity::class.java))
    }

    /** Borra temporales viejos de análisis/extracciones anteriores (best-effort). */
    private fun cleanStaleTemps(keep: File?) {
        try {
            cacheDir.listFiles { f ->
                (f.name.startsWith("rea_input_") || f.name.startsWith("rea_extraccion_")) && f != keep
            }?.forEach {
                try {
                    it.delete()
                } catch (t: Throwable) {
                }
            }
            File(cacheDir, "rea_input.apk").delete()
        } catch (t: Throwable) {
        }
    }

    private fun shareReport() {
        if (lastReport.isEmpty()) return
        try {
            // Vía fichero: EXTRA_TEXT con MB tumba el Binder (TransactionTooLarge).
            File(cacheDir, ZipShareProvider.REPORT_NAME).writeText(lastReport)
            val i = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_SUBJECT, "Informe REA Mobile")
                putExtra(Intent.EXTRA_STREAM, ZipShareProvider.reportUri())
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(i, "Compartir informe"))
        } catch (t: Throwable) {
            Toast.makeText(this, "No se pudo compartir: ${t.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun shareZip() {
        try {
            val zip = File(cacheDir, ZipShareProvider.FILE_NAME)
            if (!zip.isFile()) {
                Toast.makeText(this, "Sin ZIP: usa Extraer primero", Toast.LENGTH_SHORT).show()
                return
            }
            val i = Intent(Intent.ACTION_SEND).apply {
                type = "application/zip"
                putExtra(Intent.EXTRA_STREAM, ZipShareProvider.zipUri())
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(i, "Compartir ZIP"))
        } catch (t: Throwable) {
            Toast.makeText(this, "No se pudo compartir: ${t.message}", Toast.LENGTH_SHORT).show()
        }
    }
}
