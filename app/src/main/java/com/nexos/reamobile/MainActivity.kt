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
import com.nexos.reamobile.engine.auth.AuthJson
import com.nexos.reamobile.engine.auth.ReaAuthenticityEngine
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
    private lateinit var btnAuth: Button
    private lateinit var progress: ProgressBar
    private var lastReport: String = ""
    private var lastApk: File? = null
    private var lastAuthOptions: ReaAuthenticityEngine.Options? = null
    private var disclaimer: AlertDialog? = null

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
        btnAuth = Button(this).apply {
            text = "Autenticidad"
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
        root.addView(btnAuth)
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
        btnAuth.setOnClickListener { showAuthDialog() }
        showDisclaimerOnce()
        restoreState(savedInstanceState)
    }

    override fun onDestroy() {
        try {
            disclaimer?.dismiss()
        } catch (t: Throwable) {
        }
        disclaimer = null
        super.onDestroy()
    }

    override fun onSaveInstanceState(out: Bundle) {
        super.onSaveInstanceState(out)
        // El informe vive en caché (puede pasar 1 MB); aquí solo ruta y paquete.
        out.putString("lastApk", lastApk?.absolutePath)
        out.putString("pkg", Session.pkg)
    }

    /** Restaura informe+APK tras muerte del proceso (H7). */
    private fun restoreState(saved: Bundle?) {
        if (saved == null || Session.apk != null) return
        try {
            val path = saved.getString("lastApk") ?: return
            val apk = File(path)
            if (!apk.isFile) return
            val rep = File(cacheDir, "rea_ultimo_informe.txt")
            if (!rep.isFile) return
            lastApk = apk
            Session.apk = apk
            lastReport = rep.readText()
            Session.pkg = saved.getString("pkg", "?") ?: "?"
            txt.text = Session.capForView(lastReport)
            btnShare.isEnabled = true
            btnExtract.isEnabled = true
            btnView.isEnabled = true
            btnAuth.isEnabled = Session.auth != null
        } catch (t: Throwable) {
        }
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
        disclaimer = AlertDialog.Builder(this)
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
        btnAuth.isEnabled = false
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
                val authOpts = loadAuthOptions()
                val report = ReaEngine.analyze(tmp, authOpts)
                val pmSection = packageManagerSection(tmp.absolutePath)
                lastReport = report.toText() + "\n" + pmSection
                try {
                    File(cacheDir, "rea_ultimo_informe.txt").writeText(lastReport)
                } catch (t: Throwable) {
                }
                runOnUiThread {
                    lastApk = tmp
                    Session.apk = tmp
                    Session.pkg = report.packageName
                    Session.appClasses = report.appClasses
                    Session.appClassTotal = report.appClassTotal
                    Session.resetCache()
                    Session.auth = report.auth
                    lastAuthOptions = authOpts
                    txt.text = Session.capForView(lastReport)
                    btnShare.isEnabled = true
                    btnExtract.isEnabled = true
                    btnView.isEnabled = true
                    btnAuth.isEnabled = report.auth != null
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
        btnAuth.isEnabled = false
        progress.visibility = View.VISIBLE
        txt.text = "Extrayendo…"
        Thread {
            try {
                val tmpZip = File(cacheDir, "rea_extraccion_" + System.currentTimeMillis() + ".zip")
                cleanStaleTemps(tmpZip)
                val res = ReaEngine.extractToZip(apk, tmpZip, lastAuthOptions)
                if (res.error != null) {
                    try {
                        tmpZip.delete()
                    } catch (t: Throwable) {
                    }
                    throw IllegalStateException(res.error)
                }
                val out = File(cacheDir, ZipShareProvider.FILE_NAME)
                if (out.exists()) out.delete()
                if (!tmpZip.renameTo(out)) throw IllegalStateException("no se pudo publicar el ZIP")
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
                    btnAuth.isEnabled = Session.auth != null
                }
            }
        }.start()
    }

    @SuppressLint("NewApi")
    private fun saveZipToDownloads(zip: File, pkg: String): String {
        val safePkg = if (pkg == "?" || pkg.isEmpty()) "apk"
        else ReaEngine.safeFileName(pkg.replace('.', '_'), 48)
        val name = ReaEngine.safeFileName(safePkg + "_rea_mobile.zip", 64)
        if (Build.VERSION.SDK_INT >= 29) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "application/zip")
                put(MediaStore.Downloads.RELATIVE_PATH, "Download/REA-Mobile")
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val uri: Uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw IllegalStateException("MediaStore rechazó la inserción")
            try {
                contentResolver.openOutputStream(uri)?.use { out ->
                    FileInputStream(zip).use { inp -> inp.copyTo(out) }
                } ?: throw IllegalStateException("sin stream de salida")
            } finally {
                val done = ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }
                try {
                    contentResolver.update(uri, done, null, null)
                } catch (t: Throwable) {
                }
            }
            return "Descargas/REA-Mobile/$name"
        } else {
            val dir = getExternalFilesDir(null)
                ?: throw IllegalStateException("sin almacenamiento externo")
            var dest = File(dir, name)
            var n = 1
            while (dest.exists() && n < 100) {
                n++
                dest = File(dir, name.removeSuffix(".zip") + "_$n.zip")
            }
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

    /** Carga allowlist/baseline/sellos bundled (best-effort, acotado). */
    private fun loadAuthOptions(): ReaAuthenticityEngine.Options {
        val o = ReaAuthenticityEngine.Options()
        try {
            o.allowlistJson = readAssetCapped("rea_allowlist.json")
            o.baselineJson = readAssetCapped("rea_baseline.json")
            val stamps = readAssetCapped("rea_trusted_stamps.json")
            if (!stamps.isNullOrEmpty()) {
                val p = AuthJson.parse(stamps)
                if (p.error == null) {
                    val obj = AuthJson.asObject(p.root)
                    if (obj != null) {
                        for (s in AuthJson.strList(obj, "sha256")) {
                            if (s.isNotEmpty()) o.trustedStamps.add(s)
                        }
                    }
                }
            }
        } catch (t: Throwable) {
        }
        return o
    }

    private fun readAssetCapped(name: String): String? {
        return try {
            assets.open(name).use { ins ->
                val buf = ByteArray(2 * 1024 * 1024)
                val sb = StringBuilder()
                while (true) {
                    val n = ins.read(buf)
                    if (n <= 0) break
                    sb.append(String(buf, 0, n, Charsets.UTF_8))
                    if (sb.length > 2 * 1024 * 1024) break
                }
                sb.toString()
            }
        } catch (t: Throwable) {
            null
        }
    }

    /** Diálogo de autenticidad: 6 indicadores en texto + veredicto. */
    private fun showAuthDialog() {
        val auth = Session.auth
        if (auth == null) {
            Toast.makeText(this, "Sin resultado de autenticidad", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val v = auth.verdict
            val items = arrayOf(
                "Veredicto: ${verdictText(v.overall)} (confianza ${v.confidence})",
                "Firma: ${triText(v.apkSignatureValid, "válida", "inválida", "no comprobada")}",
                "Firmante: ${signerText()}",
                "Procedencia: ${triText(v.playProvenance, "confirmada", "no atribuida", "desconocida")}",
                "Versión oficial: ${baselineText()}",
                "Modificaciones: ${modText()}",
                "Rotación: ${rotationText()}"
            )
            AlertDialog.Builder(this)
                .setTitle("Autenticidad y procedencia")
                .setItems(items) { _, which -> showAuthDetail(which) }
                .setPositiveButton("Cerrar", null)
                .show()
        } catch (t: Throwable) {
            Toast.makeText(this, "No se pudo mostrar: ${t.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun verdictText(overall: String): String {
        return when (overall) {
            "OFFICIAL" -> "oficial"
            "NOT_OFFICIAL" -> "no oficial"
            "SUSPICIOUS" -> "sospechoso"
            else -> "desconocido (sin datos suficientes)"
        }
    }

    private fun triText(t: com.nexos.reamobile.engine.auth.AuthTri, yes: String, no: String, unk: String): String {
        return try {
            when (t) {
                com.nexos.reamobile.engine.auth.AuthTri.TRUE -> yes
                com.nexos.reamobile.engine.auth.AuthTri.FALSE -> no
                else -> unk
            }
        } catch (e: Throwable) {
            unk
        }
    }

    private fun signerText(): String {
        val auth = Session.auth ?: return "desconocido"
        return when (auth.signature.allowMatch) {
            "MATCH" -> "reconocido (oficial)"
            "MISMATCH" -> "distinto al oficial"
            "ERROR" -> "no comprobado (error de allowlist)"
            else -> "desconocido (sin referencias)"
        }
    }

    private fun baselineText(): String {
        val auth = Session.auth ?: return "desconocida"
        return when (auth.verdict.officialBaselineMatch) {
            com.nexos.reamobile.engine.auth.AuthTri.TRUE -> "coincide con la oficial"
            com.nexos.reamobile.engine.auth.AuthTri.FALSE -> "distinta a la oficial"
            else -> "sin referencia (no valorable)"
        }
    }

    private fun modText(): String {
        val auth = Session.auth ?: return "no valorables"
        return when (auth.verdict.modificationIndicators) {
            com.nexos.reamobile.engine.auth.AuthTri.TRUE -> "detectadas (ver evidencia)"
            com.nexos.reamobile.engine.auth.AuthTri.FALSE -> "no detectadas"
            else -> "no valorables"
        }
    }

    private fun rotationText(): String {
        val auth = Session.auth ?: return "desconocida"
        val r = auth.rotation
        if (r.lineagePresent != com.nexos.reamobile.engine.auth.AuthTri.TRUE) return "sin linaje"
        return when (r.lineageMatchesOfficial) {
            com.nexos.reamobile.engine.auth.AuthTri.TRUE -> "linaje oficial (${r.certificates.size} niveles)"
            com.nexos.reamobile.engine.auth.AuthTri.FALSE -> "linaje no oficial"
            else -> "linaje no comprobado"
        }
    }

    /** Detalle técnico de un indicador con su evidencia. */
    private fun showAuthDetail(which: Int) {
        val auth = Session.auth ?: return
        try {
            val sb = StringBuilder()
            when (which) {
                0 -> {
                    sb.append("Veredicto: ${verdictText(auth.verdict.overall)}\n")
                    sb.append("Confianza: ${auth.verdict.confidence}\n\nMotivos:\n")
                    for (s in auth.verdict.reasons) sb.append("- ").append(s).append('\n')
                    if (auth.verdict.warnings.isNotEmpty()) {
                        sb.append("\nAvisos:\n")
                        for (s in auth.verdict.warnings) sb.append("- ").append(s).append('\n')
                    }
                    if (auth.verdict.unknowns.isNotEmpty()) {
                        sb.append("\nSin comprobar:\n")
                        for (s in auth.verdict.unknowns) sb.append("- ").append(s).append('\n')
                    }
                }
                1 -> {
                    sb.append("v1: ${auth.signature.v1.detail}\n")
                    sb.append("v2: ${auth.signature.v2.detail}\n")
                    sb.append("v3: ${auth.signature.v3.detail}\n")
                    sb.append("v3.1: ${auth.signature.v31.detail}\n")
                    sb.append("integridad: ${auth.signature.integrityOk}\n")
                    sb.append("método: ${auth.signature.method}\n")
                    appendEvidence(sb, auth, "signature")
                }
                2 -> {
                    for (c in auth.signature.signerCerts) {
                        sb.append("sha256: ${c.sha256}\n")
                        sb.append("sujeto: ${c.subjectDn}\n")
                        sb.append("emisor: ${c.issuerDn}\n")
                        sb.append("serie: ${c.serial}\n")
                        sb.append("válido: ${c.notBefore} .. ${c.notAfter}\n")
                        sb.append("algoritmo: ${c.sigAlg}\n\n")
                    }
                    sb.append("allowlist: ${auth.signature.allowMatch}")
                    if (auth.signature.allowVersion.isNotEmpty()) {
                        sb.append(" (v${auth.signature.allowVersion}, ${auth.signature.allowSource})")
                    }
                    sb.append('\n')
                    appendEvidence(sb, auth, "signer")
                }
                3 -> {
                    sb.append("sello presente: ${auth.provenance.stampPresent}\n")
                    sb.append("sello verificado: ${auth.provenance.stampVerified}\n")
                    sb.append("cert sello: ${auth.provenance.stampCertSha256}\n")
                    sb.append("identidad confiable: ${auth.provenance.stampMatchesTrusted}\n")
                    sb.append("distribuido por Play: ${auth.provenance.distributedByPlay}\n")
                    sb.append(auth.provenance.detail).append('\n')
                    appendEvidence(sb, auth, "provenance")
                }
                4 -> {
                    sb.append("paquete: ${auth.baseline.packageMatch}\n")
                    sb.append("versión oficial: ${auth.baseline.versionKnownOfficial}\n")
                    sb.append("apk: ${auth.baseline.apkSha256Match}\n")
                    sb.append("dex: ${auth.baseline.dexHashesMatch}\n")
                    sb.append("permisos: +${auth.baseline.permissionsDiff.added.size} -${auth.baseline.permissionsDiff.removed.size}\n")
                    sb.append("exportados: +${auth.baseline.exportedComponentsDiff.added.size} -${auth.baseline.exportedComponentsDiff.removed.size}\n")
                    sb.append("nativas: ${auth.baseline.nativeLibsDiff.match}\n")
                    sb.append("splits: ${auth.baseline.splitsMatch}\n")
                    sb.append("variante: ${auth.baseline.variantMatch}\n")
                    sb.append(auth.baseline.detail).append('\n')
                    appendEvidence(sb, auth, "baseline")
                }
                5 -> {
                    sb.append("debuggable: ${auth.repack.debuggable}\n")
                    sb.append("testOnly: ${auth.repack.testOnly}\n")
                    sb.append("allowBackup anómalo: ${auth.repack.allowBackupAnomaly}\n")
                    sb.append("cleartext: ${auth.repack.cleartextTraffic}\n")
                    sb.append("v1 inesperado: ${auth.repack.v1Unexpected}\n")
                    sb.append("splits ausentes: ${auth.repack.splitsMissing}\n")
                    sb.append("manifest modificado: ${auth.repack.manifestModified}\n")
                    sb.append("dex modificado: ${auth.repack.dexModified}\n")
                    sb.append("nativas modificadas: ${auth.repack.nativeLibsModified}\n")
                    sb.append(auth.repack.detail).append('\n')
                    appendEvidence(sb, auth, "repack")
                }
                else -> {
                    sb.append("linaje presente: ${auth.rotation.lineagePresent}\n")
                    sb.append("linaje válido: ${auth.rotation.lineageValid}\n")
                    sb.append("clave observada: ${auth.rotation.observedKey}\n")
                    sb.append("coincide con oficial: ${auth.rotation.lineageMatchesOfficial}\n")
                    if (auth.rotation.sdkNote.isNotEmpty()) sb.append("sdk: ${auth.rotation.sdkNote}\n")
                    if (auth.rotation.capsNote.isNotEmpty()) sb.append("caps: ${auth.rotation.capsNote}\n")
                    var i = 0
                    for (c in auth.rotation.certificates) {
                        sb.append("nivel $i: ${c.shortPrint} ${c.subjectDn}\n")
                        i++
                    }
                    sb.append(auth.rotation.detail).append('\n')
                    appendEvidence(sb, auth, "rotation")
                }
            }
            var text = sb.toString()
            if (text.length > 8000) text = text.substring(0, 8000) + "\n[…recortado…]"
            AlertDialog.Builder(this)
                .setTitle("Evidencia técnica")
                .setMessage(text)
                .setPositiveButton("Cerrar", null)
                .show()
        } catch (t: Throwable) {
            Toast.makeText(this, "No se pudo mostrar: ${t.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun appendEvidence(sb: StringBuilder, auth: com.nexos.reamobile.engine.auth.AuthResult.Report, category: String) {
        try {
            sb.append("\nEvidencia:\n")
            var n = 0
            for (e in auth.evidence) {
                if (e.category == category && n < 20) {
                    sb.append("- ").append(e.toText()).append('\n')
                    n++
                }
            }
            if (n == 0) sb.append("(sin evidencia de esta categoría)\n")
        } catch (t: Throwable) {
        }
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
