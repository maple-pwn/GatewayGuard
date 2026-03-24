package com.gatewayguard.android

import android.app.Activity
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private lateinit var statusView: TextView

    private val backendUrl = "http://127.0.0.1:8000"
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val filePicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) {
            pushImportResult("{\"error\":\"No file selected\"}")
            return@registerForActivityResult
        }
        ioScope.launch {
            val result = runCatching { importUriToBackend(uri) }
                .getOrElse { "{\"error\":${JSONObject.quote(it.message ?: "import failed")}}" }
            pushImportResult(result)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusView = findViewById(R.id.statusView)
        webView = findViewById(R.id.webView)
        configureWebView()

        ioScope.launch { startBackendAndLoadUi() }
    }

    override fun onDestroy() {
        super.onDestroy()
        ioScope.cancel()
    }

    private fun configureWebView() {
        webView.settings.javaScriptEnabled = true
        webView.settings.domStorageEnabled = true
        webView.webViewClient = WebViewClient()
        webView.webChromeClient = WebChromeClient()
        webView.addJavascriptInterface(AndroidBridge(this), "AndroidBridge")
    }

    private suspend fun startBackendAndLoadUi() {
        withContext(Dispatchers.Main) { statusView.text = "Starting Python backend..." }
        try {
            if (!Python.isStarted()) {
                Python.start(AndroidPlatform(applicationContext))
            }
            val py = Python.getInstance()
            py.getModule("android_entry").callAttr(
                "start_backend",
                filesDir.absolutePath,
                "127.0.0.1",
                8000
            )
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                statusView.text = "Backend startup failed: ${e.message}"
            }
            return
        }

        val ready = waitBackendReady()
        withContext(Dispatchers.Main) {
            if (ready) {
                statusView.text = "Backend ready: $backendUrl/ui/"
                webView.loadUrl("$backendUrl/ui/")
            } else {
                statusView.text = "Backend not ready. Check /api/system/logs/recent when available."
            }
        }
    }

    private suspend fun waitBackendReady(timeoutMs: Long = 60000): Boolean {
        val start = System.currentTimeMillis()
        while (System.currentTimeMillis() - start < timeoutMs) {
            if (isReadyOnce()) return true
            delay(1000)
        }
        return false
    }

    private fun isReadyOnce(): Boolean {
        return runCatching {
            val connection = URI.create("$backendUrl/health/ready").toURL().openConnection() as HttpURLConnection
            connection.connectTimeout = 1500
            connection.readTimeout = 1500
            connection.requestMethod = "GET"
            connection.responseCode in 200..299
        }.getOrDefault(false)
    }

    private fun pickCaptureFile() {
        filePicker.launch(arrayOf("*/*"))
    }

    private suspend fun importUriToBackend(uri: Uri): String {
        val importsDir = File(filesDir, "imports")
        if (!importsDir.exists()) importsDir.mkdirs()

        val displayName = queryDisplayName(uri) ?: "capture_${System.currentTimeMillis()}.pcap"
        val safeName = displayName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        val dest = File(importsDir, safeName)

        contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Cannot open selected file" }
            FileOutputStream(dest).use { output -> input.copyTo(output) }
        }

        val encoded = URLEncoder.encode(dest.absolutePath, "UTF-8")
        val url = URI.create("$backendUrl/api/traffic/import?file_path=$encoded").toURL()
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 8000
            readTimeout = 30000
        }
        val body = runCatching {
            connection.inputStream.bufferedReader().use { it.readText() }
        }.getOrElse {
            connection.errorStream?.bufferedReader()?.use { it.readText() }
                ?: "{\"error\":\"import request failed\"}"
        }

        withContext(Dispatchers.Main) {
            statusView.text = "Imported file copied to private dir: ${dest.name}"
        }
        return body
    }

    private fun queryDisplayName(uri: Uri): String? {
        var cursor: Cursor? = null
        return try {
            cursor = contentResolver.query(uri, null, null, null, null)
            if (cursor != null && cursor.moveToFirst()) {
                val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (index >= 0) cursor.getString(index) else null
            } else null
        } finally {
            cursor?.close()
        }
    }

    private fun pushImportResult(jsonPayload: String) {
        val quoted = JSONObject.quote(jsonPayload)
        runOnUiThread {
            if (::webView.isInitialized) {
                webView.evaluateJavascript("window.onNativeImportResult($quoted);", null)
            }
        }
    }

    class AndroidBridge(private val activity: MainActivity) {
        @JavascriptInterface
        fun pickCaptureFile() {
            activity.runOnUiThread { activity.pickCaptureFile() }
        }
    }
}
