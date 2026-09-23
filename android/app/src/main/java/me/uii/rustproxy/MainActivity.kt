package me.uii.rustproxy

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.text.method.PasswordTransformationMethod
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject

class MainActivity : Activity() {
    private lateinit var configStore: ConfigStore
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var password: EditText
    private lateinit var agentId: EditText
    private lateinit var status: TextView
    private lateinit var assistant: TextView
    private lateinit var legacyWarning: TextView
    private lateinit var connectButton: Button

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            showStatus(intent.getStringExtra(AgentStatus.EXTRA_JSON) ?: AgentStatus.current())
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        configStore = ConfigStore(this)
        setContentView(buildScreen())
        loadConfig()
        showStatus(AgentStatus.current())
        showLegacyWarning()
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(AgentStatus.ACTION_CHANGED)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(statusReceiver, filter)
        }
    }

    override fun onResume() {
        super.onResume()
        assistant.text = if (AssistantBridge.isDefault(this)) {
            "Assistant: RustProxy is active"
        } else {
            "Assistant: select RustProxy to enable IP reset"
        }
    }

    override fun onStop() {
        unregisterReceiver(statusReceiver)
        super.onStop()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != SCAN_QR || resultCode != RESULT_OK) return
        val raw = data?.getStringExtra(QrScannerActivity.EXTRA_QR) ?: return
        try {
            val parsed = AgentConfig.fromQr(raw, agentId.text.toString().ifBlank { configStore.defaultAgentId() })
            applyConfig(parsed)
            configStore.save(parsed)
            AgentStatus.publish(this, "disconnected", "QR saved. Tap Connect to VPS")
        } catch (error: Exception) {
            AgentStatus.publish(this, "disconnected", error.message ?: "Invalid QR code")
        }
    }

    private fun buildScreen(): View {
        val padding = (20 * resources.displayMetrics.density).toInt()
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding, padding, padding)
        }
        fun text(value: String) = TextView(this).apply { this.text = value }
        fun input(hint: String, type: Int = InputType.TYPE_CLASS_TEXT) = EditText(this).apply {
            this.hint = hint
            contentDescription = hint
            inputType = type
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            )
        }

        column.addView(text("RustProxy"))
        legacyWarning = text("").also(column::addView)
        status = text("Status: loading").also(column::addView)
        assistant = text("Assistant: checking").also(column::addView)
        column.addView(Button(this).apply {
            text = "Scan QR"
            setOnClickListener { startActivityForResult(Intent(this@MainActivity, QrScannerActivity::class.java), SCAN_QR) }
        })
        column.addView(text("Server"))
        host = input("Host or IP").also(column::addView)
        port = input("Control port", InputType.TYPE_CLASS_NUMBER).also(column::addView)
        column.addView(text("Password"))
        password = input("Agent password").apply {
            transformationMethod = PasswordTransformationMethod.getInstance()
        }.also(column::addView)
        column.addView(text("Agent ID"))
        agentId = input("Unique device ID").also(column::addView)
        column.addView(Button(this).apply {
            text = "Set App as Assistant"
            setOnClickListener {
                val intent = Intent(Settings.ACTION_VOICE_INPUT_SETTINGS)
                if (intent.resolveActivity(packageManager) == null) {
                    AgentStatus.publish(this@MainActivity, "disconnected", "Assistant settings are unavailable on this device")
                } else {
                    startActivity(intent)
                }
            }
        })
        connectButton = Button(this).apply {
            text = "Connect to VPS"
            setOnClickListener { connect() }
        }
        column.addView(connectButton)
        column.addView(Button(this).apply {
            text = "Disconnect"
            setOnClickListener {
                startService(Intent(this@MainActivity, ProxyForegroundService::class.java).setAction(ProxyForegroundService.ACTION_STOP))
            }
        })
        return ScrollView(this).apply { addView(column) }
    }

    private fun loadConfig() {
        val config = runCatching { configStore.load() }.getOrNull()
        if (config == null) {
            agentId.setText(configStore.defaultAgentId())
            port.setText(DEFAULT_PORT)
        } else {
            applyConfig(config)
        }
    }

    private fun applyConfig(config: AgentConfig) {
        host.setText(config.host)
        port.setText(config.port.toString())
        password.setText(config.password)
        agentId.setText(config.agentId)
    }

    private fun connect() {
        val config = try {
            val fingerprint = configStore.load()?.fingerprint
            AgentConfig(
                host.text.toString().trim().also { require(it.isNotEmpty()) { "Server is required" } },
                port.text.toString().toInt().also { require(it in 1..65535) { "Port must be 1–65535" } },
                password.text.toString(),
                agentId.text.toString().trim().also { require(it.isNotEmpty()) { "Agent ID is required" } },
                fingerprint,
            )
        } catch (error: Exception) {
            AgentStatus.publish(this, "disconnected", error.message ?: "Invalid settings")
            return
        }
        configStore.save(config)
        val permissions = buildList {
            if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                add(Manifest.permission.POST_NOTIFICATIONS)
            }
            if (checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) {
                add(Manifest.permission.READ_PHONE_STATE)
            }
        }
        if (permissions.isNotEmpty()) {
            requestPermissions(permissions.toTypedArray(), NOTIFICATION_PERMISSION)
        }
        startForegroundService(Intent(this, ProxyForegroundService::class.java).setAction(ProxyForegroundService.ACTION_START))
    }

    private fun showStatus(raw: String) {
        val json = runCatching { JSONObject(raw) }.getOrElse { JSONObject().put("state", "disconnected").put("error", raw) }
        val state = json.optString("state", "disconnected")
        val error = json.optString("error").takeIf { it.isNotBlank() && it != "null" }
        connectButton.isEnabled = state != "connecting"
        status.text = buildString {
            append("Status: ").append(state)
            if (error != null) append(" — ").append(error)
        }
    }

    private fun showLegacyWarning() {
        legacyWarning.text = try {
            packageManager.getApplicationInfo(LEGACY_PACKAGE, 0)
            "Legacy RustProxy is still installed. Remove it only after this app connects."
        } catch (_: PackageManager.NameNotFoundException) {
            ""
        }
    }

    private companion object {
        const val SCAN_QR = 10
        const val NOTIFICATION_PERMISSION = 11
        const val DEFAULT_PORT = "8080"
        const val LEGACY_PACKAGE = "com.barissenel.rustproxy"
    }
}
