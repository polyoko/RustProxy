package me.uii.rustproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.PowerManager
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class ProxyForegroundService : Service() {
    private val worker = Executors.newSingleThreadExecutor()
    private val agentRunning = AtomicBoolean(false)
    private lateinit var wakeLock: PowerManager.WakeLock

    override fun onCreate() {
        super.onCreate()
        System.loadLibrary("rust_proxy")
        wakeLock = (getSystemService(Context.POWER_SERVICE) as PowerManager)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "RustProxy:agent").apply { acquire() }
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, notification("Connecting to VPS"))
        when (intent?.action) {
            ACTION_STOP -> stopAgentAndService()
            else -> startAgentFromSavedConfig()
        }
        return START_STICKY
    }

    private fun startAgentFromSavedConfig() {
        val config = runCatching { ConfigStore(this).load() }.getOrElse {
            AgentStatus.publish(this, "disconnected", "Stored password is unavailable; scan the QR code again")
            null
        }
        if (config == null) {
            AgentStatus.publish(this, "disconnected", "Configure the server before connecting")
            return
        }
        if (!agentRunning.compareAndSet(false, true)) return
        worker.execute {
            try {
                startAgent(config.serverAddress, config.agentId, config.password)
            } finally {
                agentRunning.set(false)
            }
        }
    }

    private fun stopAgentAndService() {
        if (agentRunning.get()) stopAgent()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /** Called from Rust through RegisterNatives. */
    fun onStatus(json: String) {
        AgentStatus.publishJson(this, json)
        val state = runCatching { org.json.JSONObject(json).optString("state") }.getOrDefault("disconnected")
        val text = when (state) {
            "connected" -> "Connected to VPS"
            "connecting" -> "Connecting to VPS"
            else -> "Disconnected"
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, notification(text))
    }

    /** Called from Rust through RegisterNatives. */
    fun resetIpViaAssistant() {
        if (!AssistantBridge.isDefault(this) || !AssistantBridge.requestAirplaneReset()) {
            AgentStatus.publish(this, "connected", "RustProxy is not the active Assistant")
        }
    }

    /** Called from Rust so agent_cache.json stays in this app's private files directory. */
    fun getCacheDirPath(): String = filesDir.absolutePath

    /** Called from Rust; an absent fingerprint deliberately retains the v1 compatibility path. */
    fun getServerFingerprint(): String = ConfigStore(this).load()?.fingerprint.orEmpty()

    /** Called from Rust once per telemetry tick. */
    fun getDeviceStatusJson(): String = DeviceTelemetry.collect(this)

    private fun notification(text: String): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("RustProxy")
            .setContentText(text)
            .setContentIntent(openApp)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "RustProxy tunnel", NotificationManager.IMPORTANCE_LOW),
        )
    }

    override fun onDestroy() {
        if (agentRunning.get()) stopAgent()
        if (::wakeLock.isInitialized && wakeLock.isHeld) wakeLock.release()
        worker.shutdownNow()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private external fun startAgent(serverAddress: String, agentId: String, password: String)
    private external fun stopAgent()

    companion object {
        const val ACTION_START = "me.uii.rustproxy.START"
        const val ACTION_STOP = "me.uii.rustproxy.STOP"
        private const val CHANNEL_ID = "agent"
        private const val NOTIFICATION_ID = 1
    }
}
