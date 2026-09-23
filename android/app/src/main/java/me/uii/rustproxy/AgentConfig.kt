package me.uii.rustproxy

import android.content.Context
import org.json.JSONObject
import java.util.UUID

data class AgentConfig(
    val host: String,
    val port: Int,
    val password: String,
    val agentId: String,
    val fingerprint: String? = null,
) {
    val serverAddress: String
        get() = if (host.contains(":") && !host.startsWith("[")) "[$host]:$port" else "$host:$port"

    companion object {
        fun fromQr(raw: String, agentId: String): AgentConfig {
            val json = JSONObject(raw)
            val host = json.optString("h").trim()
            val port = json.optInt("p", 0)
            require(host.isNotEmpty()) { "QR code is missing host" }
            require(port in 1..65535) { "QR code has an invalid port" }
            require(json.has("pwd")) { "QR code is missing password" }
            return AgentConfig(
                host,
                port,
                json.optString("pwd"),
                agentId,
                json.optString("fp").trim().takeIf { it.isNotEmpty() },
            )
        }
    }
}

class ConfigStore(context: Context) {
    private val preferences = context.getSharedPreferences("agent-config", Context.MODE_PRIVATE)
    private val secrets = SecretStore(context)

    fun defaultAgentId(): String {
        return preferences.getString("agent_id", null) ?: UUID.randomUUID().toString().also {
            preferences.edit().putString("agent_id", it).apply()
        }
    }

    fun load(): AgentConfig? {
        val host = preferences.getString("host", "") ?: ""
        val port = preferences.getInt("port", 0)
        if (host.isBlank() || port !in 1..65535) return null
        return AgentConfig(
            host,
            port,
            secrets.read() ?: "",
            defaultAgentId(),
            preferences.getString("fp", null),
        )
    }

    fun save(config: AgentConfig) {
        preferences.edit()
            .putString("host", config.host)
            .putInt("port", config.port)
            .putString("agent_id", config.agentId)
            .putString("fp", config.fingerprint)
            .apply()
        secrets.write(config.password)
    }
}
