package me.uii.rustproxy

import android.content.Context
import android.content.Intent
import org.json.JSONObject

object AgentStatus {
    const val ACTION_CHANGED = "me.uii.rustproxy.STATUS_CHANGED"
    const val EXTRA_JSON = "status_json"

    @Volatile
    private var latest = "{\"state\":\"disconnected\"}"

    fun current(): String = latest

    fun publish(context: Context, state: String, error: String? = null) {
        val payload = JSONObject().put("state", state).apply {
            if (!error.isNullOrBlank()) put("error", error)
        }.toString()
        publishJson(context, payload)
    }

    fun publishJson(context: Context, json: String) {
        latest = json
        context.sendBroadcast(Intent(ACTION_CHANGED).setPackage(context.packageName).putExtra(EXTRA_JSON, json))
    }
}
