package me.uii.rustproxy

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.service.voice.VoiceInteractionService
import android.service.voice.VoiceInteractionSession
import android.service.voice.VoiceInteractionSessionService
import android.speech.RecognitionService
import android.speech.SpeechRecognizer

object AssistantBridge {
    @Volatile
    private var service: RustProxyVoiceInteractionService? = null

    fun attach(value: RustProxyVoiceInteractionService) {
        service = value
    }

    fun detach(value: RustProxyVoiceInteractionService) {
        if (service === value) service = null
    }

    fun requestAirplaneReset(): Boolean = service?.requestAirplaneReset() ?: false

    fun isDefault(context: Context): Boolean = VoiceInteractionService.isActiveService(
        context,
        ComponentName(context, RustProxyVoiceInteractionService::class.java),
    )
}

class RustProxyVoiceInteractionService : VoiceInteractionService() {
    private val handler = Handler(Looper.getMainLooper())

    override fun onReady() {
        super.onReady()
        AssistantBridge.attach(this)
    }

    override fun onShutdown() {
        AssistantBridge.detach(this)
        super.onShutdown()
    }

    override fun onShowSessionFailed(args: Bundle) {
        AgentStatus.publish(this, "connected", "Assistant session could not start")
    }

    fun requestAirplaneReset(): Boolean {
        handler.post {
            showSession(
                Bundle().apply { putBoolean(RustProxyVoiceSession.RESET_KEY, true) },
                VoiceInteractionSession.SHOW_SOURCE_APPLICATION,
            )
        }
        return true
    }
}

class RustProxyVoiceSessionService : VoiceInteractionSessionService() {
    override fun onNewSession(args: Bundle?): VoiceInteractionSession = RustProxyVoiceSession(this)
}

class RustProxyVoiceSession(context: Context) : VoiceInteractionSession(context) {
    private val handler = Handler(Looper.getMainLooper())

    override fun onShow(args: Bundle?, showFlags: Int) {
        super.onShow(args, showFlags)
        if (args?.getBoolean(RESET_KEY) == true) resetAirplaneMode()
    }

    private fun resetAirplaneMode() {
        try {
            setAirplaneMode(true)
            // ponytail: fixed delay; T4 replaces this with ConnectivityManager confirmation.
            handler.postDelayed({ setAirplaneMode(false) }, 10_000)
        } catch (error: Exception) {
            AgentStatus.publish(context, "connected", "Assistant could not change flight mode: ${error.message}")
        }
    }

    private fun setAirplaneMode(enabled: Boolean) {
        startVoiceActivity(
            Intent(Settings.ACTION_VOICE_CONTROL_AIRPLANE_MODE)
                .putExtra(Settings.EXTRA_AIRPLANE_MODE_ENABLED, enabled),
        )
    }

    companion object {
        const val RESET_KEY = "reset_airplane_mode"
    }
}

class RustProxyRecognitionService : RecognitionService() {
    override fun onStartListening(recognizerIntent: Intent?, callback: Callback?) {
        callback?.error(SpeechRecognizer.ERROR_CLIENT)
    }

    override fun onStopListening(callback: Callback?) = Unit

    override fun onCancel(callback: Callback?) = Unit
}
