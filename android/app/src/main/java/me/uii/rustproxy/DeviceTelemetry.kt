package me.uii.rustproxy

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.telephony.TelephonyManager
import org.json.JSONObject

object DeviceTelemetry {
    fun collect(context: Context): String {
        val hasPhoneState = context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED
        val telephony = context.getSystemService(TelephonyManager::class.java)
        val battery = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = battery?.getIntExtra(BatteryManager.EXTRA_LEVEL, 0) ?: 0
        val scale = battery?.getIntExtra(BatteryManager.EXTRA_SCALE, 100) ?: 100
        val status = battery?.getIntExtra(BatteryManager.EXTRA_STATUS, BatteryManager.BATTERY_STATUS_UNKNOWN)
        val temperature = battery?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0)?.div(10.0) ?: 0.0

        return JSONObject()
            .put("carrier", if (hasPhoneState) telephony?.networkOperatorName.orEmpty().ifBlank { "unknown" } else "permission required")
            .put("net", if (hasPhoneState) networkName(telephony?.dataNetworkType ?: TelephonyManager.NETWORK_TYPE_UNKNOWN) else "unknown")
            .put("signal", if (hasPhoneState) signalLevel(telephony) else 0)
            .put("battery", if (scale > 0) (level * 100 / scale).coerceIn(0, 100) else 0)
            .put("temp_c", temperature)
            .put("charging", status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL)
            .put("health", batteryHealth(battery?.getIntExtra(BatteryManager.EXTRA_HEALTH, BatteryManager.BATTERY_HEALTH_UNKNOWN)))
            .put("app", appVersion(context))
            .put("proto", 2)
            .put("assistant", AssistantBridge.isDefault(context))
            .put("transport", transport(context))
            .toString()
    }

    private fun networkName(type: Int) = when (type) {
        TelephonyManager.NETWORK_TYPE_LTE -> "LTE"
        TelephonyManager.NETWORK_TYPE_NR -> "NR"
        TelephonyManager.NETWORK_TYPE_HSPAP, TelephonyManager.NETWORK_TYPE_HSPA,
        TelephonyManager.NETWORK_TYPE_HSDPA, TelephonyManager.NETWORK_TYPE_HSUPA,
        TelephonyManager.NETWORK_TYPE_UMTS -> "3G"
        TelephonyManager.NETWORK_TYPE_EDGE, TelephonyManager.NETWORK_TYPE_GPRS,
        TelephonyManager.NETWORK_TYPE_CDMA, TelephonyManager.NETWORK_TYPE_1xRTT -> "2G"
        else -> "unknown"
    }

    private fun signalLevel(telephony: TelephonyManager?): Int = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            telephony?.signalStrength?.level ?: 0
        } else {
            telephony?.allCellInfo?.maxOfOrNull { it.cellSignalStrength.level } ?: 0
        }
    }.getOrDefault(0).coerceIn(0, 4)

    private fun batteryHealth(value: Int?) = when (value) {
        BatteryManager.BATTERY_HEALTH_GOOD -> "good"
        BatteryManager.BATTERY_HEALTH_OVERHEAT -> "overheat"
        BatteryManager.BATTERY_HEALTH_DEAD -> "dead"
        BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "over_voltage"
        BatteryManager.BATTERY_HEALTH_COLD -> "cold"
        BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "failure"
        else -> "unknown"
    }

    private fun appVersion(context: Context): String {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            "${info.versionName ?: "unknown"}+${info.longVersionCode}"
        } else {
            info.versionName ?: "unknown"
        }
    }

    private fun transport(context: Context): String {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val capabilities = manager.getNetworkCapabilities(manager.activeNetwork)
        return if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) "cellular" else "wifi"
    }
}
