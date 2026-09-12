package com.kragvor.signal

import android.Manifest
import android.content.pm.PackageManager
import android.location.GnssMeasurementsEvent
import android.location.GnssStatus
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.os.Build
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoWcdma
import android.telephony.PhoneStateListener
import android.telephony.SignalStrength
import android.telephony.TelephonyCallback
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import com.getcapacitor.annotation.Permission
import com.getcapacitor.annotation.PermissionCallback
import org.json.JSONArray

/**
 * Exposes real radio-layer readings to JS: cellular signal strength across
 * every visible cell (not just the serving one), Wi-Fi RSSI, and GNSS
 * satellite/AGC data. This is the layer a browser genuinely cannot reach —
 * everything the web-only Jammer Detector does (navigator.connection,
 * navigator.onLine, GPS *accuracy*) is an indirect symptom; this plugin
 * reads the actual radio measurements those symptoms are downstream of.
 *
 * Two real, documented jamming tells live here, both GNSS-side:
 *   1. GNSS AGC (automatic gain control) rising — the receiver's front end
 *      turning up gain to fight a raised RF noise floor. A sustained rise
 *      of several dB above baseline, with no corresponding satellite
 *      improvement, is a recognized jamming signature.
 *   2. Satellites simultaneously dropping out of the fix across the whole
 *      sky (not just a few sinking below the horizon) while AGC is
 *      elevated. Either alone can have mundane causes (tunnel, dense
 *      urban canyon, a warming-up GPS chip); the two together are a much
 *      stronger signal than anything the web layer can produce.
 * Cellular/Wi-Fi collapse is included too, but is inherently noisier — a
 * dead cell tower, a crowded venue, or walking into a basement all look
 * similar from here. Treat all of this as evidence to correlate, not a
 * standalone verdict — there is still no substitute for a real spectrum
 * analyzer / SDR if certainty matters.
 *
 * NOTE: written against the documented Capacitor 5/6 Android plugin API
 * and Android's TelephonyManager/LocationManager/GNSS APIs, but not
 * compiled here — there's no Android SDK/Gradle in this environment.
 * Build it once in Android Studio inside the scaffolded project (see
 * android-native/README.md); the first `./gradlew assembleDebug` will
 * surface anything that needs adjusting for your exact Capacitor/AGP
 * version, and I'm glad to fix whatever it flags.
 */
@CapacitorPlugin(
    name = "SignalDetector",
    permissions = [
        Permission(strings = [Manifest.permission.ACCESS_FINE_LOCATION], alias = "location"),
        Permission(strings = [Manifest.permission.READ_PHONE_STATE], alias = "phoneState")
    ]
)
class SignalDetectorPlugin : Plugin() {

    private var telephonyManager: TelephonyManager? = null
    private var wifiManager: WifiManager? = null
    private var locationManager: LocationManager? = null
    private var monitoring = false

    // Held as Any? because the concrete listener type differs by SDK level
    // (TelephonyCallback on API 31+, the older PhoneStateListener below it).
    private var telephonyCallback: Any? = null
    private var gnssStatusCallback: GnssStatus.Callback? = null
    private var gnssMeasurementsCallback: GnssMeasurementsEvent.Callback? = null

    override fun load() {
        telephonyManager = context.getSystemService(TelephonyManager::class.java)
        wifiManager = context.applicationContext.getSystemService(WifiManager::class.java)
        locationManager = context.getSystemService(LocationManager::class.java)
    }

    @PluginMethod
    fun start(call: PluginCall) {
        if (monitoring) { call.resolve(); return }
        if (!hasRequiredPermissions()) {
            requestAllPermissions(call, "permissionCallback")
            return
        }
        beginMonitoring()
        call.resolve()
    }

    @PermissionCallback
    private fun permissionCallback(call: PluginCall) {
        if (hasRequiredPermissions()) {
            beginMonitoring()
            call.resolve()
        } else {
            call.reject("Location/phone-state permission was denied")
        }
    }

    @PluginMethod
    fun stop(call: PluginCall) {
        endMonitoring()
        call.resolve()
    }

    @PluginMethod
    fun getSnapshot(call: PluginCall) {
        val ret = JSObject()
        ret.put("cellular", readCellularSnapshot())
        ret.put("wifi", readWifiSnapshot())
        call.resolve(ret)
    }

    override fun handleOnDestroy() {
        endMonitoring()
    }

    private fun hasRequiredPermissions(): Boolean {
        val fine = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val phone = ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED
        return fine && phone
    }

    private fun beginMonitoring() {
        monitoring = true
        registerTelephony()
        registerGnss()
    }

    private fun endMonitoring() {
        monitoring = false
        unregisterTelephony()
        unregisterGnss()
    }

    // ---------------- Cellular ----------------

    private fun readCellularSnapshot(): JSObject {
        val obj = JSObject()
        val tm = telephonyManager ?: return obj
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) {
            return obj
        }
        try {
            val infos: List<CellInfo> = tm.allCellInfo ?: emptyList()
            val dbmList = infos.mapNotNull { info -> cellDbm(info) }
            obj.put("visibleCellCount", infos.size)
            if (dbmList.isNotEmpty()) obj.put("strongestDbm", dbmList.max())
            obj.put("allDbm", JSONArray(dbmList))
        } catch (e: SecurityException) {
            // Permission revoked mid-session — leave the snapshot empty rather than crash.
        }
        return obj
    }

    private fun cellDbm(info: CellInfo): Int? {
        return when (info) {
            is CellInfoLte -> info.cellSignalStrength?.dbm
            is CellInfoGsm -> info.cellSignalStrength?.dbm
            is CellInfoWcdma -> info.cellSignalStrength?.dbm
            else -> {
                // CellInfoNr (5G) only exists from API 29 — referenced via
                // reflection-free SDK gating so this still compiles and runs
                // cleanly on older devices that never produce that class.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && info is android.telephony.CellInfoNr) {
                    (info.cellSignalStrength as? android.telephony.CellSignalStrengthNr)?.dbm
                } else null
            }
        }
    }

    private fun registerTelephony() {
        val tm = telephonyManager ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val cb = object : TelephonyCallback(), TelephonyCallback.SignalStrengthsListener {
                override fun onSignalStrengthsChanged(signalStrength: SignalStrength) {
                    emitCellular(signalStrength)
                }
            }
            telephonyCallback = cb
            tm.registerTelephonyCallback(context.mainExecutor, cb)
        } else {
            @Suppress("DEPRECATION")
            val listener = object : PhoneStateListener() {
                override fun onSignalStrengthsChanged(signalStrength: SignalStrength) {
                    emitCellular(signalStrength)
                }
            }
            telephonyCallback = listener
            @Suppress("DEPRECATION")
            tm.listen(listener, PhoneStateListener.LISTEN_SIGNAL_STRENGTHS)
        }
    }

    private fun unregisterTelephony() {
        val tm = telephonyManager ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            (telephonyCallback as? TelephonyCallback)?.let { tm.unregisterTelephonyCallback(it) }
        } else {
            @Suppress("DEPRECATION")
            (telephonyCallback as? PhoneStateListener)?.let { tm.listen(it, PhoneStateListener.LISTEN_NONE) }
        }
        telephonyCallback = null
    }

    private fun emitCellular(ss: SignalStrength) {
        val obj = JSObject()
        obj.put("level", ss.level) // Android's own coarse 0(none)-4(great) bucket, always available
        obj.put("dbm", extractDbm(ss))
        obj.put("at", System.currentTimeMillis())
        notifyListeners("cellularUpdate", obj)
    }

    // getCellSignalStrengths() only exists from API 29 — gate on SDK_INT
    // rather than try/catch(Exception), since calling a method the
    // framework doesn't have throws NoSuchMethodError (an Error, not an
    // Exception) and would not be caught by a plain catch block.
    private fun extractDbm(ss: SignalStrength): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val first = ss.cellSignalStrengths.firstOrNull()
            if (first != null) return first.dbm
        }
        return ss.level
    }

    // ---------------- Wi-Fi ----------------

    private fun readWifiSnapshot(): JSObject {
        val obj = JSObject()
        try {
            val info = wifiManager?.connectionInfo
            if (info != null) obj.put("rssi", info.rssi)
        } catch (e: Exception) {
            // Best-effort; leave the field out on failure.
        }
        return obj
    }

    // ---------------- GNSS ----------------

    private fun registerGnss() {
        val lm = locationManager ?: return
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) return

        val statusCb = object : GnssStatus.Callback() {
            override fun onSatelliteStatusChanged(status: GnssStatus) {
                val total = status.satelliteCount
                var used = 0
                var cn0Sum = 0.0
                for (i in 0 until total) {
                    if (status.usedInFix(i)) used++
                    cn0Sum += status.getCn0DbHz(i)
                }
                val obj = JSObject()
                obj.put("satellitesTotal", total)
                obj.put("satellitesUsed", used)
                obj.put("avgCn0", if (total > 0) cn0Sum / total else 0.0)
                obj.put("at", System.currentTimeMillis())
                notifyListeners("gnssStatusUpdate", obj)
            }
        }
        gnssStatusCallback = statusCb
        lm.registerGnssStatusCallback(statusCb, null)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val measCb = object : GnssMeasurementsEvent.Callback() {
                override fun onGnssMeasurementsReceived(event: GnssMeasurementsEvent) {
                    val agcValues = event.measurements.mapNotNull { m ->
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && m.hasAutomaticGainControlLevelDb())
                            m.automaticGainControlLevelDb else null
                    }
                    if (agcValues.isNotEmpty()) {
                        val obj = JSObject()
                        obj.put("avgAgcDb", agcValues.average())
                        obj.put("maxAgcDb", agcValues.max())
                        obj.put("measurementCount", agcValues.size)
                        obj.put("at", System.currentTimeMillis())
                        notifyListeners("gnssAgcUpdate", obj)
                    }
                }
            }
            gnssMeasurementsCallback = measCb
            lm.registerGnssMeasurementsCallback(measCb)
        }
    }

    private fun unregisterGnss() {
        val lm = locationManager ?: return
        gnssStatusCallback?.let { lm.unregisterGnssStatusCallback(it) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            gnssMeasurementsCallback?.let { lm.unregisterGnssMeasurementsCallback(it) }
        }
        gnssStatusCallback = null
        gnssMeasurementsCallback = null
    }
}
