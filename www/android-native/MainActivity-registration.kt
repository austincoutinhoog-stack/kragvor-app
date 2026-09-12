// android/app/src/main/java/<your/package>/MainActivity.kt
//
// Capacitor auto-discovers plugins annotated with @CapacitorPlugin in most
// current CLI versions, so this may already work with no changes. If the
// plugin doesn't show up at runtime (window.Capacitor.isPluginAvailable
// returns false), register it explicitly like this instead:

package com.kragvor.app // replace with your actual applicationId's package

import android.os.Bundle
import com.getcapacitor.BridgeActivity
import com.kragvor.signal.SignalDetectorPlugin

class MainActivity : BridgeActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        registerPlugin(SignalDetectorPlugin::class.java)
        super.onCreate(savedInstanceState)
    }
}
