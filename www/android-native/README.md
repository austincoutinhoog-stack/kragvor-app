# Native signal detection — setup

This app is currently a flat static site (`index.html` + `app.js` +
`service-worker.js`). Getting real radio-layer readings requires an actual
native Android project, not just a WebView wrapper — this folder is the
missing piece. I can't run `npm`/Gradle/Android Studio in the environment
I write code in (no network, no Android SDK), so these steps are written
out in full rather than already executed for you. Nothing here has been
compiled — the first Android Studio build is what will actually confirm
it's correct, and I'm glad to fix whatever errors that surfaces.

## 1. Scaffold a Capacitor project around the existing site

From a folder containing this project's files (`index.html`, `app.js`,
`styles.css`, `signal-native.js`, `manifest.json`, `service-worker.js`,
`decode/`, icons):

```bash
npm init -y
npm install @capacitor/core @capacitor/android
npx cap init "KRAGVOR" "com.kragvor.app" --web-dir "."
npx cap add android
```

Use whatever `applicationId` you actually want instead of
`com.kragvor.app` — just keep it consistent with the `package` line in
`MainActivity-registration.kt` below.

## 2. Copy the plugin into the generated Android project

```bash
mkdir -p android/app/src/main/java/com/kragvor/signal
cp android-native/java/com/kragvor/signal/SignalDetectorPlugin.kt \
   android/app/src/main/java/com/kragvor/signal/
```

## 3. Register the plugin

Capacitor auto-discovers most `@CapacitorPlugin`-annotated classes. If
`window.Capacitor.isPluginAvailable("SignalDetector")` still comes back
`false` once running, register it explicitly — see
`android-native/MainActivity-registration.kt` for the exact change to
`android/app/src/main/java/<your/package>/MainActivity.kt`.

## 4. Add permissions

Merge the lines in `android-native/AndroidManifest-additions.xml` into
`android/app/src/main/AndroidManifest.xml` (inside `<manifest>`, above
`<application>`). Read the comment in that file about `READ_PHONE_STATE`
and Play Console's sensitive-permission review before a production release.

## 5. Sync and build

```bash
npx cap sync android
npx cap open android
```

That opens Android Studio. Build/run from there (or `./gradlew
assembleDebug` from `android/` once you have the SDK set up). This is
where actual compiler errors will surface — Capacitor/AGP/Kotlin version
mismatches are the most likely source of small adjustments needed;
`SignalDetectorPlugin.kt` was written against the current documented
Capacitor 5/6 Android plugin API, but I have no way to compile-verify it
in this sandbox.

## 6. Runtime permission prompts

`SignalDetectorPlugin.start()` calls `requestAllPermissions()`
automatically, so the OS location/phone-state prompts appear the first
time monitoring starts — no extra JS-side code needed for that part.

## What you'll see change in the app

- With everything above wired up and running on a real device (not the
  Android emulator, which fakes cellular/GNSS data — an emulator can tell
  you the plugin *runs* without errors, but its cellular/GNSS numbers are
  synthetic and won't reflect real jamming behavior), the Jammer Detector
  screen shows a banner: *"Native radio access active..."*, and the info
  button's explanation text updates to describe the two native heuristics.
- Log entries start appearing with real dBm/AGC/satellite figures in the
  detail text (`cell_dbm_drop`, `gnss_agc_spike`, `gnss_sat_dropout`), and
  a `native_gnss_jam` CRITICAL entry specifically when GNSS AGC is
  elevated and satellites are dropping out at the same time — the
  strongest signal this whole app can produce without dedicated RF
  hardware.
- Without this native build (plain browser, or the APK before this is
  wired in), `window.KragvorNativeSignal.isAvailable()` returns `false`
  and everything falls back to exactly the browser-only behavior that
  existed before — nothing here changes that path.

## Calibration

`GNSS_AGC_RISE_DB` (in `app.js`, currently `6`) is a starting point, not a
validated threshold — AGC baselines vary by GNSS chipset. If you have
access to a legal GPS signal simulator or a known noisy environment,
watch the `avgAgcDb` values in the log/console and adjust that constant
to what's actually noise for your target devices before relying on it.
