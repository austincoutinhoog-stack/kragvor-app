/* KRAGVOR — native signal bridge.
   Wraps the Capacitor "SignalDetector" plugin (android-native/) in a small
   API on window.KragvorNativeSignal. In a plain browser, or a build where
   the native Android project hasn't been wired up yet, window.Capacitor
   simply won't exist — every method below resolves to "unavailable"
   instead of throwing, so app.js's Jammer Detector keeps working exactly
   as it did before this file existed. Load this before app.js.
*/
(function () {
  "use strict";

  function getPlugin() {
    const cap = window.Capacitor;
    if (!cap || typeof cap.isPluginAvailable !== "function") return null;
    if (!cap.isPluginAvailable("SignalDetector")) return null;
    return (cap.Plugins && cap.Plugins.SignalDetector) || null;
  }

  function isAvailable() { return getPlugin() !== null; }

  let listenerHandles = [];

  // onEvent(kind, data) is called for "cellular", "gnssStatus", "gnssAgc".
  async function start(onEvent) {
    const plugin = getPlugin();
    if (!plugin) return { ok: false, reason: "unavailable" };
    try {
      listenerHandles.push(await plugin.addListener("cellularUpdate", (data) => onEvent("cellular", data)));
      listenerHandles.push(await plugin.addListener("gnssStatusUpdate", (data) => onEvent("gnssStatus", data)));
      listenerHandles.push(await plugin.addListener("gnssAgcUpdate", (data) => onEvent("gnssAgc", data)));
      await plugin.start();
      return { ok: true };
    } catch (err) {
      await stop(); // clean up any listeners that did attach before the failure
      return { ok: false, reason: (err && err.message) || "start_failed" };
    }
  }

  async function stop() {
    const handles = listenerHandles;
    listenerHandles = [];
    for (const h of handles) { try { await h.remove(); } catch (e) { /* already gone */ } }
    const plugin = getPlugin();
    if (!plugin) return;
    try { await plugin.stop(); } catch (e) { /* plugin already stopped/destroyed */ }
  }

  async function snapshot() {
    const plugin = getPlugin();
    if (!plugin) return null;
    try { return await plugin.getSnapshot(); } catch (e) { return null; }
  }

  window.KragvorNativeSignal = { isAvailable, start, stop, snapshot };
})();
