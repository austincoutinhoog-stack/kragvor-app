/* =========================================================
   KRAGVOR bridge — syncs DECODE's existing localStorage-based
   stats to the account's decode_stats row in Supabase.
   Deliberately does NOT touch the game's own save/load logic;
   it only seeds localStorage before the game reads it, and
   pushes localStorage to Supabase after the game writes to it.
   The game keeps working exactly as before if this bridge is
   ever absent (e.g. opened standalone, outside KRAGVOR).
   ========================================================= */
(function () {
  "use strict";

  var STORAGE_KEY = "kragvor_word01_stats";
  var DAILY_STORAGE_KEY = "kragvor_word01_daily";
  var DAILY_STREAK_KEY = "kragvor_word01_daily_streak";

  var params = new URLSearchParams((location.hash || "").replace(/^#/, ""));
  var accessToken = params.get("at");
  var refreshToken = params.get("rt");
  var supabaseUrl = params.get("su");
  var supabaseAnonKey = params.get("sk");
  var userId = params.get("uid");

  // Tokens only ever need to be read once, right here — drop them from
  // the visible/history URL immediately rather than leaving them sitting
  // in the address bar or iframe history entry.
  if (window.history && history.replaceState) {
    try { history.replaceState(null, "", location.pathname + location.search); } catch (e) {}
  }

  var client = null;
  if (accessToken && refreshToken && supabaseUrl && supabaseAnonKey && userId && window.supabase) {
    client = window.supabase.createClient(supabaseUrl, supabaseAnonKey, {
      auth: { persistSession: false, autoRefreshToken: true },
    });
  }

  function readLocalRaw(key) {
    try { return localStorage.getItem(key); } catch (e) { return null; }
  }
  function readLocalJSON(key, fallback) {
    try {
      var raw = readLocalRaw(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (e) {
      return fallback;
    }
  }

  function rowToLocal(row) {
    var stats = {
      played: row.played || 0,
      won: row.won || 0,
      currentStreak: row.current_streak || 0,
      bestStreak: row.best_streak || 0,
      bestScore: row.best_score === undefined ? null : row.best_score,
    };
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(stats)); } catch (e) {}
    if (row.last_daily_record) {
      try { localStorage.setItem(DAILY_STORAGE_KEY, JSON.stringify(row.last_daily_record)); } catch (e) {}
    }
    try { localStorage.setItem(DAILY_STREAK_KEY, String(row.daily_streak || 0)); } catch (e) {}
  }

  function pull() {
    if (!client) return Promise.resolve();
    return client.auth.setSession({ access_token: accessToken, refresh_token: refreshToken })
      .then(function () {
        return client.from("decode_stats").select("*").eq("user_id", userId).maybeSingle();
      })
      .then(function (res) {
        // Only a genuine cloud row seeds local storage — an account that
        // has never synced before (no row yet) keeps whatever progress
        // already exists on this device untouched, so nothing already
        // played here is ever silently discarded.
        if (res && res.data) rowToLocal(res.data);
      })
      .catch(function () {});
  }

  var readyResolve;
  window.__decodeSyncReady = new Promise(function (resolve) { readyResolve = resolve; });
  var settled = false;
  function finish() {
    if (settled) return;
    settled = true;
    readyResolve();
  }
  pull().then(finish, finish);
  // Never let a slow/unreachable network hold up actually playing the game.
  setTimeout(finish, 4000);

  var pushInFlight = false;
  var pushAgainAfter = false;
  function push() {
    if (!client) return;
    if (pushInFlight) { pushAgainAfter = true; return; }
    pushInFlight = true;
    var stats = readLocalJSON(STORAGE_KEY, {});
    var daily = readLocalJSON(DAILY_STORAGE_KEY, null);
    var dailyStreakRaw = Number(readLocalRaw(DAILY_STREAK_KEY) || 0);
    var dailyStreak = Number.isFinite(dailyStreakRaw) ? dailyStreakRaw : 0;

    client.from("decode_stats").upsert({
      user_id: userId,
      played: stats.played || 0,
      won: stats.won || 0,
      current_streak: stats.currentStreak || 0,
      best_streak: stats.bestStreak || 0,
      best_score: stats.bestScore === undefined ? null : stats.bestScore,
      daily_streak: dailyStreak,
      last_daily_record: daily,
      updated_at: new Date().toISOString(),
    }, { onConflict: "user_id" }).then(done, done);

    function done() {
      pushInFlight = false;
      if (pushAgainAfter) { pushAgainAfter = false; push(); }
    }
  }

  window.__decodeSyncPush = push;
})();
