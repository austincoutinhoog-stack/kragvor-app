/* ==========================================================================
   KRAGVOR — application logic
   Single-file SPA, offline-first (localStorage), hash-based routing.
   ========================================================================== */

/* ==========================================================================
   PART 0 — Supabase client & backend bridge
   The real authentication/authorization boundary lives on the server
   (Supabase Auth + Postgres RLS + the edge functions below). This module
   only ever holds the public anon key, never a service-role key.
   ========================================================================== */
(() => {
  "use strict";

  const SUPABASE_URL = "https://uzdrfywwivvrgulhpszp.supabase.co";
  const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InV6ZHJmeXd3aXZ2cmd1bGhwc3pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg1NzIzNTksImV4cCI6MjEwNDE0ODM1OX0.xlL7hNX9sn4Vy5pxDGgTmhKQlAOFlgmN5rbchBe2tfU";

  // Back the Supabase Auth session with sessionStorage rather than
  // localStorage. This still gives us a genuine, signed backend session
  // while the tab/app is open (surviving a hash-route change or an
  // accidental refresh), but — matching KRAGVOR's existing requirement —
  // closing the app/tab clears it, so login is required on every fresh
  // open. This is deliberately NOT a "Remember Me" mechanism.
  const sessionStorageAdapter = {
    getItem: (key) => { try { return window.sessionStorage.getItem(key); } catch (e) { return null; } },
    setItem: (key, value) => { try { window.sessionStorage.setItem(key, value); } catch (e) {} },
    removeItem: (key) => { try { window.sessionStorage.removeItem(key); } catch (e) {} },
  };

  const client = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      storage: sessionStorageAdapter,
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: false,
    },
  });

  // Calls one of KRAGVOR's Supabase Edge Functions. When requireAuth is
  // true (the default), the CURRENT real Supabase session's access token is
  // attached as a Bearer token — the function then independently verifies
  // that token and looks up the caller's own profile row server-side. No
  // client-supplied identity or role is ever trusted.
  async function callEdgeFunction(name, body, { requireAuth = true } = {}) {
    const headers = { "Content-Type": "application/json" };
    if (requireAuth) {
      const { data } = await client.auth.getSession();
      const session = data && data.session;
      if (!session) return { ok: false, error: "not_authenticated" };
      headers["Authorization"] = `Bearer ${session.access_token}`;
    }
    let res, body_;
    try {
      res = await fetch(`${SUPABASE_URL}/functions/v1/${name}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body || {}),
      });
      body_ = await res.json().catch(() => ({}));
    } catch (e) {
      // The device's own connectivity state tells us whether this was
      // really "no internet" versus some other failure (server down,
      // misconfiguration, CORS, DNS) — don't claim "offline" when the
      // device genuinely has a connection.
      return { ok: false, error: navigator.onLine ? "server_unreachable" : "offline" };
    }
    if (!res.ok) {
      return { ok: false, status: res.status, error: body_.error || "request_failed", detail: body_.detail };
    }
    return body_;
  }

  window.__KRAGVOR_SUPABASE__ = { client, callEdgeFunction, SUPABASE_URL, SUPABASE_ANON_KEY };
})();

(() => {
  "use strict";

  /* ---------------------------------------------------------------------
     Storage keys & defaults
     --------------------------------------------------------------------- */
  const LS_ACCOUNTS   = "kragvor_accounts_v1";
  const LS_FAVORITES  = "kragvor_favorites_v1";
  const LS_PREFS      = "kragvor_prefs_v1";
  const SS_SESSION    = "kragvor_session_v1";
  const LS_SECLOG      = "kragvor_seclog_v1";
  const LS_LOGINGUARD  = "kragvor_loginguard_v1";
  const LS_NOTES        = "kragvor_notes_v1";
  const LS_CALCHISTORY  = "kragvor_calchistory_v1";
  const LS_VAULT        = "kragvor_vault_v1";
  const LS_VAULT_RECOVERY = "kragvor_vault_recovery_v1";
  const LS_JAMLOG        = "kragvor_jamlog_v1";
  const SS_VAULT_UNLOCKED  = "kragvor_vault_unlocked_v1";

  // Credentials are never stored in plaintext. Accounts created or updated
  // going forward use a versioned PBKDF2 credential string of the form
  // "pbkdf2$<iterations>$<saltHex>$<hashHex>" (see hashSecretV2 / setCredential
  // below). This seeded record was generated offline the same way — no
  // plaintext password is stored anywhere in this file.
  const DEFAULT_OWNER = {
    id: "owner-1",
    firstName: "Austin",
    lastName: "Coutinho",
    credential: "pbkdf2$210000$b3f1a9c2d84e4f10a6d7c9e2f0b13a55$f459807f4f841f085ecdd93b152defc06fdf4d2e812a3cbdffa78170a3ee07df",
    type: "owner",
    birthYear: null,
    enabled: true,
    createdAt: Date.now()
  };

  const APPS_REGISTRY = [];

  /* ---------------------------------------------------------------------
     Tiny helpers
     --------------------------------------------------------------------- */
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const norm = (s) => (s || "").toString().trim().toLowerCase();
  const escapeHtml = (s) =>
    (s || "").toString().replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  const uid = (prefix) => `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;

  function readJSON(storage, key, fallback) {
    try {
      const raw = storage.getItem(key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (e) {
      return fallback;
    }
  }
  function writeJSON(storage, key, value) {
    storage.setItem(key, JSON.stringify(value));
  }

  /* ---------------------------------------------------------------------
     Password / PIN hashing — never store secrets in plaintext.
     --------------------------------------------------------------------- */
  async function sha256Hex(str) {
    const enc = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest("SHA-256", enc);
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  async function hashSecret(secret, salt) {
    // Legacy (pre-PBKDF2) single-round SHA-256 verification path, kept only
    // so accounts created before the KDF upgrade can still log in and be
    // transparently migrated. New credentials never use this.
    return sha256Hex(`${salt}:${norm(secret)}`);
  }
  function newSalt() {
    return uid("salt");
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  function hexToBytes(hex) {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
    return arr;
  }
  function randomSaltHex(numBytes = 16) {
    const arr = new Uint8Array(numBytes);
    crypto.getRandomValues(arr);
    return bytesToHex(arr);
  }
  function timingSafeEqualHex(a, b) {
    if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  const PBKDF2_ITERATIONS = 210000; // OWASP-recommended baseline for PBKDF2-HMAC-SHA256

  async function pbkdf2Hex(secret, saltHex, iterations, lengthBytes = 32) {
    const keyMaterial = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret), "PBKDF2", false, ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: hexToBytes(saltHex), iterations, hash: "SHA-256" },
      keyMaterial,
      lengthBytes * 8
    );
    return bytesToHex(new Uint8Array(bits));
  }

  // Versioned credential format: "pbkdf2$<iterations>$<saltHex>$<hashHex>".
  // The version prefix means the KDF or its parameters can be upgraded
  // again later without breaking existing accounts.
  async function hashSecretV2(secret, saltHex, iterations = PBKDF2_ITERATIONS) {
    const hashHex = await pbkdf2Hex(norm(secret), saltHex, iterations, 32);
    return `pbkdf2$${iterations}$${saltHex}$${hashHex}`;
  }
  async function makeCredential(secret) {
    return hashSecretV2(secret, randomSaltHex(16));
  }
  async function verifyCredentialString(secret, credential) {
    const parts = (credential || "").split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;
    const iterations = parseInt(parts[1], 10);
    if (!Number.isFinite(iterations) || iterations <= 0) return false;
    const candidate = await pbkdf2Hex(norm(secret), parts[2], iterations, 32);
    return timingSafeEqualHex(candidate, parts[3]);
  }

  // Verifies a secret against whichever credential format the account
  // currently has. Legacy (pre-KDF) accounts are checked with the old
  // single-round SHA-256 path so they keep working, and are transparently
  // upgraded to the versioned PBKDF2 format on next successful login.
  async function verifyAccountCredential(account, secret) {
    if (account.credential) return verifyCredentialString(secret, account.credential);
    if (account.passwordHash && account.salt) {
      return (await hashSecret(secret, account.salt)) === account.passwordHash;
    }
    return false;
  }
  async function setAccountCredential(account, secret) {
    account.credential = await makeCredential(secret);
    delete account.salt;
    delete account.passwordHash;
  }
  function accountNeedsMigration(account) {
    return !account.credential && !!(account.passwordHash && account.salt);
  }

  /* ---------------------------------------------------------------------
     Accounts store
     --------------------------------------------------------------------- */
  function getAccounts() {
    let accounts = readJSON(localStorage, LS_ACCOUNTS, null);
    if (!accounts || !Array.isArray(accounts) || accounts.length === 0) {
      accounts = [DEFAULT_OWNER];
      writeJSON(localStorage, LS_ACCOUNTS, accounts);
    }
    return accounts;
  }
  function saveAccounts(accounts) {
    writeJSON(localStorage, LS_ACCOUNTS, accounts);
  }
  function findAccount(id) {
    return getAccounts().find((a) => a.id === id) || null;
  }

  /* ---------------------------------------------------------------------
     Session
     ------------------------------------------------------------------
     The authenticated identity now comes from Supabase Auth + the
     `profiles` table (RLS-protected: `id = auth.uid()`), not from a
     locally-editable localStorage/sessionStorage record. `_cachedProfile`
     is only a synchronous read cache of the last SERVER-CONFIRMED profile
     row so the hundreds of existing `currentUser()` call sites throughout
     the app keep working without becoming async; it is populated only by
     `refreshCurrentUserProfile()`, which always re-queries Supabase.
     A person editing sessionStorage by hand cannot forge this — every
     actual data read/write is separately re-checked by Postgres RLS and,
     for owner-only actions, by the `family-manage` edge function against
     the caller's real row.
     --------------------------------------------------------------------- */
  const SUPA = window.__KRAGVOR_SUPABASE__;
  let _cachedProfile = null; // { id, firstName, lastName, type, birthYear, enabled }

  function mapProfileRow(row) {
    if (!row) return null;
    return {
      id: row.id,
      firstName: row.first_name,
      lastName: row.last_name,
      type: row.account_type,
      birthYear: row.birth_year,
      enabled: row.is_active,
    };
  }

  // Re-fetches the caller's OWN profile row (RLS guarantees it can only
  // ever be their own) and refreshes the synchronous cache. Returns null
  // (and clears the cache) if there's no session or the account is gone/disabled.
  async function refreshCurrentUserProfile() {
    const { data: userData } = await SUPA.client.auth.getUser();
    const authUser = userData && userData.user;
    if (!authUser) { _cachedProfile = null; return null; }

    const { data: row, error } = await SUPA.client
      .from("profiles")
      .select("id, first_name, last_name, account_type, birth_year, is_active")
      .eq("id", authUser.id)
      .single();

    if (error || !row || !row.is_active) {
      _cachedProfile = null;
      return null;
    }
    _cachedProfile = mapProfileRow(row);
    return _cachedProfile;
  }

  // Called once at app boot to rehydrate an existing (sessionStorage-backed)
  // Supabase session, if any, before the router does its first render.
  async function restoreSessionOnBoot() {
    const { data } = await SUPA.client.auth.getSession();
    if (!data || !data.session) { _cachedProfile = null; return null; }
    const profile = await refreshCurrentUserProfile();
    if (profile) window.dispatchEvent(new CustomEvent("kragvor:session-ready"));
    return profile;
  }

  function getSession() {
    // Retained for compatibility with any code that only wants to know
    // "is someone logged in" without the full profile.
    return _cachedProfile ? { accountId: _cachedProfile.id } : null;
  }
  function clearSession() {
    _cachedProfile = null;
  }
  function currentUser() {
    return _cachedProfile;
  }
  function isOwner() {
    const u = currentUser();
    return !!u && u.type === "owner";
  }

  /* ---------------------------------------------------------------------
     Security event log
     Never log: passwords, PINs, private vault contents, tokens, keys.
     --------------------------------------------------------------------- */
  const SEVERITY = { NORMAL: "NORMAL", SUSPICIOUS: "SUSPICIOUS", HIGH_RISK: "HIGH RISK", CRITICAL: "CRITICAL" };

  function getSecurityLog() {
    return readJSON(localStorage, LS_SECLOG, []);
  }
  function logSecurityEvent(type, { accountId = null, accountName = null, status = "info", severity = SEVERITY.NORMAL, detail = "" } = {}) {
    const log = getSecurityLog();
    log.unshift({
      id: uid("evt"),
      type,
      accountId,
      accountName,
      status,
      severity,
      detail,
      at: Date.now()
    });
    // Cap growth — keep the most recent 500 events.
    if (log.length > 500) log.length = 500;
    writeJSON(localStorage, LS_SECLOG, log);
    return log[0];
  }

  /* ---------------------------------------------------------------------
     Login rate limiting / brute-force protection
     Keyed by the attempted (normalized) name so unknown/mistyped accounts
     are also throttled, not just accounts that exist.
     --------------------------------------------------------------------- */
  const LOGIN_MAX_ATTEMPTS = 5;
  const LOGIN_WINDOW_MS = 10 * 60 * 1000;   // 10 minutes
  const LOGIN_LOCK_MS = 5 * 60 * 1000;      // 5 minute lockout

  function loginGuardKey(first, last) {
    return `${norm(first)}|${norm(last)}`;
  }
  function getLoginGuards() {
    return readJSON(localStorage, LS_LOGINGUARD, {});
  }
  function saveLoginGuards(g) {
    writeJSON(localStorage, LS_LOGINGUARD, g);
  }
  function checkLoginGuard(first, last) {
    const guards = getLoginGuards();
    const key = loginGuardKey(first, last);
    const g = guards[key];
    if (g && g.lockedUntil && g.lockedUntil > Date.now()) {
      return { locked: true, retryAt: g.lockedUntil };
    }
    return { locked: false };
  }
  function registerFailedLogin(first, last) {
    const guards = getLoginGuards();
    const key = loginGuardKey(first, last);
    const now = Date.now();
    let g = guards[key] || { count: 0, windowStart: now, lockedUntil: 0 };
    if (now - g.windowStart > LOGIN_WINDOW_MS) {
      g = { count: 0, windowStart: now, lockedUntil: 0 };
    }
    g.count += 1;
    let justLocked = false;
    if (g.count >= LOGIN_MAX_ATTEMPTS) {
      g.lockedUntil = now + LOGIN_LOCK_MS;
      justLocked = true;
    }
    guards[key] = g;
    saveLoginGuards(guards);
    return { count: g.count, justLocked, lockedUntil: g.lockedUntil };
  }
  function clearLoginGuard(first, last) {
    const guards = getLoginGuards();
    delete guards[loginGuardKey(first, last)];
    saveLoginGuards(guards);
  }

  /* ---------------------------------------------------------------------
     Auth — real backend authentication.
     Credentials are sent to the `login` Supabase Edge Function, which is
     the ONLY place the password check happens. It returns a genuine
     Supabase Auth session (never anything fabricated client-side), which
     we hand to the Supabase client so every subsequent request carries a
     real, signed access token. login_success/login_failed events are
     logged server-side by that same function — a client can't fabricate
     them (see PART 0 / `security_events` RLS: no client INSERT policy).
     The client-side login-guard below is only a UX speed bump against
     rapid re-submits; it is not the security boundary.
     --------------------------------------------------------------------- */
  async function attemptLogin(firstName, lastName, password) {
    const guard = checkLoginGuard(firstName, lastName);
    if (guard.locked) {
      return { ok: false, reason: "locked", retryAt: guard.retryAt };
    }

    const res = await SUPA.callEdgeFunction(
      "login",
      { firstName, lastName, password },
      { requireAuth: false }
    );

    if (!res.ok) {
      if (res.error === "account_disabled") {
        return { ok: false, reason: "disabled" };
      }
      if (res.error === "offline") {
        return { ok: false, reason: "offline" };
      }
      if (res.error === "server_unreachable") {
        return { ok: false, reason: "server_unreachable" };
      }
      const guardRes = registerFailedLogin(firstName, lastName);
      if (guardRes.justLocked) {
        return { ok: false, reason: "locked", retryAt: guardRes.lockedUntil };
      }
      return { ok: false, reason: "invalid" };
    }

    // Hand the genuine access/refresh tokens to the Supabase client so it
    // (and every future request in this tab) is a truly authenticated
    // session — not something we're simulating locally.
    const { error: setErr } = await SUPA.client.auth.setSession({
      access_token: res.session.access_token,
      refresh_token: res.session.refresh_token,
    });
    if (setErr) return { ok: false, reason: "invalid" };

    clearLoginGuard(firstName, lastName);
    const profile = await refreshCurrentUserProfile();
    if (!profile) {
      // Session was established but the profile couldn't be confirmed
      // (e.g. disabled between login and now) — don't let the app in.
      await SUPA.client.auth.signOut();
      return { ok: false, reason: "invalid" };
    }

    // Local, best-effort mirror for the existing (not-yet-backend-wired)
    // Security Center UI. The authoritative log lives server-side in
    // `security_events`, written by the `login` edge function itself.
    logSecurityEvent("login_success", {
      accountId: profile.id, accountName: `${profile.firstName} ${profile.lastName}`,
      status: "success", severity: SEVERITY.NORMAL, detail: "Signed in."
    });
    window.dispatchEvent(new CustomEvent("kragvor:session-ready"));
    return { ok: true, account: profile };
  }

  // Changes the CURRENTLY authenticated account's own password. The
  // current password is verified by actually re-running it through the
  // `login` edge function (the same server-side check used to sign in) —
  // never by comparing against anything stored client-side — before the
  // new password is set via Supabase Auth's own updateUser call.
  async function changeOwnPassword(currentPassword, newPassword) {
    const u = currentUser();
    if (!u) return { ok: false, reason: "not_authenticated" };
    if (!newPassword || !newPassword.trim()) return { ok: false, reason: "weak_password" };

    const verify = await SUPA.callEdgeFunction(
      "login",
      { firstName: u.firstName, lastName: u.lastName, password: currentPassword },
      { requireAuth: false }
    );
    if (!verify.ok) {
      if (verify.error === "offline" || verify.error === "server_unreachable") {
        return { ok: false, reason: verify.error };
      }
      return { ok: false, reason: "current_incorrect" };
    }

    // That verification call itself opened a session for this same
    // account — re-anchor the client to it before changing the password,
    // then update.
    await SUPA.client.auth.setSession({
      access_token: verify.session.access_token,
      refresh_token: verify.session.refresh_token,
    });

    const { error } = await SUPA.client.auth.updateUser({ password: newPassword });
    if (error) return { ok: false, reason: "update_failed", detail: error.message };

    logSecurityEvent("password_changed", {
      accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
      status: "success", severity: SEVERITY.NORMAL, detail: "Account holder changed their own password."
    });
    SUPA.callEdgeFunction("log-event", { eventType: "password_changed" }).catch(() => {});
    return { ok: true };
  }

  async function logout() {
    const u = currentUser();
    if (u) {
      logSecurityEvent("logout", {
        accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
        status: "success", severity: SEVERITY.NORMAL, detail: "Signed out."
      });
      // Best-effort server-side log too; never blocks logout on failure.
      SUPA.callEdgeFunction("log-event", { eventType: "logout" }).catch(() => {});
    }
    // Let other modules (Vault) clear any sensitive in-memory state before
    // the session actually clears.
    window.dispatchEvent(new CustomEvent("kragvor:logout"));
    await SUPA.client.auth.signOut();
    clearSession();
    location.hash = "#/login";
  }

  /* ---------------------------------------------------------------------
     Favorites (per account)
     --------------------------------------------------------------------- */
  function favKey(accountId) {
    return `${accountId}`;
  }
  function favoritesDirtyKey(accountId) { return `kragvor_favs_dirty_v1_${accountId}`; }
  function markFavoritesDirty(accountId) { localStorage.setItem(favoritesDirtyKey(accountId), "1"); }
  function clearFavoritesDirty(accountId) { localStorage.removeItem(favoritesDirtyKey(accountId)); }
  function isFavoritesDirty(accountId) { return localStorage.getItem(favoritesDirtyKey(accountId)) === "1"; }

  async function pushFavoritesToCloud() {
    const u = currentUser();
    if (!u || !navigator.onLine) return false;
    try {
      const { data: existing } = await SUPA.client.from("settings").select("data").eq("user_id", u.id).maybeSingle();
      const mergedData = { ...(existing && existing.data ? existing.data : {}), favoriteApps: getFavorites() };
      const { error } = await SUPA.client.from("settings").upsert(
        { user_id: u.id, data: mergedData, updated_at: new Date().toISOString() },
        { onConflict: "user_id" }
      );
      if (error) return false;
      clearFavoritesDirty(u.id);
      return true;
    } catch (e) {
      return false;
    }
  }
  async function pullFavoritesFromCloud() {
    const u = currentUser();
    if (!u || !navigator.onLine) return false;
    if (isFavoritesDirty(u.id)) return true; // unsynced local change takes priority
    const { data, error } = await SUPA.client.from("settings").select("data").eq("user_id", u.id).maybeSingle();
    if (error) return false;
    const cloudFavorites = data && data.data && Array.isArray(data.data.favoriteApps) ? data.data.favoriteApps : null;
    if (!cloudFavorites) return true; // nothing set in the cloud yet
    const all = readJSON(localStorage, LS_FAVORITES, {});
    all[favKey(u.id)] = cloudFavorites;
    writeJSON(localStorage, LS_FAVORITES, all);
    return true;
  }
  window.addEventListener("kragvor:session-ready", () => { pullFavoritesFromCloud(); pushFavoritesToCloud(); });
  window.addEventListener("online", () => { pullFavoritesFromCloud(); pushFavoritesToCloud(); });
  setInterval(() => { pushFavoritesToCloud(); }, 20000);

  function getFavorites() {
    const u = currentUser();
    if (!u) return [];
    const all = readJSON(localStorage, LS_FAVORITES, {});
    return all[favKey(u.id)] || [];
  }
  function toggleFavorite(appId) {
    const u = currentUser();
    if (!u) return;
    const all = readJSON(localStorage, LS_FAVORITES, {});
    const key = favKey(u.id);
    const list = new Set(all[key] || []);
    if (list.has(appId)) list.delete(appId); else list.add(appId);
    all[key] = Array.from(list);
    writeJSON(localStorage, LS_FAVORITES, all);
    markFavoritesDirty(u.id);
    pushFavoritesToCloud(); // fire-and-forget
  }
  function isFavoritesDirtyForCurrentUser() {
    const u = currentUser();
    return u ? isFavoritesDirty(u.id) : false;
  }

  /* ---------------------------------------------------------------------
     Account data purge — invoked when an account is permanently deleted.
     All per-account stores are namespaced by accountId, so this removes
     every trace of that account's private data (Notes, Vault, Vault
     images, Calculator history, Favorites, recovery cooldown state, and
     the session-scoped Vault unlock flag) rather than leaving it orphaned.
     --------------------------------------------------------------------- */
  function purgeAccountData(accountId) {
    if (!accountId) return;
    [LS_NOTES, LS_CALCHISTORY, LS_VAULT, LS_VAULT_RECOVERY, LS_FAVORITES, "kragvor_recent_searches_v1"].forEach((key) => {
      const all = readJSON(localStorage, key, {});
      if (Object.prototype.hasOwnProperty.call(all, accountId)) {
        delete all[accountId];
        writeJSON(localStorage, key, all);
      }
    });
    const unlockMap = readJSON(sessionStorage, SS_VAULT_UNLOCKED, {});
    if (Object.prototype.hasOwnProperty.call(unlockMap, accountId)) {
      delete unlockMap[accountId];
      writeJSON(sessionStorage, SS_VAULT_UNLOCKED, unlockMap);
    }
    // The account is permanently gone server-side too (family-manage's
    // "remove" cascades through the database) — nothing queued against it
    // could ever succeed, so stop it from retrying forever.
    [`kragvor_syncqueue_v1_${accountId}`, `kragvor_vault_dirty_v1_${accountId}`, `kragvor_favs_dirty_v1_${accountId}`]
      .forEach((key) => localStorage.removeItem(key));
  }

  /* ---------------------------------------------------------------------
     Preferences (appearance)
     --------------------------------------------------------------------- */
  function getPrefs() {
    return readJSON(localStorage, LS_PREFS, { reduceMotion: false, compact: false });
  }
  function setPrefs(patch) {
    const p = { ...getPrefs(), ...patch };
    writeJSON(localStorage, LS_PREFS, p);
    applyPrefs();
  }
  function applyPrefs() {
    const p = getPrefs();
    document.documentElement.style.setProperty("--dur", p.reduceMotion ? "0.001ms" : "180ms");
    document.body.classList.toggle("compact", !!p.compact);
  }

  /* ---------------------------------------------------------------------
     Icons (hand-authored minimal line icons, no external deps)
     --------------------------------------------------------------------- */
  const ICONS = {
    dashboard: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.2"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.2"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.2"/></svg>`,
    apps: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="4" y="4" width="6" height="6" rx="1.4"/><rect x="14" y="4" width="6" height="6" rx="1.4"/><rect x="4" y="14" width="6" height="6" rx="1.4"/><circle cx="17" cy="17" r="3"/></svg>`,
    favorites: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 4.5c1.6-2.6 6.5-2.6 7.6 1.2 1 3.3-2.7 6.6-7.6 10.8-4.9-4.2-8.6-7.5-7.6-10.8C5.5 1.9 10.4 1.9 12 4.5z"/></svg>`,
    settings: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/><circle cx="12" cy="12" r="3"/></svg>`,
    account: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="8" r="3.2"/><path d="M5 20c1-3.6 4-5.5 7-5.5s6 1.9 7 5.5"/></svg>`,
    family: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="8" cy="8" r="2.6"/><circle cx="17" cy="8" r="2.6"/><path d="M3 19c.7-2.8 2.6-4.3 5-4.3s4.3 1.5 5 4.3M13 19c.6-2.4 2.2-3.7 4.3-3.7s3.7 1.3 4.3 3.7"/></svg>`,
    appearance: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="8.5"/><path d="M12 3.5A8.5 8.5 0 0 0 12 20.5z" fill="currentColor" stroke="none" opacity="0.85"/></svg>`,
    info: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.2M12 8.2v.2"/></svg>`,
    logout: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M9 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3M15 16l4-4-4-4M19 12H9"/></svg>`,
    chevron: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 6l6 6-6 6"/></svg>`,
    plus: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14"/></svg>`,
    edit: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 20h4l10-10-4-4L4 16v4z"/></svg>`,
    power: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3v8"/><path d="M6 6.5a8 8 0 1 0 12 0"/></svg>`,
    trash: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M5 7h14M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2M7 7l1 13h8l1-13"/></svg>`,
    lock: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="5" y="10.5" width="14" height="9" rx="1.6"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/></svg>`,
    close: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M6 6l12 12M18 6L6 18"/></svg>`,
    check: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 12l5 5L20 6"/></svg>`,
    star: `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M12 3l2.6 5.9 6.4.6-4.8 4.3 1.4 6.3L12 17l-5.6 3.1 1.4-6.3-4.8-4.3 6.4-.6z"/></svg>`,
    starOutline: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3l2.6 5.9 6.4.6-4.8 4.3 1.4 6.3L12 17l-5.6 3.1 1.4-6.3-4.8-4.3 6.4-.6z"/></svg>`,
    glyph: `<svg viewBox="0 0 100 100" fill="none"><rect width="100" height="100" rx="18" fill="#0a0b0d"/><rect x="30" y="24" width="9" height="52" fill="#b08d57"/><path d="M42 46l30-22h11L48 48z" fill="#b08d57"/><path d="M42 54l30 22h11L48 52z" fill="#b08d57"/></svg>`,
    search: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M20 20l-4.8-4.8"/></svg>`,
    calculator: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="5" y="3" width="14" height="18" rx="2"/><path d="M8 7.5h8M8 12h1M11.5 12h1M15 12h1M8 15.5h1M11.5 15.5h1M15 15.5h1M8 19h1M11.5 19h1M15 19h1"/></svg>`,
    decode: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3.5" y="4" width="4.2" height="4.2" rx="0.8"/><rect x="9.9" y="4" width="4.2" height="4.2" rx="0.8"/><rect x="16.3" y="4" width="4.2" height="4.2" rx="0.8"/><rect x="3.5" y="10.4" width="4.2" height="4.2" rx="0.8" fill="currentColor" opacity="0.85"/><rect x="9.9" y="10.4" width="4.2" height="4.2" rx="0.8"/><path d="M4 19h16"/></svg>`,
    notes: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M6 3h9l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v5h5"/><path d="M8 12.5h8M8 16h5"/></svg>`,
    vault: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3.5" y="4" width="17" height="16" rx="2"/><circle cx="12" cy="12" r="4"/><path d="M12 9.5v1.2M12 15.5V12M14.4 13.4l-1-.6"/></svg>`,
    shield: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3l7 3v5.5c0 4.6-3 8.2-7 9.5-4-1.3-7-4.9-7-9.5V6z"/><path d="M9 12l2 2 4-4.5"/></svg>`,
    alert: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 4l9 15.5H3z"/><path d="M12 10v4.5M12 17.2v.2"/></svg>`,
    activity: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M3 12h4l2.5-7L14 19l2.5-7H21"/></svg>`,
    eye: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>`,
    eyeOff: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M3 3l18 18"/><path d="M10.6 5.2A10.6 10.6 0 0 1 12 5c6.4 0 10 7 10 7a15.6 15.6 0 0 1-3.4 4.3M6.5 6.6C4 8.3 2 12 2 12s3.6 7 10 7c1.3 0 2.5-.2 3.6-.6"/><path d="M9.9 10.1a3 3 0 0 0 4.2 4.2"/></svg>`,
    image: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3.5" y="4.5" width="17" height="15" rx="2"/><circle cx="9" cy="10" r="1.7"/><path d="M4 17l5-5 3.5 3.5L16 12l4.5 5.5"/></svg>`,
    copy: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="8.5" y="8.5" width="12" height="12" rx="1.6"/><path d="M15.5 8.5V5.5a1 1 0 0 0-1-1h-10a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/></svg>`,
    pin: `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3l2 5 5 .8-3.6 3.5.9 5-4.3-2.4-4.3 2.4.9-5L5 8.8 10 8z"/></svg>`,
    folder: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M3.5 6.5a1.5 1.5 0 0 1 1.5-1.5h4l2 2h8a1.5 1.5 0 0 1 1.5 1.5v8a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 16.5z"/></svg>`,
    archive: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3.5" y="4.5" width="17" height="4.5" rx="1"/><path d="M5 9v9.5a1.5 1.5 0 0 0 1.5 1.5h11a1.5 1.5 0 0 0 1.5-1.5V9"/><path d="M10 13h4"/></svg>`,
    x: `<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M6 6l12 12M18 6L6 18"/></svg>`,
    o: `<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><circle cx="12" cy="12" r="7.5"/></svg>`,
    signal: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="2.5" y="14" width="3" height="6.5" rx="0.8"/><rect x="8" y="10.3" width="3" height="10.2" rx="0.8"/><rect x="13.5" y="6.6" width="3" height="13.9" rx="0.8"/><rect x="19" y="3" width="3" height="17.5" rx="0.8" opacity="0.4"/><path d="M2.5 2.5l19 19" stroke-width="1.8"/></svg>`
  };

  window.__KRAGVOR__ = { ICONS }; // exposed only for debugging convenience

  /* ---------------------------------------------------------------------
     Toasts
     --------------------------------------------------------------------- */
  function toast(message, type = "") {
    const host = $("#toast-host");
    const el = document.createElement("div");
    el.className = `toast ${type}`.trim();
    el.textContent = message;
    host.appendChild(el);
    setTimeout(() => {
      el.style.transition = "opacity 200ms ease";
      el.style.opacity = "0";
      setTimeout(() => el.remove(), 220);
    }, 2600);
  }

  /* ---------------------------------------------------------------------
     Legacy local data migration.
     Before Checkpoint 1, every local record (Notes, Calculator history,
     Vault, Favorites) was keyed under the hardcoded id "owner-1". The real
     Owner account now has a genuine Supabase-issued id, so anything that
     existed locally under "owner-1" before this integration would
     otherwise become invisible. Runs once per newly-authenticated Owner
     account, copies that data under the real id, and queues it for
     upload — never deletes the legacy copy until the new copy exists.
     ------------------------------------------------------------------- */
  const LEGACY_OWNER_ID = "owner-1";
  function legacyMigrationFlagKey(newId) { return `kragvor_legacy_migrated_v1_${newId}`; }

  function runLegacyOwnerMigration() {
    const u = currentUser();
    if (!u || u.type !== "owner" || u.id === LEGACY_OWNER_ID) return;
    const flagKey = legacyMigrationFlagKey(u.id);
    if (localStorage.getItem(flagKey) === "1") return;

    let migratedSomething = false;
    const SYNC = window.__KRAGVOR_SYNC__;

    // Notes: legacy ids weren't UUIDs, so each gets a fresh one on the way in.
    const notesAll = readJSON(localStorage, LS_NOTES, {});
    const legacyNotes = notesAll[LEGACY_OWNER_ID];
    if (Array.isArray(legacyNotes) && legacyNotes.length) {
      const migrated = legacyNotes.map((n) => ({
        id: crypto.randomUUID(), title: n.title || "", body: n.body || "",
        category: n.category || "General", pinned: !!n.pinned, favorite: !!n.favorite,
        archived: !!n.archived, deletedAt: n.deletedAt || null,
        createdAt: n.createdAt || Date.now(), updatedAt: n.updatedAt || Date.now(), version: 1,
      }));
      notesAll[u.id] = (notesAll[u.id] || []).concat(migrated);
      writeJSON(localStorage, LS_NOTES, notesAll);
      if (SYNC) migrated.forEach((n) => SYNC.enqueue("notes", "insert", {
        id: n.id, user_id: u.id, title: n.title, content: n.body, category: n.category,
        pinned: n.pinned, is_favorite: n.favorite, is_archived: n.archived,
        deleted_at: n.deletedAt ? new Date(n.deletedAt).toISOString() : null,
        created_at: new Date(n.createdAt).toISOString(), updated_at: new Date(n.updatedAt).toISOString(),
      }));
      migratedSomething = true;
    }

    // Calculator history: same idea — fresh UUIDs, queued as inserts.
    const calcAll = readJSON(localStorage, LS_CALCHISTORY, {});
    const legacyCalc = calcAll[LEGACY_OWNER_ID];
    if (Array.isArray(legacyCalc) && legacyCalc.length) {
      const migrated = legacyCalc.map((h) => ({ id: crypto.randomUUID(), expression: h.expression, result: h.result, at: h.at || Date.now() }));
      calcAll[u.id] = (calcAll[u.id] || []).concat(migrated);
      writeJSON(localStorage, LS_CALCHISTORY, calcAll);
      if (SYNC) migrated.forEach((h) => SYNC.enqueue("calculator_history", "insert", {
        id: h.id, user_id: u.id, expression: h.expression, result: h.result,
        created_at: new Date(h.at).toISOString(),
      }));
      migratedSomething = true;
    }

    // Favorites: plain array copy, no id remapping needed.
    const favAll = readJSON(localStorage, LS_FAVORITES, {});
    const legacyFavKey = favKey(LEGACY_OWNER_ID);
    if (Array.isArray(favAll[legacyFavKey]) && favAll[legacyFavKey].length) {
      const key = favKey(u.id);
      const merged = Array.from(new Set([...(favAll[key] || []), ...favAll[legacyFavKey]]));
      favAll[key] = merged;
      writeJSON(localStorage, LS_FAVORITES, favAll);
      markFavoritesDirty(u.id);
      pushFavoritesToCloud();
      migratedSomething = true;
    }

    // Vault: copy the whole encrypted record as-is (still under the SAME
    // PIN — nothing is decrypted or re-encrypted here). The Vault module's
    // own session-ready push picks this up once the dirty flag is set.
    // A one-time in-session upgrade for any pre-Checkpoint-5 image shape
    // happens separately, on next successful unlock (see the Vault module).
    const vaultAll = readJSON(localStorage, LS_VAULT, {});
    if (vaultAll[LEGACY_OWNER_ID] && vaultAll[LEGACY_OWNER_ID].pinSet && !vaultAll[u.id]?.pinSet) {
      vaultAll[u.id] = { ...vaultAll[LEGACY_OWNER_ID], updatedAt: Date.now(), cloudVersion: 0 };
      writeJSON(localStorage, LS_VAULT, vaultAll);
      localStorage.setItem(`kragvor_vault_dirty_v1_${u.id}`, "1");
      migratedSomething = true;
    }

    localStorage.setItem(flagKey, "1");
    if (migratedSomething) {
      logSecurityEvent("legacy_data_migrated", {
        accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
        status: "success", severity: SEVERITY.NORMAL, detail: "Pre-existing local data was migrated to this cloud account."
      });
      toast("Your existing data was found and is syncing to the cloud.", "success");
    }
  }
  window.addEventListener("kragvor:session-ready", runLegacyOwnerMigration);

  /* Continued in part 2: router + view rendering */
  window.__KRAGVOR_CORE__ = {
    LS_ACCOUNTS, LS_FAVORITES, LS_PREFS, SS_SESSION,
    LS_SECLOG, LS_LOGINGUARD, LS_NOTES, LS_CALCHISTORY, LS_VAULT, LS_VAULT_RECOVERY, LS_JAMLOG, SS_VAULT_UNLOCKED,
    DEFAULT_OWNER, APPS_REGISTRY, SEVERITY,
    $, $$, norm, escapeHtml, uid,
    readJSON, writeJSON,
    sha256Hex, hashSecret, newSalt,
    hashSecretV2, makeCredential, verifyCredentialString,
    verifyAccountCredential, setAccountCredential, accountNeedsMigration,
    getAccounts, saveAccounts, findAccount,
    getSession, clearSession, currentUser, isOwner,
    refreshCurrentUserProfile, restoreSessionOnBoot,
    attemptLogin, logout, changeOwnPassword,
    getFavorites, toggleFavorite, purgeAccountData, isFavoritesDirtyForCurrentUser,
    getPrefs, setPrefs, applyPrefs,
    getSecurityLog, logSecurityEvent,
    ICONS, toast
  };
})();

/* ==========================================================================
   PART 1.5 — SYNC ENGINE
   A small, generic offline-first sync queue shared by every account-owned
   data type (Notes now; Calculator history, Favorites, and Settings in
   later checkpoints reuse the same engine). A local write is ALWAYS the
   source of truth for what the UI shows immediately; this engine's only
   job is getting it to Supabase — and honestly reporting whether that has
   actually happened, never claiming "Synced" before the server confirms.
   ========================================================================== */
(() => {
  "use strict";
  const C = window.__KRAGVOR_CORE__;
  const SUPA = window.__KRAGVOR_SUPABASE__;
  const { readJSON, writeJSON, currentUser } = C;

  const LS_QUEUE_PREFIX = "kragvor_syncqueue_v1_"; // + accountId, so accounts never share a queue

  function queueKey() {
    const u = currentUser();
    return u ? `${LS_QUEUE_PREFIX}${u.id}` : null;
  }
  function getQueue() {
    const key = queueKey();
    if (!key) return [];
    return readJSON(localStorage, key, []);
  }
  function saveQueue(list) {
    const key = queueKey();
    if (!key) return;
    writeJSON(localStorage, key, list);
  }

  let status = "idle"; // idle | syncing | offline | pending | error
  let flushing = false;
  const listeners = new Set();
  const conflictHandlers = {}; // table -> async (localItemPayload, serverRowOrNull) => void

  function getStatus() { return { state: status, pending: getQueue().length }; }
  function setStatus(next) {
    status = next;
    listeners.forEach((fn) => { try { fn(getStatus()); } catch (e) {} });
  }
  function onStatusChange(fn) { listeners.add(fn); return () => listeners.delete(fn); }
  function registerConflictHandler(table, fn) { conflictHandlers[table] = fn; }

  // Queues one operation and immediately (fire-and-forget) attempts to
  // flush. Callers never await this: the local write already happened and
  // the UI already reflects it — this only concerns getting it to the cloud.
  //   op: "insert" | "update" | "delete"
  //   payload: "insert" -> full row object (must include id, user_id)
  //            "update" -> { id, patch: <row-shaped partial>, clientPatch: <original patch, for conflict copies> }
  //            "delete" -> { id }
  //   expectedVersion: required for "update" — the version this edit was based on
  function enqueue(table, op, payload, expectedVersion) {
    let list = getQueue();

    if (op === "update") {
      const existing = list.find((i) => i.table === table && i.op !== "delete" && i.payload.id === payload.id);
      if (existing) {
        if (existing.op === "insert") {
          Object.assign(existing.payload, payload.patch);
        } else {
          Object.assign(existing.payload.patch, payload.patch);
          Object.assign(existing.payload.clientPatch, payload.clientPatch);
        }
        saveQueue(list);
        setStatus(navigator.onLine ? "pending" : "offline");
        flush();
        return;
      }
    }

    if (op === "delete") {
      const hadPendingInsert = list.some((i) => i.table === table && i.op === "insert" && i.payload.id === payload.id);
      list = list.filter((i) => !(i.table === table && i.payload.id === payload.id));
      if (hadPendingInsert) {
        // Created and deleted entirely offline — the server never saw it,
        // so there's nothing to delete remotely.
        saveQueue(list);
        setStatus(list.length ? (navigator.onLine ? "pending" : "offline") : "idle");
        flush();
        return;
      }
    }

    list.push({
      qid: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
      table, op, payload, expectedVersion, attempts: 0, ts: Date.now(),
    });
    saveQueue(list);
    setStatus(navigator.onLine ? "pending" : "offline");
    flush();
  }

  async function applyOp(item) {
    const table = item.table;
    if (item.op === "insert") {
      const { error } = await SUPA.client.from(table).upsert(item.payload, { onConflict: "id" });
      return !error;
    }
    if (item.op === "update") {
      const { data, error } = await SUPA.client
        .from(table)
        .update(item.payload.patch)
        .eq("id", item.payload.id)
        .eq("version", item.expectedVersion)
        .select("id");
      if (error) return false;
      if (!data || data.length === 0) {
        // Zero rows affected: either the version moved on (a genuine
        // conflicting write from another device) or the row is gone. Never
        // blindly retry a stale version — resolve it once via the
        // registered handler (if any), then drop this queued op either way.
        const { data: serverRow } = await SUPA.client.from(table).select("*").eq("id", item.payload.id).maybeSingle();
        const handler = conflictHandlers[table];
        if (handler) { try { await handler(item.payload, serverRow || null); } catch (e) {} }
        return true;
      }
      return true;
    }
    if (item.op === "delete") {
      const { error } = await SUPA.client.from(table).delete().eq("id", item.payload.id);
      return !error;
    }
    return true; // unknown op — drop rather than loop forever
  }

  async function flush() {
    if (flushing) return;
    if (!navigator.onLine) { setStatus("offline"); return; }
    if (!currentUser()) return;
    flushing = true;
    setStatus(getQueue().length ? "syncing" : "idle");
    try {
      let list = getQueue();
      while (list.length) {
        const item = list[0];
        let ok = false;
        try { ok = await applyOp(item); } catch (e) { ok = false; }
        if (ok) {
          list = list.slice(1);
          saveQueue(list);
        } else {
          item.attempts = (item.attempts || 0) + 1;
          saveQueue(list);
          setStatus(navigator.onLine ? "error" : "offline");
          flushing = false;
          return; // stop at first failure; the online event / poll retries later
        }
      }
      setStatus("idle");
    } finally {
      flushing = false;
    }
  }

  window.addEventListener("online", flush);
  window.addEventListener("kragvor:session-ready", flush);
  setInterval(flush, 20000);

  window.__KRAGVOR_SYNC__ = { enqueue, flush, getQueue, getStatus, onStatusChange, registerConflictHandler };
})();

/* ==========================================================================
   PART 2 — Router, view rendering, modals
   ========================================================================== */
(() => {
  "use strict";
  const C = window.__KRAGVOR_CORE__;
  const {
    $, $$, norm, escapeHtml, uid,
    getAccounts, saveAccounts, findAccount,
    getSession, clearSession, currentUser, isOwner,
    restoreSessionOnBoot,
    attemptLogin, logout,
    getFavorites, toggleFavorite,
    getPrefs, setPrefs,
    ICONS, toast,
    APPS_REGISTRY
  } = C;

  const appEl = $("#app");
  let loginBusy = false;
  let bootDone = false;

  /* ---------------------------------------------------------------------
     Routing
     --------------------------------------------------------------------- */
  function currentRoute() {
    const hash = location.hash.replace(/^#/, "") || "/login";
    return hash;
  }
  function navigate(path) {
    location.hash = path;
  }
  window.addEventListener("hashchange", render);
  window.addEventListener("DOMContentLoaded", async () => {
    C.applyPrefs();
    renderBootScreen();
    // Rehydrate any existing Supabase session (backed by sessionStorage,
    // so it only survives within this same open app/tab) and confirm the
    // account is still real and active before deciding what to render.
    await restoreSessionOnBoot();
    bootDone = true;
    render();
    setupNetworkStatus();
    registerServiceWorker();
  });

  function renderBootScreen() {
    appEl.innerHTML = `
      <div class="login-screen">
        <div class="login-card" style="align-items:center;text-align:center;">
          <div class="glyph">${ICONS.glyph}</div>
          <div class="hint" style="margin-top:14px;">Loading KRAGVOR&hellip;</div>
        </div>
      </div>
    `;
  }

  function render() {
    if (!bootDone) { renderBootScreen(); return; }

    const route = currentRoute();
    const user = currentUser();

    if (!user) {
      if (route !== "/login") { navigate("/login"); return; }
      renderLogin();
      return;
    }
    if (route === "/login") { navigate("/dashboard"); return; }
    window.__KRAGVOR_VIEWS__.renderShell(route, user);
  }

  /* ---------------------------------------------------------------------
     LOGIN VIEW
     --------------------------------------------------------------------- */
  function renderLogin() {
    appEl.innerHTML = `
      <div class="login-screen">
        <div class="login-card">
          <div class="login-mark">
            <div class="glyph">${ICONS.glyph}</div>
            <div class="tagline">
              <strong>Welcome to KRAGVOR</strong>
              Sign in to your personal command center.
            </div>
          </div>

          <div id="login-banner"></div>

          <form id="login-form" novalidate>
            <div class="field" id="f-first">
              <label for="in-first">First name</label>
              <div class="input-wrap">
                <input id="in-first" type="text" autocomplete="given-name" autocapitalize="words" />
              </div>
              <div class="error-msg" hidden></div>
            </div>
            <div class="field" id="f-last">
              <label for="in-last">Last name</label>
              <div class="input-wrap">
                <input id="in-last" type="text" autocomplete="family-name" autocapitalize="words" />
              </div>
              <div class="error-msg" hidden></div>
            </div>
            <div class="field" id="f-pass">
              <label for="in-pass">Password</label>
              <div class="input-wrap">
                <input id="in-pass" type="password" autocomplete="current-password" />
                <button type="button" class="pw-toggle" id="pw-toggle">Show</button>
              </div>
              <div class="error-msg" hidden></div>
            </div>

            <button type="submit" class="btn btn-primary btn-block" id="login-btn">
              <span id="login-btn-label">Login</span>
            </button>
          </form>

          <div class="login-footer">
            Are you family or a friend?
            <button type="button" class="btn-text" id="learn-more-link">Learn more</button>
          </div>
        </div>
      </div>
    `;

    $("#pw-toggle").addEventListener("click", () => {
      const input = $("#in-pass");
      const showing = input.type === "text";
      input.type = showing ? "password" : "text";
      $("#pw-toggle").textContent = showing ? "Show" : "Hide";
    });

    $("#learn-more-link").addEventListener("click", openLearnMoreModal);

    $("#login-form").addEventListener("submit", (e) => {
      e.preventDefault();
      handleLoginSubmit();
    });
  }

  function setFieldError(fieldId, message) {
    const field = $(`#${fieldId}`);
    const errEl = field.querySelector(".error-msg");
    if (message) {
      field.classList.add("has-error");
      errEl.hidden = false;
      errEl.textContent = message;
    } else {
      field.classList.remove("has-error");
      errEl.hidden = true;
      errEl.textContent = "";
    }
  }

  function handleLoginSubmit() {
    if (loginBusy) return;

    const first = $("#in-first").value;
    const last = $("#in-last").value;
    const pass = $("#in-pass").value;

    setFieldError("f-first", "");
    setFieldError("f-last", "");
    setFieldError("f-pass", "");
    $("#login-banner").innerHTML = "";

    let hasError = false;
    if (!first.trim()) { setFieldError("f-first", "Please enter your first name."); hasError = true; }
    if (!last.trim()) { setFieldError("f-last", "Please enter your last name."); hasError = true; }
    if (!pass.trim()) { setFieldError("f-pass", "Please enter your password."); hasError = true; }
    if (hasError) return;

    loginBusy = true;
    const btn = $("#login-btn");
    btn.disabled = true;
    $("#login-btn-label").innerHTML = `<span class="spinner"></span> Signing in`;
    btn.style.display = "inline-flex";
    btn.style.gap = "8px";

    // Small deliberate delay so the loading state is perceivable and to
    // discourage rapid brute-force submissions.
    setTimeout(async () => {
      const result = await attemptLogin(first, last, pass);
      loginBusy = false;
      if (!result.ok) {
        btn.disabled = false;
        $("#login-btn-label").textContent = "Login";
        let msg = "Invalid login details.";
        if (result.reason === "locked") {
          const mins = Math.max(1, Math.ceil((result.retryAt - Date.now()) / 60000));
          msg = `Too many failed attempts. Try again in about ${mins} minute${mins === 1 ? "" : "s"}.`;
        } else if (result.reason === "disabled") {
          msg = "This account has been disabled. Contact the account owner.";
        } else if (result.reason === "offline") {
          msg = "You're offline — signing in needs a connection.";
        } else if (result.reason === "server_unreachable") {
          msg = "Couldn't reach KRAGVOR's server. Please try again in a moment.";
        }
        $("#login-banner").innerHTML = `<div class="form-banner">${escapeHtml(msg)}</div>`;
        return;
      }
      toast(`Welcome back, ${result.account.firstName}`, "success");
      navigate("/dashboard");
    }, 550);
  }

  function openLearnMoreModal() {
    openModal({
      eyebrow: "Family & Friend Access",
      title: "How to access KRAGVOR",
      bodyHtml: `
        <div class="info-block">
          <h4>Getting access</h4>
          <p style="font-size:13.5px;color:var(--text-dim);line-height:1.6;">
            Approved family members and friends each receive their own personal
            login, created by the owner. There is no self-signup &mdash; access
            is granted individually.
          </p>
        </div>

        <div class="info-block">
          <h4>Password format</h4>
          <p style="font-size:13.5px;color:var(--text-dim);line-height:1.6;">
            Passwords follow a simple pattern: <strong style="color:var(--text)">first name + birth year</strong>.
          </p>
          <dl class="credential-example">
            <dt>First name</dt><dd>Alex</dd>
            <dt>Last name</dt><dd>Smith</dd>
            <dt>Birth year</dt><dd>2004</dd>
            <dt>Password</dt><dd class="pw-value">alex2004</dd>
          </dl>
          <p class="hint" style="margin-top:10px;">This is a fictional example only &mdash; not a real account.</p>
        </div>

        <div class="notice-line">${ICONS.check}<span>Names and passwords are not case-sensitive.</span></div>
        <div class="notice-line">${ICONS.lock}<span>Your login credentials are personal. Do not share your login information with others.</span></div>
      `,
      footHtml: `<button class="btn btn-primary" id="learn-more-got-it">Got it</button>`,
    });
    $("#learn-more-got-it").addEventListener("click", closeModal);
  }

  /* ---------------------------------------------------------------------
     MODAL SYSTEM
     --------------------------------------------------------------------- */
  function openModal({ eyebrow, title, subtitle, bodyHtml, footHtml }) {
    closeModal();
    const backdrop = document.createElement("div");
    backdrop.className = "modal-backdrop";
    backdrop.id = "active-modal";
    backdrop.innerHTML = `
      <div class="modal" role="dialog" aria-modal="true">
        <button class="modal-close" id="modal-close-btn" aria-label="Close">${ICONS.close}</button>
        <div class="modal-head">
          ${eyebrow ? `<div class="modal-eyebrow">${escapeHtml(eyebrow)}</div>` : ""}
          <div class="modal-title">${escapeHtml(title)}</div>
          ${subtitle ? `<div class="modal-subtitle">${escapeHtml(subtitle)}</div>` : ""}
        </div>
        <div class="modal-body">
          ${bodyHtml}
          ${footHtml ? `<div class="modal-foot">${footHtml}</div>` : ""}
        </div>
      </div>
    `;
    document.body.appendChild(backdrop);
    backdrop.addEventListener("click", (e) => { if (e.target === backdrop) closeModal(); });
    $("#modal-close-btn").addEventListener("click", closeModal);
  }
  function closeModal() {
    const existing = $("#active-modal");
    if (existing) existing.remove();
  }

  function openConfirmModal({ title, message, confirmLabel = "Confirm", danger = false, onConfirm }) {
    openModal({
      title,
      bodyHtml: `<p style="font-size:13.5px;color:var(--text-dim);line-height:1.6;">${escapeHtml(message)}</p>`,
      footHtml: `
        <button class="btn btn-ghost" id="confirm-cancel">Cancel</button>
        <button class="btn ${danger ? "btn-danger" : "btn-primary"}" id="confirm-ok">${escapeHtml(confirmLabel)}</button>
      `
    });
    $("#confirm-cancel").addEventListener("click", closeModal);
    $("#confirm-ok").addEventListener("click", () => { closeModal(); onConfirm(); });
  }

  /* Continued in part 3: shell + dashboard/apps/favorites/settings views */
  window.__KRAGVOR_ROUTER__ = {
    appEl, currentRoute, navigate, render,
    openModal, closeModal, openConfirmModal, setFieldError
  };
})();

/* ==========================================================================
   PART 3 — App shell, dashboard, apps, favorites, settings
   ========================================================================== */
(() => {
  "use strict";
  const C = window.__KRAGVOR_CORE__;
  const R = window.__KRAGVOR_ROUTER__;
  const {
    $, $$, norm, escapeHtml, uid,
    getAccounts, saveAccounts, findAccount,
    currentUser, isOwner, logout,
    getFavorites, toggleFavorite,
    getPrefs, setPrefs,
    ICONS, toast,
    APPS_REGISTRY
  } = C;
  const { appEl, currentRoute, navigate, openModal, closeModal, openConfirmModal } = R;

  const NAV_ITEMS = [
    { key: "dashboard", label: "Dashboard", icon: "dashboard", path: "/dashboard" },
    { key: "apps", label: "Apps", icon: "apps", path: "/apps" },
    { key: "favorites", label: "Favorites", icon: "favorites", path: "/favorites" },
    { key: "settings", label: "Settings", icon: "settings", path: "/settings" },
  ];

  function activeNavKey(route) {
    if (route.startsWith("/dashboard")) return "dashboard";
    if (route.startsWith("/apps")) return "apps";
    if (route.startsWith("/favorites")) return "favorites";
    if (route.startsWith("/settings")) return "settings";
    return "dashboard";
  }

  function initials(user) {
    return `${(user.firstName || "?")[0] || ""}${(user.lastName || "")[0] || ""}`.toUpperCase();
  }

  function renderShell(route, user) {
    const active = activeNavKey(route);

    appEl.innerHTML = `
      <div class="shell">
        <aside class="sidebar">
          <div class="sidebar-brand">
            <div class="glyph" style="width:22px;height:22px;">${ICONS.glyph}</div>
            <span class="wordmark">KRAGVOR</span>
          </div>
          <nav class="nav-group">
            ${NAV_ITEMS.map(item => `
              <button class="nav-item ${active === item.key ? "active" : ""}" data-nav="${item.path}">
                <span class="accent-bar"></span>
                ${ICONS[item.icon]}
                <span>${item.label}</span>
              </button>
            `).join("")}
          </nav>
          <div class="sidebar-foot">
            <div class="user-chip">
              <div class="avatar">${initials(user)}</div>
              <div class="who">
                <div class="name">${escapeHtml(user.firstName)} ${escapeHtml(user.lastName)}</div>
                <div class="role">${escapeHtml(user.type)}</div>
              </div>
            </div>
          </div>
        </aside>

        <main class="main">
          <div class="topbar">
            <h1 id="view-title">KRAGVOR</h1>
            <div class="topbar-actions">
              <button class="icon-btn" id="topbar-search-btn" aria-label="Universal search">${ICONS.search}</button>
              <div class="status-pill" id="status-pill">
                <span class="status-dot" id="status-dot"></span>
                <span id="status-label">Checking</span>
              </div>
            </div>
          </div>
          <div class="view" id="view-root"></div>
        </main>

        <nav class="bottom-nav">
          ${NAV_ITEMS.map(item => `
            <button class="bn-item ${active === item.key ? "active" : ""}" data-nav="${item.path}">
              ${ICONS[item.icon]}
              <span>${item.label}</span>
            </button>
          `).join("")}
        </nav>
      </div>
    `;

    $$("[data-nav]").forEach(btn => {
      btn.addEventListener("click", () => navigate(btn.getAttribute("data-nav")));
    });
    $("#topbar-search-btn").addEventListener("click", () => navigate("/search"));

    setupNetworkStatus(); // refresh pill each shell render
    renderView(route, user);
  }

  function renderView(route, user) {
    const root = $("#view-root");
    const title = $("#view-title");
    if (!root) return;

    if (route.startsWith("/apps/")) {
      const appId = route.slice("/apps/".length).split("/")[0];
      const app = APPS_REGISTRY.find(a => a.id === appId);
      title.textContent = app ? app.name : "App";
      if (app && typeof app.render === "function") {
        return app.render(root, user, route);
      }
      root.innerHTML = `<div class="empty-state"><div class="glyph">${ICONS.apps}</div><p>This app isn't available yet.</p></div>`;
      return;
    }
    if (route.startsWith("/search")) {
      title.textContent = "Search";
      return window.__KRAGVOR_SEARCH__ ? window.__KRAGVOR_SEARCH__.renderSearchView(root, user) : (root.innerHTML = "");
    }
    if (route.startsWith("/security")) {
      title.textContent = "Security Center";
      return window.__KRAGVOR_SECURITY__ ? window.__KRAGVOR_SECURITY__.renderSecurityView(root, user, route) : (root.innerHTML = "");
    }
    if (route.startsWith("/apps")) {
      title.textContent = "Apps";
      return renderAppsView(root);
    }
    if (route.startsWith("/favorites")) {
      title.textContent = "Favorites";
      return renderFavoritesView(root);
    }
    if (route.startsWith("/settings/family-friends")) {
      title.textContent = "Family & Friends";
      return window.__KRAGVOR_FAMILY__.renderFamilyFriendsView(root, user);
    }
    if (route.startsWith("/settings/account")) {
      title.textContent = "Account";
      return renderAccountView(root, user);
    }
    if (route.startsWith("/settings/appearance")) {
      title.textContent = "Appearance";
      return renderAppearanceView(root);
    }
    if (route.startsWith("/settings/about")) {
      title.textContent = "Application Information";
      return renderAboutView(root);
    }
    if (route.startsWith("/settings")) {
      title.textContent = "Settings";
      return renderSettingsHome(root, user);
    }
    // default
    title.textContent = "Dashboard";
    return renderDashboardView(root, user);
  }

  /* ---------------------------------------------------------------------
     DASHBOARD
     --------------------------------------------------------------------- */
  function renderDashboardView(root, user) {
    const favIds = new Set(getFavorites());
    const favApps = APPS_REGISTRY.filter(a => favIds.has(a.id));

    root.innerHTML = `
      <div class="welcome-block">
        <div class="eyebrow">${greeting()}</div>
        <h2>Welcome back, ${escapeHtml(user.firstName)}</h2>
      </div>

      <div class="section-label">Quick access</div>
      <div class="card-grid" id="quick-access"></div>

      <div class="section-label">Apps</div>
      <div style="display:flex;flex-direction:column;gap:10px;" id="dash-apps"></div>
    `;

    const quick = $("#quick-access");
    const quickTiles = [
      { icon: "search", title: "Search", desc: "Find notes, vault items & more", path: "/search" },
      { icon: "shield", title: "Security Center", desc: "Account & vault protection", path: "/security" },
      { icon: "apps", title: "Open Apps", desc: "Browse available tools", path: "/apps" },
      { icon: "favorites", title: "Favorites", desc: favApps.length ? `${favApps.length} pinned` : "Pin apps for quick reach", path: "/favorites" },
      { icon: "account", title: "Account", desc: "Your profile & password", path: "/settings/account" },
    ];
    if (isOwner()) {
      quickTiles.push({ icon: "family", title: "Family & Friends", desc: "Manage access", path: "/settings/family-friends" });
    }
    quick.innerHTML = quickTiles.map(t => `
      <button class="tile" data-nav="${t.path}">
        <div class="tile-icon">${ICONS[t.icon]}</div>
        <h3>${t.title}</h3>
        <p>${t.desc}</p>
      </button>
    `).join("");

    const dashApps = $("#dash-apps");
    dashApps.innerHTML = APPS_REGISTRY.length
      ? APPS_REGISTRY.map(app => appCardHtml(app, favIds.has(app.id))).join("")
      : `<div class="empty-state"><div class="glyph">${ICONS.apps}</div><p>No apps installed yet.</p></div>`;

    bindAppCardEvents(root);
    $$("[data-nav]", root).forEach(btn => btn.addEventListener("click", () => navigate(btn.getAttribute("data-nav"))));
  }

  function greeting() {
    const h = new Date().getHours();
    if (h < 5) return "Late night";
    if (h < 12) return "Good morning";
    if (h < 18) return "Good afternoon";
    return "Good evening";
  }

  /* ---------------------------------------------------------------------
     APPS
     --------------------------------------------------------------------- */
  function appCardHtml(app, isFav) {
    return `
      <div class="app-card" data-open-app="${app.id}">
        <div class="tile-icon ${app.id === "vault" ? "secure" : ""}">${ICONS[app.icon] || ICONS.apps}</div>
        <div class="body">
          <h3>${escapeHtml(app.name)}</h3>
          <p>${escapeHtml(app.desc)}</p>
        </div>
        <button class="fav-btn ${isFav ? "on" : ""}" data-fav="${app.id}" aria-label="Toggle favorite">
          ${isFav ? ICONS.star : ICONS.starOutline}
        </button>
        ${ICONS.chevron}
      </div>
    `;
  }

  function bindAppCardEvents(root) {
    $$("[data-fav]", root).forEach(btn => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        toggleFavorite(btn.getAttribute("data-fav"));
        renderView(currentRoute(), currentUser());
      });
    });
    $$("[data-open-app]", root).forEach(el => {
      el.addEventListener("click", (e) => {
        if (e.target.closest("[data-fav]")) return;
        navigate(`/apps/${el.getAttribute("data-open-app")}`);
      });
    });
  }

  function renderAppsView(root) {
    const favIds = new Set(getFavorites());
    if (!APPS_REGISTRY.length) {
      root.innerHTML = `
        <div class="empty-state">
          <div class="glyph">${ICONS.apps}</div>
          <p>No apps installed yet.</p>
        </div>
      `;
      return;
    }
    root.innerHTML = `
      <div class="section-label">Available</div>
      <div class="app-card-list">
        ${APPS_REGISTRY.map(app => appCardHtml(app, favIds.has(app.id))).join("")}
      </div>
    `;
    bindAppCardEvents(root);
  }

  function renderFavoritesView(root) {
    const favIds = new Set(getFavorites());
    const favApps = APPS_REGISTRY.filter(a => favIds.has(a.id));
    if (!favApps.length) {
      root.innerHTML = `
        <div class="empty-state">
          <div class="glyph">${ICONS.favorites}</div>
          <p>Nothing pinned yet. Star an app from Apps to keep it here for quick reach.</p>
        </div>
      `;
      return;
    }
    root.innerHTML = `<div class="app-card-list">${favApps.map(a => appCardHtml(a, true)).join("")}</div>`;
    bindAppCardEvents(root);
  }

  /* ---------------------------------------------------------------------
     SETTINGS — home
     --------------------------------------------------------------------- */
  function renderSettingsHome(root, user) {
    const owner = user.type === "owner";
    root.innerHTML = `
      <div class="settings-group-label">Account</div>
      <div class="settings-list">
        ${settingsRow("account", "Account", "Profile & password", "/settings/account")}
      </div>

      <div class="settings-group-label">Security</div>
      <div class="settings-list">
        ${settingsRow("shield", "Security Center", owner ? "Owner security dashboard" : "Your account security", "/security")}
        ${owner
          ? settingsRow("family", "Family & Friends", "Manage access", "/settings/family-friends")
          : settingsRowLocked("family", "Family & Friends", "Owner only")}
      </div>

      <div class="settings-group-label">App</div>
      <div class="settings-list">
        ${settingsRow("appearance", "Appearance", "Theme & motion", "/settings/appearance")}
        ${settingsRow("info", "Application Information", "Version & storage", "/settings/about")}
      </div>

      <div class="settings-list" style="margin-top:22px;">
        <div class="settings-row danger" id="logout-row">
          <div class="icon">${ICONS.logout}</div>
          <div class="grow"><div class="title">Logout</div></div>
        </div>
      </div>
    `;
    $$("[data-nav]", root).forEach(el => el.addEventListener("click", () => navigate(el.getAttribute("data-nav"))));
    $("#logout-row").addEventListener("click", () => {
      openConfirmModal({
        title: "Log out of KRAGVOR?",
        message: "You'll need to sign in again to access your command center.",
        confirmLabel: "Logout",
        danger: true,
        onConfirm: logout
      });
    });
  }
  function settingsRow(icon, title, sub, path) {
    return `
      <div class="settings-row" data-nav="${path}">
        <div class="icon">${ICONS[icon]}</div>
        <div class="grow"><div class="title">${title}</div><div class="sub">${sub}</div></div>
        ${ICONS.chevron}
      </div>
    `;
  }
  function settingsRowLocked(icon, title, sub) {
    return `
      <div class="settings-row locked">
        <div class="icon">${ICONS.lock}</div>
        <div class="grow"><div class="title">${title}</div><div class="sub">${sub}</div></div>
      </div>
    `;
  }

  /* ---------------------------------------------------------------------
     SETTINGS — Account (any logged-in user)
     --------------------------------------------------------------------- */
  function renderAccountView(root, user) {
    root.innerHTML = `
      <button class="back-link" id="back-settings">${ICONS.chevron} Settings</button>
      <div class="detail-card">
        <div class="kv-list">
          <div class="kv-row"><span class="k">First name</span><span class="v">${escapeHtml(user.firstName)}</span></div>
          <div class="kv-row"><span class="k">Last name</span><span class="v">${escapeHtml(user.lastName)}</span></div>
          <div class="kv-row"><span class="k">Account type</span><span class="v" style="text-transform:capitalize;">${escapeHtml(user.type)}</span></div>
          ${user.birthYear ? `<div class="kv-row"><span class="k">Birth year</span><span class="v">${escapeHtml(String(user.birthYear))}</span></div>` : ""}
        </div>
      </div>

      <div class="section-label">Security</div>
      <div class="detail-card">
        <button class="btn btn-ghost" id="change-pw-btn" style="width:100%;">Change password</button>
      </div>
    `;
    $("#back-settings").addEventListener("click", () => navigate("/settings"));
    $("#change-pw-btn").addEventListener("click", () => openChangePasswordModal(user));
  }

  function openChangePasswordModal(user) {
    openModal({
      title: "Change password",
      subtitle: "You'll use this the next time you sign in.",
      bodyHtml: `
        <div class="form-grid">
          <div class="field" id="cp-current" style="margin-bottom:0;">
            <label>Current password</label>
            <div class="input-wrap"><input type="password" id="cp-current-input" /></div>
            <div class="error-msg" hidden></div>
          </div>
          <div class="field" id="cp-new" style="margin-bottom:0;">
            <label>New password</label>
            <div class="input-wrap"><input type="password" id="cp-new-input" /></div>
            <div class="error-msg" hidden></div>
          </div>
        </div>
      `,
      footHtml: `
        <button class="btn btn-ghost" id="cp-cancel">Cancel</button>
        <button class="btn btn-primary" id="cp-save">Save</button>
      `
    });
    $("#cp-cancel").addEventListener("click", closeModal);
    $("#cp-save").addEventListener("click", async () => {
      const current = $("#cp-current-input").value;
      const next = $("#cp-new-input").value;
      R.setFieldError("cp-current", "");
      R.setFieldError("cp-new", "");

      if (!next.trim()) {
        R.setFieldError("cp-new", "Enter a new password.");
        return;
      }

      const saveBtn = $("#cp-save");
      saveBtn.disabled = true;
      const originalLabel = saveBtn.textContent;
      saveBtn.textContent = "Saving\u2026";

      const result = await C.changeOwnPassword(current, next);

      saveBtn.disabled = false;
      saveBtn.textContent = originalLabel;

      if (!result.ok) {
        if (result.reason === "current_incorrect") {
          R.setFieldError("cp-current", "Current password is incorrect.");
        } else if (result.reason === "offline") {
          toast("You're offline — try again once you're connected.", "error");
        } else if (result.reason === "server_unreachable") {
          toast("Couldn't reach the server. Try again in a moment.", "error");
        } else {
          toast("Couldn't update your password. Try again.", "error");
        }
        return;
      }
      closeModal();
      toast("Password updated", "success");
    });
  }

  /* ---------------------------------------------------------------------
     SETTINGS — Appearance
     --------------------------------------------------------------------- */
  function renderAppearanceView(root) {
    const prefs = getPrefs();
    root.innerHTML = `
      <button class="back-link" id="back-settings">${ICONS.chevron} Settings</button>
      <div class="detail-card">
        <div class="toggle-row">
          <div>
            <div class="label">Reduce motion</div>
            <div class="desc">Minimize transitions and animation</div>
          </div>
          <div class="switch ${prefs.reduceMotion ? "on" : ""}" id="sw-motion"><span class="knob"></span></div>
        </div>
        <div class="toggle-row">
          <div>
            <div class="label">Compact density</div>
            <div class="desc">Tighter spacing across the app</div>
          </div>
          <div class="switch ${prefs.compact ? "on" : ""}" id="sw-compact"><span class="knob"></span></div>
        </div>
      </div>
      <div class="result-note" style="margin-top:14px;">
        KRAGVOR uses a fixed dark theme, designed for the command-center experience.
      </div>
    `;
    $("#back-settings").addEventListener("click", () => navigate("/settings"));
    $("#sw-motion").addEventListener("click", () => {
      setPrefs({ reduceMotion: !getPrefs().reduceMotion });
      renderAppearanceView(root);
    });
    $("#sw-compact").addEventListener("click", () => {
      setPrefs({ compact: !getPrefs().compact });
      renderAppearanceView(root);
    });
  }

  /* ---------------------------------------------------------------------
     SETTINGS — Application Information
     --------------------------------------------------------------------- */
  function renderAboutView(root) {
    const accounts = getAccounts();
    root.innerHTML = `
      <button class="back-link" id="back-settings">${ICONS.chevron} Settings</button>
      <div class="detail-card">
        <div class="kv-list">
          <div class="kv-row"><span class="k">App</span><span class="v">KRAGVOR</span></div>
          <div class="kv-row"><span class="k">Version</span><span class="v">1.0.0</span></div>
          <div class="kv-row"><span class="k">Accounts</span><span class="v">${accounts.length}</span></div>
          <div class="kv-row"><span class="k">Connection</span><span class="v" id="about-conn">\u2014</span></div>
        </div>
      </div>
      <div class="detail-card" style="margin-top:12px;">
        <button class="btn btn-ghost" id="check-updates-btn" style="width:100%;">Check for updates</button>
      </div>
    `;
    $("#back-settings").addEventListener("click", () => navigate("/settings"));
    $("#about-conn").textContent = navigator.onLine ? "Online" : "Offline";

    $("#check-updates-btn").addEventListener("click", async () => {
      if (!navigator.onLine) { toast("No connection \u2014 you\u2019re working offline.", "error"); return; }
      try {
        if ("serviceWorker" in navigator) {
          const reg = await navigator.serviceWorker.getRegistration();
          if (reg) reg.update();
        }
        toast("You\u2019re up to date", "success");
      } catch (e) {
        toast("Couldn\u2019t reach the server.", "error");
      }
    });
  }

  /* Continued in part 4: Family & Friends management (owner-only) */
  window.__KRAGVOR_VIEWS__ = { renderShell, renderView, appCardHtml, bindAppCardEvents };
})();

/* ==========================================================================
   PART 4 — Family & Friends management (owner-only, enforced at the data layer)
   ========================================================================== */
(() => {
  "use strict";
  const C = window.__KRAGVOR_CORE__;
  const R = window.__KRAGVOR_ROUTER__;
  const SUPA = window.__KRAGVOR_SUPABASE__;
  const {
    $, $$, norm, escapeHtml,
    purgeAccountData,
    currentUser, isOwner,
    ICONS, toast
  } = C;
  const { navigate, openModal, closeModal, openConfirmModal, setFieldError } = R;

  // Local cache of the last list fetched from the backend, kept only so
  // click handlers (edit/toggle/remove) don't need to refetch on every
  // click. It is always repopulated from Supabase on view load/refresh —
  // it is never the source of truth.
  let _accountsCache = [];

  function mapAccountRow(row) {
    return {
      id: row.id,
      firstName: row.firstName || row.first_name,
      lastName: row.lastName || row.last_name,
      type: row.accountType || row.account_type,
      birthYear: row.birthYear != null ? row.birthYear : row.birth_year,
      enabled: row.isActive != null ? row.isActive : row.is_active,
      createdAt: row.created_at,
    };
  }

  /* ---- Authorization guards live here, independent of any UI state ----
     NOTE: this is a UX-level guard only (hides the button/avoids a wasted
     round trip). The real enforcement is server-side: family-manage
     independently re-checks that the CALLER's own authenticated profile
     row has account_type = 'owner' before doing anything, and every
     mutation is scoped to `created_by = caller`. A tampered client can't
     bypass either check. */
  function guardOwnerAction(actionFn) {
    return function (...args) {
      if (!isOwner()) {
        toast("Only the owner can do that.", "error");
        return { ok: false, reason: "not-authorized" };
      }
      return actionFn(...args);
    };
  }

  function nameTaken(accounts, firstName, lastName, excludeId) {
    return accounts.some(a =>
      a.id !== excludeId &&
      norm(a.firstName) === norm(firstName) &&
      norm(a.lastName) === norm(lastName)
    );
  }

  async function fetchFamilyFriendList() {
    const res = await SUPA.callEdgeFunction("family-manage", { action: "list" });
    if (!res.ok) return { ok: false, error: res.error };
    _accountsCache = res.accounts.map(mapAccountRow);
    return { ok: true, accounts: _accountsCache };
  }

  const addFamilyFriend = guardOwnerAction(async (firstName, lastName, birthYear, type) => {
    if (nameTaken(_accountsCache, firstName, lastName)) {
      return { ok: false, reason: "duplicate-name" };
    }
    const res = await SUPA.callEdgeFunction("family-manage", {
      action: "create",
      firstName, lastName, birthYear: Number(birthYear), accountType: type,
    });
    if (!res.ok) {
      if (res.error === "offline" || res.error === "server_unreachable") return { ok: false, reason: "offline" };
      return { ok: false, reason: "server-error" };
    }
    C.logSecurityEvent("account_created", {
      accountId: res.account.id, accountName: `${res.account.firstName} ${res.account.lastName}`,
      status: "success", severity: C.SEVERITY.NORMAL, detail: `${type === "family" ? "Family" : "Friend"} account created by owner.`
    });
    // Plaintext password is returned once, for the owner to share directly.
    // The backend never stores or returns it again after this response.
    return { ok: true, account: mapAccountRow(res.account), plainPassword: res.plainPassword };
  });

  const updateFamilyFriend = guardOwnerAction(async (id, patch) => {
    const acct = _accountsCache.find(a => a.id === id);
    if (!acct) return { ok: false };

    const nextFirst = patch.firstName != null ? patch.firstName : acct.firstName;
    const nextLast = patch.lastName != null ? patch.lastName : acct.lastName;
    if (nameTaken(_accountsCache, nextFirst, nextLast, id)) {
      return { ok: false, reason: "duplicate-name" };
    }

    const res = await SUPA.callEdgeFunction("family-manage", {
      action: "update",
      id,
      firstName: patch.firstName,
      lastName: patch.lastName,
      birthYear: patch.birthYear != null ? Number(patch.birthYear) : undefined,
      accountType: patch.type,
    });
    if (!res.ok) {
      if (res.error === "offline" || res.error === "server_unreachable") return { ok: false, reason: "offline" };
      return { ok: false, reason: "server-error" };
    }
    C.logSecurityEvent("account_updated", {
      accountId: id, accountName: `${nextFirst} ${nextLast}`,
      status: "success", severity: C.SEVERITY.NORMAL,
      detail: res.passwordChanged ? "Account details updated by owner; password regenerated." : "Account details updated by owner."
    });
    return { ok: true, plainPassword: res.plainPassword, passwordChanged: res.passwordChanged };
  });

  const setAccountEnabled = guardOwnerAction(async (id, enabled) => {
    const acct = _accountsCache.find(a => a.id === id);
    if (!acct) return { ok: false };
    const res = await SUPA.callEdgeFunction("family-manage", { action: "setEnabled", id, enabled });
    if (!res.ok) {
      if (res.error === "offline" || res.error === "server_unreachable") return { ok: false, reason: "offline" };
      return { ok: false, reason: "server-error" };
    }
    C.logSecurityEvent(enabled ? "account_enabled" : "account_disabled", {
      accountId: acct.id, accountName: `${acct.firstName} ${acct.lastName}`,
      status: "success", severity: enabled ? C.SEVERITY.NORMAL : C.SEVERITY.SUSPICIOUS,
      detail: enabled ? "Account re-enabled by owner." : "Account disabled by owner."
    });
    return { ok: true };
  });

  const removeFamilyFriend = guardOwnerAction(async (id) => {
    const acct = _accountsCache.find(a => a.id === id);
    if (!acct) return { ok: false };
    const res = await SUPA.callEdgeFunction("family-manage", { action: "remove", id });
    if (!res.ok) {
      if (res.error === "offline" || res.error === "server_unreachable") return { ok: false, reason: "offline" };
      return { ok: false, reason: "server-error" };
    }
    // Clear any pre-migration local leftovers so nothing orphaned lingers
    // in this browser's storage after a real, permanent cloud deletion.
    purgeAccountData(id);
    C.logSecurityEvent("account_removed", {
      accountId: id, accountName: `${acct.firstName} ${acct.lastName}`,
      status: "success", severity: C.SEVERITY.SUSPICIOUS, detail: "Account and all associated cloud data permanently removed by owner."
    });
    return { ok: true };
  });

  /* ---------------------------------------------------------------------
     VIEW
     --------------------------------------------------------------------- */
  function renderFamilyFriendsView(root, user) {
    // Route-level guard: never render management UI for a non-owner,
    // regardless of how the route was reached.
    if (!isOwner()) {
      root.innerHTML = `
        <div class="empty-state">
          <div class="glyph">${ICONS.lock}</div>
          <p>This section is only available to the owner.</p>
        </div>
      `;
      setTimeout(() => { if (currentUser() && !isOwner()) navigate("/dashboard"); }, 900);
      return;
    }

    root.innerHTML = `
      <button class="back-link" id="back-settings">${ICONS.chevron} Settings</button>

      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;gap:12px;">
        <div class="section-label" style="margin:0;">Family & Friends</div>
        <button class="btn btn-primary btn-sm" id="add-ff-btn">${ICONS.plus} Add Family/Friend</button>
      </div>

      <div id="ff-list">
        <div class="empty-state"><div class="glyph">${ICONS.family}</div><p>Loading\u2026</p></div>
      </div>
    `;

    $("#back-settings").addEventListener("click", () => navigate("/settings"));
    $("#add-ff-btn").addEventListener("click", () => openAddFamilyFriendModal(root, user));

    loadFamilyFriendList(root, user);
  }

  async function loadFamilyFriendList(root, user) {
    const listEl = $("#ff-list", root);
    if (!listEl) return; // navigated away while loading
    const res = await fetchFamilyFriendList();
    if (!$("#ff-list", root)) return; // navigated away meanwhile

    if (!res.ok) {
      $("#ff-list", root).innerHTML = `
        <div class="empty-state">
          <div class="glyph">${ICONS.family}</div>
          <p>Couldn't load Family &amp; Friends${(res.error === "offline" || res.error === "server_unreachable") ? " \u2014 check your connection" : ""}. <a href="#" id="ff-retry">Retry</a></p>
        </div>
      `;
      const retry = $("#ff-retry", root);
      if (retry) retry.addEventListener("click", (e) => { e.preventDefault(); loadFamilyFriendList(root, user); });
      return;
    }

    const accounts = res.accounts;
    $("#ff-list", root).innerHTML = accounts.length ? accounts.map(rowHtml).join("") : `
      <div class="empty-state">
        <div class="glyph">${ICONS.family}</div>
        <p>No family or friend accounts yet. Add one to grant access.</p>
      </div>
    `;

    $$("[data-edit-id]", root).forEach(btn =>
      btn.addEventListener("click", () => openEditFamilyFriendModal(root, btn.getAttribute("data-edit-id")))
    );
    $$("[data-toggle-id]", root).forEach(btn =>
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-toggle-id");
        const acct = _accountsCache.find(a => a.id === id);
        const nextEnabled = !acct.enabled;
        btn.disabled = true;
        const res = await setAccountEnabled(id, nextEnabled);
        btn.disabled = false;
        if (res.ok) {
          toast(nextEnabled ? "Account enabled" : "Account disabled", "success");
          loadFamilyFriendList(root, user);
        } else if (res.reason === "offline") {
          toast("You're offline \u2014 try again once you're connected.", "error");
        } else if (res.reason === "server-error") {
          toast("Couldn't update that account. Try again.", "error");
        }
      })
    );
    $$("[data-remove-id]", root).forEach(btn =>
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-remove-id");
        const acct = _accountsCache.find(a => a.id === id);
        openConfirmModal({
          title: `Remove ${acct.firstName} ${acct.lastName}?`,
          message: "This permanently deletes their account, login access, and all of their cloud data. This can't be undone.",
          confirmLabel: "Remove",
          danger: true,
          onConfirm: async () => {
            const res = await removeFamilyFriend(id);
            if (res.ok) {
              toast("Account removed", "success");
              loadFamilyFriendList(root, user);
            } else if (res.reason === "offline") {
              toast("You're offline \u2014 try again once you're connected.", "error");
            } else if (res.reason === "server-error") {
              toast("Couldn't remove that account. Try again.", "error");
            }
          }
        });
      })
    );
  }

  function rowHtml(acct) {
    return `
      <div class="list-row">
        <div class="grow">
          <div class="title">${escapeHtml(acct.firstName)} ${escapeHtml(acct.lastName)}</div>
          <div class="sub">
            <span class="badge ${acct.type === "family" ? "badge-family" : "badge-friend"}">${acct.type}</span>
            &nbsp;
            <span class="badge ${acct.enabled ? "badge-enabled" : "badge-disabled"}">${acct.enabled ? "Enabled" : "Disabled"}</span>
          </div>
        </div>
        <div class="row-actions">
          <button class="icon-btn" data-edit-id="${acct.id}" aria-label="Edit">${ICONS.edit}</button>
          <button class="icon-btn" data-toggle-id="${acct.id}" aria-label="Toggle">${ICONS.power}</button>
          <button class="icon-btn danger" data-remove-id="${acct.id}" aria-label="Remove">${ICONS.trash}</button>
        </div>
      </div>
    `;
  }

  /* ---------------------------------------------------------------------
     Add modal
     --------------------------------------------------------------------- */
  function openAddFamilyFriendModal(root, user) {
    let selectedType = "family";

    openModal({
      eyebrow: "New account",
      title: "Add Family/Friend",
      subtitle: "The password is generated automatically \u2014 first name + birth year.",
      bodyHtml: `
        <div class="form-grid">
          <div class="field" id="add-first" style="margin-bottom:0;">
            <label>First name</label>
            <div class="input-wrap"><input id="add-first-input" type="text" /></div>
            <div class="error-msg" hidden></div>
          </div>
          <div class="field" id="add-last" style="margin-bottom:0;">
            <label>Last name</label>
            <div class="input-wrap"><input id="add-last-input" type="text" /></div>
            <div class="error-msg" hidden></div>
          </div>
          <div class="field" id="add-year" style="margin-bottom:0;">
            <label>Birth year</label>
            <div class="input-wrap"><input id="add-year-input" type="number" inputmode="numeric" placeholder="e.g. 2004" /></div>
            <div class="error-msg" hidden></div>
          </div>
          <div>
            <label style="display:block;font-size:12.5px;color:var(--text-dim);margin-bottom:7px;font-weight:500;">Account type</label>
            <div class="radio-row" id="add-type-row">
              <div class="radio-opt selected" data-type="family">Family</div>
              <div class="radio-opt" data-type="friend">Friend</div>
            </div>
          </div>
          <div>
            <div class="generated-pw"><span>Password</span><span id="add-pw-preview">\u2014</span></div>
            <div class="hint">Generated from first name + birth year. Share it with them directly.</div>
          </div>
        </div>
      `,
      footHtml: `
        <button class="btn btn-ghost" id="add-cancel">Cancel</button>
        <button class="btn btn-primary" id="add-create">Create Account</button>
      `
    });

    const updatePreview = () => {
      const f = $("#add-first-input").value.trim();
      const y = $("#add-year-input").value.trim();
      $("#add-pw-preview").textContent = (f && y) ? norm(`${f}${y}`) : "\u2014";
    };
    $("#add-first-input").addEventListener("input", updatePreview);
    $("#add-year-input").addEventListener("input", updatePreview);

    $$("[data-type]", document).forEach(opt => {
      opt.addEventListener("click", () => {
        selectedType = opt.getAttribute("data-type");
        $$("[data-type]").forEach(o => o.classList.remove("selected"));
        opt.classList.add("selected");
      });
    });

    $("#add-cancel").addEventListener("click", closeModal);
    $("#add-create").addEventListener("click", async () => {
      const first = $("#add-first-input").value.trim();
      const last = $("#add-last-input").value.trim();
      const year = $("#add-year-input").value.trim();

      setFieldError("add-first", "");
      setFieldError("add-last", "");
      setFieldError("add-year", "");

      let hasError = false;
      if (!first) { setFieldError("add-first", "First name is required."); hasError = true; }
      if (!last) { setFieldError("add-last", "Last name is required."); hasError = true; }
      if (!year || isNaN(Number(year)) || Number(year) < 1900 || Number(year) > new Date().getFullYear()) {
        setFieldError("add-year", "Enter a valid birth year.");
        hasError = true;
      }
      if (hasError) return;

      const res = await addFamilyFriend(first, last, year, selectedType);
      if (res.ok) {
        closeModal();
        toast(`${res.account.firstName}'s account created \u2014 password: ${res.plainPassword}`, "success");
        renderFamilyFriendsView(root, user);
      } else if (res.reason === "duplicate-name") {
        setFieldError("add-last", "An account with this first and last name already exists.");
      } else if (res.reason === "offline") {
        toast("You're offline \u2014 try again once you're connected.", "error");
      } else if (res.reason === "server-error") {
        toast("Couldn't create that account. Try again.", "error");
      }
    });
  }

  /* ---------------------------------------------------------------------
     Edit modal
     --------------------------------------------------------------------- */
  function openEditFamilyFriendModal(root, id) {
    const acct = _accountsCache.find(a => a.id === id);
    if (!acct) return;
    let selectedType = acct.type;

    openModal({
      eyebrow: "Edit account",
      title: `${acct.firstName} ${acct.lastName}`,
      subtitle: "Password updates automatically if the name or birth year changes.",
      bodyHtml: `
        <div class="form-grid">
          <div class="field" id="edit-first" style="margin-bottom:0;">
            <label>First name</label>
            <div class="input-wrap"><input id="edit-first-input" type="text" value="${escapeHtml(acct.firstName)}" /></div>
            <div class="error-msg" hidden></div>
          </div>
          <div class="field" id="edit-last" style="margin-bottom:0;">
            <label>Last name</label>
            <div class="input-wrap"><input id="edit-last-input" type="text" value="${escapeHtml(acct.lastName)}" /></div>
            <div class="error-msg" hidden></div>
          </div>
          <div class="field" id="edit-year" style="margin-bottom:0;">
            <label>Birth year</label>
            <div class="input-wrap"><input id="edit-year-input" type="number" inputmode="numeric" value="${acct.birthYear || ""}" /></div>
            <div class="error-msg" hidden></div>
          </div>
          <div>
            <label style="display:block;font-size:12.5px;color:var(--text-dim);margin-bottom:7px;font-weight:500;">Account type</label>
            <div class="radio-row" id="edit-type-row">
              <div class="radio-opt ${acct.type === "family" ? "selected" : ""}" data-etype="family">Family</div>
              <div class="radio-opt ${acct.type === "friend" ? "selected" : ""}" data-etype="friend">Friend</div>
            </div>
          </div>
          <div class="hint">Password is derived from first name + birth year and is never shown once set. Saving with a new name or birth year issues a new password.</div>
        </div>
      `,
      footHtml: `
        <button class="btn btn-ghost" id="edit-cancel">Cancel</button>
        <button class="btn btn-primary" id="edit-save">Save changes</button>
      `
    });

    $$("[data-etype]", document).forEach(opt => {
      opt.addEventListener("click", () => {
        selectedType = opt.getAttribute("data-etype");
        $$("[data-etype]").forEach(o => o.classList.remove("selected"));
        opt.classList.add("selected");
      });
    });

    $("#edit-cancel").addEventListener("click", closeModal);
    $("#edit-save").addEventListener("click", async () => {
      const first = $("#edit-first-input").value.trim();
      const last = $("#edit-last-input").value.trim();
      const year = $("#edit-year-input").value.trim();

      setFieldError("edit-first", "");
      setFieldError("edit-last", "");
      setFieldError("edit-year", "");

      let hasError = false;
      if (!first) { setFieldError("edit-first", "First name is required."); hasError = true; }
      if (!last) { setFieldError("edit-last", "Last name is required."); hasError = true; }
      if (!year || isNaN(Number(year)) || Number(year) < 1900 || Number(year) > new Date().getFullYear()) {
        setFieldError("edit-year", "Enter a valid birth year.");
        hasError = true;
      }
      if (hasError) return;

      const res = await updateFamilyFriend(id, {
        firstName: first, lastName: last, birthYear: Number(year), type: selectedType
      });
      if (res.ok) {
        closeModal();
        toast(res.passwordChanged ? `Account updated \u2014 new password: ${res.plainPassword}` : "Account updated", "success");
        renderFamilyFriendsView(root, currentUser());
      } else if (res.reason === "duplicate-name") {
        setFieldError("edit-last", "An account with this first and last name already exists.");
      } else if (res.reason === "offline") {
        toast("You're offline \u2014 try again once you're connected.", "error");
      } else if (res.reason === "server-error") {
        toast("Couldn't update that account. Try again.", "error");
      }
    });
  }

  window.__KRAGVOR_FAMILY__ = { renderFamilyFriendsView };
})();

/* ==========================================================================
   PART 5 — Network status + service worker registration (global scope,
   referenced from earlier parts; hoisted before first use)
   ========================================================================== */
function globalSyncSnapshot() {
  const generic = window.__KRAGVOR_SYNC__ ? window.__KRAGVOR_SYNC__.getStatus() : { state: "idle", pending: 0 };
  const vaultDirty = window.__KRAGVOR_VAULT__ && window.__KRAGVOR_VAULT__.isDirty ? window.__KRAGVOR_VAULT__.isDirty() : false;
  const favDirty = window.__KRAGVOR_CORE__ && window.__KRAGVOR_CORE__.isFavoritesDirtyForCurrentUser
    ? window.__KRAGVOR_CORE__.isFavoritesDirtyForCurrentUser() : false;
  const pending = generic.pending + (vaultDirty ? 1 : 0) + (favDirty ? 1 : 0);

  if (!navigator.onLine) return { state: "offline", pending };
  if (generic.state === "error") return { state: "error", pending };
  if (generic.state === "syncing") return { state: "syncing", pending };
  if (pending > 0) return { state: "pending", pending };
  return { state: "idle", pending: 0 };
}

// A single, always-visible, HONEST readout of whether this account's data
// is actually confirmed synced to Supabase — never just "did the local
// write succeed". Reflects Notes/Calculator's sync queue plus Vault and
// Favorites' dirty flags, all of which persist in localStorage and
// survive an app close/reopen, so nothing queued is ever silently lost.
function setupNetworkStatus() {
  const dot = document.getElementById("status-dot");
  const label = document.getElementById("status-label");
  if (!dot || !label) return;
  const TEXT = {
    idle: "Synced",
    syncing: "Syncing\u2026",
    pending: (n) => `Pending (${n})`,
    offline: (n) => (n ? `Offline \u00b7 ${n} pending` : "Offline"),
    error: "Sync failed \u2014 retrying",
  };
  function update() {
    const { state, pending } = globalSyncSnapshot();
    const isOnlineLook = state === "idle" || state === "syncing";
    dot.className = `status-dot ${isOnlineLook ? "online" : "offline"}`;
    const t = TEXT[state];
    label.textContent = typeof t === "function" ? t(pending) : t;
  }
  update();
  window.addEventListener("online", update);
  window.addEventListener("offline", update);
  window.addEventListener("kragvor:session-ready", update);
  window.addEventListener("kragvor:logout", update);
  if (window.__KRAGVOR_SYNC__) window.__KRAGVOR_SYNC__.onStatusChange(update);
  // Vault/Favorites dirty flags don't emit change events (they're simple
  // localStorage flags), so a light poll catches those transitions too.
  setInterval(update, 5000);
}

function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("service-worker.js").catch(() => {
      /* offline-first app still works without SW registration succeeding */
    });
  });
}

/* ==========================================================================
   PART 6 — CALCULATOR
   Standard + Scientific modes, safe expression evaluator (no eval),
   per-account calculation history.
   ========================================================================== */
(() => {
  "use strict";
  const C = window.__KRAGVOR_CORE__;
  const R = window.__KRAGVOR_ROUTER__;
  const SUPA = window.__KRAGVOR_SUPABASE__;
  const SYNC = window.__KRAGVOR_SYNC__;
  const {
    $, $$, escapeHtml, readJSON, writeJSON,
    LS_CALCHISTORY, currentUser, ICONS, toast, APPS_REGISTRY
  } = C;
  const { navigate } = R;

  /* ---------------------------------------------------------------------
     Safe expression parser/evaluator (recursive descent).
     Supports: + - * / % ^ ( ) decimals, unary +/-, trailing ! (factorial),
     functions: sqrt sin cos tan asin acos atan log ln exp, constant: pi
     ------------------------------------------------------------------- */
  function evaluateExpression(expr) {
    const src = expr.replace(/\s+/g, "").replace(/×/g, "*").replace(/÷/g, "/").replace(/π/g, "pi");
    let i = 0;

    function peek() { return src[i]; }
    function eatNum() {
      const start = i;
      while (i < src.length && /[0-9.]/.test(src[i])) i++;
      return parseFloat(src.slice(start, i));
    }
    function eatIdent() {
      const start = i;
      while (i < src.length && /[a-zA-Z]/.test(src[i])) i++;
      return src.slice(start, i);
    }
    function factorial(n) {
      if (n < 0 || Math.floor(n) !== n) throw new Error("Factorial requires a non-negative integer");
      if (n > 170) throw new Error("Too large");
      let r = 1;
      for (let k = 2; k <= n; k++) r *= k;
      return r;
    }

    function parseExpr() { return parseAddSub(); }
    function parseAddSub() {
      let v = parseMulDiv();
      while (peek() === "+" || peek() === "-") {
        const op = src[i++];
        const rhs = parseMulDiv();
        v = op === "+" ? v + rhs : v - rhs;
      }
      return v;
    }
    function parseMulDiv() {
      let v = parsePow();
      while (peek() === "*" || peek() === "/" || peek() === "%") {
        const op = src[i++];
        const rhs = parsePow();
        if (op === "*") v = v * rhs;
        else if (op === "/") { if (rhs === 0) throw new Error("Division by zero"); v = v / rhs; }
        else v = v % rhs;
      }
      return v;
    }
    function parsePow() {
      let v = parseUnary();
      if (peek() === "^") {
        i++;
        const rhs = parsePow(); // right-associative
        v = Math.pow(v, rhs);
      }
      return v;
    }
    function parseUnary() {
      if (peek() === "-") { i++; return -parseUnary(); }
      if (peek() === "+") { i++; return parseUnary(); }
      return parsePostfix();
    }
    function parsePostfix() {
      let v = parseAtom();
      while (peek() === "!") { i++; v = factorial(v); }
      return v;
    }
    function parseAtom() {
      if (peek() === "(") {
        i++;
        const v = parseAddSub();
        if (peek() !== ")") throw new Error("Mismatched parentheses");
        i++;
        return v;
      }
      if (/[0-9.]/.test(peek() || "")) return eatNum();
      if (/[a-zA-Z]/.test(peek() || "")) {
        const ident = eatIdent();
        if (ident === "pi") return Math.PI;
        if (ident === "e") return Math.E;
        // function call
        if (peek() === "(") {
          i++;
          const arg = parseAddSub();
          if (peek() !== ")") throw new Error("Mismatched parentheses");
          i++;
          switch (ident) {
            case "sqrt": if (arg < 0) throw new Error("Invalid input"); return Math.sqrt(arg);
            case "sin": return Math.sin(arg * Math.PI / 180);
            case "cos": return Math.cos(arg * Math.PI / 180);
            case "tan": return Math.tan(arg * Math.PI / 180);
            case "asin": if (arg < -1 || arg > 1) throw new Error("Invalid input"); return Math.asin(arg) * 180 / Math.PI;
            case "acos": if (arg < -1 || arg > 1) throw new Error("Invalid input"); return Math.acos(arg) * 180 / Math.PI;
            case "atan": return Math.atan(arg) * 180 / Math.PI;
            case "log": if (arg <= 0) throw new Error("Invalid input"); return Math.log10(arg);
            case "ln": if (arg <= 0) throw new Error("Invalid input"); return Math.log(arg);
            case "exp": return Math.exp(arg);
            default: throw new Error(`Unknown function: ${ident}`);
          }
        }
        throw new Error(`Unknown identifier: ${ident}`);
      }
      throw new Error("Unexpected input");
    }

    if (!src) throw new Error("Empty expression");
    const result = parseExpr();
    if (i !== src.length) throw new Error("Unexpected input");
    if (!isFinite(result)) throw new Error("Result out of range");
    return result;
  }

  function formatResult(n) {
    if (Number.isInteger(n)) return String(n);
    return parseFloat(n.toFixed(10)).toString();
  }

  /* ---------------------------------------------------------------------
     Per-account calculation history — synced the same way Notes are:
     local write first (instant, offline-safe), then queued to Supabase.
     History entries are immutable once created (only ever added or
     removed, never edited), so no version/conflict machinery is needed —
     just insert and delete.
     ------------------------------------------------------------------- */
  function getCalcHistory() {
    const u = currentUser();
    if (!u) return [];
    const all = readJSON(localStorage, LS_CALCHISTORY, {});
    return all[u.id] || [];
  }
  function saveCalcHistoryList(list) {
    const u = currentUser();
    if (!u) return;
    const all = readJSON(localStorage, LS_CALCHISTORY, {});
    all[u.id] = list;
    writeJSON(localStorage, LS_CALCHISTORY, all);
  }
  function pushCalcHistory(expression, result) {
    const u = currentUser();
    if (!u) return;
    const item = { id: crypto.randomUUID(), expression, result, at: Date.now() };
    const list = getCalcHistory();
    list.unshift(item);
    if (list.length > 200) list.length = 200;
    saveCalcHistoryList(list);
    SYNC.enqueue("calculator_history", "insert", {
      id: item.id, user_id: u.id, expression: item.expression, result: item.result,
      created_at: new Date(item.at).toISOString(),
    });
  }
  function deleteCalcHistoryItem(id) {
    if (!currentUser()) return;
    saveCalcHistoryList(getCalcHistory().filter(x => x.id !== id));
    SYNC.enqueue("calculator_history", "delete", { id });
  }
  function clearCalcHistory() {
    if (!currentUser()) return;
    const current = getCalcHistory();
    saveCalcHistoryList([]);
    current.forEach(item => SYNC.enqueue("calculator_history", "delete", { id: item.id }));
  }

  async function pullCalcHistoryFromCloud() {
    const u = currentUser();
    if (!u || !navigator.onLine) return false;
    const { data, error } = await SUPA.client
      .from("calculator_history").select("*").eq("user_id", u.id).is("deleted_at", null);
    if (error || !data) return false;

    const local = getCalcHistory();
    const pendingDeleteIds = new Set(
      SYNC.getQueue().filter(i => i.table === "calculator_history" && i.op === "delete").map(i => i.payload.id)
    );
    const localById = new Map(local.map(h => [h.id, h]));
    const merged = data
      .filter(row => !pendingDeleteIds.has(row.id))
      .map(row => localById.get(row.id) || { id: row.id, expression: row.expression, result: row.result, at: new Date(row.created_at).getTime() });

    // Keep local-only entries the pull hasn't seen yet (created fully
    // offline and still queued for upload).
    const seen = new Set(data.map(r => r.id));
    for (const loc of local) {
      if (!seen.has(loc.id) && !pendingDeleteIds.has(loc.id)) merged.push(loc);
    }
    merged.sort((a, b) => b.at - a.at);
    if (merged.length > 200) merged.length = 200;
    saveCalcHistoryList(merged);
    return true;
  }

  let calcViewMounted = false;
  window.addEventListener("kragvor:session-ready", () => {
    pullCalcHistoryFromCloud().then((ok) => { if (ok && calcViewMounted) refreshMountedCalc(); });
  });
  window.addEventListener("online", () => {
    pullCalcHistoryFromCloud().then((ok) => { if (ok && calcViewMounted) refreshMountedCalc(); });
  });
  window.addEventListener("kragvor:logout", () => { calcViewMounted = false; });
  let refreshMountedCalc = () => {};

  const STD_KEYS = [
    ["C","(",")","%"],
    ["7","8","9","÷"],
    ["4","5","6","×"],
    ["1","2","3","-"],
    ["±","0",".","+"],
  ];
  const SCI_KEYS = [
    ["sin(","cos(","tan(","^"],
    ["asin(","acos(","atan(","sqrt("],
    ["log(","ln(","π","e"],
    ["(",")","!","%"],
  ];

  let calcState = { expr: "", mode: "standard" };

  function renderCalculatorApp(root) {
    calcState = { expr: "", mode: calcState.mode || "standard" };
    calcViewMounted = true;
    refreshMountedCalc = () => { if (calcViewMounted) paintCalculator(root); };
    const stopWatching = () => { if (!document.body.contains(root)) { calcViewMounted = false; window.removeEventListener("hashchange", stopWatching); } };
    window.addEventListener("hashchange", stopWatching);
    paintCalculator(root);
  }

  function paintCalculator(root) {
    const history = getCalcHistory();
    root.innerHTML = `
      <div class="calc-wrap">
        <div class="calc-mode-toggle">
          <button class="seg ${calcState.mode === "standard" ? "on" : ""}" data-mode="standard">Standard</button>
          <button class="seg ${calcState.mode === "scientific" ? "on" : ""}" data-mode="scientific">Scientific</button>
        </div>
        <div class="calc-display">
          <div class="calc-expr" id="calc-expr">${escapeHtml(calcState.expr) || "0"}</div>
          <div class="calc-result" id="calc-result">${calcState.result !== undefined ? escapeHtml(calcState.result) : ""}</div>
        </div>
        <div class="calc-pad">
          ${calcState.mode === "scientific" ? SCI_KEYS.map(row => `<div class="calc-row sci">${row.map(k => keyBtn(k)).join("")}</div>`).join("") : ""}
          ${STD_KEYS.map(row => `<div class="calc-row">${row.map(k => keyBtn(k)).join("")}</div>`).join("")}
          <div class="calc-row"><button class="calc-key" data-key="⌫">⌫</button><button class="calc-key eq" data-key="=">=</button></div>
        </div>

        <div class="section-label" style="display:flex;justify-content:space-between;align-items:center;">
          <span>History</span>
          ${history.length ? `<button class="btn-text" id="calc-clear-history">Clear all</button>` : ""}
        </div>
        <div id="calc-history">
          ${history.length ? history.map(historyRow).join("") : `<div class="empty-state" style="padding:24px 12px;"><p>No calculations yet.</p></div>`}
        </div>
      </div>
    `;
    bindCalculator(root);
  }

  function keyBtn(k) {
    const cls = ["+","-","×","÷","="].includes(k) ? "calc-key op" : (k === "C" ? "calc-key clear" : "calc-key");
    return `<button class="${cls}" data-key="${escapeHtml(k)}">${escapeHtml(k)}</button>`;
  }

  function historyRow(item) {
    const time = new Date(item.at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    return `
      <div class="list-row">
        <div class="grow" data-reuse="${item.id}" style="cursor:pointer;">
          <div class="title" style="font-family:var(--font-display);">${escapeHtml(item.expression)} = ${escapeHtml(item.result)}</div>
          <div class="sub">${time}</div>
        </div>
        <div class="row-actions">
          <button class="icon-btn" data-copy="${item.id}" aria-label="Copy result">${ICONS.copy}</button>
          <button class="icon-btn danger" data-del-calc="${item.id}" aria-label="Delete">${ICONS.trash}</button>
        </div>
      </div>
    `;
  }

  function bindCalculator(root) {
    $$(".seg", root).forEach(btn => btn.addEventListener("click", () => {
      calcState.mode = btn.getAttribute("data-mode");
      paintCalculator(root);
    }));

    $$("[data-key]", root).forEach(btn => btn.addEventListener("click", () => handleKey(root, btn.getAttribute("data-key"))));

    const history = getCalcHistory();
    $$("[data-reuse]", root).forEach(el => el.addEventListener("click", () => {
      const item = history.find(h => h.id === el.getAttribute("data-reuse"));
      if (item) { calcState.expr = item.expression; calcState.result = undefined; paintCalculator(root); }
    }));
    $$("[data-copy]", root).forEach(btn => btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const item = history.find(h => h.id === btn.getAttribute("data-copy"));
      if (item) copyText(item.result);
    }));
    $$("[data-del-calc]", root).forEach(btn => btn.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteCalcHistoryItem(btn.getAttribute("data-del-calc"));
      paintCalculator(root);
    }));
    const clearBtn = $("#calc-clear-history", root);
    if (clearBtn) clearBtn.addEventListener("click", () => {
      R.openConfirmModal({
        title: "Clear all history?",
        message: "This removes every saved calculation for your account. This can't be undone.",
        confirmLabel: "Clear",
        danger: true,
        onConfirm: () => { clearCalcHistory(); paintCalculator(root); }
      });
    });
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => toast("Copied", "success")).catch(() => toast("Couldn't copy", "error"));
    } else {
      toast("Copy isn't supported here.", "error");
    }
  }

  const OP_CHARS = ["+", "-", "×", "÷", "("];

  // Finds the trailing numeric operand in an expression string, correctly
  // distinguishing a binary minus ("200-10" -> operand "10") from a unary
  // sign already attached to a number ("4×-3" -> operand "-3").
  function findTrailingOperand(expr) {
    const bare = expr.match(/\d*\.?\d+$/);
    if (!bare) return null;
    let start = bare.index;
    let value = bare[0];
    if (start > 0 && expr[start - 1] === "-") {
      const beforeMinus = expr.slice(0, start - 1);
      const beforeMinusLast = beforeMinus[beforeMinus.length - 1];
      if (beforeMinus === "" || OP_CHARS.includes(beforeMinusLast)) {
        value = "-" + value;
        start -= 1;
      }
    }
    return { prefix: expr.slice(0, start), value };
  }

  // Real calculator percentage semantics, not JS modulo:
  //  "50%"        -> 0.5
  //  "200×10%"    -> 200×0.1   (=20)
  //  "200+10%"    -> 200+20    (10% of 200, added)
  //  "200-10%"    -> 200-20
  function applyPercent(expr) {
    const t = findTrailingOperand(expr);
    if (!t) return expr;
    const { prefix, value } = t;
    if (!prefix) return formatResult(parseFloat(value) / 100);
    const lastChar = prefix[prefix.length - 1];
    if (lastChar === "×" || lastChar === "÷") {
      return prefix + formatResult(parseFloat(value) / 100);
    }
    if (lastChar === "+" || lastChar === "-") {
      const beforeOp = prefix.slice(0, -1);
      let base = 0;
      try { base = beforeOp ? evaluateExpression(beforeOp) : 0; } catch (e) { base = 0; }
      return prefix + formatResult((base * parseFloat(value)) / 100);
    }
    return prefix + formatResult(parseFloat(value) / 100);
  }

  // Negates the CURRENT operand (the number being entered or just
  // completed), not the whole expression — "5+3" -> "5-3", not "-5+3".
  function toggleSign(expr) {
    const t = findTrailingOperand(expr);
    if (!t) return expr;
    const { prefix, value } = t;
    if (!prefix) return value.startsWith("-") ? value.slice(1) : "-" + value;
    const lastChar = prefix[prefix.length - 1];
    if (lastChar === "+") return prefix.slice(0, -1) + "-" + value;
    if (lastChar === "-") return prefix.slice(0, -1) + "+" + value;
    if (lastChar === "×" || lastChar === "÷" || lastChar === "(") {
      return prefix + (value.startsWith("-") ? value.slice(1) : "-" + value);
    }
    return expr.startsWith("-") ? expr.slice(1) : "-" + expr;
  }

  function handleKey(root, key) {
    const exprEl = $("#calc-expr", root);
    const resultEl = $("#calc-result", root);

    if (key === "C") {
      calcState.expr = ""; calcState.result = undefined; calcState.justEvaluated = false;
    } else if (key === "⌫") {
      if (calcState.justEvaluated) {
        // Editing a finalized result via backspace isn't well-defined —
        // treat it the same as starting fresh.
        calcState.expr = ""; calcState.result = undefined;
      } else {
        calcState.expr = calcState.expr.slice(0, -1);
      }
      calcState.justEvaluated = false;
    } else if (key === "±") {
      if (calcState.justEvaluated && calcState.result && calcState.result !== "Error") {
        calcState.expr = toggleSign(calcState.result);
      } else {
        calcState.expr = toggleSign(calcState.expr);
      }
      calcState.result = undefined; calcState.justEvaluated = false;
    } else if (key === "%") {
      if (calcState.justEvaluated && calcState.result && calcState.result !== "Error") {
        calcState.expr = formatResult(parseFloat(calcState.result) / 100);
      } else {
        calcState.expr = applyPercent(calcState.expr);
      }
      calcState.result = undefined; calcState.justEvaluated = false;
    } else if (key === "=") {
      if (!calcState.expr.trim()) return;
      try {
        const value = evaluateExpression(calcState.expr);
        const formatted = formatResult(value);
        pushCalcHistory(calcState.expr, formatted);
        calcState.result = formatted;
      } catch (e) {
        calcState.result = "Error";
      }
      calcState.justEvaluated = true;
      paintCalculator(root);
      return;
    } else {
      // Digits, "." , parentheses, operators, and scientific function keys.
      const isOperator = ["×", "÷", "+", "-", "^"].includes(key);
      if (calcState.justEvaluated) {
        if (isOperator && calcState.result && calcState.result !== "Error") {
          // Chain from the previous result: "2+2=" then "×3=" -> "4×3" = 12.
          calcState.expr = calcState.result + key;
        } else {
          calcState.expr = key === "." ? "0." : key;
        }
      } else {
        calcState.expr += key;
      }
      calcState.result = undefined;
      calcState.justEvaluated = false;
    }

    exprEl.textContent = calcState.expr || "0";
    resultEl.textContent = calcState.result !== undefined ? calcState.result : "";
  }

  APPS_REGISTRY.push({
    id: "calculator", name: "Calculator", desc: "Standard & scientific, with history",
    icon: "calculator", render: (root) => renderCalculatorApp(root)
  });

  window.__KRAGVOR_CALC__ = { evaluateExpression, applyPercent, toggleSign };
})();

/* ==========================================================================
   PART 7 — TIC-TAC-TOE (strong, realistically beatable opponent)
   Used exclusively by Vault PIN recovery. Player is always X, AI is O.
   ========================================================================== */
(() => {
  "use strict";
  const WIN_LINES = [
    [0,1,2],[3,4,5],[6,7,8],
    [0,3,6],[1,4,7],[2,5,8],
    [0,4,8],[2,4,6]
  ];

  function getWinner(board) {
    for (const [a,b,c] of WIN_LINES) {
      if (board[a] && board[a] === board[b] && board[a] === board[c]) return board[a];
    }
    if (board.every(c => c)) return "draw";
    return null;
  }

  // Minimax with alpha-beta pruning gives the AI perfect knowledge of every
  // move's true strategic value. Move SELECTION (below) is what keeps the
  // opponent human-feeling and beatable rather than a perfect machine.
  function minimax(board, depth, isMaximizing, alpha, beta) {
    const winner = getWinner(board);
    if (winner === "O") return 10 - depth;
    if (winner === "X") return depth - 10;
    if (winner === "draw") return 0;

    if (isMaximizing) {
      let best = -Infinity;
      for (let i = 0; i < 9; i++) {
        if (board[i]) continue;
        board[i] = "O";
        best = Math.max(best, minimax(board, depth + 1, false, alpha, beta));
        board[i] = null;
        alpha = Math.max(alpha, best);
        if (beta <= alpha) break;
      }
      return best;
    } else {
      let best = Infinity;
      for (let i = 0; i < 9; i++) {
        if (board[i]) continue;
        board[i] = "X";
        best = Math.min(best, minimax(board, depth + 1, true, alpha, beta));
        board[i] = null;
        beta = Math.min(beta, best);
        if (beta <= alpha) break;
      }
      return best;
    }
  }

  function scoredMoves(board) {
    const moves = [];
    for (let i = 0; i < 9; i++) {
      if (board[i]) continue;
      board[i] = "O";
      const score = minimax(board, 0, false, -Infinity, Infinity);
      board[i] = null;
      moves.push({ index: i, score });
    }
    moves.sort((a, b) => b.score - a.score);
    return moves;
  }

  // Move selection: normally play the single best move (with natural
  // variety among genuinely tied options, so it doesn't repeat identical
  // patterns). Occasionally — calibrated so it's a real, exploitable
  // opening across a 3-game match without ever throwing a game outright —
  // it instead plays its second-best distinct option: still a deliberate,
  // reasonable move a decent player might choose, just not the sharpest
  // one. That is what makes the AI beatable rather than a random blunder.
  function bestAiMove(board, options = {}) {
    const moves = scoredMoves(board);
    if (!moves.length) return -1;

    const filledCount = board.filter(Boolean).length;
    const mistakeChance = options.mistakeChance != null ? options.mistakeChance : 0.12;
    const distinctScores = [...new Set(moves.map(m => m.score))];

    // Never fumble the AI's opening move, and only "misjudge" when there's
    // an actual second-tier option to fall back to (never a random pick).
    if (filledCount >= 1 && distinctScores.length > 1 && Math.random() < mistakeChance) {
      const nearMissScore = distinctScores[1];
      const nearMissTier = moves.filter(m => m.score === nearMissScore);
      return nearMissTier[Math.floor(Math.random() * nearMissTier.length)].index;
    }

    const topScore = moves[0].score;
    const topTier = moves.filter(m => m.score === topScore);
    return topTier[Math.floor(Math.random() * topTier.length)].index;
  }

  window.__KRAGVOR_TTT__ = { getWinner, bestAiMove, WIN_LINES };
})();

/* ==========================================================================
   PART 8 — NOTES
   Per-account notes with categories, pin, favorite, archive, trash/recovery,
   autosave, and full integration with Universal Search.
   ========================================================================== */
(() => {
  "use strict";
  const C = window.__KRAGVOR_CORE__;
  const R = window.__KRAGVOR_ROUTER__;
  const SUPA = window.__KRAGVOR_SUPABASE__;
  const SYNC = window.__KRAGVOR_SYNC__;
  const {
    $, $$, escapeHtml, readJSON, writeJSON,
    LS_NOTES, currentUser, ICONS, toast, APPS_REGISTRY, logSecurityEvent, SEVERITY, isOwner
  } = C;
  const { navigate, openModal, closeModal, openConfirmModal } = R;

  const TRASH_RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

  /* ---------------------------------------------------------------------
     Store — strictly scoped to the current account (RLS enforces this
     server-side too: every row is filtered to `user_id = auth.uid()`).
     Local storage is the fast, always-available offline cache; Supabase is
     the cloud source of truth. Every mutation here (a) writes local
     storage immediately so the UI never waits on the network, then
     (b) queues the equivalent Supabase write via the sync engine.
     ------------------------------------------------------------------- */
  function getAllNotesRaw() {
    const u = currentUser();
    if (!u) return [];
    const all = readJSON(localStorage, LS_NOTES, {});
    return all[u.id] || [];
  }
  function saveAllNotesRaw(list) {
    const u = currentUser();
    if (!u) return;
    const all = readJSON(localStorage, LS_NOTES, {});
    all[u.id] = list;
    writeJSON(localStorage, LS_NOTES, all);
  }
  function purgeExpiredTrash(list) {
    const now = Date.now();
    return list.filter(n => !(n.deletedAt && (now - n.deletedAt) > TRASH_RETENTION_MS));
  }
  function getNotes() {
    const before = getAllNotesRaw();
    const list = purgeExpiredTrash(before);
    // Anything purged locally past retention must also be permanently
    // removed from the cloud, not just dropped from this one device's cache.
    if (list.length !== before.length) {
      const keptIds = new Set(list.map(n => n.id));
      before.forEach(n => { if (!keptIds.has(n.id)) SYNC.enqueue("notes", "delete", { id: n.id }); });
      saveAllNotesRaw(list);
    }
    return list;
  }
  function getActiveNotes() { return getNotes().filter(n => !n.deletedAt && !n.archived); }
  function getArchivedNotes() { return getNotes().filter(n => !n.deletedAt && n.archived); }
  function getTrashedNotes() { return getNotes().filter(n => !!n.deletedAt); }

  /* ---- Row <-> client-note mapping ---- */
  function rowToNote(row) {
    return {
      id: row.id, title: row.title || "", body: row.content || "",
      category: row.category || "General", pinned: !!row.pinned, favorite: !!row.is_favorite,
      archived: !!row.is_archived, deletedAt: row.deleted_at ? new Date(row.deleted_at).getTime() : null,
      createdAt: new Date(row.created_at).getTime(), updatedAt: new Date(row.updated_at).getTime(),
      version: row.version || 1,
    };
  }
  function noteToInsertRow(note, userId) {
    return {
      id: note.id, user_id: userId, title: note.title || "", content: note.body || "",
      category: note.category || "General", pinned: !!note.pinned, is_favorite: !!note.favorite,
      is_archived: !!note.archived, deleted_at: note.deletedAt ? new Date(note.deletedAt).toISOString() : null,
      created_at: new Date(note.createdAt).toISOString(), updated_at: new Date(note.updatedAt).toISOString(),
    };
  }
  function clientPatchToRow(patch, updatedAtMs) {
    const row = { updated_at: new Date(updatedAtMs).toISOString() };
    if ("title" in patch) row.title = patch.title;
    if ("body" in patch) row.content = patch.body;
    if ("category" in patch) row.category = patch.category;
    if ("pinned" in patch) row.pinned = !!patch.pinned;
    if ("favorite" in patch) row.is_favorite = !!patch.favorite;
    if ("archived" in patch) row.is_archived = !!patch.archived;
    if ("deletedAt" in patch) row.deleted_at = patch.deletedAt ? new Date(patch.deletedAt).toISOString() : null;
    return row;
  }

  function createNote() {
    const u = currentUser();
    const list = getNotes();
    const now = Date.now();
    const note = {
      id: crypto.randomUUID(), title: "", body: "",
      category: "General", pinned: false, favorite: false,
      archived: false, deletedAt: null,
      createdAt: now, updatedAt: now, version: 1,
    };
    list.unshift(note);
    saveAllNotesRaw(list);
    if (u) {
      logSecurityEvent("note_created", {
        accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
        status: "success", severity: SEVERITY.NORMAL, detail: "A new note was created."
      });
      SYNC.enqueue("notes", "insert", noteToInsertRow(note, u.id));
    }
    return note;
  }
  function updateNote(id, patch) {
    const list = getNotes();
    const note = list.find(n => n.id === id);
    if (!note) return null;
    const expectedVersion = note.version || 1;
    const updatedAt = Date.now();
    Object.assign(note, patch, { updatedAt });
    note.version = expectedVersion + 1; // optimistic; reconciled by the conflict handler if wrong
    saveAllNotesRaw(list);
    const u = currentUser();
    if (u) {
      SYNC.enqueue(
        "notes", "update",
        { id, patch: clientPatchToRow(patch, updatedAt), clientPatch: { ...patch, updatedAt } },
        expectedVersion
      );
    }
    return note;
  }
  function softDeleteNote(id) {
    updateNote(id, { deletedAt: Date.now() });
    const u = currentUser();
    if (u) logSecurityEvent("note_deleted", {
      accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
      status: "success", severity: SEVERITY.NORMAL, detail: "A note was moved to trash."
    });
  }
  function restoreNote(id) { updateNote(id, { deletedAt: null }); }
  function permanentlyDeleteNote(id) {
    saveAllNotesRaw(getNotes().filter(n => n.id !== id));
    SYNC.enqueue("notes", "delete", { id });
  }
  function emptyTrash() {
    const trashed = getTrashedNotes();
    saveAllNotesRaw(getNotes().filter(n => !n.deletedAt));
    trashed.forEach(n => SYNC.enqueue("notes", "delete", { id: n.id }));
  }
  function getCategories() {
    const set = new Set(["General"]);
    getNotes().forEach(n => { if (n.category) set.add(n.category); });
    return Array.from(set);
  }
  function wordCount(text) { const t = (text || "").trim(); return t ? t.split(/\s+/).length : 0; }

  /* ---------------------------------------------------------------------
     Cloud sync — pull (catch up on changes made on other devices) and
     conflict resolution (never silently destroy a concurrent edit).
     ------------------------------------------------------------------- */
  async function pullNotesFromCloud() {
    const u = currentUser();
    if (!u || !navigator.onLine) return false;
    const { data, error } = await SUPA.client.from("notes").select("*").eq("user_id", u.id);
    if (error || !data) return false;

    const local = getAllNotesRaw();
    const localById = new Map(local.map(n => [n.id, n]));
    const pendingIds = new Set(SYNC.getQueue().filter(i => i.table === "notes").map(i => i.payload.id));
    const seen = new Set();
    const merged = [];

    for (const row of data) {
      seen.add(row.id);
      if (pendingIds.has(row.id)) {
        // We have an unsynced local change for this note — leave it as-is;
        // the queue flush (and its conflict handler) will reconcile it.
        merged.push(localById.get(row.id) || rowToNote(row));
        continue;
      }
      const loc = localById.get(row.id);
      merged.push(!loc || (row.version || 1) >= (loc.version || 1) ? rowToNote(row) : loc);
    }
    // Keep local-only notes the pull hasn't seen yet (created fully offline
    // and still queued, or already known to be pending).
    for (const loc of local) {
      if (!seen.has(loc.id)) merged.push(loc);
    }
    saveAllNotesRaw(merged);
    return true;
  }

  // A conflicting update (this device's edit was based on a version the
  // server no longer has) never silently overwrites, and never silently
  // discards the local edit either: the server's copy wins under the
  // original id, and the local edit survives as a clearly-labeled copy
  // that also gets queued for upload.
  SYNC.registerConflictHandler("notes", async (payload, serverRow) => {
    const u = currentUser();
    const list = getAllNotesRaw();
    const idx = list.findIndex(n => n.id === payload.id);

    if (!serverRow) {
      // The note was deleted (on another device, or by trash retention)
      // before this queued edit landed — nothing left to reconcile against.
      if (idx !== -1) { list.splice(idx, 1); saveAllNotesRaw(list); }
      return;
    }

    const serverAsLocal = rowToNote(serverRow);
    if (idx === -1) {
      list.push(serverAsLocal);
      saveAllNotesRaw(list);
      return;
    }

    const conflictCopy = {
      ...list[idx],
      ...payload.clientPatch,
      id: crypto.randomUUID(),
      title: `${(payload.clientPatch.title ?? list[idx].title) || "Untitled"} (edited elsewhere)`,
      version: 1,
      createdAt: Date.now(), updatedAt: Date.now(),
    };
    list[idx] = serverAsLocal;
    list.push(conflictCopy);
    saveAllNotesRaw(list);
    if (u) SYNC.enqueue("notes", "insert", noteToInsertRow(conflictCopy, u.id));
  });

  let notesViewMounted = false;
  let notesPollTimer = null;

  window.addEventListener("kragvor:session-ready", () => {
    pullNotesFromCloud().then((ok) => { if (ok && notesViewMounted) refreshMountedNotesView(); });
  });
  window.addEventListener("online", () => {
    pullNotesFromCloud().then((ok) => { if (ok && notesViewMounted) refreshMountedNotesView(); });
  });
  window.addEventListener("kragvor:logout", () => {
    notesViewMounted = false;
    clearInterval(notesPollTimer);
  });

  let refreshMountedNotesView = () => {};

  /* ---------------------------------------------------------------------
     VIEW STATE
     ------------------------------------------------------------------- */
  let notesState = { tab: "active", categoryFilter: "all", sort: "updated", query: "" };

  function renderNotesApp(root, user, route) {
    const editId = route.split("/").slice(3).join("/"); // /apps/notes/<id>
    if (editId) return renderNoteEditor(root, editId);
    notesState = { tab: "active", categoryFilter: "all", sort: "updated", query: "" };
    paintNotesList(root);
  }

  function sortNotes(list) {
    const arr = [...list];
    arr.sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      if (notesState.sort === "created") return b.createdAt - a.createdAt;
      if (notesState.sort === "title") return (a.title || "Untitled").localeCompare(b.title || "Untitled");
      return b.updatedAt - a.updatedAt;
    });
    return arr;
  }

  let notesSyncUnsub = null;

  function paintNotesList(root) {
    const categories = getCategories();
    notesViewMounted = true;
    refreshMountedNotesView = () => { if (notesViewMounted) renderNotesResults(root); };
    clearInterval(notesPollTimer);
    if (notesSyncUnsub) notesSyncUnsub();
    notesPollTimer = setInterval(() => {
      pullNotesFromCloud().then((ok) => { if (ok) refreshMountedNotesView(); });
    }, 20000);

    root.innerHTML = `
      <div class="notes-toolbar">
        <div class="input-wrap" style="flex:1;">
          <input id="notes-search" type="text" placeholder="Search your notes" value="${escapeHtml(notesState.query)}" autocomplete="off" />
        </div>
        <button class="btn btn-primary btn-sm" id="notes-new">${ICONS.plus} New</button>
      </div>

      <div id="notes-sync-status" class="hint" style="margin-top:6px;"></div>

      <div class="calc-mode-toggle" style="margin-top:12px;">
        <button class="seg ${notesState.tab === "active" ? "on" : ""}" data-tab="active">Notes</button>
        <button class="seg ${notesState.tab === "archive" ? "on" : ""}" data-tab="archive">Archive</button>
        <button class="seg ${notesState.tab === "trash" ? "on" : ""}" data-tab="trash">Trash</button>
      </div>

      <div class="chip-row" id="notes-chip-row">
        <button class="chip ${notesState.categoryFilter === "all" ? "on" : ""}" data-cat="all">All</button>
        ${categories.map(c => `<button class="chip ${notesState.categoryFilter === c ? "on" : ""}" data-cat="${escapeHtml(c)}">${escapeHtml(c)}</button>`).join("")}
      </div>

      <div id="notes-list-region" style="margin-top:12px;"></div>
    `;
    renderNotesResults(root);
    bindNotesShell(root);
    paintSyncStatus(root);
    notesSyncUnsub = SYNC.onStatusChange(() => paintSyncStatus(root));
    const stopWatching = () => { if (!document.body.contains(root)) { notesViewMounted = false; if (notesSyncUnsub) { notesSyncUnsub(); notesSyncUnsub = null; } clearInterval(notesPollTimer); window.removeEventListener("hashchange", stopWatching); } };
    window.addEventListener("hashchange", stopWatching);
  }

  function paintSyncStatus(root) {
    const el = $("#notes-sync-status", root);
    if (!el) return;
    const { state, pending } = SYNC.getStatus();
    const text = {
      idle: "Synced",
      syncing: "Syncing\u2026",
      offline: pending ? `Offline \u2014 ${pending} change${pending === 1 ? "" : "s"} will sync when you're back online.` : "Offline",
      pending: `Pending \u2014 ${pending} change${pending === 1 ? "" : "s"} waiting to sync.`,
      error: "Sync failed \u2014 will retry automatically.",
    }[state] || "";
    el.textContent = text;
  }

  function currentFilteredNotes() {
    let list = notesState.tab === "archive" ? getArchivedNotes()
      : notesState.tab === "trash" ? getTrashedNotes()
      : getActiveNotes();
    if (notesState.categoryFilter !== "all") list = list.filter(n => n.category === notesState.categoryFilter);
    if (notesState.query.trim()) {
      const q = notesState.query.trim().toLowerCase();
      list = list.filter(n => (n.title || "").toLowerCase().includes(q) || (n.body || "").toLowerCase().includes(q));
    }
    return sortNotes(list);
  }

  // Only repaints the results region + trash-empty button, never the
  // toolbar/search input itself — typing a query no longer destroys and
  // recreates the input, so focus and cursor position are preserved.
  function renderNotesResults(root) {
    const list = currentFilteredNotes();
    $("#notes-list-region", root).innerHTML = `
      <div id="notes-list" style="display:flex;flex-direction:column;gap:8px;">
        ${list.length ? list.map(noteRow).join("") : `
          <div class="empty-state">
            <div class="glyph">${ICONS.notes}</div>
            <p>${notesState.tab === "trash" ? "Trash is empty." : notesState.tab === "archive" ? "No archived notes." : "No notes yet. Create your first one."}</p>
          </div>
        `}
      </div>
      ${notesState.tab === "trash" && list.length ? `<button class="btn btn-danger btn-sm" id="notes-empty-trash" style="margin-top:12px;">Empty trash</button>` : ""}
    `;
    bindNotesResults(root);
  }

  function noteRow(n) {
    const time = new Date(n.updatedAt).toLocaleDateString([], { month: "short", day: "numeric" });
    const preview = (n.body || "").replace(/\n/g, " ").slice(0, 90);
    return `
      <div class="list-row note-row" data-open-note="${n.id}">
        <div class="grow">
          <div class="title">
            ${n.pinned ? ICONS.pin : ""}
            ${escapeHtml(n.title || "Untitled")}
            ${n.favorite ? `<span style="color:var(--accent);margin-left:4px;">${ICONS.star}</span>` : ""}
          </div>
          <div class="sub">${escapeHtml(n.category)} &middot; ${time}${preview ? " &middot; " + escapeHtml(preview) : ""}</div>
        </div>
        ${n.deletedAt ? `
          <div class="row-actions">
            <button class="icon-btn" data-restore="${n.id}" aria-label="Restore">${ICONS.check}</button>
            <button class="icon-btn danger" data-perm-del="${n.id}" aria-label="Delete forever">${ICONS.trash}</button>
          </div>
        ` : ""}
      </div>
    `;
  }

  function bindNotesShell(root) {
    $("#notes-new", root).addEventListener("click", () => {
      const n = createNote();
      navigate(`/apps/notes/${n.id}`);
    });
    let searchDebounce = null;
    $("#notes-search", root).addEventListener("input", (e) => {
      notesState.query = e.target.value;
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => renderNotesResults(root), 80);
    });
    $$("[data-tab]", root).forEach(btn => btn.addEventListener("click", () => {
      notesState.tab = btn.getAttribute("data-tab");
      notesState.categoryFilter = "all";
      paintNotesList(root); // tab change can affect available categories too
    }));
    $$("[data-cat]", root).forEach(btn => btn.addEventListener("click", () => {
      notesState.categoryFilter = btn.getAttribute("data-cat");
      $$("[data-cat]", root).forEach(b => b.classList.toggle("on", b === btn));
      renderNotesResults(root);
    }));
  }

  function bindNotesResults(root) {
    $$("[data-open-note]", root).forEach(el => el.addEventListener("click", (e) => {
      if (e.target.closest("[data-restore],[data-perm-del]")) return;
      navigate(`/apps/notes/${el.getAttribute("data-open-note")}`);
    }));
    $$("[data-restore]", root).forEach(btn => btn.addEventListener("click", (e) => {
      e.stopPropagation();
      restoreNote(btn.getAttribute("data-restore"));
      toast("Note restored", "success");
      renderNotesResults(root);
    }));
    $$("[data-perm-del]", root).forEach(btn => btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const id = btn.getAttribute("data-perm-del");
      openConfirmModal({
        title: "Delete permanently?",
        message: "This note will be permanently deleted and cannot be recovered.",
        confirmLabel: "Delete forever",
        danger: true,
        onConfirm: () => { permanentlyDeleteNote(id); toast("Note permanently deleted", "success"); renderNotesResults(root); }
      });
    }));
    const emptyBtn = $("#notes-empty-trash", root);
    if (emptyBtn) emptyBtn.addEventListener("click", () => {
      openConfirmModal({
        title: "Empty trash?",
        message: "All notes in trash will be permanently deleted.",
        confirmLabel: "Empty trash",
        danger: true,
        onConfirm: () => { emptyTrash(); toast("Trash emptied", "success"); renderNotesResults(root); }
      });
    });
  }

  /* ---------------------------------------------------------------------
     EDITOR
     Autosave is debounced for typing, but pending changes are always
     flushed synchronously before the editor is left or destroyed (back
     navigation, action buttons, route change, or the tab/app closing) so
     a change is never silently lost to timing.
     ------------------------------------------------------------------- */
  let autosaveTimer = null;
  let pendingFlush = null;

  function flushPendingNote() {
    if (pendingFlush) {
      clearTimeout(autosaveTimer);
      pendingFlush();
      pendingFlush = null;
    }
  }
  window.addEventListener("pagehide", flushPendingNote);
  window.addEventListener("beforeunload", flushPendingNote);
  window.addEventListener("hashchange", () => {
    if (!R.currentRoute().startsWith("/apps/notes/")) flushPendingNote();
  }, { passive: true });

  function renderNoteEditor(root, id) {
    flushPendingNote(); // leaving whatever note was previously open, if any
    notesViewMounted = false;
    clearInterval(notesPollTimer);
    const note = getNotes().find(n => n.id === id);
    if (!note) {
      root.innerHTML = `<div class="empty-state"><div class="glyph">${ICONS.notes}</div><p>Note not found.</p></div>`;
      return;
    }
    const categories = getCategories();

    root.innerHTML = `
      <button class="back-link" id="note-back">${ICONS.chevron} Notes</button>

      <div class="note-editor-toolbar">
        <button class="icon-btn ${note.pinned ? "active" : ""}" id="note-pin" aria-label="Pin">${ICONS.pin}</button>
        <button class="icon-btn ${note.favorite ? "active" : ""}" id="note-fav" aria-label="Favorite">${note.favorite ? ICONS.star : ICONS.starOutline}</button>
        <select id="note-category" class="mini-select">
          ${categories.map(c => `<option value="${escapeHtml(c)}" ${c === note.category ? "selected" : ""}>${escapeHtml(c)}</option>`).join("")}
          <option value="__new__">+ New category</option>
        </select>
        <button class="icon-btn" id="note-archive" aria-label="Archive">${ICONS.archive}</button>
        <button class="icon-btn" id="note-share" aria-label="Copy">${ICONS.copy}</button>
        <button class="icon-btn danger" id="note-delete" aria-label="Delete">${ICONS.trash}</button>
      </div>

      <input id="note-title" class="note-title-input" type="text" placeholder="Title" value="${escapeHtml(note.title)}" />
      <textarea id="note-body" class="note-body-input" placeholder="Start writing&hellip;">${escapeHtml(note.body)}</textarea>

      <div class="note-meta">
        <span id="note-save-state">Saved</span>
        <span>&middot;</span>
        <span id="note-wc">${wordCount(note.body)} words</span>
        <span>&middot;</span>
        <span id="note-cc">${note.body.length} characters</span>
        <span>&middot;</span>
        <span>Edited ${new Date(note.updatedAt).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</span>
      </div>
    `;

    const titleEl = $("#note-title"), bodyEl = $("#note-body");
    const doSave = () => {
      updateNote(id, { title: titleEl.value, body: bodyEl.value });
      const saveState = $("#note-save-state");
      if (saveState) saveState.textContent = "Saved";
      const wc = $("#note-wc"), cc = $("#note-cc");
      if (wc) wc.textContent = `${wordCount(bodyEl.value)} words`;
      if (cc) cc.textContent = `${bodyEl.value.length} characters`;
    };
    pendingFlush = doSave;

    $("#note-back").addEventListener("click", () => { flushPendingNote(); navigate("/apps/notes"); });

    const scheduleAutosave = () => {
      const saveState = $("#note-save-state");
      if (saveState) saveState.textContent = "Saving\u2026";
      clearTimeout(autosaveTimer);
      autosaveTimer = setTimeout(doSave, 500);
    };
    titleEl.addEventListener("input", scheduleAutosave);
    bodyEl.addEventListener("input", scheduleAutosave);

    $("#note-pin").addEventListener("click", () => {
      flushPendingNote();
      updateNote(id, { pinned: !note.pinned });
      renderNoteEditor(root, id);
    });
    $("#note-fav").addEventListener("click", () => {
      flushPendingNote();
      updateNote(id, { favorite: !note.favorite });
      renderNoteEditor(root, id);
    });
    $("#note-category").addEventListener("change", (e) => {
      if (e.target.value === "__new__") {
        openModal({
          title: "New category",
          bodyHtml: `<div class="field" style="margin-bottom:0;"><div class="input-wrap"><input id="new-cat-input" type="text" placeholder="Category name" /></div></div>`,
          footHtml: `<button class="btn btn-ghost" id="new-cat-cancel">Cancel</button><button class="btn btn-primary" id="new-cat-save">Create</button>`
        });
        $("#new-cat-cancel").addEventListener("click", () => { closeModal(); renderNoteEditor(root, id); });
        $("#new-cat-save").addEventListener("click", () => {
          const val = $("#new-cat-input").value.trim();
          flushPendingNote();
          if (val) updateNote(id, { category: val });
          closeModal();
          renderNoteEditor(root, id);
        });
      } else {
        flushPendingNote();
        updateNote(id, { category: e.target.value });
      }
    });
    $("#note-archive").addEventListener("click", () => {
      flushPendingNote();
      updateNote(id, { archived: !note.archived });
      toast(note.archived ? "Note unarchived" : "Note archived", "success");
      navigate("/apps/notes");
    });
    $("#note-share").addEventListener("click", () => {
      const text = `${titleEl.value}\n\n${bodyEl.value}`;
      if (navigator.share) {
        navigator.share({ title: titleEl.value || "Note", text }).catch(() => {});
      } else if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => toast("Copied to clipboard", "success"));
      }
    });
    $("#note-delete").addEventListener("click", () => {
      openConfirmModal({
        title: "Move to trash?",
        message: "This note will be moved to trash and permanently deleted after 30 days.",
        confirmLabel: "Delete",
        danger: true,
        onConfirm: () => { pendingFlush = null; clearTimeout(autosaveTimer); softDeleteNote(id); toast("Note moved to trash", "success"); navigate("/apps/notes"); }
      });
    });
  }

  APPS_REGISTRY.push({
    id: "notes", name: "Notes", desc: "Write, organize, and search your notes",
    icon: "notes", render: (root, user, route) => renderNotesApp(root, user, route)
  });

  window.__KRAGVOR_NOTES__ = { getActiveNotes, getNotes, wordCount };
})();

/* ==========================================================================
   PART 9 — VAULT
   Real encryption at rest (AES-GCM), not merely a hidden UI.

   Design (KEK/DEK pattern):
     - A random 256-bit AES-GCM "master key" (DEK) is generated once and
       encrypts all Vault content (entries, images, albums).
     - The Vault PIN never encrypts content directly. Instead it is run
       through PBKDF2 to derive a "key-encryption key" (KEK) that wraps
       (encrypts) the master key. Changing the PIN just re-wraps the same
       master key — it doesn't require re-encrypting all Vault data.
     - Nothing here is decryptable without the correct PIN. That also means
       a genuinely forgotten PIN cannot be "recovered" without losing the
       old data — see the Recovery section for how that limitation is
       handled honestly instead of faked.
     - Decrypted content only ever lives in an in-memory variable for the
       current tab. It is never written to local/sessionStorage in
       plaintext, and is dropped the moment the Vault locks.
   ========================================================================== */
(() => {
  "use strict";
  const C = window.__KRAGVOR_CORE__;
  const R = window.__KRAGVOR_ROUTER__;
  const SUPA = window.__KRAGVOR_SUPABASE__;
  const {
    $, $$, escapeHtml, uid, readJSON, writeJSON,
    LS_VAULT, LS_VAULT_RECOVERY, hashSecret,
    currentUser, ICONS, toast, APPS_REGISTRY, logSecurityEvent, SEVERITY
  } = C;
  const { navigate, openModal, closeModal, openConfirmModal, currentRoute } = R;
  const TTT = () => window.__KRAGVOR_TTT__;

  const RECOVERY_COOLDOWN_MS = 24 * 60 * 60 * 1000;
  const PIN_MAX_ATTEMPTS = 5;
  const PIN_LOCK_MS = 60 * 1000; // escalating base lockout for wrong PIN guesses
  const KDF_ITERATIONS = 150000; // PBKDF2-HMAC-SHA256 rounds for the PIN-derived KEK
  const AUTO_LOCK_OPTIONS = [
    { value: 0.33, label: "Immediate" },
    { value: 1, label: "1 minute" },
    { value: 5, label: "5 minutes" },
    { value: 15, label: "15 minutes" },
    { value: 30, label: "30 minutes" }
  ];
  const DEFAULT_AUTO_LOCK_MINUTES = 5;

  /* ---------------------------------------------------------------------
     Low-level crypto helpers (AES-GCM + PBKDF2 via Web Crypto)
     ------------------------------------------------------------------- */
  function bufToB64(buf) {
    let binary = "";
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  function b64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }
  function randomHex(numBytes) {
    const arr = new Uint8Array(numBytes);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
  }
  function hexToBytes(hex) {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
    return arr;
  }

  async function deriveKek(pin, saltHex, iterations) {
    const keyMaterial = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(C.norm ? C.norm(pin) : pin), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: hexToBytes(saltHex), iterations, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  async function generateMasterKey() {
    return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  }
  async function wrapMasterKey(masterKey, kek) {
    const raw = await crypto.subtle.exportKey("raw", masterKey);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, raw);
    const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, "0")).join("");
    return { ivHex, ct: bufToB64(ct) };
  }
  async function unwrapMasterKey(wrapped, kek) {
    const iv = hexToBytes(wrapped.ivHex);
    const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, kek, b64ToBuf(wrapped.ct)); // throws if PIN wrong
    return crypto.subtle.importKey("raw", raw, "AES-GCM", true, ["encrypt", "decrypt"]);
  }
  async function encryptJSON(obj, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(obj));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
    return { ivHex: Array.from(iv).map(b => b.toString(16).padStart(2, "0")).join(""), ct: bufToB64(ct) };
  }
  async function decryptJSON(blob, key) {
    const iv = hexToBytes(blob.ivHex);
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, b64ToBuf(blob.ct));
    return JSON.parse(new TextDecoder().decode(plaintext));
  }
  // Raw-bytes variants, used for Vault images: the encrypted object stored
  // in Supabase Storage is just [12-byte IV][ciphertext] — the server sees
  // opaque bytes, never the image content.
  async function encryptBytes(bytes, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
    const combined = new Uint8Array(iv.length + ct.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ct), iv.length);
    return combined;
  }
  async function decryptBytes(combinedBytes, key) {
    const iv = combinedBytes.slice(0, 12);
    const ct = combinedBytes.slice(12);
    return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  }
  function dataUrlToBytes(dataUrl) {
    const b64 = dataUrl.split(",")[1] || "";
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  /* ---------------------------------------------------------------------
     Numeric PIN field helper — numeric keypad only, digit-only input,
     clean masked typography.
     ------------------------------------------------------------------- */
  function pinFieldHtml(id, placeholder, { toggle = false, disabled = false } = {}) {
    return `
      <div class="pin-field">
        <input id="${id}" class="pin-input masked" type="tel" inputmode="numeric" pattern="[0-9]*"
          autocomplete="off" maxlength="8" placeholder="${escapeHtml(placeholder)}" ${disabled ? "disabled" : ""} />
        ${toggle ? `<button type="button" class="pw-toggle" id="${id}-toggle">Show</button>` : ""}
      </div>
    `;
  }
  function bindPinField(id) {
    const el = $(`#${id}`);
    if (!el) return;
    el.addEventListener("input", () => {
      const digits = el.value.replace(/\D/g, "").slice(0, 8);
      if (digits !== el.value) el.value = digits;
    });
  }
  function bindPinToggle(id) {
    const el = $(`#${id}`);
    const btn = $(`#${id}-toggle`);
    if (!el || !btn) return;
    btn.addEventListener("click", () => {
      const isMasked = el.classList.contains("masked");
      el.classList.toggle("masked", !isMasked);
      btn.textContent = isMasked ? "Hide" : "Show";
    });
  }

  /* ---------------------------------------------------------------------
     Encrypted record store — non-secret metadata lives in localStorage;
     decrypted content only ever lives in the in-memory `session` below.
     ------------------------------------------------------------------- */
  function getAllVaultRecords() { return readJSON(localStorage, LS_VAULT, {}); }
  function saveAllVaultRecords(v) { writeJSON(localStorage, LS_VAULT, v); }
  function emptyVaultRecord() {
    return {
      version: 2, pinSet: false, kdf: null, wrappedKey: null, data: null,
      failedAttempts: 0, lockoutUntil: 0, autoLockMinutes: DEFAULT_AUTO_LOCK_MINUTES,
      updatedAt: 0, cloudVersion: 0
    };
  }
  function getVaultRecord() {
    const u = currentUser();
    if (!u) return emptyVaultRecord();
    const all = getAllVaultRecords();
    if (!all[u.id]) { all[u.id] = emptyVaultRecord(); saveAllVaultRecords(all); }
    return all[u.id];
  }
  // Writes the record locally WITHOUT marking it dirty or pushing — used
  // internally after a push/pull/conflict resolution to record bookkeeping
  // (like the confirmed cloud version) without looping back into another push.
  function writeVaultRecordLocalOnly(accountId, rec) {
    const all = getAllVaultRecords();
    all[accountId] = rec;
    saveAllVaultRecords(all);
  }
  function saveVaultRecord(rec) {
    const u = currentUser();
    if (!u) return;
    rec.updatedAt = Date.now();
    writeVaultRecordLocalOnly(u.id, rec);
    markVaultDirty();
    pushVaultToCloud(); // fire-and-forget: local write already happened
  }

  /* ---------------------------------------------------------------------
     Cloud sync — the whole encrypted record (kdf params, wrapped master
     key, and the encrypted entries/images/albums blob) is always synced
     as ONE atomic unit, since the wrapped key and the data it protects
     must always correspond to each other. The server only ever stores
     ciphertext + public KDF parameters — never the PIN, the master key,
     or plaintext content.

     Conflict handling: pushes are optimistic-concurrency (conditioned on
     the version this device last confirmed), exactly like Notes. A push
     that loses that race is NEVER allowed to blindly overwrite a newer
     cloud copy — the device's unsynced encrypted content is preserved
     locally (still encrypted) for recovery, the newer cloud copy is
     adopted, and the person is told what happened.
     ------------------------------------------------------------------- */
  function vaultDirtyKey() {
    const u = currentUser();
    return u ? `kragvor_vault_dirty_v1_${u.id}` : null;
  }
  function markVaultDirty() {
    const k = vaultDirtyKey();
    if (k) localStorage.setItem(k, "1");
  }
  function clearVaultDirty() {
    const k = vaultDirtyKey();
    if (k) localStorage.removeItem(k);
  }
  function isVaultDirty() {
    const k = vaultDirtyKey();
    return k ? localStorage.getItem(k) === "1" : false;
  }

  let vaultPushInFlight = false;
  async function pushVaultToCloud() {
    const u = currentUser();
    if (!u || !navigator.onLine || vaultPushInFlight) return false;
    const rec = getVaultRecord();
    if (!rec.pinSet) return true; // nothing set up yet — nothing to push
    vaultPushInFlight = true;
    try {
      const payload = {
        pin_set: true, kdf: rec.kdf,
        wrapped_key: JSON.stringify(rec.wrappedKey), encrypted_data: JSON.stringify(rec.data),
        auto_lock_minutes: rec.autoLockMinutes, updated_at: new Date(rec.updatedAt || Date.now()).toISOString(),
      };
      const expectedVersion = rec.cloudVersion || 0;

      if (expectedVersion > 0) {
        // We believe a cloud row already exists at this version — only
        // overwrite it if that's still true.
        const { data, error } = await SUPA.client.from("vault_blob")
          .update(payload).eq("user_id", u.id).eq("version", expectedVersion).select("version");
        if (error) return false;
        if (!data || data.length === 0) {
          await resolveVaultPushConflict();
          return true;
        }
        rec.cloudVersion = data[0].version;
        writeVaultRecordLocalOnly(u.id, rec);
        clearVaultDirty();
        return true;
      }

      // No confirmed cloud version yet — this is either the very first
      // push for this account, or this device has never synced before.
      // Try to create the row; if one already exists, that's a conflict.
      const { data, error } = await SUPA.client.from("vault_blob")
        .insert({ user_id: u.id, ...payload }).select("version");
      if (error) {
        if (error.code === "23505") { // unique_violation — a row already exists
          await resolveVaultPushConflict();
          return true;
        }
        return false;
      }
      rec.cloudVersion = data[0].version;
      writeVaultRecordLocalOnly(u.id, rec);
      clearVaultDirty();
      return true;
    } catch (e) {
      return false;
    } finally {
      vaultPushInFlight = false;
    }
  }

  // Called when a push loses the optimistic-concurrency race (another
  // device's write landed first). Backs up this device's unsynced,
  // still-encrypted content locally — up to 5 backups — then adopts the
  // cloud's current copy so this device converges instead of looping.
  async function resolveVaultPushConflict() {
    const u = currentUser();
    if (!u) return;
    const localRec = getVaultRecord();
    const backupKey = `kragvor_vault_conflict_backup_v1_${u.id}`;
    const backups = readJSON(localStorage, backupKey, []);
    backups.unshift({ savedAt: Date.now(), kdf: localRec.kdf, wrappedKey: localRec.wrappedKey, data: localRec.data });
    if (backups.length > 5) backups.length = 5;
    writeJSON(localStorage, backupKey, backups);

    const { data } = await SUPA.client.from("vault_blob").select("*").eq("user_id", u.id).maybeSingle();
    if (data) {
      if (isUnlocked()) clearSensitiveSession("Vault updated from another device.");
      writeVaultRecordLocalOnly(u.id, {
        version: 2, pinSet: true, kdf: data.kdf,
        wrappedKey: JSON.parse(data.wrapped_key), data: JSON.parse(data.encrypted_data),
        failedAttempts: 0, lockoutUntil: 0,
        autoLockMinutes: Number(data.auto_lock_minutes) || DEFAULT_AUTO_LOCK_MINUTES,
        updatedAt: new Date(data.updated_at).getTime(), cloudVersion: data.version,
      });
    }
    clearVaultDirty(); // this specific conflicting push is resolved; stop retrying it

    logSecurityEvent("vault_sync_conflict", {
      accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
      status: "success", severity: SEVERITY.SUSPICIOUS,
      detail: "A Vault change from another device took precedence; this device's unsynced changes were preserved locally for recovery."
    });
    toast("Vault was updated on another device. Your unsynced changes were saved locally, not lost.", "error");
  }

  // Pulls the cloud copy down onto a device that doesn't have the latest
  // (or any) local Vault record for this account yet — the "new phone"
  // case. Never overwrites a local copy that has unsynced changes (that
  // would silently destroy data); the push path above handles that race
  // (via resolveVaultPushConflict) instead.
  async function pullVaultFromCloud() {
    const u = currentUser();
    if (!u || !navigator.onLine) return false;
    if (isVaultDirty()) return true; // unsynced local changes take priority
    const { data, error } = await SUPA.client.from("vault_blob").select("*").eq("user_id", u.id).maybeSingle();
    if (error) return false;
    if (!data || !data.pin_set) return true; // no cloud Vault yet for this account

    const rec = getVaultRecord();
    if (rec.pinSet && (rec.cloudVersion || 0) >= data.version) return true; // local is already current

    // A different (or first-time-on-this-device) encrypted copy just
    // landed locally. Any existing unlocked session decrypted the OLD
    // copy under the old master key and is no longer valid — drop it so
    // the person re-enters their PIN against the copy that's now here.
    if (isUnlocked()) clearSensitiveSession("Vault updated from another device.");

    writeVaultRecordLocalOnly(u.id, {
      version: 2, pinSet: true,
      kdf: data.kdf,
      wrappedKey: JSON.parse(data.wrapped_key),
      data: JSON.parse(data.encrypted_data),
      failedAttempts: 0, lockoutUntil: 0,
      autoLockMinutes: Number(data.auto_lock_minutes) || DEFAULT_AUTO_LOCK_MINUTES,
      updatedAt: new Date(data.updated_at).getTime(),
      cloudVersion: data.version,
    });
    return true;
  }

  window.addEventListener("kragvor:session-ready", () => { pushVaultToCloud(); pullVaultFromCloud(); });
  window.addEventListener("online", () => { pushVaultToCloud(); pullVaultFromCloud(); });
  setInterval(() => { pushVaultToCloud(); }, 20000);
  function emptyContent() { return { entries: [], images: [], albums: ["General"] }; }

  /* ---------------------------------------------------------------------
     In-memory decrypted session — the ONLY place plaintext Vault content
     exists. Cleared on lock, backgrounding, navigating away, idle
     timeout, or logout. Never persisted.
     ------------------------------------------------------------------- */
  let session = null; // { accountId, masterKey, data }
  let lastActivityAt = Date.now();
  let idleTimer = null;

  function isUnlocked() {
    const u = currentUser();
    return !!(u && session && session.accountId === u.id);
  }
  function getVault() {
    if (isUnlocked()) return session.data;
    return emptyContent(); // safe stub; never used for real rendering while locked
  }
  async function persistVault() {
    if (!isUnlocked()) return;
    const rec = getVaultRecord();
    rec.data = await encryptJSON(session.data, session.masterKey);
    saveVaultRecord(rec);
  }
  function markActivity() { lastActivityAt = Date.now(); }

  function clearSensitiveSession(reason) {
    const wasUnlocked = isUnlocked();
    session = null;
    clearImageUrlCache();
    if (wasUnlocked) {
      const u = currentUser();
      if (u) logSecurityEvent("vault_locked", {
        accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
        status: "success", severity: SEVERITY.NORMAL, detail: reason || "Vault locked."
      });
    }
  }
  function lockVault(reason) { clearSensitiveSession(reason); }

  // Auto-lock triggers: backgrounding, leaving the Vault route, idle timeout,
  // and logout. All of these clear the in-memory session outright.
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) clearSensitiveSession("App backgrounded.");
  });
  window.addEventListener("hashchange", () => {
    if (!currentRoute().startsWith("/apps/vault") && isUnlocked()) {
      clearSensitiveSession("Left the Vault.");
    }
  }, { passive: true });
  window.addEventListener("kragvor:logout", () => { session = null; });
  ["pointerdown", "keydown", "touchstart"].forEach(evt => {
    window.addEventListener(evt, () => { if (isUnlocked()) markActivity(); }, { passive: true });
  });
  if (!idleTimer) {
    idleTimer = setInterval(() => {
      if (!isUnlocked()) return;
      const rec = getVaultRecord();
      const minutes = rec.autoLockMinutes != null ? rec.autoLockMinutes : DEFAULT_AUTO_LOCK_MINUTES;
      if (Date.now() - lastActivityAt > minutes * 60 * 1000) {
        clearSensitiveSession("Auto-locked after inactivity.");
        if (currentRoute().startsWith("/apps/vault")) navigate("/apps/vault");
      }
    }, 8000);
  }

  /* ---------------------------------------------------------------------
     Entries & images CRUD — operate on the in-memory session, then
     persist an updated encrypted blob.
     ------------------------------------------------------------------- */
  async function addEntry(entry) {
    const v = getVault();
    const rec = {
      id: uid("vitem"), kind: entry.kind, title: entry.title || "Untitled",
      username: entry.username || "", secret: entry.secret || "",
      notes: entry.notes || "", customFields: entry.customFields || [],
      category: entry.category || "General", favorite: false,
      createdAt: Date.now(), updatedAt: Date.now()
    };
    v.entries.unshift(rec);
    if (rec.category && !v.albums.includes(rec.category)) v.albums.push(rec.category);
    await persistVault();
    return rec;
  }
  async function updateEntry(id, patch) {
    const v = getVault();
    const rec = v.entries.find(e => e.id === id);
    if (!rec) return null;
    Object.assign(rec, patch, { updatedAt: Date.now() });
    await persistVault();
    return rec;
  }
  async function deleteEntry(id) {
    const v = getVault();
    v.entries = v.entries.filter(e => e.id !== id);
    await persistVault();
  }
  // Pre-Checkpoint-5 local Vaults stored image bytes directly as an
  // embedded `dataUrl` inside the encrypted blob. Anything still in that
  // shape is converted to the current pending-upload shape (so it gets a
  // real Storage upload like any other new image) the first time it's
  // seen after an unlock — a one-time, in-memory-only transform; nothing
  // is ever decrypted or written anywhere except back into the same
  // encrypted Vault record.
  function upgradeLegacyImageShape() {
    if (!isUnlocked()) return;
    const images = session.data.images || [];
    let changed = false;
    images.forEach((img) => {
      if (img.dataUrl && !img.pendingDataUrl && !img.storagePath) {
        img.pendingDataUrl = img.dataUrl;
        img.mimeType = img.mimeType || "image/jpeg";
        delete img.dataUrl;
        changed = true;
      }
    });
    if (changed) {
      persistVault();
      images.filter(i => i.pendingDataUrl).forEach(i => uploadVaultImage(i.id));
    }
  }

  async function addImage(dataUrl, album, mimeType) {
    const v = getVault();
    const rec = {
      id: uid("vimg"), album: album || "General", favorite: false, addedAt: Date.now(),
      storagePath: null, pendingDataUrl: dataUrl, mimeType: mimeType || "image/jpeg",
    };
    v.images.unshift(rec);
    if (!v.albums.includes(rec.album)) v.albums.push(rec.album);
    await persistVault(); // local write + whole-blob cloud push happen immediately
    const u = currentUser();
    if (u) logSecurityEvent("vault_image_added", {
      accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
      status: "success", severity: SEVERITY.NORMAL, detail: "A private image was added to the Vault."
    });
    uploadVaultImage(rec.id); // fire-and-forget; queued/retried like everything else
    return rec;
  }
  async function deleteImage(id) {
    const v = getVault();
    const rec = v.images.find(i => i.id === id);
    v.images = v.images.filter(i => i.id !== id);
    await persistVault();
    imageUrlCache.delete(id);
    if (rec && rec.storagePath) {
      const u = currentUser();
      if (u && navigator.onLine) {
        SUPA.client.storage.from("vault-images").remove([rec.storagePath]).catch(() => {});
      }
      // If offline, the orphaned Storage object is harmless (private,
      // unreferenced, account-scoped) and can be swept up later; the
      // important thing — the metadata is already gone locally and in
      // the encrypted blob just pushed above — already happened.
    }
  }

  /* ---------- Vault image upload/download — bytes never leave the device
     unencrypted. The Storage object is [12-byte IV][AES-GCM ciphertext]
     under the SAME Vault master key that protects entries. ---------- */
  let vaultImageUploadInFlight = new Set();
  async function uploadVaultImage(id) {
    const u = currentUser();
    if (!u || !navigator.onLine || !isUnlocked() || vaultImageUploadInFlight.has(id)) return false;
    const rec = session.data.images.find(i => i.id === id);
    if (!rec || !rec.pendingDataUrl) return true; // already uploaded, or gone
    vaultImageUploadInFlight.add(id);
    try {
      const bytes = dataUrlToBytes(rec.pendingDataUrl);
      const encrypted = await encryptBytes(bytes, session.masterKey);
      const path = `${u.id}/${rec.id}`;
      const { error } = await SUPA.client.storage.from("vault-images")
        .upload(path, encrypted, { contentType: "application/octet-stream", upsert: true });
      if (error) return false;
      // Re-check the record still exists (it may have been deleted while
      // the upload was in flight) before writing the storage path back.
      if (isUnlocked()) {
        const stillThere = session.data.images.find(i => i.id === id);
        if (stillThere) {
          stillThere.storagePath = path;
          delete stillThere.pendingDataUrl;
          await persistVault();
        } else {
          // Deleted mid-upload — clean up the object we just wrote.
          SUPA.client.storage.from("vault-images").remove([path]).catch(() => {});
        }
      }
      return true;
    } catch (e) {
      return false;
    } finally {
      vaultImageUploadInFlight.delete(id);
    }
  }
  function retryPendingVaultImageUploads() {
    if (!isUnlocked() || !navigator.onLine) return;
    session.data.images.filter(i => i.pendingDataUrl).forEach(i => uploadVaultImage(i.id));
  }
  window.addEventListener("online", retryPendingVaultImageUploads);
  window.addEventListener("kragvor:session-ready", retryPendingVaultImageUploads);
  setInterval(retryPendingVaultImageUploads, 20000);

  // In-memory only — decrypted object URLs for the current unlocked
  // session, never written to disk. Cleared on lock/logout.
  const imageUrlCache = new Map(); // id -> objectURL
  function clearImageUrlCache() {
    imageUrlCache.forEach((url) => URL.revokeObjectURL(url));
    imageUrlCache.clear();
  }
  window.addEventListener("kragvor:logout", clearImageUrlCache);

  async function resolveImageUrl(rec) {
    if (rec.pendingDataUrl) return rec.pendingDataUrl; // not uploaded yet — show the local copy directly
    if (imageUrlCache.has(rec.id)) return imageUrlCache.get(rec.id);
    if (!rec.storagePath || !isUnlocked()) return null;
    try {
      const { data, error } = await SUPA.client.storage.from("vault-images").download(rec.storagePath);
      if (error || !data) return null;
      const buf = new Uint8Array(await data.arrayBuffer());
      const plain = await decryptBytes(buf, session.masterKey);
      const url = URL.createObjectURL(new Blob([plain], { type: rec.mimeType || "image/jpeg" }));
      imageUrlCache.set(rec.id, url);
      return url;
    } catch (e) {
      return null;
    }
  }
  async function toggleEntryFavorite(id) {
    const v = getVault();
    const rec = v.entries.find(e => e.id === id);
    if (rec) { rec.favorite = !rec.favorite; await persistVault(); }
  }
  async function toggleImageFavorite(id) {
    const v = getVault();
    const rec = v.images.find(i => i.id === id);
    if (rec) { rec.favorite = !rec.favorite; await persistVault(); }
  }
  async function setAutoLockMinutes(minutes) {
    const rec = getVaultRecord();
    rec.autoLockMinutes = minutes;
    saveVaultRecord(rec);
  }

  /* ---------------------------------------------------------------------
     PIN setup / verify / change
     ------------------------------------------------------------------- */
  async function setupPin(pin) {
    const u = currentUser();
    const rec = getVaultRecord();
    const saltHex = randomHex(16);
    const kek = await deriveKek(pin, saltHex, KDF_ITERATIONS);
    const masterKey = await generateMasterKey();
    rec.kdf = { saltHex, iterations: KDF_ITERATIONS };
    rec.wrappedKey = await wrapMasterKey(masterKey, kek);
    const content = emptyContent();
    rec.data = await encryptJSON(content, masterKey);
    rec.pinSet = true;
    rec.failedAttempts = 0;
    rec.lockoutUntil = 0;
    saveVaultRecord(rec);
    session = { accountId: u.id, masterKey, data: content };
    markActivity();
    logSecurityEvent("vault_pin_set", {
      accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
      status: "success", severity: SEVERITY.NORMAL, detail: "Vault PIN created."
    });
  }

  async function verifyPin(pin) {
    const u = currentUser();
    const rec = getVaultRecord();
    if (rec.lockoutUntil && rec.lockoutUntil > Date.now()) {
      return { ok: false, locked: true, retryAt: rec.lockoutUntil };
    }
    try {
      const kek = await deriveKek(pin, rec.kdf.saltHex, rec.kdf.iterations);
      const masterKey = await unwrapMasterKey(rec.wrappedKey, kek);
      const content = rec.data ? await decryptJSON(rec.data, masterKey) : emptyContent();

      rec.failedAttempts = 0;
      rec.lockoutUntil = 0;
      saveVaultRecord(rec);
      session = { accountId: u.id, masterKey, data: content };
      markActivity();
      upgradeLegacyImageShape();
      logSecurityEvent("vault_unlocked", {
        accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
        status: "success", severity: SEVERITY.NORMAL, detail: "Vault unlocked."
      });
      return { ok: true };
    } catch (e) {
      // AES-GCM authentication failure (or malformed record) == wrong PIN.
      rec.failedAttempts = (rec.failedAttempts || 0) + 1;
      let locked = false;
      if (rec.failedAttempts >= PIN_MAX_ATTEMPTS) {
        rec.lockoutUntil = Date.now() + PIN_LOCK_MS * Math.min(rec.failedAttempts - PIN_MAX_ATTEMPTS + 1, 6);
        locked = true;
      }
      saveVaultRecord(rec);
      logSecurityEvent("vault_pin_failed", {
        accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
        status: "failed", severity: rec.failedAttempts >= 3 ? SEVERITY.SUSPICIOUS : SEVERITY.NORMAL,
        detail: `Incorrect Vault PIN entered (${rec.failedAttempts} recent attempts).`
      });
      if (locked) {
        logSecurityEvent("vault_pin_lockout", {
          accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
          status: "locked", severity: SEVERITY.HIGH_RISK, detail: "Vault temporarily locked after repeated incorrect PIN attempts."
        });
      }
      return { ok: false, locked, retryAt: rec.lockoutUntil };
    }
  }

  // Re-wraps the SAME master key under a new PIN. Existing Vault content
  // does not need to be re-encrypted since the master key never changes.
  async function changePin(newPin) {
    const u = currentUser();
    if (!isUnlocked()) return;
    const rec = getVaultRecord();
    const saltHex = randomHex(16);
    const kek = await deriveKek(newPin, saltHex, KDF_ITERATIONS);
    rec.kdf = { saltHex, iterations: KDF_ITERATIONS };
    rec.wrappedKey = await wrapMasterKey(session.masterKey, kek);
    rec.failedAttempts = 0;
    rec.lockoutUntil = 0;
    saveVaultRecord(rec);
    logSecurityEvent("vault_pin_set", {
      accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
      status: "success", severity: SEVERITY.NORMAL, detail: "Vault PIN changed."
    });
  }

  /* ---------------------------------------------------------------------
     Recovery cooldown + in-progress state
     A completed game is recorded the moment it concludes (not just on
     final failure), so reloading mid-sequence can't be used to erase a
     loss and dodge the cooldown. An in-progress game that hasn't finished
     yet is allowed to reset on reload — only concluded games count.
     ------------------------------------------------------------------- */
  function getRecoveryState() {
    const u = currentUser();
    if (!u) return { cooldownUntil: 0, gamesWon: 0, inProgress: false };
    const all = readJSON(localStorage, LS_VAULT_RECOVERY, {});
    return all[u.id] || { cooldownUntil: 0, gamesWon: 0, inProgress: false };
  }
  function saveRecoveryState(state) {
    const u = currentUser();
    if (!u) return;
    const all = readJSON(localStorage, LS_VAULT_RECOVERY, {});
    all[u.id] = state;
    writeJSON(localStorage, LS_VAULT_RECOVERY, all);
  }

  /* ---------------------------------------------------------------------
     VIEW STATE / ROUTER
     ------------------------------------------------------------------- */
  let vaultState = { tab: "items", album: "all", query: "", showSecrets: {} };

  function isLegacyRecord(rec) {
    return !!(rec.pinSet && rec.pinHash && rec.salt && !rec.kdf);
  }

  let vaultCloudCheckedForAccount = null;

  function renderVaultApp(root, user, route) {
    const sub = route.split("/").slice(3).join("/"); // segment(s) after /apps/vault/
    if (sub === "recovery") return renderRecoveryIntro(root);
    if (sub.startsWith("image/")) return renderImageViewer(root, sub.split("/")[1]);

    const rec = getVaultRecord();
    // A device that has never synced this account's Vault locally has no
    // way to know whether one already exists in the cloud. Check once per
    // account per session before ever offering "set up a new PIN" — a
    // brand-new phone logging into an existing account must be offered
    // the unlock screen for the Vault that already exists, not a fresh setup.
    if (!rec.pinSet && vaultCloudCheckedForAccount !== user.id) {
      root.innerHTML = `
        <div class="vault-gate">
          <div class="glyph" style="width:32px;height:32px;color:var(--accent);">${ICONS.vault}</div>
          <p>Checking for an existing Vault\u2026</p>
        </div>
      `;
      pullVaultFromCloud().then((ok) => {
        if (ok) vaultCloudCheckedForAccount = user.id;
        renderVaultApp(root, user, route);
      });
      return;
    }

    // Vaults created before the encryption-at-rest upgrade store their PIN
    // as a hash and their content in plaintext. Rather than discard that
    // existing data, ask for the current PIN once and transparently
    // re-encrypt everything into the new format.
    if (isLegacyRecord(rec)) return renderLegacyMigration(root);
    if (!rec.pinSet) return renderPinSetup(root);
    if (!isUnlocked()) return renderUnlockScreen(root);
    vaultState = { tab: "items", album: "all", query: "", showSecrets: {} };
    paintVaultHome(root);
  }

  async function migrateLegacyVault(pin) {
    const u = currentUser();
    const rec = getVaultRecord();
    const legacyHash = await hashSecret(pin, rec.salt);
    if (legacyHash !== rec.pinHash) return { ok: false };

    const content = {
      entries: Array.isArray(rec.entries) ? rec.entries : [],
      images: Array.isArray(rec.images) ? rec.images : [],
      albums: Array.isArray(rec.albums) && rec.albums.length ? rec.albums : ["General"]
    };
    const saltHex = randomHex(16);
    const kek = await deriveKek(pin, saltHex, KDF_ITERATIONS);
    const masterKey = await generateMasterKey();
    const newRec = {
      version: 2, pinSet: true,
      kdf: { saltHex, iterations: KDF_ITERATIONS },
      wrappedKey: await wrapMasterKey(masterKey, kek),
      data: await encryptJSON(content, masterKey),
      failedAttempts: 0, lockoutUntil: 0,
      autoLockMinutes: DEFAULT_AUTO_LOCK_MINUTES
    };
    saveVaultRecord(newRec);
    session = { accountId: u.id, masterKey, data: content };
    markActivity();
    upgradeLegacyImageShape();
    logSecurityEvent("vault_pin_set", {
      accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
      status: "success", severity: SEVERITY.NORMAL, detail: "Vault upgraded to encrypted storage; existing data preserved."
    });
    return { ok: true };
  }

  function renderLegacyMigration(root) {
    root.innerHTML = `
      <div class="vault-gate">
        <div class="glyph" style="width:32px;height:32px;color:var(--accent);">${ICONS.shield}</div>
        <h2>Upgrading Vault Security</h2>
        <p>KRAGVOR now encrypts Vault contents at rest. Enter your current Vault PIN once to upgrade &mdash; your existing items and images are preserved.</p>
        ${pinFieldHtml("pin-migrate", "Current Vault PIN", { toggle: true })}
        <div class="error-msg" id="pin-migrate-error" hidden></div>
        <button class="btn btn-primary btn-block" id="pin-migrate-btn" style="margin-top:8px;">Upgrade Vault</button>
      </div>
    `;
    bindPinField("pin-migrate"); bindPinToggle("pin-migrate");
    $("#pin-migrate-btn").addEventListener("click", async () => {
      const pin = $("#pin-migrate").value.trim();
      if (!pin) return;
      const res = await migrateLegacyVault(pin);
      if (res.ok) {
        toast("Vault upgraded", "success");
        paintVaultHome(root);
      } else {
        $("#pin-migrate-error").hidden = false;
        $("#pin-migrate-error").textContent = "Incorrect PIN.";
      }
    });
  }

  /* ---------- PIN setup ---------- */
  function renderPinSetup(root) {
    root.innerHTML = `
      <div class="vault-gate">
        <div class="glyph" style="width:36px;height:36px;color:var(--accent);">${ICONS.vault}</div>
        <h2>Set up your Vault PIN</h2>
        <p>Choose a PIN to protect your private notes, passwords, and images. Vault contents are encrypted using a key derived from this PIN, so it's separate from your KRAGVOR login and can't be recovered without it.</p>
        ${pinFieldHtml("pin-new", "New PIN", { toggle: true })}
        ${pinFieldHtml("pin-confirm", "Confirm PIN")}
        <div class="error-msg" id="pin-setup-error" hidden></div>
        <button class="btn btn-primary btn-block" id="pin-setup-save" style="margin-top:8px;">Create PIN</button>
      </div>
    `;
    bindPinField("pin-new"); bindPinField("pin-confirm"); bindPinToggle("pin-new");
    $("#pin-setup-save").addEventListener("click", async () => {
      const a = $("#pin-new").value.trim(), b = $("#pin-confirm").value.trim();
      const err = $("#pin-setup-error");
      if (!/^\d{4,8}$/.test(a)) { err.hidden = false; err.textContent = "PIN must be 4\u20138 digits."; return; }
      if (a !== b) { err.hidden = false; err.textContent = "PINs don't match."; return; }
      err.hidden = true;
      const btn = $("#pin-setup-save");
      btn.disabled = true;
      await setupPin(a);
      toast("Vault PIN created", "success");
      paintVaultHome(root);
    });
  }

  /* ---------- Unlock ---------- */
  function renderUnlockScreen(root) {
    const rec = getVaultRecord();
    const locked = rec.lockoutUntil && rec.lockoutUntil > Date.now();
    const recov = getRecoveryState();
    const cooldown = recov.cooldownUntil && recov.cooldownUntil > Date.now();

    root.innerHTML = `
      <div class="vault-gate">
        <div class="glyph" style="width:32px;height:32px;color:var(--accent);">${ICONS.lock}</div>
        <h2>Vault Locked</h2>
        <p>Enter your Vault PIN to continue.</p>
        ${pinFieldHtml("pin-unlock", "Vault PIN", { toggle: true, disabled: locked })}
        <div class="error-msg" id="pin-unlock-error" hidden></div>
        <button class="btn btn-primary btn-block" id="pin-unlock-btn" style="margin-top:8px;" ${locked ? "disabled" : ""}>Unlock</button>
        <button class="btn-text" id="pin-forgot" style="margin-top:12px;">Forgot PIN?</button>
        ${cooldown ? `<div class="hint" style="margin-top:8px;">Recovery is on a 24-hour cooldown after a failed attempt.</div>` : ""}
      </div>
    `;
    bindPinField("pin-unlock"); bindPinToggle("pin-unlock");
    if (locked) {
      $("#pin-unlock-error").hidden = false;
      const mins = Math.max(1, Math.ceil((rec.lockoutUntil - Date.now()) / 60000));
      $("#pin-unlock-error").textContent = `Too many incorrect attempts. Try again in ${mins} minute${mins === 1 ? "" : "s"}.`;
    }
    $("#pin-forgot").addEventListener("click", () => navigate("/apps/vault/recovery"));
    if (!locked) {
      let busy = false;
      const submit = async () => {
        if (busy) return;
        const pin = $("#pin-unlock").value.trim();
        if (!pin) return;
        busy = true;
        const res = await verifyPin(pin);
        busy = false;
        if (res.ok) { paintVaultHome(root); return; }
        renderUnlockScreen(root);
      };
      $("#pin-unlock-btn").addEventListener("click", submit);
      $("#pin-unlock").addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
    }
  }

  /* ---------- Vault home ---------- */
  function filteredEntriesAndImages() {
    const v = getVault();
    let entries = v.entries;
    let images = v.images;
    if (vaultState.album !== "all") {
      entries = entries.filter(e => e.category === vaultState.album);
      images = images.filter(i => i.album === vaultState.album);
    }
    if (vaultState.query.trim()) {
      const q = vaultState.query.trim().toLowerCase();
      entries = entries.filter(e =>
        e.title.toLowerCase().includes(q) ||
        (e.username || "").toLowerCase().includes(q) ||
        (e.notes || "").toLowerCase().includes(q) ||
        (e.customFields || []).some(f => (f.key || "").toLowerCase().includes(q) || (f.value || "").toLowerCase().includes(q))
      );
    }
    if (vaultState.tab === "favorites") {
      entries = entries.filter(e => e.favorite);
      images = images.filter(i => i.favorite);
    }
    return { entries, images, albums: v.albums };
  }

  function paintVaultHome(root) {
    const { albums } = filteredEntriesAndImages();
    root.innerHTML = `
      <div class="notes-toolbar">
        <div class="input-wrap" style="flex:1;">
          <input id="vault-search" type="text" placeholder="Search vault items" value="${escapeHtml(vaultState.query)}" autocomplete="off" />
        </div>
        <button class="icon-btn" id="vault-lock-btn" aria-label="Lock vault">${ICONS.lock}</button>
      </div>

      <div class="calc-mode-toggle" style="margin-top:12px;">
        <button class="seg ${vaultState.tab === "items" ? "on" : ""}" data-vtab="items">Items</button>
        <button class="seg ${vaultState.tab === "images" ? "on" : ""}" data-vtab="images">Images</button>
        <button class="seg ${vaultState.tab === "favorites" ? "on" : ""}" data-vtab="favorites">Favorites</button>
      </div>

      <div class="chip-row" id="vault-chip-row">
        <button class="chip ${vaultState.album === "all" ? "on" : ""}" data-valbum="all">All</button>
        ${(getVault().albums).map(a => `<button class="chip ${vaultState.album === a ? "on" : ""}" data-valbum="${escapeHtml(a)}">${escapeHtml(a)}</button>`).join("")}
      </div>

      <div id="vault-body" style="margin-top:12px;"></div>

      <div class="vault-fab-row" id="vault-fab-row"></div>

      <div class="section-label" style="margin-top:22px;">Vault security</div>
      <div class="detail-card">
        <div class="field" style="margin-bottom:12px;">
          <label style="font-size:12px;color:var(--text-faint);margin-bottom:6px;display:block;">Auto-lock after inactivity</label>
          <select id="vault-autolock-select" class="mini-select" style="width:100%;">
            ${AUTO_LOCK_OPTIONS.map(o => `<option value="${o.value}" ${getVaultRecord().autoLockMinutes === o.value ? "selected" : ""}>${o.label}</option>`).join("")}
          </select>
        </div>
        <button class="btn btn-ghost btn-sm" id="vault-change-pin" style="width:100%;">Change Vault PIN</button>
      </div>
    `;
    renderVaultBody(root);
    bindVaultHome(root);
  }

  function renderVaultBody(root) {
    const { entries, images } = filteredEntriesAndImages();
    $("#vault-body", root).innerHTML = vaultState.tab === "images" ? imagesGridHtml(images) : entriesListHtml(entries);
    $("#vault-fab-row", root).innerHTML = vaultState.tab === "images" ? `
      <label class="btn btn-primary btn-sm btn-block" id="vault-add-image">${ICONS.plus} Add Image<input type="file" accept="image/*" id="vault-image-input" style="display:none;" /></label>
    ` : `<button class="btn btn-primary btn-sm btn-block" id="vault-add-item">${ICONS.plus} Add Item</button>`;
    bindVaultBody(root);
    if (vaultState.tab === "images") loadVaultThumbnails(root, images);
  }

  // Thumbnails paint blank/placeholder first (no plaintext ever touches the
  // template string), then each is decrypted and filled in individually —
  // a slow or failed download for one image never blocks the rest.
  function loadVaultThumbnails(root, images) {
    images.forEach((rec) => {
      resolveImageUrl(rec).then((url) => {
        const el = $(`[data-thumb-img="${rec.id}"]`, root);
        if (el && url) el.src = url;
      });
    });
  }

  function entriesListHtml(entries) {
    if (!entries.length) return `<div class="empty-state"><div class="glyph">${ICONS.vault}</div><p>No items yet.</p></div>`;
    return `<div style="display:flex;flex-direction:column;gap:8px;">${entries.map(entryRow).join("")}</div>`;
  }
  const KIND_LABEL = { password: "Password", secure_note: "Secure Note", code: "Code", custom: "Custom" };
  function entryRow(e) {
    const revealed = !!vaultState.showSecrets[e.id];
    return `
      <div class="list-row vault-row">
        <div class="grow" data-open-entry="${e.id}" style="cursor:pointer;">
          <div class="title">${escapeHtml(e.title)} ${e.favorite ? `<span style="color:var(--accent);">${ICONS.star}</span>` : ""}</div>
          <div class="sub">${KIND_LABEL[e.kind] || "Item"} &middot; ${escapeHtml(e.category)}${e.username ? " &middot; " + escapeHtml(e.username) : ""}</div>
          ${e.secret ? `<div class="secret-line">${revealed ? escapeHtml(e.secret) : "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"}</div>` : ""}
        </div>
        <div class="row-actions">
          ${e.secret ? `<button class="icon-btn" data-reveal="${e.id}" aria-label="Show">${revealed ? ICONS.eyeOff : ICONS.eye}</button>` : ""}
        </div>
      </div>
    `;
  }
  function imagesGridHtml(images) {
    if (!images.length) return `<div class="empty-state"><div class="glyph">${ICONS.image}</div><p>No images yet.</p></div>`;
    return `<div class="vault-image-grid">${images.map(i => `
      <div class="vault-thumb" data-open-image="${i.id}">
        <img data-thumb-img="${i.id}" alt="" />
        ${i.favorite ? `<span class="thumb-fav">${ICONS.star}</span>` : ""}
        ${i.pendingDataUrl && !i.storagePath ? `<span class="thumb-pending" title="Waiting to sync">${ICONS.sync || "\u21bb"}</span>` : ""}
      </div>
    `).join("")}</div>`;
  }

  // Search / tab / album changes only repaint #vault-body and the FAB row —
  // the search input itself is never destroyed, so focus and cursor
  // position survive every keystroke.
  function bindVaultBody(root) {
    $$("[data-reveal]", root).forEach(btn => btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const id = btn.getAttribute("data-reveal");
      vaultState.showSecrets[id] = !vaultState.showSecrets[id];
      renderVaultBody(root);
    }));
    $$("[data-open-entry]", root).forEach(el => el.addEventListener("click", () => openEntryModal(root, el.getAttribute("data-open-entry"))));
    $$("[data-open-image]", root).forEach(el => el.addEventListener("click", () => navigate(`/apps/vault/image/${el.getAttribute("data-open-image")}`)));

    const addItemBtn = $("#vault-add-item", root);
    if (addItemBtn) addItemBtn.addEventListener("click", () => openEntryModal(root, null));
    const imgInput = $("#vault-image-input", root);
    if (imgInput) imgInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (!file.type.startsWith("image/")) { toast("Please choose an image file.", "error"); return; }
      const reader = new FileReader();
      reader.onload = async () => {
        await addImage(reader.result, vaultState.album !== "all" ? vaultState.album : "General", file.type);
        toast("Image added", "success");
        paintVaultHome(root);
      };
      reader.readAsDataURL(file);
    });
  }

  function bindVaultHome(root) {
    let searchDebounce = null;
    $("#vault-search", root).addEventListener("input", (e) => {
      vaultState.query = e.target.value;
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => renderVaultBody(root), 80);
    });
    $("#vault-lock-btn", root).addEventListener("click", () => { clearSensitiveSession("Manually locked by user."); renderVaultApp(root, currentUser(), currentRoute()); });
    $$("[data-vtab]", root).forEach(btn => btn.addEventListener("click", () => {
      vaultState.tab = btn.getAttribute("data-vtab");
      $$("[data-vtab]", root).forEach(b => b.classList.toggle("on", b === btn));
      renderVaultBody(root);
    }));
    $$("[data-valbum]", root).forEach(btn => btn.addEventListener("click", () => {
      vaultState.album = btn.getAttribute("data-valbum");
      $$("[data-valbum]", root).forEach(b => b.classList.toggle("on", b === btn));
      renderVaultBody(root);
    }));
    $("#vault-change-pin", root).addEventListener("click", () => openChangePinModal(root));
    $("#vault-autolock-select", root).addEventListener("change", (e) => {
      setAutoLockMinutes(parseFloat(e.target.value));
      toast("Auto-lock updated", "success");
    });
  }

  function openChangePinModal(root) {
    openModal({
      title: "Change Vault PIN",
      bodyHtml: `
        <div class="form-grid">
          <div class="field" id="cpin-current" style="margin-bottom:0;"><label>Current PIN</label><div class="input-wrap"><input type="tel" inputmode="numeric" pattern="[0-9]*" autocomplete="off" class="pin-input masked" id="cpin-current-input" maxlength="8" /></div><div class="error-msg" hidden></div></div>
          <div class="field" id="cpin-new" style="margin-bottom:0;"><label>New PIN</label><div class="input-wrap"><input type="tel" inputmode="numeric" pattern="[0-9]*" autocomplete="off" class="pin-input masked" id="cpin-new-input" maxlength="8" /></div><div class="error-msg" hidden></div></div>
        </div>
      `,
      footHtml: `<button class="btn btn-ghost" id="cpin-cancel">Cancel</button><button class="btn btn-primary" id="cpin-save">Save</button>`
    });
    bindPinField("cpin-current-input"); bindPinField("cpin-new-input");
    $("#cpin-cancel").addEventListener("click", closeModal);
    $("#cpin-save").addEventListener("click", async () => {
      const current = $("#cpin-current-input").value.trim();
      const next = $("#cpin-new-input").value.trim();
      const res = await verifyPin(current);
      if (!res.ok) { R.setFieldError("cpin-current", "Current PIN is incorrect."); return; }
      if (!/^\d{4,8}$/.test(next)) { R.setFieldError("cpin-new", "PIN must be 4\u20138 digits."); return; }
      await changePin(next);
      closeModal();
      toast("Vault PIN updated", "success");
    });
  }

  /* ---------- Entry create/edit modal ---------- */
  function openEntryModal(root, id) {
    const v = getVault();
    const entry = id ? v.entries.find(e => e.id === id) : null;
    let customFields = entry ? [...entry.customFields] : [];
    let kind = entry ? entry.kind : "password";

    function bodyHtml() {
      return `
        <div class="form-grid">
          <div class="field" style="margin-bottom:0;"><label>Type</label>
            <select id="ve-kind" class="mini-select" style="width:100%;">
              ${Object.entries(KIND_LABEL).map(([k, l]) => `<option value="${k}" ${kind === k ? "selected" : ""}>${l}</option>`).join("")}
            </select>
          </div>
          <div class="field" style="margin-bottom:0;"><label>Title</label><div class="input-wrap"><input id="ve-title" type="text" value="${escapeHtml(entry ? entry.title : "")}" /></div></div>
          <div class="field" style="margin-bottom:0;"><label>Username / label (optional)</label><div class="input-wrap"><input id="ve-username" type="text" value="${escapeHtml(entry ? entry.username : "")}" /></div></div>
          <div class="field" style="margin-bottom:0;"><label>Secret value</label><div class="input-wrap"><input id="ve-secret" type="text" value="${escapeHtml(entry ? entry.secret : "")}" /></div></div>
          <div class="field" style="margin-bottom:0;"><label>Category / Album</label><div class="input-wrap"><input id="ve-category" type="text" value="${escapeHtml(entry ? entry.category : "General")}" /></div></div>
          <div class="field" style="margin-bottom:0;"><label>Notes</label><div class="input-wrap"><textarea id="ve-notes" rows="3" style="width:100%;background:var(--surface);border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);padding:10px;">${escapeHtml(entry ? entry.notes : "")}</textarea></div></div>
          <div id="ve-custom-fields">${customFields.map((f, idx) => customFieldRow(f, idx)).join("")}</div>
          <button type="button" class="btn-text" id="ve-add-field">+ Add custom field</button>
        </div>
      `;
    }
    function customFieldRow(f, idx) {
      return `
        <div class="custom-field-row" data-idx="${idx}">
          <input type="text" class="cf-key" placeholder="Field name" value="${escapeHtml(f.key || "")}" />
          <input type="text" class="cf-val" placeholder="Value" value="${escapeHtml(f.value || "")}" />
          <button type="button" class="icon-btn danger cf-remove" aria-label="Remove">${ICONS.close}</button>
        </div>
      `;
    }

    openModal({
      eyebrow: entry ? "Edit item" : "New vault item",
      title: entry ? entry.title || "Untitled" : "Add a vault item",
      bodyHtml: bodyHtml(),
      footHtml: `
        ${entry ? `<button class="btn btn-danger" id="ve-delete">Delete</button>` : ""}
        <button class="btn btn-ghost" id="ve-cancel">Cancel</button>
        <button class="btn btn-primary" id="ve-save">${entry ? "Save" : "Create"}</button>
      `
    });

    function bindFieldRows() {
      $$(".cf-remove", document).forEach((btn, idx) => {
        btn.onclick = () => { customFields.splice(idx, 1); refreshFields(); };
      });
    }
    function refreshFields() {
      $("#ve-custom-fields").innerHTML = customFields.map((f, idx) => customFieldRow(f, idx)).join("");
      bindFieldRows();
    }
    bindFieldRows();
    $("#ve-kind").addEventListener("change", (e) => { kind = e.target.value; });
    $("#ve-add-field").addEventListener("click", () => { customFields.push({ key: "", value: "" }); refreshFields(); });
    $("#ve-cancel").addEventListener("click", closeModal);

    const delBtn = $("#ve-delete");
    if (delBtn) delBtn.addEventListener("click", () => {
      closeModal();
      openConfirmModal({
        title: "Delete this item?",
        message: "This vault item will be permanently deleted.",
        confirmLabel: "Delete",
        danger: true,
        onConfirm: async () => { await deleteEntry(entry.id); toast("Item deleted", "success"); paintVaultHome(root); }
      });
    });

    $("#ve-save").addEventListener("click", async () => {
      // Re-read custom field inputs from DOM into the array before saving.
      $$(".custom-field-row", document).forEach((rowEl, idx) => {
        customFields[idx] = {
          key: rowEl.querySelector(".cf-key").value.trim(),
          value: rowEl.querySelector(".cf-val").value.trim()
        };
      });
      const payload = {
        kind, title: $("#ve-title").value.trim() || "Untitled",
        username: $("#ve-username").value.trim(),
        secret: $("#ve-secret").value.trim(),
        category: $("#ve-category").value.trim() || "General",
        notes: $("#ve-notes").value.trim(),
        customFields: customFields.filter(f => f.key || f.value)
      };
      if (entry) await updateEntry(entry.id, payload); else await addEntry(payload);
      closeModal();
      toast(entry ? "Item updated" : "Item added", "success");
      paintVaultHome(root);
    });
  }

  /* ---------- Image viewer ---------- */
  function renderImageViewer(root, id) {
    if (!isUnlocked()) { navigate("/apps/vault"); return; }
    const img = getVault().images.find(i => i.id === id);
    if (!img) { navigate("/apps/vault"); return; }
    root.innerHTML = `
      <button class="back-link" id="img-back">${ICONS.chevron} Vault</button>
      <div class="vault-fullscreen">
        <img data-fullscreen-img alt="" style="display:none;" />
        <div class="empty-state" id="img-loading"><div class="glyph">${ICONS.image}</div><p>Decrypting\u2026</p></div>
      </div>
      <div class="vault-fab-row">
        <button class="btn btn-ghost btn-sm" id="img-fav">${img.favorite ? "Unfavorite" : "Favorite"}</button>
        <button class="btn btn-danger btn-sm" id="img-delete">Delete</button>
      </div>
    `;
    resolveImageUrl(img).then((url) => {
      const imgEl = $("[data-fullscreen-img]", root);
      const loadingEl = $("#img-loading", root);
      if (!imgEl) return; // navigated away while decrypting
      if (url) {
        imgEl.src = url;
        imgEl.style.display = "";
        if (loadingEl) loadingEl.remove();
      } else if (loadingEl) {
        loadingEl.querySelector("p").textContent = "Couldn't load this image. Check your connection and try again.";
      }
    });
    $("#img-back").addEventListener("click", () => navigate("/apps/vault"));
    $("#img-fav").addEventListener("click", async () => { await toggleImageFavorite(id); navigate("/apps/vault"); });
    $("#img-delete").addEventListener("click", () => {
      openConfirmModal({
        title: "Delete image?",
        message: "This private image will be permanently deleted.",
        confirmLabel: "Delete",
        danger: true,
        onConfirm: async () => { await deleteImage(id); toast("Image deleted", "success"); navigate("/apps/vault"); }
      });
    });
  }

  /* ---------------------------------------------------------------------
     PIN RECOVERY — 3 consecutive Tic-Tac-Toe wins/draws vs. a strong but
     realistically beatable AI.

     IMPORTANT, and stated plainly to the user before they start: because
     Vault contents are genuinely encrypted with a key derived from the
     PIN, a forgotten PIN cannot be used to decrypt the existing data —
     there is no secret backdoor. Winning recovery resets the Vault PIN
     and starts a fresh, empty Vault. It does not and cannot restore the
     old encrypted contents. This is stated up front rather than silently
     wiping data or pretending recovery "unlocks" the old items.
     ------------------------------------------------------------------- */
  function renderRecoveryIntro(root) {
    const recov = getRecoveryState();
    const cooldownActive = recov.cooldownUntil && recov.cooldownUntil > Date.now();

    if (cooldownActive) {
      const hrs = Math.max(1, Math.ceil((recov.cooldownUntil - Date.now()) / 3600000));
      root.innerHTML = `
        <button class="back-link" id="rec-back">${ICONS.chevron} Vault</button>
        <div class="vault-gate">
          <div class="glyph" style="width:34px;height:34px;color:var(--danger);">${ICONS.lock}</div>
          <h2>Recovery unavailable</h2>
          <p>A previous recovery attempt failed. Recovery is locked for approximately ${hrs} more hour${hrs === 1 ? "" : "s"}. This cooldown cannot be bypassed, reset, or restarted.</p>
        </div>
      `;
      $("#rec-back").addEventListener("click", () => navigate("/apps/vault"));
      return;
    }

    root.innerHTML = `
      <button class="back-link" id="rec-back">${ICONS.chevron} Vault</button>
      <div class="vault-gate">
        <div class="glyph" style="width:34px;height:34px;color:var(--accent);">${ICONS.shield}</div>
        <h2>Vault PIN Recovery</h2>
        <p>To reset your Vault PIN, win or draw <strong style="color:var(--text)">3 consecutive games</strong> of Tic-Tac-Toe against a very difficult strategic opponent. You go first, as X.</p>
        <div class="notice-line" style="text-align:left;">${ICONS.alert}<span>Losing even one game fails recovery immediately and starts a 24-hour cooldown that cannot be skipped or restarted.</span></div>
        <div class="notice-line" style="text-align:left;">${ICONS.lock}<span><strong style="color:var(--text)">Your existing Vault items and images cannot be recovered.</strong> They're encrypted with your current PIN, so completing this resets the Vault with a brand-new PIN and empty contents.</span></div>
        <button class="btn btn-primary btn-block" id="rec-start" style="margin-top:14px;">Begin Recovery</button>
      </div>
    `;
    $("#rec-back").addEventListener("click", () => navigate("/apps/vault"));
    $("#rec-start").addEventListener("click", () => {
      saveRecoveryState({ cooldownUntil: 0, gamesWon: 0, inProgress: true });
      startRecoveryFlow(root);
    });
  }

  function startRecoveryFlow(root) {
    const recov = getRecoveryState();
    playRound(root, (recov.gamesWon || 0) + 1);
  }

  function playRound(root, round) {
    const board = Array(9).fill(null);
    let over = false;

    function paint(statusMsg) {
      root.innerHTML = `
        <div class="vault-gate">
          <div class="ttt-progress">
            ${[1, 2, 3].map(n => `<span class="ttt-dot ${n < round ? "done" : n === round ? "current" : ""}"></span>`).join("")}
          </div>
          <h2>Recovery Challenge</h2>
          <p class="ttt-status">Game ${round} of 3 &middot; ${statusMsg || "Your move (X)"}</p>
          <div class="ttt-board">
            ${board.map((cell, idx) => `
              <button class="ttt-cell" data-cell="${idx}" ${cell || over ? "disabled" : ""}>
                ${cell === "X" ? ICONS.x : cell === "O" ? ICONS.o : ""}
              </button>
            `).join("")}
          </div>
        </div>
      `;
      $$("[data-cell]", root).forEach(btn => btn.addEventListener("click", () => onCellClick(Number(btn.getAttribute("data-cell")))));
    }

    function onCellClick(idx) {
      if (over || board[idx]) return;
      board[idx] = "X";
      let winner = TTT().getWinner(board);
      if (winner) return finishRound(winner);
      paint("Opponent is thinking\u2026");
      setTimeout(() => {
        const aiMove = TTT().bestAiMove(board);
        if (aiMove !== -1) board[aiMove] = "O";
        winner = TTT().getWinner(board);
        if (winner) return finishRound(winner);
        paint("Your move (X).");
      }, 380);
    }

    function finishRound(winner) {
      over = true;
      if (winner === "X" || winner === "draw") {
        // Record this completed game immediately — reloading the app now
        // cannot erase the progress or force a restart from Game 1.
        const recov = getRecoveryState();
        const gamesWon = round;
        saveRecoveryState({ cooldownUntil: 0, gamesWon, inProgress: gamesWon < 3 });
        paint(winner === "X" ? "You won this game." : "This game ended in a draw.");
        setTimeout(() => {
          if (gamesWon >= 3) recoverySuccess(root);
          else playRound(root, gamesWon + 1);
        }, 900);
      } else {
        paint("You lost this game.");
        setTimeout(() => recoveryFailure(root), 900);
      }
    }

    paint();
  }

  function recoveryFailure(root) {
    saveRecoveryState({ cooldownUntil: Date.now() + RECOVERY_COOLDOWN_MS, gamesWon: 0, inProgress: false });
    const u = currentUser();
    logSecurityEvent("vault_recovery_failed", {
      accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
      status: "failed", severity: SEVERITY.HIGH_RISK, detail: "Vault PIN recovery failed. 24-hour cooldown started."
    });
    root.innerHTML = `
      <div class="vault-gate">
        <div class="glyph" style="width:34px;height:34px;color:var(--danger);">${ICONS.close}</div>
        <h2>Recovery failed</h2>
        <p>You lost a game before completing all 3. A 24-hour cooldown has started and cannot be bypassed.</p>
        <button class="btn btn-primary btn-block" id="rec-fail-ok" style="margin-top:12px;">Back to Vault</button>
      </div>
    `;
    $("#rec-fail-ok").addEventListener("click", () => navigate("/apps/vault"));
  }

  async function recoverySuccess(root) {
    const u = currentUser();
    saveRecoveryState({ cooldownUntil: 0, gamesWon: 0, inProgress: false });
    logSecurityEvent("vault_recovery_completed", {
      accountId: u.id, accountName: `${u.firstName} ${u.lastName}`,
      status: "success", severity: SEVERITY.NORMAL, detail: "Vault PIN recovery completed. Vault reset with a new PIN."
    });
    root.innerHTML = `
      <div class="vault-gate">
        <div class="glyph" style="width:36px;height:36px;color:var(--success);">${ICONS.check}</div>
        <h2>Recovery successful</h2>
        <p>Create a new Vault PIN below. This starts your Vault fresh — previous items and images are not recoverable.</p>
        ${pinFieldHtml("rec-new-pin", "New PIN")}
        ${pinFieldHtml("rec-confirm-pin", "Confirm PIN")}
        <div class="error-msg" id="rec-pin-error" hidden></div>
        <button class="btn btn-primary btn-block" id="rec-pin-save" style="margin-top:8px;">Set New PIN</button>
      </div>
    `;
    bindPinField("rec-new-pin"); bindPinField("rec-confirm-pin");
    $("#rec-pin-save").addEventListener("click", async () => {
      const a = $("#rec-new-pin").value.trim(), b = $("#rec-confirm-pin").value.trim();
      const err = $("#rec-pin-error");
      if (!/^\d{4,8}$/.test(a)) { err.hidden = false; err.textContent = "PIN must be 4\u20138 digits."; return; }
      if (a !== b) { err.hidden = false; err.textContent = "PINs don't match."; return; }
      // A genuinely fresh Vault: new master key, new empty content, new PIN.
      // The old encrypted record (unreadable without the old PIN) is
      // replaced outright rather than left around as dead data.
      const all = getAllVaultRecords();
      delete all[u.id];
      saveAllVaultRecords(all);
      await setupPin(a);
      toast("Vault PIN reset", "success");
      navigate("/apps/vault");
    });
  }

  function getVaultMeta() {
    const rec = getVaultRecord();
    return { pinSet: rec.pinSet, autoLockMinutes: rec.autoLockMinutes };
  }

  APPS_REGISTRY.push({
    id: "vault", name: "Vault", desc: "Encrypted passwords, notes & images",
    icon: "vault", render: (root, user, route) => renderVaultApp(root, user, route)
  });

  window.__KRAGVOR_VAULT__ = { getVault, getVaultMeta, isUnlocked, lockVault, isDirty: isVaultDirty };
})();

/* ==========================================================================
   PART 10 — SECURITY CENTER
   Real, account-scoped security status, event log, and alerts. An
   additional Owner Dashboard tab is visible only to the owner account.
   ========================================================================== */
(() => {
  "use strict";
  const C = window.__KRAGVOR_CORE__;
  const R = window.__KRAGVOR_ROUTER__;
  const SUPA = window.__KRAGVOR_SUPABASE__;
  const {
    $, $$, escapeHtml, currentUser, isOwner,
    ICONS, toast, SEVERITY
  } = C;
  const { navigate } = R;
  const VAULT = () => window.__KRAGVOR_VAULT__;

  const RECENT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
  const ALERT_WINDOW_MS = 48 * 60 * 60 * 1000;

  const EVENT_LABELS = {
    login_success: "Successful login", login_failed: "Failed login attempt",
    account_lockout: "Account temporarily locked", logout: "Signed out",
    vault_locked: "Vault locked", vault_unlocked: "Vault unlocked",
    vault_pin_set: "Vault PIN created/changed", vault_pin_changed: "Vault PIN created/changed",
    vault_pin_failed: "Incorrect Vault PIN",
    vault_pin_lockout: "Vault temporarily locked", vault_recovery_failed: "Vault recovery failed",
    vault_recovery_completed: "Vault recovery completed", vault_image_added: "Private image added",
    password_changed: "Password changed", account_created: "Account created",
    account_updated: "Account details updated", account_enabled: "Account enabled",
    account_disabled: "Account disabled", account_removed: "Account removed",
    family_account_created: "Family/Friend account created", family_account_updated: "Family/Friend account updated",
    family_account_enabled: "Family/Friend account enabled", family_account_disabled: "Family/Friend account disabled",
    family_account_removed: "Family/Friend account removed", owner_bootstrap: "Owner account created",
    security_setting_changed: "Security setting changed", vault_sync_conflict: "Vault sync conflict resolved",
    note_created: "Note created", note_deleted: "Note moved to trash",
    legacy_data_migrated: "Pre-existing local data migrated to cloud"
  };

  function statusFor(events, vaultMeta, recoveryState) {
    const recent = events.filter(e => Date.now() - e.at < RECENT_WINDOW_MS);
    if (recent.some(e => e.severity === SEVERITY.CRITICAL)) return "HIGH RISK";
    if (recent.some(e => e.severity === SEVERITY.HIGH_RISK)) return "ATTENTION NEEDED";
    if (recent.some(e => e.severity === SEVERITY.SUSPICIOUS)) return "SUSPICIOUS ACTIVITY";
    // An absence of bad events isn't enough on its own — actual protective
    // configuration matters too. An unconfigured Vault or an active
    // recovery cooldown both warrant attention even with a clean log.
    if (vaultMeta && !vaultMeta.pinSet) return "ATTENTION NEEDED";
    if (recoveryState && recoveryState.cooldownUntil && recoveryState.cooldownUntil > Date.now()) return "ATTENTION NEEDED";
    return "SECURE";
  }
  function statusClass(status) {
    if (status === "SECURE") return "status-secure";
    if (status === "ATTENTION NEEDED") return "status-attention";
    if (status === "SUSPICIOUS ACTIVITY") return "status-suspicious";
    return "status-highrisk";
  }
  function sevClass(sev) {
    if (sev === SEVERITY.CRITICAL) return "sev-critical";
    if (sev === SEVERITY.HIGH_RISK) return "sev-high";
    if (sev === SEVERITY.SUSPICIOUS) return "sev-suspicious";
    return "sev-normal";
  }
  function timeAgo(ts) {
    const diff = Date.now() - ts;
    const mins = Math.round(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.round(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.round(hrs / 24);
    return `${days}d ago`;
  }

  const SEV_FROM_DB = {
    normal: SEVERITY.NORMAL, suspicious: SEVERITY.SUSPICIOUS,
    high_risk: SEVERITY.HIGH_RISK, critical: SEVERITY.CRITICAL,
  };

  // security_events.detail is a small structured jsonb object, not a
  // human sentence — build an honest, non-sensitive description per event
  // type. Never includes passwords, PINs, tokens, or secret values (the
  // server never stores those in detail to begin with).
  function detailToText(detail, type) {
    switch (type) {
      case "family_account_created": return `A ${detail.accountType === "friend" ? "friend" : "family"} account was created.`;
      case "family_account_updated": return detail.identityChanged ? "Account details updated; password regenerated." : "Account details updated.";
      case "family_account_enabled": return "Account re-enabled.";
      case "family_account_disabled": return "Account disabled.";
      case "family_account_removed": return `${detail.firstName || ""} ${detail.lastName || ""}`.trim() + " was permanently removed.";
      case "owner_bootstrap": return "Owner account created.";
      case "login_success": return "Signed in.";
      case "login_failed": return "Failed login attempt.";
      case "logout": return "Signed out.";
      case "password_changed": return "Password changed.";
      case "vault_locked": return "Vault locked.";
      case "vault_unlocked": return "Vault unlocked.";
      case "vault_pin_changed": return "Vault PIN changed.";
      case "security_setting_changed": return "Security setting changed.";
      default: return "";
    }
  }

  function mapEventRow(row, accountName) {
    return {
      type: row.event_type, accountId: row.subject_id, accountName,
      at: new Date(row.created_at).getTime(),
      severity: SEV_FROM_DB[row.severity] || SEVERITY.NORMAL,
      detail: detailToText(row.detail || {}, row.event_type),
    };
  }

  async function fetchMySecurityEvents() {
    const u = currentUser();
    if (!u || !navigator.onLine) return [];
    const { data, error } = await SUPA.client
      .from("security_events").select("*").eq("subject_id", u.id)
      .order("created_at", { ascending: false }).limit(100);
    if (error || !data) return [];
    return data.map(row => mapEventRow(row, `${u.firstName} ${u.lastName}`));
  }

  // Real, RLS-enforced: the query only ever returns the caller's own
  // events plus events for accounts THEY created as Owner — Postgres, not
  // this client code, is what guarantees a non-owner or a different
  // owner's accounts can never appear here.
  async function fetchOwnedAccountEvents() {
    if (!isOwner() || !navigator.onLine) return { events: [], accounts: [] };
    const listRes = await SUPA.callEdgeFunction("family-manage", { action: "list" });
    const accounts = listRes.ok ? listRes.accounts.map(r => ({
      id: r.id, firstName: r.first_name, lastName: r.last_name, type: r.account_type, enabled: r.is_active,
    })) : [];
    const nameById = new Map(accounts.map(a => [a.id, `${a.firstName} ${a.lastName}`]));
    const u = currentUser();
    if (u) nameById.set(u.id, `${u.firstName} ${u.lastName}`);

    const { data, error } = await SUPA.client
      .from("security_events").select("*").order("created_at", { ascending: false }).limit(300);
    const events = (!error && data ? data : []).map(row => mapEventRow(row, nameById.get(row.subject_id) || "Unknown"));
    return { events, accounts };
  }

  let secState = { section: null };
  let secCache = { myEvents: [], allEvents: [], accounts: [] };

  function renderSecurityView(root, user, route) {
    if (secState.section === "owner" && !isOwner()) secState.section = null;
    root.innerHTML = `<div class="empty-state"><div class="glyph">${ICONS.shield}</div><p>Loading\u2026</p></div>`;
    loadSecurityData().then(() => paintSecurity(root, user));
  }

  async function loadSecurityData() {
    const [mine, owned] = await Promise.all([
      fetchMySecurityEvents(),
      isOwner() ? fetchOwnedAccountEvents() : Promise.resolve({ events: [], accounts: [] }),
    ]);
    secCache.myEvents = mine;
    secCache.allEvents = isOwner() ? owned.events : mine;
    secCache.accounts = owned.accounts;
  }

  function paintSecurity(root, user) {
    const myEvents = secCache.myEvents, allEvents = secCache.allEvents;
    const vaultMeta = VAULT().getVaultMeta();
    const recoveryState = C.readJSON(localStorage, C.LS_VAULT_RECOVERY, {})[user.id] || null;
    const status = statusFor(myEvents, vaultMeta, recoveryState);

    if (!secState.section) {
      paintSummary(root, user, myEvents, allEvents, status, vaultMeta);
    } else {
      paintDetail(root, user, myEvents, allEvents, status, vaultMeta, secState.section);
    }
  }

  /* ---------- Summary screen (progressive disclosure entry point) ---------- */
  function paintSummary(root, user, myEvents, allEvents, status, vaultMeta) {
    const recentAlerts = myEvents.filter(e => Date.now() - e.at < ALERT_WINDOW_MS && e.severity !== SEVERITY.NORMAL);
    const recentActivity = myEvents.filter(e => Date.now() - e.at < RECENT_WINDOW_MS);
    const loginEvents = myEvents.filter(e => ["login_success", "login_failed", "account_lockout"].includes(e.type));
    const lastLogin = myEvents.find(e => e.type === "login_success");

    root.innerHTML = `
      <div class="sec-status-banner ${statusClass(status)}">
        ${ICONS.shield}
        <div>
          <div class="sec-status-label">${status === "SECURE" ? "SAFE" : status}</div>
          <div class="sec-status-sub">${recentAlerts.length ? `${recentAlerts.length} item${recentAlerts.length === 1 ? "" : "s"} need attention` : (vaultMeta.pinSet ? "No issues in the last 7 days" : "Set up a Vault PIN to protect private data")}</div>
        </div>
      </div>

      <div class="settings-list" style="margin-top:16px;">
        ${summaryRow("activity", "Recent Activity", recentActivity.length ? `${recentActivity.length} recent event${recentActivity.length === 1 ? "" : "s"}` : "Nothing recent", "activity")}
        ${summaryRow("login", "Login Activity", lastLogin ? `Last login ${timeAgo(lastLogin.at)}` : "No logins recorded", "login")}
        ${summaryRow("account", "Account Security", "Password protected", "account")}
        ${summaryRow("vault", "Vault Security", vaultMeta.pinSet ? (VAULT().isUnlocked() ? "Unlocked" : "Protected") : "Not set up", "vault")}
        ${summaryRow("shield", "Active Sessions", "This device only", "sessions")}
        ${summaryRow("settings", "Security Settings", "Lockout & recovery policy", "settings")}
        ${isOwner() ? summaryRow("family", "Owner Dashboard", "All accounts & activity", "owner") : ""}
      </div>
    `;
    $$("[data-section]", root).forEach(el => el.addEventListener("click", () => {
      secState.section = el.getAttribute("data-section");
      paintSecurity(root, user);
    }));
  }

  function summaryRow(icon, title, sub, section) {
    return `
      <div class="settings-row" data-section="${section}">
        <div class="icon">${ICONS[icon] || ICONS.shield}</div>
        <div class="grow"><div class="title">${escapeHtml(title)}</div><div class="sub">${escapeHtml(sub)}</div></div>
        ${ICONS.chevron}
      </div>
    `;
  }

  /* ---------- Detail screens ---------- */
  function paintDetail(root, user, myEvents, allEvents, status, vaultMeta, section) {
    let inner = "";
    let title = "Security Center";

    if (section === "activity") {
      title = "Recent Activity";
      const recentAlerts = myEvents.filter(e => Date.now() - e.at < ALERT_WINDOW_MS && e.severity !== SEVERITY.NORMAL);
      inner = `
        ${recentAlerts.length ? `
          <div class="section-label">Alerts</div>
          <div class="result-group" style="margin-bottom:6px;">${recentAlerts.slice(0, 8).map(alertRow).join("")}</div>
        ` : ""}
        <div class="section-label">All activity</div>
        ${logHtml(myEvents.slice(0, 40))}
      `;
    } else if (section === "login") {
      title = "Login Activity";
      const events = myEvents.filter(e => ["login_success", "login_failed", "account_lockout"].includes(e.type));
      inner = logHtml(events.slice(0, 40));
    } else if (section === "account") {
      title = "Account Security";
      inner = `
        <div class="detail-card">
          <div class="kv-list">
            <div class="kv-row"><span class="k">Account type</span><span class="v" style="text-transform:capitalize;">${escapeHtml(user.type)}</span></div>
            <div class="kv-row"><span class="k">Account status</span><span class="v">${user.enabled ? "Enabled" : "Disabled"}</span></div>
            <div class="kv-row"><span class="k">Password protection</span><span class="v">Managed by Supabase Auth, never stored as plaintext</span></div>
            <div class="kv-row"><span class="k">Automatic login</span><span class="v">Disabled</span></div>
          </div>
        </div>
        <div class="hint" style="margin-top:10px;">KRAGVOR requires you to sign in every time the app is opened. Authentication is verified by the server on every request \u2014 this isn't just a client-side check.</div>
      `;
    } else if (section === "vault") {
      title = "Vault Security";
      const unlocked = VAULT().isUnlocked();
      const v = unlocked ? VAULT().getVault() : null;
      inner = `
        <div class="detail-card">
          <div class="kv-list">
            <div class="kv-row"><span class="k">Vault PIN</span><span class="v">${vaultMeta.pinSet ? "Configured" : "Not set up"}</span></div>
            <div class="kv-row"><span class="k">Current state</span><span class="v">${unlocked ? "Unlocked" : "Locked"}</span></div>
            <div class="kv-row"><span class="k">Encryption</span><span class="v">AES-GCM, PIN-derived key</span></div>
            <div class="kv-row"><span class="k">Auto-lock</span><span class="v">${vaultMeta.autoLockMinutes < 1 ? "Immediate" : vaultMeta.autoLockMinutes + " min idle"}</span></div>
            ${v ? `<div class="kv-row"><span class="k">Items stored</span><span class="v">${v.entries.length} item${v.entries.length === 1 ? "" : "s"}, ${v.images.length} image${v.images.length === 1 ? "" : "s"}</span></div>` : ""}
          </div>
          <button class="btn btn-ghost btn-sm btn-block" style="margin-top:12px;" data-nav="/apps/vault">Open Vault</button>
        </div>
      `;
    } else if (section === "sessions") {
      title = "Active Sessions";
      inner = `
        <div class="detail-card">
          <div class="kv-list">
            <div class="kv-row"><span class="k">This device</span><span class="v">Active now</span></div>
          </div>
        </div>
        <div class="hint" style="margin-top:10px;">KRAGVOR only knows about the current browser session on this device — there's no account-wide session inventory across devices in this version.</div>
      `;
    } else if (section === "settings") {
      title = "Security Settings";
      inner = `
        <div class="detail-card">
          <div class="kv-list">
            <div class="kv-row"><span class="k">Login lockout</span><span class="v">5 failed attempts &rarr; 5 min lock</span></div>
            <div class="kv-row"><span class="k">Vault PIN lockout</span><span class="v">5 failed attempts &rarr; escalating lock</span></div>
            <div class="kv-row"><span class="k">Vault encryption</span><span class="v">AES-GCM, PBKDF2-derived key</span></div>
            <div class="kv-row"><span class="k">Vault recovery</span><span class="v">3 consecutive Tic-Tac-Toe wins/draws</span></div>
            <div class="kv-row"><span class="k">Recovery cooldown</span><span class="v">24 hours after a failed attempt</span></div>
            <div class="kv-row"><span class="k">Password storage</span><span class="v">Managed by Supabase Auth, never plaintext</span></div>
            <div class="kv-row"><span class="k">Remember me / auto-login</span><span class="v">Disabled by design</span></div>
          </div>
        </div>
        <div class="hint" style="margin-top:10px;">Account access is authenticated and authorized on the server for every request \u2014 a device can't grant itself access it doesn't have.</div>
      `;
    } else if (section === "owner" && isOwner()) {
      title = "Owner Dashboard";
      inner = ownerHtml(allEvents, secCache.accounts);
    }

    root.innerHTML = `
      <button class="back-link" id="sec-back">${ICONS.chevron} Security Center</button>
      <div class="section-label" style="margin-top:0;">${escapeHtml(title)}</div>
      ${inner}
    `;
    $("#sec-back").addEventListener("click", () => { secState.section = null; paintSecurity(root, user); });
    $$("[data-nav]", root).forEach(btn => btn.addEventListener("click", () => navigate(btn.getAttribute("data-nav"))));
  }

  function alertRow(e) {
    return `
      <div class="list-row" style="border-color:${e.severity === SEVERITY.CRITICAL || e.severity === SEVERITY.HIGH_RISK ? "rgba(193,85,74,0.4)" : "var(--border-soft)"};">
        <div class="grow">
          <div class="title">${escapeHtml(EVENT_LABELS[e.type] || e.type)}</div>
          <div class="sub">${escapeHtml(e.detail || "")} &middot; ${timeAgo(e.at)}</div>
        </div>
        <span class="sev-badge ${sevClass(e.severity)}">${e.severity}</span>
      </div>
    `;
  }

  function logHtml(events, compact = false) {
    if (!events.length) return `<div class="empty-state" style="padding:${compact ? "16px 8px" : "32px 12px"};"><p>No activity yet.</p></div>`;
    return `<div style="display:flex;flex-direction:column;gap:6px;">${events.map(e => `
      <div class="list-row" style="padding:${compact ? "10px 12px" : "14px 16px"};">
        <div class="grow">
          <div class="title" style="font-size:${compact ? "13px" : "14px"};">${escapeHtml(EVENT_LABELS[e.type] || e.type)}</div>
          <div class="sub">${escapeHtml(e.detail || "")} &middot; ${timeAgo(e.at)}</div>
        </div>
        <span class="sev-badge ${sevClass(e.severity)}">${e.severity}</span>
      </div>
    `).join("")}</div>`;
  }

  function ownerHtml(allEvents, accounts) {
    const globalStatus = statusFor(allEvents);
    const suspicious = allEvents.filter(e => Date.now() - e.at < ALERT_WINDOW_MS && e.severity !== SEVERITY.NORMAL);
    const failedLogins = allEvents.filter(e => e.type === "login_failed" && Date.now() - e.at < RECENT_WINDOW_MS);
    const loginEvents = allEvents.filter(e => e.type === "login_success").slice(0, 8);

    return `
      <div class="sec-status-banner ${statusClass(globalStatus)}" style="margin-top:0;">
        ${ICONS.shield}
        <div>
          <div class="sec-status-label">${globalStatus === "SECURE" ? "SAFE" : globalStatus}</div>
          <div class="sec-status-sub">Across all accounts, last 7 days.</div>
        </div>
      </div>

      <div class="owner-stat-grid">
        <div class="owner-stat"><div class="n">${accounts.length + 1}</div><div class="l">Accounts</div></div>
        <div class="owner-stat"><div class="n">${failedLogins.length}</div><div class="l">Failed logins (7d)</div></div>
        <div class="owner-stat"><div class="n">${suspicious.length}</div><div class="l">Flagged events (48h)</div></div>
        <div class="owner-stat"><div class="n">${accounts.filter(a => a.enabled).length + 1}</div><div class="l">Active accounts</div></div>
      </div>

      <div class="section-label">Suspicious activity</div>
      ${suspicious.length ? `<div style="display:flex;flex-direction:column;gap:8px;">${suspicious.slice(0, 10).map(e => `
        <div class="list-row">
          <div class="grow">
            <div class="title">${escapeHtml(EVENT_LABELS[e.type] || e.type)} &mdash; ${escapeHtml(e.accountName || "Unknown")}</div>
            <div class="sub">${escapeHtml(e.detail || "")} &middot; ${timeAgo(e.at)}</div>
          </div>
          <span class="sev-badge ${sevClass(e.severity)}">${e.severity}</span>
        </div>
      `).join("")}</div>` : `<div class="empty-state" style="padding:24px 12px;"><p>No suspicious activity recently.</p></div>`}

      <div class="section-label">Family &amp; friend account status</div>
      <div style="display:flex;flex-direction:column;gap:8px;">
        ${accounts.map(a => {
          const lastLogin = allEvents.find(e => e.accountId === a.id && e.type === "login_success");
          return `
            <div class="list-row">
              <div class="grow">
                <div class="title">${escapeHtml(a.firstName)} ${escapeHtml(a.lastName)}</div>
                <div class="sub">
                  <span class="badge ${a.enabled ? "badge-enabled" : "badge-disabled"}">${a.enabled ? "Enabled" : "Disabled"}</span>
                  &nbsp;&middot; Last login: ${lastLogin ? timeAgo(lastLogin.at) : "Never"}
                </div>
              </div>
            </div>
          `;
        }).join("") || `<div class="empty-state" style="padding:24px 12px;"><p>No family or friend accounts yet.</p></div>`}
      </div>
      <div class="hint" style="margin-top:6px;">Each account's Notes, Vault, and Calculator history stay private to that account \u2014 the Owner Dashboard only shows account status and security activity, never their content.</div>

      <div class="section-label">Recent logins</div>
      ${logHtml(loginEvents, true)}

      <div class="section-label">Security configuration</div>
      <div class="detail-card">
        <div class="kv-list">
          <div class="kv-row"><span class="k">Login lockout</span><span class="v">5 failed attempts &rarr; 5 min lock</span></div>
          <div class="kv-row"><span class="k">Vault PIN lockout</span><span class="v">5 failed attempts &rarr; escalating lock</span></div>
          <div class="kv-row"><span class="k">Vault recovery</span><span class="v">3 consecutive Tic-Tac-Toe wins/draws</span></div>
          <div class="kv-row"><span class="k">Recovery cooldown</span><span class="v">24 hours after a failed attempt</span></div>
          <div class="kv-row"><span class="k">Password storage</span><span class="v">PBKDF2 (210,000 rounds), salted</span></div>
          <div class="kv-row"><span class="k">Remember me / auto-login</span><span class="v">Disabled by design</span></div>
        </div>
      </div>

      <div class="section-label">Active sessions</div>
      <div class="detail-card">
        <div class="kv-list">
          <div class="kv-row"><span class="k">This device</span><span class="v">Active now</span></div>
        </div>
        <div class="hint" style="margin-top:8px;">KRAGVOR tracks the current browser session only. There is no cross-device session index in this version.</div>
      </div>

      <div class="section-label">Full security log</div>
      ${logHtml(allEvents.slice(0, 30))}
    `;
  }

  window.__KRAGVOR_SECURITY__ = { renderSecurityView };
})();

/* ==========================================================================
   PART 11 — DECODE (word-guessing game)
   The game itself is a separate, self-contained app (decode/index.html +
   script.js) embedded via an iframe rather than ported line-by-line into
   this file — it already has its own tested game logic, and an iframe
   keeps that logic, its DOM/CSS, and this app's completely isolated from
   each other. Account-scoping is handled by a small bridge script inside
   the iframe (decode/kragvor-bridge.js) that syncs the game's existing
   localStorage-based stats to a `decode_stats` row for the authenticated
   account — never by KRAGVOR reaching into the iframe's internals.
   The Owner-only "Players" view (list + reset) is native KRAGVOR UI, not
   part of the game, matching how Family & Friends/Owner Dashboard work.
   ========================================================================== */
(() => {
  "use strict";
  const C = window.__KRAGVOR_CORE__;
  const R = window.__KRAGVOR_ROUTER__;
  const SUPA = window.__KRAGVOR_SUPABASE__;
  const { $, $$, escapeHtml, currentUser, isOwner, ICONS, toast, APPS_REGISTRY } = C;
  const { navigate, openConfirmModal } = R;

  async function renderDecodeApp(root, user, route) {
    const sub = route.split("/").slice(3).join("/"); // segment(s) after /apps/decode/
    if (sub === "players") return renderDecodePlayersView(root, user);

    root.innerHTML = `
      <div class="empty-state"><div class="glyph">${ICONS.decode}</div><p>Loading\u2026</p></div>
    `;

    const { data } = await SUPA.client.auth.getSession();
    const session = data && data.session;
    if (!R.currentRoute().startsWith("/apps/decode")) return; // navigated away while loading
    if (!session) {
      root.innerHTML = `
        <div class="empty-state"><div class="glyph">${ICONS.decode}</div><p>Couldn't start a game session. Check your connection and try again.</p></div>
      `;
      return;
    }

    const hash = new URLSearchParams({
      at: session.access_token,
      rt: session.refresh_token,
      su: SUPA.SUPABASE_URL,
      sk: SUPA.SUPABASE_ANON_KEY,
      uid: user.id,
    }).toString();

    root.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:12px;">
        <button class="back-link" id="decode-back" style="margin:0;">${ICONS.chevron} Dashboard</button>
        ${isOwner() ? `<button class="btn btn-ghost btn-sm" id="decode-players-btn">${ICONS.family} Player Stats</button>` : ""}
      </div>
      <div class="decode-frame-wrap" style="border-radius:16px;overflow:hidden;border:1px solid var(--border, rgba(255,255,255,0.08));height:calc(100vh - 190px);min-height:420px;">
        <iframe
          id="decode-frame"
          src="decode/index.html#${hash}"
          title="DECODE"
          style="width:100%;height:100%;border:0;display:block;"
          allow="clipboard-write"
        ></iframe>
      </div>
    `;
    $("#decode-back").addEventListener("click", () => navigate("/dashboard"));
    const playersBtn = $("#decode-players-btn");
    if (playersBtn) playersBtn.addEventListener("click", () => navigate("/apps/decode/players"));
  }

  /* ---------------------------------------------------------------------
     Owner-only: view every managed account's DECODE stats, and reset any
     of them. Route-level guard mirrors Family & Friends exactly — never
     rendered for a non-owner regardless of how the route was reached.
     Real enforcement is server-side: RLS only lets an Owner read managed
     accounts' decode_stats rows, and the reset edge function independently
     re-verifies the caller is an active Owner and that the target is
     actually one of their own accounts before touching anything.
     ------------------------------------------------------------------- */
  async function renderDecodePlayersView(root, user) {
    if (!isOwner()) {
      root.innerHTML = `
        <div class="empty-state"><div class="glyph">${ICONS.lock}</div><p>This section is only available to the owner.</p></div>
      `;
      setTimeout(() => { if (currentUser() && !isOwner()) navigate("/apps/decode"); }, 900);
      return;
    }

    root.innerHTML = `
      <button class="back-link" id="decode-players-back">${ICONS.chevron} DECODE</button>
      <div class="section-label">Player stats</div>
      <div id="decode-players-list"><div class="empty-state"><div class="glyph">${ICONS.decode}</div><p>Loading\u2026</p></div></div>
    `;
    $("#decode-players-back").addEventListener("click", () => navigate("/apps/decode"));

    const [listRes, statsRes] = await Promise.all([
      SUPA.callEdgeFunction("family-manage", { action: "list" }),
      SUPA.client.from("decode_stats").select("*"),
    ]);
    if (!R.currentRoute().startsWith("/apps/decode/players")) return; // navigated away while loading

    const accounts = listRes.ok ? listRes.accounts : [];
    const statsByUser = new Map((statsRes.data || []).map(row => [row.user_id, row]));

    const players = [
      { id: user.id, firstName: user.firstName, lastName: user.lastName, enabled: true },
      ...accounts.map(a => ({ id: a.id, firstName: a.first_name, lastName: a.last_name, enabled: a.is_active })),
    ];

    renderPlayersList(players, statsByUser);

    function renderPlayersList(players, statsByUser) {
      const listEl = $("#decode-players-list");
      if (!listEl) return;
      listEl.innerHTML = players.map(p => {
        const s = statsByUser.get(p.id);
        const played = s ? s.played : 0;
        const won = s ? s.won : 0;
        const winPct = played ? Math.round((won / played) * 100) : 0;
        return `
          <div class="list-row">
            <div class="grow">
              <div class="title">${escapeHtml(p.firstName)} ${escapeHtml(p.lastName)}${!p.enabled ? " (disabled)" : ""}</div>
              <div class="sub">${played} played &middot; ${winPct}% wins &middot; best streak ${s ? s.best_streak : 0}${s && s.best_score != null ? ` &middot; best score ${s.best_score}` : ""}</div>
            </div>
            <button class="btn btn-ghost btn-sm" data-reset-id="${p.id}" data-reset-name="${escapeHtml(p.firstName)} ${escapeHtml(p.lastName)}">Reset</button>
          </div>
        `;
      }).join("") || `<div class="empty-state"><div class="glyph">${ICONS.decode}</div><p>No players yet.</p></div>`;

      $$("[data-reset-id]", listEl).forEach(btn => btn.addEventListener("click", () => {
        const targetId = btn.getAttribute("data-reset-id");
        const targetName = btn.getAttribute("data-reset-name");
        openConfirmModal({
          title: `Reset ${targetName}'s stats?`,
          message: "This permanently clears their DECODE played/won/streak/best-score history and today's Daily result. This can't be undone.",
          confirmLabel: "Reset",
          danger: true,
          onConfirm: async () => {
            btn.disabled = true;
            const res = await SUPA.callEdgeFunction("decode-reset-stats", { targetId });
            if (res.ok) {
              toast("Stats reset", "success");
              statsByUser.delete(targetId);
              renderPlayersList(players, statsByUser);
            } else {
              btn.disabled = false;
              toast(res.error === "offline" || res.error === "server_unreachable" ? "You're offline \u2014 try again once connected." : "Couldn't reset that account's stats.", "error");
            }
          }
        });
      }));
    }
  }

  APPS_REGISTRY.push({
    id: "decode", name: "DECODE", desc: "Daily 5-letter word puzzle",
    icon: "decode", render: (root, user, route) => renderDecodeApp(root, user, route)
  });

  window.__KRAGVOR_DECODE__ = { renderDecodeApp, renderDecodePlayersView };
})();

/* ==========================================================================
   PART 11 — UNIVERSAL SEARCH
   Natural-language search across the current account's Notes, Vault
   (only when unlocked), and KRAGVOR actions/features. Never bypasses
   the Vault lock, and never touches another account's data.
   ========================================================================== */
(() => {
  "use strict";
  const C = window.__KRAGVOR_CORE__;
  const R = window.__KRAGVOR_ROUTER__;
  const { $, $$, escapeHtml, currentUser, isOwner, ICONS, APPS_REGISTRY } = C;
  const { navigate } = R;
  const NOTES = () => window.__KRAGVOR_NOTES__;
  const VAULT = () => window.__KRAGVOR_VAULT__;

  const ACTIONS = [
    { keywords: ["calculator", "calc", "math"], label: "Open Calculator", path: "/apps/calculator", icon: "calculator" },
    { keywords: ["notes", "note"], label: "Open Notes", path: "/apps/notes", icon: "notes" },
    { keywords: ["vault"], label: "Open Vault", path: "/apps/vault", icon: "vault" },
    { keywords: ["decode", "word game", "puzzle", "wordle"], label: "Open DECODE", path: "/apps/decode", icon: "decode" },
    { keywords: ["jammer", "signal", "interference", "detector", "jamming"], label: "Open Jammer Detector", path: "/apps/jammer-detector", icon: "signal" },
    { keywords: ["security", "security center"], label: "Open Security Center", path: "/security", icon: "shield" },
    { keywords: ["settings"], label: "Open Settings", path: "/settings", icon: "settings" },
    { keywords: ["apps"], label: "Open Apps", path: "/apps", icon: "apps" },
    { keywords: ["favorite", "favorites", "starred"], label: "Open Favorites", path: "/favorites", icon: "favorites" },
    { keywords: ["family", "friend", "friends"], label: "Family & Friends", path: "/settings/family-friends", icon: "family", ownerOnly: true },
    { keywords: ["account", "profile"], label: "Open Account", path: "/settings/account", icon: "account" },
  ];
  const CREATE_NOTE_PHRASES = ["create a new note", "create note", "new note", "add a note", "make a note", "write a note"];
  const VAULT_HINT_WORDS = ["password", "vault", "pin", "code", "secure note", "credential", "login for", "login to"];
  const STOP_WORDS = new Set(["what", "is", "my", "the", "find", "for", "show", "where", "did", "i", "write", "about",
    "a", "an", "of", "to", "note", "notes", "password", "vault", "open"]);

  function tokenize(q) { return q.toLowerCase().replace(/[?.!]/g, "").trim(); }
  function meaningfulTerms(q) {
    return tokenize(q).split(/\s+/).filter(t => t && !STOP_WORDS.has(t));
  }

  function matchActions(query) {
    const q = tokenize(query);
    if (!q) return [];
    const results = [];
    if (CREATE_NOTE_PHRASES.some(p => q.includes(p))) {
      results.push({ label: "Create a new note", path: "__create_note__", icon: "plus" });
    }
    ACTIONS.forEach(a => {
      if (a.ownerOnly && !isOwner()) return;
      if (a.keywords.some(k => q.includes(k)) && (q.includes("open") || q.includes("go to") || q.includes("show") || q === a.keywords[0] || q.includes(a.keywords[0]))) {
        results.push({ label: a.label, path: a.path, icon: a.icon });
      }
    });
    // de-dupe by path
    const seen = new Set();
    return results.filter(r => (seen.has(r.path) ? false : (seen.add(r.path), true)));
  }

  // Simple relevance scoring: title matches count more than body/category
  // matches, whole-query substring matches count more than scattered term
  // matches, and favorites get a small boost — good enough to rank "where
  // did I write X" results sensibly without needing a real search index.
  function scoreText(fields, terms, wholeQuery) {
    let score = 0;
    const [primary = "", secondary = "", tertiary = ""] = fields.map(f => (f || "").toLowerCase());
    if (wholeQuery && primary.includes(wholeQuery)) score += 6;
    terms.forEach(t => {
      if (primary.includes(t)) score += 3;
      else if (secondary.includes(t)) score += 2;
      else if (tertiary.includes(t)) score += 1;
    });
    return score;
  }

  function searchNotes(query) {
    const terms = meaningfulTerms(query);
    const wholeQuery = tokenize(query);
    const wantsFavorites = /favorite|starred/.test(wholeQuery);
    let pool = NOTES().getActiveNotes();
    if (wantsFavorites) pool = pool.filter(n => n.favorite);
    if (!terms.length && !wantsFavorites) return [];

    return pool
      .map(n => ({ note: n, score: scoreText([n.title, n.body, n.category], terms, wholeQuery) + (n.favorite ? 1 : 0) }))
      .filter(r => wantsFavorites || r.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 12)
      .map(r => r.note);
  }

  function looksLikeVaultQuery(query) {
    const q = tokenize(query);
    return VAULT_HINT_WORDS.some(w => q.includes(w));
  }
  function searchVault(query) {
    const terms = meaningfulTerms(query);
    const wholeQuery = tokenize(query);
    const v = VAULT().getVault();
    if (!terms.length) return v.entries.slice(0, 12);

    return v.entries
      .map(e => {
        const customText = (e.customFields || []).map(f => `${f.key} ${f.value}`).join(" ");
        return { entry: e, score: scoreText([e.title, e.username, `${e.category} ${e.notes} ${customText}`], terms, wholeQuery) };
      })
      .filter(r => r.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 12)
      .map(r => r.entry);
  }

  /* ---------------------------------------------------------------------
     Real recent searches — persisted per account, not static fake text.
     ------------------------------------------------------------------- */
  const LS_RECENT_SEARCHES = "kragvor_recent_searches_v1";
  function getRecentSearches() {
    const u = currentUser();
    if (!u) return [];
    const all = C.readJSON(localStorage, LS_RECENT_SEARCHES, {});
    return all[u.id] || [];
  }
  function recordSearch(query) {
    const u = currentUser();
    const q = query.trim();
    if (!u || q.length < 2) return;
    const all = C.readJSON(localStorage, LS_RECENT_SEARCHES, {});
    let list = (all[u.id] || []).filter(x => x.toLowerCase() !== q.toLowerCase());
    list.unshift(q);
    all[u.id] = list.slice(0, 6);
    C.writeJSON(localStorage, LS_RECENT_SEARCHES, all);
  }

  function renderSearchView(root, user) {
    root.innerHTML = `
      <div class="search-field">
        ${ICONS.search}
        <input id="usearch-input" type="text" placeholder="Search KRAGVOR&hellip;" autofocus autocomplete="off" />
      </div>
      <div id="usearch-results" style="margin-top:14px;"></div>
    `;
    const input = $("#usearch-input", root);
    const resultsEl = $("#usearch-results", root);

    const SUGGESTIONS = [
      { label: "Find my notes", query: "find my notes" },
      { label: "Find a Vault item", query: "find my password" },
      { label: "Open Calculator", query: "open calculator" },
      { label: "Open Security Center", query: "open security center" },
      { label: "Create a note", query: "create a new note" },
      { label: "Open Vault", query: "open vault" },
    ];

    let recordTimer = null;

    function paintResults(query) {
      if (!query.trim()) {
        const recent = getRecentSearches();
        resultsEl.innerHTML = recent.length ? `
          <div class="section-label">Recent Searches</div>
          <div class="suggestion-grid">
            ${recent.map(q => `<button class="suggestion-chip" data-suggest="${escapeHtml(q)}">${escapeHtml(q)}</button>`).join("")}
          </div>
        ` : `
          <div class="section-label">Try searching for</div>
          <div class="suggestion-grid">
            ${SUGGESTIONS.map(s => `<button class="suggestion-chip" data-suggest="${escapeHtml(s.query)}">${escapeHtml(s.label)}</button>`).join("")}
          </div>
        `;
        $$("[data-suggest]", resultsEl).forEach(btn => btn.addEventListener("click", () => {
          input.value = btn.getAttribute("data-suggest");
          paintResults(input.value);
        }));
        return;
      }

      clearTimeout(recordTimer);
      recordTimer = setTimeout(() => recordSearch(query), 900);

      const actionMatches = matchActions(query);
      const noteMatches = searchNotes(query);
      const vaultIntent = looksLikeVaultQuery(query);
      const vaultUnlocked = VAULT().isUnlocked();
      const vaultMatches = vaultIntent && vaultUnlocked ? searchVault(query) : [];

      let html = "";

      if (actionMatches.length) {
        html += `<div class="section-label">Actions</div><div class="result-group">`;
        html += actionMatches.map(a => `
          <div class="result-row" data-action-path="${escapeHtml(a.path)}">
            <div class="result-icon">${ICONS[a.icon] || ICONS.apps}</div>
            <div class="grow"><div class="title">${escapeHtml(a.label)}</div></div>
            ${ICONS.chevron}
          </div>
        `).join("");
        html += `</div>`;
      }

      if (vaultIntent) {
        html += `<div class="section-label">Vault</div>`;
        if (!vaultUnlocked) {
          html += `<div class="notice-line locked-notice">${ICONS.lock}<span><strong>Vault locked.</strong> Unlock Vault to access this information.</span></div>`;
        } else if (vaultMatches.length) {
          html += `<div class="result-group">` + vaultMatches.map(e => `
            <div class="result-row" data-vault-open="${e.id}">
              <div class="result-icon">${ICONS.vault}</div>
              <div class="grow"><div class="title">${escapeHtml(e.title)}</div><div class="sub">${escapeHtml(e.category)}${e.username ? " &middot; " + escapeHtml(e.username) : ""}</div></div>
              ${ICONS.chevron}
            </div>
          `).join("") + `</div>`;
        } else {
          html += `<div class="empty-inline">No matching Vault items.</div>`;
        }
      }

      if (noteMatches.length || (!actionMatches.length && !vaultIntent)) {
        html += `<div class="section-label">Notes</div>`;
        if (noteMatches.length) {
          html += `<div class="result-group">` + noteMatches.map(n => `
            <div class="result-row" data-note-open="${n.id}">
              <div class="result-icon">${ICONS.notes}</div>
              <div class="grow"><div class="title">${n.favorite ? `<span style="color:var(--accent);">${ICONS.star}</span> ` : ""}${escapeHtml(n.title || "Untitled")}</div><div class="sub">${escapeHtml(n.category)} &middot; ${escapeHtml((n.body || "").slice(0, 60))}</div></div>
              ${ICONS.chevron}
            </div>
          `).join("") + `</div>`;
        } else if (!actionMatches.length && !vaultIntent) {
          html += `<div class="empty-inline">No matches. Try different words, or open a feature directly.</div>`;
        } else {
          html += `<div class="empty-inline">No matching notes.</div>`;
        }
      }

      resultsEl.innerHTML = html;
      $$("[data-action-path]", resultsEl).forEach(el => el.addEventListener("click", () => {
        const path = el.getAttribute("data-action-path");
        recordSearch(input.value);
        if (path === "__create_note__") {
          navigate("/apps/notes");
          setTimeout(() => {
            const btn = document.getElementById("notes-new");
            if (btn) btn.click();
          }, 60);
        } else {
          navigate(path);
        }
      }));
      $$("[data-note-open]", resultsEl).forEach(el => el.addEventListener("click", () => {
        recordSearch(input.value);
        navigate(`/apps/notes/${el.getAttribute("data-note-open")}`);
      }));
      // Opens the specific matched item directly rather than just the
      // Vault home screen, since we already know it's unlocked and safe.
      $$("[data-vault-open]", resultsEl).forEach(el => el.addEventListener("click", () => {
        recordSearch(input.value);
        const entryId = el.getAttribute("data-vault-open");
        navigate("/apps/vault");
        setTimeout(() => {
          const row = document.querySelector(`[data-open-entry="${entryId}"]`);
          if (row) row.click();
        }, 60);
      }));
    }

    paintResults("");
    input.addEventListener("input", () => paintResults(input.value));
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") recordSearch(input.value); });
  }

  window.__KRAGVOR_SEARCH__ = { renderSearchView };
})();

/* ==========================================================================
   PART 12 — JAMMER DETECTOR
   A best-effort wireless-interference monitor built entirely from signals
   a browser can actually observe: connection-quality hints (where the
   platform exposes them), online/offline transitions, and GPS fix
   quality. A phone's browser has no access to raw radio-frequency data,
   so this can only ever surface *indirect, circumstantial* anomalies —
   the UI says so plainly, and nothing here claims to detect an actual RF
   jammer with certainty. Local-only per account: this reflects one
   device's radio conditions, so unlike Notes/Vault it isn't synced.

   NOTE for APK/WebView packaging: navigator.connection (the Network
   Information API) does not exist in Safari and is NOT implemented by
   the stock Android System WebView that most "website-to-APK" wrappers
   use — so on a huge share of Android devices this module would silently
   have done nothing before. It now detects that and falls back to timing
   a same-origin fetch as a rough stand-in for reachability/latency. GPS
   checks also depend on the wrapping app actually granting the
   geolocation permission prompt (WebChromeClient.onGeolocationPermissionsShowPrompt)
   and on the page being served over HTTPS — both are called out below.
   ========================================================================== */
(() => {
  "use strict";
  const C = window.__KRAGVOR_CORE__;
  const R = window.__KRAGVOR_ROUTER__;
  const {
    $, $$, escapeHtml, uid, readJSON, writeJSON,
    LS_JAMLOG, currentUser, ICONS, toast, APPS_REGISTRY, SEVERITY
  } = C;
  const { openModal, closeModal, openConfirmModal } = R;

  const SAMPLE_MS = 3000;
  const WINDOW_MS = 10 * 60 * 1000;       // anomalies count as "recent" for 10 min
  const DOWNLINK_DROP_RATIO = 0.35;       // reported downlink fell below 35% of baseline
  const DOWNLINK_RECOVER_RATIO = 0.55;    // hysteresis: needs to climb back above this to clear the flag
  const RTT_SPIKE_RATIO = 2.5;            // reported latency rose above 2.5x baseline
  const RTT_RECOVER_RATIO = 1.5;          // hysteresis: needs to fall back below this to clear the flag
  const GEO_ACCURACY_DROP_M = 120;        // GPS accuracy worsened by more than this many meters
  const EFFTYPE_RANK = { "slow-2g": 0, "2g": 1, "3g": 2, "4g": 3 };
  const CONFIRM_SAMPLES = 2;              // consecutive bad reads required before an anomaly is logged (debounce)
  const REBASELINE_MS = 60 * 1000;        // a flag continuously active this long -> adopt the current reading as the new normal instead of alerting forever.
                                           // Wall-clock, not a sample count: the connection channel samples every SAMPLE_MS
                                           // but the GPS watch fires on its own, much slower and less regular cadence, so
                                           // counting "samples" would let GPS take several minutes longer to rebaseline
                                           // than the connection channel for the same elapsed time.
  const ANALYSIS_MIN_GAP_MS = SAMPLE_MS;  // min gap between quality analyses, so a burst of native 'change' events can't double-log the same shift as the next timer tick; kept equal to SAMPLE_MS so CONFIRM_SAMPLES/REBASELINE_MS timing assumptions hold regardless of how often 'change' fires
  const PROBE_TIMEOUT_MS = 4000;
  const PROBE_PATH = "manifest.json";     // small, same-origin, always present — relative so it resolves correctly under any host path

  // ---- Native-signal thresholds (android-native/SignalDetectorPlugin) ----
  // Only active when window.KragvorNativeSignal.isAvailable() — i.e. running
  // inside the Capacitor build with the plugin registered, not a plain browser.
  const CELL_DBM_DROP_DB = 25;            // strongest visible cell's dBm fell this many dB below baseline (dB is already log-scale, so a flat delta, not a ratio, is the right comparison)
  const GNSS_AGC_RISE_DB = 6;             // GNSS AGC level rose this many dB above baseline — the receiver fighting a raised noise floor. Starting point only: AGC baselines vary by chipset, calibrate against your own device(s) if this is noisy in practice
  const SAT_USED_DROP_RATIO = 0.35;       // satellites used-in-fix fell below this fraction of baseline
  let jamState = freshState();
  let jamViewMounted = false;
  let currentJamRoot = null; // native plugin events arrive async via listeners, outside evaluateSample's call chain, so refresh() needs a remembered root to repaint into

  function freshState() {
    return {
      monitoring: false,
      baseline: null,
      probeBaseline: null,
      gpsBestAccuracy: null,
      flags: { downlink: false, rtt: false, netType: false, gps: false, probeRtt: false, probeFail: false, cellDbm: false, gnssAgc: false, gnssSat: false },
      streaks: { downlink: 0, rtt: 0, netType: 0, gps: 0, probeRtt: 0, cellDbm: 0, gnssAgc: 0, gnssSat: 0 },
      flagSince: { downlink: null, rtt: null, netType: null, gps: null, probeRtt: null, cellDbm: null, gnssAgc: null, gnssSat: null },
      correlated: false,
      nativeActive: false,
      nativeCorrelated: false,
      nativeBaseline: { cellDbm: null, agc: null, satUsed: null },
      connSupported: null,
      geoDenied: false,
      geoUnsupported: false,
      probing: false,
      probeUnreliable: false,
      lastAnalysisAt: 0,
      current: { online: navigator.onLine, effectiveType: null, downlink: null, rtt: null, geoAccuracy: null, nativeCellDbm: null, nativeAgc: null, nativeSatUsed: null, nativeSatTotal: null },
      geoWatchId: null,
      tickHandle: null, connHandler: null, onlineHandler: null, offlineHandler: null,
    };
  }

  function getConnection() { return navigator.connection || navigator.mozConnection || navigator.webkitConnection || null; }

  /* ---- Persisted per-account anomaly log (local-only) ---- */
  function getLog() {
    const u = currentUser();
    if (!u) return [];
    const all = readJSON(localStorage, LS_JAMLOG, {});
    return all[u.id] || [];
  }
  function pushLog(entry) {
    const u = currentUser();
    if (!u) return;
    const all = readJSON(localStorage, LS_JAMLOG, {});
    const list = all[u.id] || [];
    list.unshift({ id: uid("jam"), at: Date.now(), ...entry });
    all[u.id] = list.slice(0, 200);
    writeJSON(localStorage, LS_JAMLOG, all);
  }
  function clearLog() {
    const u = currentUser();
    if (!u) return;
    const all = readJSON(localStorage, LS_JAMLOG, {});
    all[u.id] = [];
    writeJSON(localStorage, LS_JAMLOG, all);
  }
  // Takes an already-fetched log instead of reading localStorage itself —
  // refresh() and paintJammer() each need both the full log (to render the
  // list) and the recent-anomalies slice (for status/chips/blips) on every
  // tick; reading+JSON-parsing localStorage twice per tick for that was
  // pure waste, worse on a low-end device inside a WebView.
  function recentAnomalies(log) { return log.filter(e => Date.now() - e.at < WINDOW_MS); }

  // Only the presence of genuinely bad-severity events should raise the
  // status — a NORMAL-severity entry (session started, connection restored,
  // a signal recovering) must never by itself read as "suspicious".
  function computeStatus(recent) {
    if (!jamState.monitoring) return "OFF";
    if (recent.some(e => e.severity === SEVERITY.CRITICAL)) return "HIGH RISK";
    if (recent.some(e => e.severity === SEVERITY.HIGH_RISK)) return "ATTENTION NEEDED";
    if (recent.some(e => e.severity === SEVERITY.SUSPICIOUS)) return "SUSPICIOUS ACTIVITY";
    return "SECURE";
  }
  function sweepColorVar(status) {
    if (status === "OFF") return "var(--text-faint)";
    if (status === "SECURE") return "var(--success)";
    if (status === "ATTENTION NEEDED") return "var(--accent-hi)";
    if (status === "SUSPICIOUS ACTIVITY") return "#d79a37";
    return "var(--danger)";
  }
  function statusLabel(status) { return status === "OFF" ? "STANDBY" : (status === "SECURE" ? "NORMAL" : status); }
  function hashStr(s) { let h = 0; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0; return Math.abs(h); }
  function sevClass(sev) {
    if (sev === SEVERITY.CRITICAL) return "sev-critical";
    if (sev === SEVERITY.HIGH_RISK) return "sev-high";
    if (sev === SEVERITY.SUSPICIOUS) return "sev-suspicious";
    return "sev-normal";
  }
  function timeAgo(ts) {
    const diff = Date.now() - ts;
    const mins = Math.round(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.round(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.round(hrs / 24)}d ago`;
  }

  function connSnapshot() {
    const nc = getConnection();
    if (!nc) return { supported: false };
    return {
      supported: true,
      effectiveType: nc.effectiveType || null,
      downlink: typeof nc.downlink === "number" ? nc.downlink : null,
      rtt: typeof nc.rtt === "number" ? nc.rtt : null,
    };
  }

  // Fallback used whenever the Network Information API isn't available
  // (Safari, and — critically for an APK build — the stock Android
  // WebView). Times a same-origin, no-store fetch as a rough stand-in for
  // reachability/RTT. A failed/aborted fetch is treated as a strong
  // connectivity signal in its own right, since navigator.onLine can lag
  // reality by a long time on mobile.
  //
  // The `__jamprobe` marker is load-bearing, not decorative: service-worker.js
  // explicitly bypasses its cache for any request carrying it (see the fetch
  // handler there). Without that, a cache-first service worker would either
  // (a) answer every probe instantly from cache — masking real degradation
  // with a permanent fake-fast reading — or, once we added a cache-busting
  // query to defeat that, (b) have the worker's own cache.put() store a new,
  // never-reused entry on every single tick, growing Cache Storage without
  // bound for as long as monitoring runs. Bypassing interception avoids both.
  function probeConnectivity() {
    return new Promise((resolve) => {
      if (!("fetch" in window)) { resolve({ ok: null, rtt: null }); return; }
      let settled = false;
      const settle = (val) => { if (!settled) { settled = true; resolve(val); } };
      // Timer-based fallback fires regardless of AbortController/signal
      // support, so a hung request (no reject, ever, on some old WebViews)
      // can't permanently wedge jamState.probing and silently kill all
      // further fallback-mode detection for the rest of the session.
      const hasAbort = "AbortController" in window;
      const ctrl = hasAbort ? new AbortController() : null;
      const timer = setTimeout(() => { if (ctrl) ctrl.abort(); settle({ ok: false, rtt: null }); }, PROBE_TIMEOUT_MS);
      const now = (window.performance && performance.now) ? () => performance.now() : () => Date.now();
      const url = `${PROBE_PATH}?__jamprobe=1&t=${Date.now()}`;
      const t0 = now();
      fetch(url, { method: "GET", cache: "no-store", signal: hasAbort ? ctrl.signal : undefined })
        .then(() => { clearTimeout(timer); settle({ ok: true, rtt: Math.round(now() - t0) }); })
        .catch(() => { clearTimeout(timer); settle({ ok: false, rtt: null }); });
    });
  }

  function activeFlagCount() {
    const f = jamState.flags;
    return [f.downlink, f.rtt, f.netType, f.gps, f.probeRtt].filter(Boolean).length;
  }

  // A real jamming-like event tends to move several independent signals
  // at once; one weak home router flapping only ever moves one. Escalate
  // when two or more channels are degraded simultaneously, edge-triggered
  // so it logs once per correlated episode rather than every tick.
  function evaluateCorrelation() {
    const count = activeFlagCount();
    if (count >= 2 && !jamState.correlated) {
      jamState.correlated = true;
      pushLog({
        type: "correlated", label: "Multiple signals degraded at once", severity: SEVERITY.CRITICAL,
        detail: "Several independent connection signals worsened together, which is more consistent with real interference than an isolated blip."
      });
    } else if (count < 2 && jamState.correlated) {
      jamState.correlated = false;
    }
  }

  // Shared edge-trigger helper: `bad` is whether this sample currently
  // fails the threshold for `key`. Handles the confirm-debounce, the
  // wall-clock rebaseline, and hysteresis-gated recovery the same way for
  // every channel so the four call sites below can't drift out of sync
  // with each other.
  function trackFlag(key, bad, { onFlag, onRebaseline, recovered, onRecover }) {
    if (bad) {
      jamState.streaks[key]++;
      if (!jamState.flags[key] && jamState.streaks[key] >= CONFIRM_SAMPLES) {
        jamState.flags[key] = true;
        jamState.flagSince[key] = Date.now();
        onFlag();
      }
      if (jamState.flags[key] && Date.now() - jamState.flagSince[key] >= REBASELINE_MS) {
        jamState.flags[key] = false; jamState.streaks[key] = 0; jamState.flagSince[key] = null;
        onRebaseline();
      }
    } else {
      jamState.streaks[key] = 0;
      if (jamState.flags[key] && recovered) {
        jamState.flags[key] = false; jamState.flagSince[key] = null;
        onRecover();
      }
    }
  }

  function analyzeNativeSample(snap) {
    if (!jamState.baseline) {
      if (snap.downlink != null) jamState.baseline = { downlink: snap.downlink, rtt: snap.rtt, effectiveType: snap.effectiveType };
      return;
    }
    const b = jamState.baseline;

    if (snap.downlink != null && b.downlink != null && b.downlink > 0) {
      const ratio = snap.downlink / b.downlink;
      trackFlag("downlink", ratio < DOWNLINK_DROP_RATIO, {
        onFlag: () => pushLog({ type: "downlink_drop", label: "Bandwidth dropped", severity: SEVERITY.SUSPICIOUS,
          detail: `Reported bandwidth fell from ~${b.downlink} to ~${snap.downlink} Mbps.` }),
        onRebaseline: () => { b.downlink = snap.downlink; pushLog({ type: "downlink_rebaselined", label: "Bandwidth stabilized at new level", severity: SEVERITY.NORMAL,
          detail: `Sustained for a while, so the new normal is now ~${snap.downlink} Mbps.` }); },
        recovered: ratio > DOWNLINK_RECOVER_RATIO,
        onRecover: () => { b.downlink = snap.downlink; pushLog({ type: "downlink_recovered", label: "Bandwidth recovered", severity: SEVERITY.NORMAL,
          detail: `Bandwidth back to ~${snap.downlink} Mbps.` }); },
      });
    }

    if (snap.rtt != null && b.rtt != null && b.rtt > 0) {
      const ratio = snap.rtt / b.rtt;
      trackFlag("rtt", ratio > RTT_SPIKE_RATIO && snap.rtt > 300, {
        onFlag: () => pushLog({ type: "rtt_spike", label: "Latency spike", severity: SEVERITY.SUSPICIOUS,
          detail: `Reported latency rose from ~${b.rtt}ms to ~${snap.rtt}ms.` }),
        onRebaseline: () => { b.rtt = snap.rtt; pushLog({ type: "rtt_rebaselined", label: "Latency stabilized at new level", severity: SEVERITY.NORMAL,
          detail: `Sustained for a while, so the new normal is now ~${snap.rtt}ms.` }); },
        recovered: ratio < RTT_RECOVER_RATIO,
        onRecover: () => { b.rtt = snap.rtt; pushLog({ type: "rtt_recovered", label: "Latency back to normal", severity: SEVERITY.NORMAL,
          detail: `Latency back to ~${snap.rtt}ms.` }); },
      });
    }

    const prevRank = EFFTYPE_RANK[b.effectiveType];
    const curRank = EFFTYPE_RANK[snap.effectiveType];
    if (prevRank != null && curRank != null) {
      trackFlag("netType", curRank < prevRank, {
        onFlag: () => pushLog({ type: "network_downgrade", label: "Network type downgraded", severity: SEVERITY.SUSPICIOUS,
          detail: `Dropped from ${b.effectiveType.toUpperCase()} to ${snap.effectiveType.toUpperCase()}.` }),
        onRebaseline: () => { b.effectiveType = snap.effectiveType; pushLog({ type: "network_rebaselined", label: "Network type stabilized at new level", severity: SEVERITY.NORMAL,
          detail: `Sustained for a while, so ${snap.effectiveType.toUpperCase()} is now the new normal.` }); },
        recovered: curRank >= prevRank,
        onRecover: () => { b.effectiveType = snap.effectiveType; pushLog({ type: "network_restored", label: "Network type restored", severity: SEVERITY.NORMAL,
          detail: `Back to ${snap.effectiveType.toUpperCase()}.` }); },
      });
    }
  }

  function analyzeProbeSample(result) {
    if (result.ok === false) {
      jamState.streaks.probeRtt = 0;
      if (!jamState.flags.probeFail) {
        jamState.flags.probeFail = true;
        pushLog({ type: "probe_fail", label: "Network probe failed", severity: SEVERITY.HIGH_RISK,
          detail: "A test request to the app server didn't complete." });
      }
      return;
    }
    if (jamState.flags.probeFail) {
      jamState.flags.probeFail = false;
      pushLog({ type: "probe_recovered", label: "Network probe recovered", severity: SEVERITY.NORMAL,
        detail: "Test requests are completing again." });
    }
    if (result.rtt == null) return;
    if (!jamState.probeBaseline) { jamState.probeBaseline = { rtt: result.rtt }; return; }
    const b = jamState.probeBaseline;
    const ratio = result.rtt / b.rtt;
    trackFlag("probeRtt", ratio > RTT_SPIKE_RATIO && result.rtt > 400, {
      onFlag: () => pushLog({ type: "probe_rtt_spike", label: "Response time spike", severity: SEVERITY.SUSPICIOUS,
        detail: `Test requests slowed from ~${b.rtt}ms to ~${result.rtt}ms.` }),
      onRebaseline: () => { b.rtt = result.rtt; pushLog({ type: "probe_rebaselined", label: "Response time stabilized at new level", severity: SEVERITY.NORMAL,
        detail: `Sustained for a while, so the new normal is now ~${result.rtt}ms.` }); },
      recovered: ratio < RTT_RECOVER_RATIO,
      onRecover: () => { b.rtt = result.rtt; pushLog({ type: "probe_rtt_recovered", label: "Response time back to normal", severity: SEVERITY.NORMAL,
        detail: `Back to ~${result.rtt}ms.` }); },
    });
  }

  // ---------------- Native-signal analysis (android-native/) ----------------
  // Real radio-layer readings via window.KragvorNativeSignal, when present.
  // Cellular dBm uses the same relative-drop pattern as the web heuristics
  // (a weak-signal area isn't itself suspicious; a *sudden drop from your
  // own recent baseline* is). GNSS AGC + satellite dropout get their own,
  // stronger correlation below — that combination is the closest thing to
  // an actual jamming signature available without dedicated RF hardware.

  function analyzeNativeCellular(data) {
    const dbm = typeof data.dbm === "number" ? data.dbm : null;
    if (dbm == null) return;
    jamState.current.nativeCellDbm = dbm;
    if (jamState.nativeBaseline.cellDbm == null) { jamState.nativeBaseline.cellDbm = dbm; return; }
    const b = jamState.nativeBaseline;
    const dropDb = b.cellDbm - dbm; // dBm is already logarithmic — compare as a flat difference, not a ratio
    trackFlag("cellDbm", dropDb > CELL_DBM_DROP_DB, {
      onFlag: () => pushLog({ type: "cell_dbm_drop", label: "Cellular signal collapsed", severity: SEVERITY.SUSPICIOUS,
        detail: `Strongest visible cell fell from ~${b.cellDbm}dBm to ~${dbm}dBm.` }),
      onRebaseline: () => { b.cellDbm = dbm; pushLog({ type: "cell_dbm_rebaselined", label: "Cellular signal stabilized at new level", severity: SEVERITY.NORMAL,
        detail: `Sustained for a while, so ~${dbm}dBm is now the new normal.` }); },
      recovered: dropDb < CELL_DBM_DROP_DB * 0.5,
      onRecover: () => { b.cellDbm = dbm; pushLog({ type: "cell_dbm_recovered", label: "Cellular signal recovered", severity: SEVERITY.NORMAL,
        detail: `Back to ~${dbm}dBm.` }); },
    });
  }

  function analyzeNativeGnssAgc(data) {
    const agc = typeof data.avgAgcDb === "number" ? data.avgAgcDb : null;
    if (agc == null) return;
    jamState.current.nativeAgc = agc;
    if (jamState.nativeBaseline.agc == null) { jamState.nativeBaseline.agc = agc; return; }
    const b = jamState.nativeBaseline;
    const riseDb = agc - b.agc;
    trackFlag("gnssAgc", riseDb > GNSS_AGC_RISE_DB, {
      onFlag: () => pushLog({ type: "gnss_agc_spike", label: "GNSS AGC elevated", severity: SEVERITY.SUSPICIOUS,
        detail: `Receiver gain rose from ~${b.agc.toFixed(1)}dB to ~${agc.toFixed(1)}dB baseline — consistent with a raised RF noise floor.` }),
      onRebaseline: () => { b.agc = agc; pushLog({ type: "gnss_agc_rebaselined", label: "GNSS AGC stabilized at new level", severity: SEVERITY.NORMAL,
        detail: `Sustained for a while, so ~${agc.toFixed(1)}dB is now the new normal.` }); },
      recovered: riseDb < GNSS_AGC_RISE_DB * 0.5,
      onRecover: () => { b.agc = agc; pushLog({ type: "gnss_agc_recovered", label: "GNSS AGC back to normal", severity: SEVERITY.NORMAL,
        detail: `Back to ~${agc.toFixed(1)}dB.` }); },
    });
    evaluateNativeCorrelation();
  }

  function analyzeNativeGnssStatus(data) {
    const used = typeof data.satellitesUsed === "number" ? data.satellitesUsed : null;
    if (used == null) return;
    jamState.current.nativeSatUsed = used;
    jamState.current.nativeSatTotal = data.satellitesTotal;
    if (jamState.nativeBaseline.satUsed == null) {
      if (used > 0) jamState.nativeBaseline.satUsed = used; // wait for a real fix before anchoring
      return;
    }
    const b = jamState.nativeBaseline;
    if (b.satUsed <= 0) { b.satUsed = used; return; }
    const ratio = used / b.satUsed;
    trackFlag("gnssSat", ratio < SAT_USED_DROP_RATIO, {
      onFlag: () => pushLog({ type: "gnss_sat_dropout", label: "Satellites dropped out", severity: SEVERITY.SUSPICIOUS,
        detail: `Satellites used in fix fell from ~${b.satUsed} to ${used}, with ${data.satellitesTotal} still visible.` }),
      onRebaseline: () => { b.satUsed = Math.max(used, 1); pushLog({ type: "gnss_sat_rebaselined", label: "Satellite fix stabilized at new level", severity: SEVERITY.NORMAL,
        detail: `Sustained for a while, so ${used} used is now the new normal.` }); },
      recovered: ratio > SAT_USED_DROP_RATIO * 1.5,
      onRecover: () => { b.satUsed = used; pushLog({ type: "gnss_sat_recovered", label: "Satellite fix recovered", severity: SEVERITY.NORMAL,
        detail: `Back to ${used} satellites used.` }); },
    });
    evaluateNativeCorrelation();
  }

  // The one heuristic here closest to an actual jamming signature: AGC
  // elevated (receiver fighting a raised noise floor) *together with*
  // satellites dropping out of the fix, at the same time. Either alone has
  // mundane explanations (a warming-up GPS chip, dense tree cover, a
  // parking garage); both together, simultaneously, is a real RF anomaly
  // no browser-only signal can produce.
  function evaluateNativeCorrelation() {
    const both = jamState.flags.gnssAgc && jamState.flags.gnssSat;
    if (both && !jamState.nativeCorrelated) {
      jamState.nativeCorrelated = true;
      pushLog({
        type: "native_gnss_jam", label: "Possible GPS jamming detected", severity: SEVERITY.CRITICAL,
        detail: "GNSS receiver gain is elevated and satellites are dropping out of the fix at the same time — the closest signature to actual jamming this app can detect without dedicated RF hardware."
      });
    } else if (!both && jamState.nativeCorrelated) {
      jamState.nativeCorrelated = false;
    }
  }

  function onNativeEvent(kind, data) {
    if (kind === "cellular") analyzeNativeCellular(data);
    else if (kind === "gnssAgc") analyzeNativeGnssAgc(data);
    else if (kind === "gnssStatus") analyzeNativeGnssStatus(data);
    if (jamViewMounted) refresh(currentJamRoot);
  }

  async function startNativeMonitoring(root) {
    const bridge = window.KragvorNativeSignal;
    if (!bridge || !bridge.isAvailable()) { jamState.nativeActive = false; return; }
    currentJamRoot = root;
    jamState.nativeBaseline = { cellDbm: null, agc: null, satUsed: null };
    jamState.nativeCorrelated = false;
    ["cellDbm", "gnssAgc", "gnssSat"].forEach((k) => { jamState.flags[k] = false; jamState.streaks[k] = 0; jamState.flagSince[k] = null; });
    const result = await bridge.start(onNativeEvent);
    jamState.nativeActive = !!result.ok;
    if (!result.ok && result.reason && result.reason !== "unavailable") {
      pushLog({ type: "native_start_failed", label: "Native signal access unavailable", severity: SEVERITY.NORMAL,
        detail: "Falling back to browser-only detection: " + result.reason });
    }
    if (jamViewMounted) refresh(root);
  }

  async function stopNativeMonitoring() {
    const bridge = window.KragvorNativeSignal;
    jamState.nativeActive = false;
    if (bridge) await bridge.stop();
  }

  async function evaluateSample(root) {
    // Online/offline transition: always checked, never throttled — it's
    // cheap and rare enough that debouncing it would only delay a signal
    // that matters.
    const prevOnline = jamState.current.online;
    jamState.current.online = navigator.onLine;
    if (prevOnline && !jamState.current.online) {
      pushLog({ type: "offline", label: "Connection dropped", severity: SEVERITY.HIGH_RISK, detail: "Device reported going offline." });
    } else if (!prevOnline && jamState.current.online) {
      pushLog({ type: "online", label: "Connection restored", severity: SEVERITY.NORMAL, detail: "Back online." });
    }

    // Throttle the quality analysis so a native connection 'change' event
    // firing right next to a timer tick can't double-log the same shift.
    const now = Date.now();
    if (now - jamState.lastAnalysisAt < ANALYSIS_MIN_GAP_MS) { if (jamViewMounted) refresh(root); return; }
    jamState.lastAnalysisAt = now;

    const snap = connSnapshot();
    if (snap.supported) {
      jamState.current.effectiveType = snap.effectiveType;
      jamState.current.downlink = snap.downlink;
      jamState.current.rtt = snap.rtt;
      analyzeNativeSample(snap);
    } else if (jamState.probeUnreliable) {
      // Running from a file:// bundle (a common quick "wrap a site as an
      // APK" approach) rather than served over http(s): fetch() to a local
      // asset is unreliable or CORS-blocked in that scheme, so a failure
      // here reflects the packaging, not the network. Skip probing rather
      // than log false interference every few seconds.
      jamState.current.effectiveType = null;
      jamState.current.downlink = null;
      jamState.current.rtt = null;
    } else if (!jamState.probing) {
      jamState.probing = true;
      const result = await probeConnectivity();
      jamState.probing = false;
      jamState.current.effectiveType = null;
      jamState.current.downlink = null;
      jamState.current.rtt = result.rtt;
      analyzeProbeSample(result);
    }

    evaluateCorrelation();
    if (jamViewMounted) refresh(root);
  }

  function startGeoWatch(root) {
    if (!("geolocation" in navigator)) { jamState.geoUnsupported = true; return; }
    jamState.geoWatchId = navigator.geolocation.watchPosition(
      (pos) => {
        const acc = pos.coords.accuracy;
        jamState.current.geoAccuracy = acc;
        jamState.geoDenied = false;
        if (jamState.gpsBestAccuracy == null || acc < jamState.gpsBestAccuracy) {
          // Accuracy improved (or this is the first fix) — adopt it right
          // away. The old logic only ever ratcheted the reference *up* on
          // degradation and never back down, so it got permanently
          // stricter over a session; this keeps the reference honest.
          jamState.gpsBestAccuracy = acc;
          jamState.streaks.gps = 0;
          if (jamState.flags.gps) {
            jamState.flags.gps = false;
            jamState.flagSince.gps = null;
            pushLog({ type: "gps_recovered", label: "GPS accuracy recovered", severity: SEVERITY.NORMAL,
              detail: `Accuracy back to ~${Math.round(acc)}m.` });
          }
        } else if (acc - jamState.gpsBestAccuracy > GEO_ACCURACY_DROP_M) {
          jamState.streaks.gps++;
          if (!jamState.flags.gps && jamState.streaks.gps >= CONFIRM_SAMPLES) {
            jamState.flags.gps = true;
            jamState.flagSince.gps = Date.now();
            pushLog({ type: "gps_degraded", label: "GPS accuracy dropped", severity: SEVERITY.SUSPICIOUS,
              detail: `GPS accuracy worsened from ~${Math.round(jamState.gpsBestAccuracy)}m to ~${Math.round(acc)}m.` });
          }
          // Wall-clock, not a sample count: GPS fixes can arrive many
          // seconds apart (and are throttled further by maximumAge below),
          // so counting "samples" the same way as the 3s-cadence connection
          // channel would make GPS take far longer than intended to
          // rebaseline after a genuine, sustained accuracy change.
          if (jamState.flags.gps && Date.now() - jamState.flagSince.gps >= REBASELINE_MS) {
            jamState.gpsBestAccuracy = acc; jamState.flags.gps = false; jamState.streaks.gps = 0; jamState.flagSince.gps = null;
            pushLog({ type: "gps_rebaselined", label: "GPS accuracy stabilized at new level", severity: SEVERITY.NORMAL,
              detail: `Sustained for a while, so the new normal is now ~${Math.round(acc)}m.` });
          }
        }
        evaluateCorrelation();
        if (jamViewMounted) refresh(root);
      },
      (err) => {
        jamState.geoDenied = err.code === err.PERMISSION_DENIED;
        if (jamViewMounted) refresh(root);
      },
      { enableHighAccuracy: false, maximumAge: 15000, timeout: 10000 }
    );
  }

  function startMonitoring(root) {
    if (jamState.monitoring) return;
    jamState.monitoring = true;
    currentJamRoot = root;

    const initial = connSnapshot();
    jamState.connSupported = initial.supported;
    jamState.baseline = (initial.supported && initial.downlink != null)
      ? { downlink: initial.downlink, rtt: initial.rtt, effectiveType: initial.effectiveType }
      : null;
    jamState.probeBaseline = null;
    jamState.gpsBestAccuracy = null;
    jamState.geoDenied = false;
    jamState.geoUnsupported = false;
    jamState.probing = false;
    jamState.probeUnreliable = !initial.supported && location.protocol === "file:";
    jamState.lastAnalysisAt = 0;
    jamState.correlated = false;
    jamState.nativeCorrelated = false;
    jamState.flags = { downlink: false, rtt: false, netType: false, gps: false, probeRtt: false, probeFail: false, cellDbm: false, gnssAgc: false, gnssSat: false };
    jamState.streaks = { downlink: 0, rtt: 0, netType: 0, gps: 0, probeRtt: 0, cellDbm: 0, gnssAgc: 0, gnssSat: 0 };
    jamState.flagSince = { downlink: null, rtt: null, netType: null, gps: null, probeRtt: null, cellDbm: null, gnssAgc: null, gnssSat: null };

    jamState.onlineHandler = () => evaluateSample(root);
    jamState.offlineHandler = () => evaluateSample(root);
    window.addEventListener("online", jamState.onlineHandler);
    window.addEventListener("offline", jamState.offlineHandler);

    const nc = getConnection();
    if (nc && nc.addEventListener) {
      jamState.connHandler = () => evaluateSample(root);
      nc.addEventListener("change", jamState.connHandler);
    }

    startGeoWatch(root);
    startNativeMonitoring(root); // no-op fallback when not running inside the Capacitor build — see signal-native.js
    jamState.tickHandle = window.setInterval(() => evaluateSample(root), SAMPLE_MS);
    pushLog({ type: "session_start", label: "Monitoring started", severity: SEVERITY.NORMAL, detail: "" });
    paintJammer(root);
  }

  function stopMonitoring(root, { silent = false } = {}) {
    if (!jamState.monitoring) return;
    jamState.monitoring = false;
    if (jamState.tickHandle) window.clearInterval(jamState.tickHandle);
    if (jamState.geoWatchId != null && navigator.geolocation) navigator.geolocation.clearWatch(jamState.geoWatchId);
    if (jamState.onlineHandler) window.removeEventListener("online", jamState.onlineHandler);
    if (jamState.offlineHandler) window.removeEventListener("offline", jamState.offlineHandler);
    const nc = getConnection();
    if (nc && nc.removeEventListener && jamState.connHandler) nc.removeEventListener("change", jamState.connHandler);
    jamState.tickHandle = null; jamState.geoWatchId = null; jamState.connHandler = null;
    jamState.probing = false;
    stopNativeMonitoring();
    if (!silent) pushLog({ type: "session_end", label: "Monitoring stopped", severity: SEVERITY.NORMAL, detail: "" });
    paintJammer(root);
  }

  function fmt(v) { return v == null ? "—" : v; }

  function showInfoModal() {
    const nativeNote = jamState.nativeActive
      ? ` When running inside the native Android build, it also reads real cellular
          signal strength and GNSS satellite/gain data directly from the radio —
          a browser alone can never see this. Elevated GPS receiver gain together
          with satellites dropping out at the same time is flagged as possible
          jamming; that combination is a real, documented signature. Everything
          else here is still a correlated hint, not a certainty — a proper
          spectrum analyzer is the only way to actually confirm a jammer.`
      : ``;
    openModal({
      title: "How this works",
      bodyHtml: `
        <p style="font-size:13px;color:var(--text-dim);line-height:1.6;">
          Tracks connection type, bandwidth/latency, and GPS accuracy for sudden,
          sustained changes, and pays extra attention when several of those signals
          shift at once. Browsers can't read raw radio signals — on some browsers
          and inside a wrapped app, connection details aren't exposed at all, so
          this falls back to timing test requests instead. Treat a flag as a rough
          hint, not a confirmed detection.${nativeNote}
        </p>
      `,
      footHtml: `<button class="btn btn-primary" id="jam-info-ok">Got it</button>`
    });
    $("#jam-info-ok").addEventListener("click", closeModal);
  }

  function logRow(e) {
    return `
      <div class="jam-log-row">
        <div class="jam-log-dot ${sevClass(e.severity)}"></div>
        <div class="grow">
          <div class="title">${escapeHtml(e.label || e.type)}</div>
          ${e.detail ? `<div class="sub">${escapeHtml(e.detail)}</div>` : ""}
        </div>
        <div class="time">${timeAgo(e.at)}</div>
      </div>
    `;
  }

  function chipsHtml(recent) {
    const c = jamState.current;
    const items = [
      { icon: c.online ? ICONS.check : ICONS.close, value: c.online ? "Online" : "Offline", label: "Link" },
      { icon: ICONS.signal, value: jamState.connSupported ? (c.effectiveType ? c.effectiveType.toUpperCase() : "—") : (jamState.probeUnreliable ? "OFF" : "PROBE"), label: "Type" },
      { icon: ICONS.activity, value: jamState.connSupported ? fmt(c.downlink) : "—", label: "Mbps" },
      { icon: ICONS.activity, value: fmt(c.rtt), label: "ms" },
      { icon: ICONS.pin, value: c.geoAccuracy != null ? Math.round(c.geoAccuracy) : "—", label: "GPS m" },
      { icon: ICONS.alert, value: recent.filter(e => e.severity !== SEVERITY.NORMAL).length, label: "Alerts" },
    ];
    return items.map(it => `
      <div class="jam-chip">
        <div class="jam-chip-icon">${it.icon}</div>
        <div class="jam-chip-value">${escapeHtml(String(it.value))}</div>
        <div class="jam-chip-label">${escapeHtml(it.label)}</div>
      </div>
    `).join("");
  }

  function blipsHtml(recent) {
    if (!jamState.monitoring) return "";
    const items = recent.filter(e => e.severity !== SEVERITY.NORMAL).slice(0, 6);
    return items.map(e => {
      const h = hashStr(e.id);
      const angle = (h % 360) * Math.PI / 180;
      const radius = 34 + (h % 3) * 26;
      const dx = (Math.cos(angle) * radius).toFixed(1);
      const dy = (Math.sin(angle) * radius).toFixed(1);
      return `<div class="jam-blip" style="left:calc(50% + ${dx}px); top:calc(50% + ${dy}px);"></div>`;
    }).join("");
  }

  // Surfaces detection-mode/permission caveats that used to fail silently:
  // no native connection API (common inside an APK WebView) and denied or
  // unsupported geolocation.
  function bannerHtml() {
    if (!jamState.monitoring) return "";
    const notes = [];
    if (jamState.nativeActive) {
      notes.push("Native radio access active — reading real cellular signal strength and GNSS satellite/AGC data, not just browser-level hints.");
    }
    if (jamState.connSupported === false) {
      if (jamState.probeUnreliable) {
        notes.push("No native connection info, and this appears to be running from local files rather than a server — network-quality probing is off since it can't be trusted in that setup. Online/offline and GPS checks are still active.");
      } else {
        notes.push("No native connection info on this browser — using a network-probe fallback for latency/reachability instead.");
      }
    }
    if (jamState.geoDenied) {
      notes.push("Location permission was denied, so GPS-accuracy checks are off.");
    } else if (jamState.geoUnsupported) {
      notes.push("Geolocation isn't available here, so GPS-accuracy checks are off.");
    }
    if (!notes.length) return "";
    return `<div class="notice-line">${ICONS.alert}<span>${notes.map(escapeHtml).join(" ")}</span></div>`;
  }

  // Repaints only the parts that change every tick (status color, blips,
  // stat chips, banner, log) — leaves the radar shell's DOM node alone so
  // its sweep animation keeps spinning smoothly instead of restarting.
  function refresh(root) {
    const log = getLog();               // single localStorage read + JSON.parse per tick
    const recent = recentAnomalies(log);
    const status = computeStatus(recent);
    const color = sweepColorVar(status);

    const radar = $("#jam-radar", root);
    if (radar) { radar.classList.toggle("off", !jamState.monitoring); radar.style.setProperty("--sweep-color", color); }

    const label = $("#jam-status-label", root);
    if (label) { label.textContent = statusLabel(status); label.style.color = color; }

    const caption = $("#jam-caption", root);
    if (caption) caption.textContent = jamState.monitoring ? "Live" : "Standby";

    const blipsEl = $("#jam-blips", root);
    if (blipsEl) blipsEl.innerHTML = blipsHtml(recent);

    const chipsEl = $("#jam-chips", root);
    if (chipsEl) chipsEl.innerHTML = chipsHtml(recent);

    const bannerEl = $("#jam-banner", root);
    if (bannerEl) bannerEl.innerHTML = bannerHtml();

    const logEl = $("#jam-log", root);
    if (logEl) logEl.innerHTML = log.length ? log.slice(0, 50).map(logRow).join("") : `<div class="empty-state" style="padding:20px 12px;"><p>No events yet.</p></div>`;
    const clearBtn = $("#jam-clear-log", root);
    if (clearBtn) clearBtn.style.display = log.length ? "" : "none";
  }

  function paintJammer(root) {
    const recent = recentAnomalies(getLog());
    const status = computeStatus(recent);
    const color = sweepColorVar(status);
    root.innerHTML = `
      <div class="jam-hero">
        <div class="jam-radar-wrap ${jamState.monitoring ? "" : "off"}" id="jam-radar" style="--sweep-color:${color};">
          <div class="jam-radar-rings"></div>
          <div class="jam-radar-sweep"></div>
          <div id="jam-blips"></div>
          <div class="jam-radar-core"></div>
        </div>
        <div class="jam-hero-status" id="jam-status-label" style="color:${color};">${statusLabel(status)}</div>
        <div class="jam-hero-caption" id="jam-caption">${jamState.monitoring ? "Live" : "Standby"}</div>
      </div>

      <div style="display:flex; gap:8px; margin-top:16px;">
        <button class="btn ${jamState.monitoring ? "btn-danger" : "btn-primary"} btn-block" id="jam-toggle">
          ${jamState.monitoring ? "Stop" : "Start Monitoring"}
        </button>
        <button class="icon-btn" id="jam-info" aria-label="How this works">${ICONS.info}</button>
      </div>

      <div id="jam-banner"></div>

      <div class="jam-chip-row" id="jam-chips"></div>

      <div class="section-label" style="display:flex;justify-content:space-between;align-items:center;margin-top:18px;">
        <span>Log</span>
        <button class="btn-text" id="jam-clear-log" style="display:none;">Clear</button>
      </div>
      <div id="jam-log"></div>
    `;
    refresh(root);

    $("#jam-toggle", root).addEventListener("click", () => {
      if (jamState.monitoring) stopMonitoring(root); else startMonitoring(root);
    });
    $("#jam-info", root).addEventListener("click", showInfoModal);
    $("#jam-clear-log", root).addEventListener("click", () => {
      openConfirmModal({
        title: "Clear log?",
        message: "This removes every recorded event for your account. This can't be undone.",
        confirmLabel: "Clear",
        danger: true,
        onConfirm: () => { clearLog(); refresh(root); }
      });
    });
  }

  function renderJammerApp(root) {
    jamViewMounted = true;
    const stopWatching = () => {
      if (!document.body.contains(root)) {
        jamViewMounted = false;
        stopMonitoring(root, { silent: true });
        window.removeEventListener("hashchange", stopWatching);
      }
    };
    window.addEventListener("hashchange", stopWatching);
    paintJammer(root);
  }

  APPS_REGISTRY.push({
    id: "jammer-detector", name: "Jammer Detector",
    desc: "Monitors your connection for signs of wireless interference",
    icon: "signal", render: (root) => renderJammerApp(root)
  });
})();
