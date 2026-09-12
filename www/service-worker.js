/* KRAGVOR service worker — cache-first offline shell. */

const CACHE_NAME = "kragvor-cache-v10";
const CORE_ASSETS = [
  "./",
  "./index.html",
  "./styles.css",
  "./app.js",
  "./signal-native.js",
  "./manifest.json",
  "./icon-192.png",
  "./icon-512.png",
  "./icon-512-maskable.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(CORE_ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);

  // Jammer Detector connectivity probes must always hit the real network,
  // uncached and un-stored: this worker is cache-first, so intercepting
  // these would either answer instantly from cache (hiding a real outage
  // behind a fake-fast reading) or, since each probe uses a unique
  // cache-busting query, have every single tick's response permanently
  // added to Cache Storage as a never-reused entry. Let the browser handle
  // these requests directly instead of touching the cache at all.
  if (url.searchParams.has("__jamprobe")) return;

  // Only ever cache-first our OWN static app files (this origin). Anything
  // else — most importantly every Supabase call (REST, Auth, Storage, Edge
  // Functions all live on a different origin) — must always hit the real
  // network. Caching those would mean every sync pull in the app (Notes,
  // Vault, Calculator, Decode, everything) could silently start serving
  // stale data forever instead of the account's real current state.
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    caches.match(req).then((cached) => cached || fetch(req).then((res) => {
      const copy = res.clone();
      caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
      return res;
    }).catch(() => cached))
  );
});
