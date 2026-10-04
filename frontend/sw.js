/**
 * TRACESEAL Service Worker
 * Offline-First Progressive Web App Engine
 * SIH Problem Statement SIH26237
 */

const CACHE_VERSION = "traceseal-v1.0.0";
const SHELL_CACHE = `traceseal-shell-${CACHE_VERSION}`;
const FONTS_CACHE = `traceseal-fonts-${CACHE_VERSION}`;
const DATA_CACHE = `traceseal-data-${CACHE_VERSION}`;

// Core application shell routes and static resources
const SHELL_ASSETS = [
  "/",
  "/login",
  "/admin",
  "/investigator",
  "/recipient",
  "/ledger-view",
  "/static/styles.css",
  "/static/app.js",
  "/manifest.json",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
  "/static/icons/icon.svg",
  "/favicon.ico"
];

// Pre-cache application shell on install
self.addEventListener("install", (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(SHELL_CACHE).then((cache) => {
      console.log("[ServiceWorker] Pre-caching TRACESEAL application shell...");
      return cache.addAll(SHELL_ASSETS).catch((err) => {
        console.warn("[ServiceWorker] Pre-caching non-critical asset warning:", err);
      });
    })
  );
});

// Clean up previous cache versions on activate
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (![SHELL_CACHE, FONTS_CACHE, DATA_CACHE].includes(key)) {
            console.log("[ServiceWorker] Removing stale cache:", key);
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch router with offline-first resilient fallback
self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // 1. External Fonts (Google Fonts CDN: fonts.googleapis.com, fonts.gstatic.com)
  // Cache-first strategy: once downloaded, never block or depend on external CDN
  if (url.hostname === "fonts.googleapis.com" || url.hostname === "fonts.gstatic.com") {
    event.respondWith(
      caches.match(req).then((cached) => {
        if (cached) return cached;
        return fetch(req)
          .then((networkRes) => {
            if (networkRes && networkRes.status === 200) {
              const resClone = networkRes.clone();
              caches.open(FONTS_CACHE).then((cache) => cache.put(req, resClone));
            }
            return networkRes;
          })
          .catch(() => {
            // Offline fallback for fonts: return empty font or CSS so UI renders with fallback fonts
            return new Response("", { headers: { "Content-Type": "text/css" } });
          });
      })
    );
    return;
  }

  // 2. Navigation Requests (HTML Pages: /, /login, /admin, /investigator, /recipient, /ledger-view)
  if (req.mode === "navigate" || (req.method === "GET" && req.headers.get("accept")?.includes("text/html"))) {
    event.respondWith(
      fetch(req)
        .then((networkRes) => {
          // If online and page fetched successfully, cache latest copy
          if (networkRes && networkRes.status === 200) {
            const resClone = networkRes.clone();
            caches.open(SHELL_CACHE).then((cache) => cache.put(req, resClone));
          }
          return networkRes;
        })
        .catch(async () => {
          // Offline fallback: match the exact page or find best matching cached shell page
          const cached = await caches.match(req);
          if (cached) return cached;

          const pathname = url.pathname;
          const matchedByPath = await caches.match(pathname);
          if (matchedByPath) return matchedByPath;

          // Default fallback to login or home
          const fallback = await caches.match("/login") || await caches.match("/");
          return fallback || new Response("TRACESEAL is running in offline mode.", {
            headers: { "Content-Type": "text/html" }
          });
        })
    );
    return;
  }

  // 3. Static Assets (/static/*, images, manifest, css, js)
  if (url.pathname.startsWith("/static/") || url.pathname === "/manifest.json" || url.pathname.endsWith(".ico")) {
    event.respondWith(
      caches.match(req).then((cached) => {
        // Stale-While-Revalidate: return cached immediately, update in background if online
        const fetchPromise = fetch(req)
          .then((networkRes) => {
            if (networkRes && networkRes.status === 200) {
              const resClone = networkRes.clone();
              caches.open(SHELL_CACHE).then((cache) => cache.put(req, resClone));
            }
            return networkRes;
          })
          .catch(() => cached);

        return cached || fetchPromise;
      })
    );
    return;
  }

  // 4. API Requests (/api/*)
  if (url.pathname.startsWith("/api/")) {
    if (req.method === "GET") {
      // Network-First for API GET, with automatic cache fallback on network loss
      event.respondWith(
        fetch(req)
          .then((networkRes) => {
            if (networkRes && networkRes.status === 200) {
              const resClone = networkRes.clone();
              caches.open(DATA_CACHE).then((cache) => cache.put(req, resClone));
            }
            return networkRes;
          })
          .catch(async () => {
            // Network failed or offline: serve cached API response
            const cached = await caches.match(req);
            if (cached) {
              console.log("[ServiceWorker] Serving cached API response for:", url.pathname);
              return cached;
            }
            return new Response(JSON.stringify({
              error: "offline",
              message: "Network unavailable. Operating in offline-first mode.",
              cached: false
            }), {
              status: 503,
              headers: { "Content-Type": "application/json" }
            });
          })
      );
      return;
    }
  }

  // Default fetch behavior
  event.respondWith(
    fetch(req).catch(() => caches.match(req))
  );
});

// Background Sync Event (Sync queued operations when connectivity returns)
self.addEventListener("sync", (event) => {
  if (event.tag === "sync-warnings" || event.tag === "sync-outbox") {
    console.log("[ServiceWorker] Background sync triggered for tag:", event.tag);
    event.waitUntil(
      self.clients.matchAll().then((clients) => {
        clients.forEach((client) => {
          client.postMessage({ type: "TRIGGER_SYNC" });
        });
      })
    );
  }
});
