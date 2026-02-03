/* Saran SW - safe for Safari (avoid redirected responses) */
const VERSION = 'saran-sw-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/styles.css',
  '/app.js',
  '/manifest.webmanifest',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/maskable-512.png',
];

function cloneNoRedirect(resp) {
  // Safari can throw: "Response served by service worker has redirections"
  // if you return/cached a redirected Response. Rebuild the Response.
  return resp.arrayBuffer().then(buf => new Response(buf, {
    status: resp.status,
    statusText: resp.statusText,
    headers: resp.headers,
  }));
}

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(VERSION);
    for (const url of ASSETS) {
      try {
        const resp = await fetch(url, { cache: 'reload' });
        if (resp.ok) {
          const clean = await cloneNoRedirect(resp.clone());
          await cache.put(url, clean);
        }
      } catch (_) {}
    }
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map(k => (k !== VERSION) ? caches.delete(k) : null));
    self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Only handle same-origin
  if (url.origin !== location.origin) return;

  // Never cache API calls
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(req));
    return;
  }

  // SPA navigation: serve cached index.html
  if (req.mode === 'navigate') {
    event.respondWith((async () => {
      const cache = await caches.open(VERSION);
      const cached = await cache.match('/index.html');
      if (cached) return cached;
      const resp = await fetch('/index.html', { cache: 'reload' });
      if (resp.ok) {
        const clean = await cloneNoRedirect(resp.clone());
        await cache.put('/index.html', clean);
      }
      return resp;
    })());
    return;
  }

  // Assets: stale-while-revalidate
  event.respondWith((async () => {
    const cache = await caches.open(VERSION);
    const cached = await cache.match(req);
    const fetchPromise = (async () => {
      try {
        const resp = await fetch(req, { cache: 'no-cache' });
        if (resp && resp.ok) {
          const clean = await cloneNoRedirect(resp.clone());
          await cache.put(req, clean);
        }
        return resp;
      } catch (e) {
        return null;
      }
    })();

    if (cached) {
      event.waitUntil(fetchPromise);
      return cached;
    }
    const resp = await fetchPromise;
    return resp || new Response('Offline', { status: 503 });
  })());
});
