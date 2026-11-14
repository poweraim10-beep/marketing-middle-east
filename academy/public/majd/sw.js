// «المجد» app shell: keeps the page and icons available offline; orders always come fresh from the server.
const CACHE = 'majd-v3';
const SHELL = ['/majd/', '/majd/manifest.webmanifest', '/majd/icons/icon-192.png'];
self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).catch(() => {})); self.skipWaiting(); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))); self.clients.claim(); });
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/majd-api/')) return;
  if (!u.pathname.startsWith('/majd/')) return;
  // network first, cache as fallback, so updates show up right away
  e.respondWith(fetch(e.request).then((r) => { const c = r.clone(); caches.open(CACHE).then((x) => x.put(e.request, c)); return r; }).catch(() => caches.match(e.request).then((r) => r || caches.match('/majd/'))));
});
