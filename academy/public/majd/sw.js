// «توصيلة المجد» service worker: app shell offline + phone notifications.
// Pushes carry no payload; the text is fetched from /majd-api/notif with the signed-in token kept in Cache Storage.
const CACHE = 'majd-v5';
const SHELL = ['/majd/', '/majd/manifest.webmanifest', '/majd/icons/icon-192.png'];

self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).catch(() => {})); self.skipWaiting(); });
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE && k !== 'majd-auth').map((k) => caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/majd-api/')) return;
  if (!u.pathname.startsWith('/majd/')) return;
  // network first so updates show right away; cache only when offline
  e.respondWith(fetch(e.request).then((r) => { const c = r.clone(); caches.open(CACHE).then((x) => x.put(e.request, c)); return r; }).catch(() => caches.match(e.request).then((r) => r || caches.match('/majd/'))));
});

self.addEventListener('push', (event) => {
  event.waitUntil((async () => {
    let item = null;
    try {
      const c = await caches.open('majd-auth');
      const r = await c.match('/majd-auth-token');
      const tok = r ? await r.text() : '';
      if (tok) {
        const res = await fetch('/majd-api/notif', { headers: { authorization: 'Bearer ' + tok }, cache: 'no-store' });
        if (res.ok) item = (await res.json()).item;
      }
    } catch (e) {}
    await self.registration.showNotification((item && item.title) || '🛵 توصيلة المجد', {
      body: (item && item.body) || 'في تحديث جديد على الطلبات، افتح التطبيق.',
      icon: '/majd/icons/icon-192.png',
      badge: '/majd/icons/icon-192.png',
      dir: 'rtl',
      lang: 'ar',
      tag: item ? 'majd-' + item.id : 'majd',
      renotify: true,
      vibrate: [200, 100, 200],
      data: { url: '/majd/' },
      requireInteraction: true,
    });
  })());
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      if (new URL(c.url).pathname.startsWith('/majd/')) { await c.focus(); return; }
    }
    await self.clients.openWindow('/majd/');
  })());
});
