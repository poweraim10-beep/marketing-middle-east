// MME Academy service worker: shows phone notifications for new courses / lectures.
// Pushes carry no payload; the text is fetched from the academy with the student's own session.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  event.waitUntil((async () => {
    let n = null;
    try {
      const r = await fetch('/api/notifications/latest', { credentials: 'include', cache: 'no-store' });
      if (r.ok) n = (await r.json()).item;
    } catch (e) {}
    const title = (n && n.title) || '🔔 إشعار جديد من أكاديمية MME';
    await self.registration.showNotification(title, {
      body: (n && n.body) || 'في إشي جديد إلك بالأكاديمية، اضغط وشوفه.',
      icon: '/icons/icon-192.png',
      badge: '/icons/badge-96.png',
      dir: 'rtl',
      lang: 'ar',
      tag: n ? 'mme-' + n.id : 'mme',
      renotify: true,
      data: { url: '/' + ((n && n.link) || '#/my') },
    });
  })());
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = new URL((event.notification.data && event.notification.data.url) || '/', self.location.origin).href;
  event.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) {
      if (new URL(c.url).origin === self.location.origin) { await c.focus(); try { await c.navigate(url); } catch (e) {} return; }
    }
    await self.clients.openWindow(url);
  })());
});
