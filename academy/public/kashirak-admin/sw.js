const C='ksr-admin-v41', SHELL=['./','index.html','manifest.webmanifest','icons/icon-192.png','icons/icon-512.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(SHELL)));self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim()).then(()=>self.clients.matchAll({type:'window'})).then(cs=>Promise.all(cs.filter(c=>c.visibilityState==='hidden'&&'navigate' in c).map(c=>c.navigate(c.url).catch(()=>{}))))))});
self.addEventListener('fetch',e=>{const u=new URL(e.request.url); if(e.request.method!=='GET'||u.origin!==location.origin||!u.pathname.startsWith('/kashirak-admin/')) return;
  e.respondWith(fetch(e.request).then(r=>{const c=r.clone(); caches.open(C).then(x=>x.put(e.request,c)); return r}).catch(()=>caches.match(e.request)))});
