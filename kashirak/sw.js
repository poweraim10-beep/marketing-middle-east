/* كاشيرك الذكي: يحفظ ملفات التطبيق على الجهاز ليشتغل بدون إنترنت */
const CACHE='kashirak-v33';
const CORE=['./','index.html','manifest.webmanifest','icons/icon-192-v2.png','icons/icon-512-v2.png','icons/maskable-512-v2.png','icons/apple-touch-icon-v2.png','icons/logo.svg','icons/logo-3d-256.png','icons/feat/barcode.jpg','icons/feat/chart.jpg','icons/feat/ledger.jpg','icons/feat/card.jpg','icons/feat/shield.jpg','icons/feat/receipt.jpg','icons/feat/coins.jpg','icons/feat/gift.jpg','icons/feat/calc.jpg'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(CORE)).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())
  /* إصدار جديد: أي نسخة قديمة مفتوحة بالخلفية بتتحدّث لحالها، والسلة محفوظة */
  .then(()=>self.clients.matchAll({type:'window'})).then(cs=>Promise.all(cs.filter(c=>c.visibilityState==='hidden'&&'navigate' in c).map(c=>c.navigate(c.url).catch(()=>{})))))});
self.addEventListener('fetch',e=>{
  const r=e.request; if(r.method!=='GET') return;
  const u=new URL(r.url);
  if(r.mode==='navigate'){ /* الصفحة: من الشبكة إن وُجدت، وإلا من النسخة المحفوظة */
    e.respondWith(fetch(r).then(res=>{const cp=res.clone();caches.open(CACHE).then(c=>c.put('index.html',cp));return res}).catch(()=>caches.match('index.html')));return}
  if(u.origin===location.origin||/fonts\.(googleapis|gstatic)\.com|unpkg\.com/.test(u.host)){ /* الخطوط والملفات: المحفوظ أولًا */
    e.respondWith(caches.match(r).then(hit=>hit||fetch(r).then(res=>{if(res.ok||res.type==='opaque'){const cp=res.clone();caches.open(CACHE).then(c=>c.put(r,cp))}return res})));
  }
});
