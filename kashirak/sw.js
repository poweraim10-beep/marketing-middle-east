/* كاشيرك الذكي: يحفظ ملفات التطبيق على الجهاز ليشتغل بدون إنترنت */
const IMGC='ksr-img-v1';
const CACHE='kashirak-v195';
const PAGE='./';                 /* مفتاح واحد ثابت لصفحة التطبيق */
const FILES=['manifest.webmanifest','qr.js','fonts/alexandria.woff','icons/icon-192-v2.png','icons/icon-512-v2.png','icons/maskable-512-v2.png','icons/apple-touch-icon-v2.png','icons/logo.svg','icons/logo-3d-256.png','icons/feat/barcode.jpg','icons/feat/chart.jpg','icons/feat/ledger.jpg','icons/feat/card.jpg','icons/feat/shield.jpg','icons/feat/receipt.jpg','icons/feat/coins.jpg','icons/feat/gift.jpg','icons/feat/calc.jpg','icons/land-shot.webp','icons/3d/acct.webp','icons/3d/assets.webp','icons/3d/att.webp','icons/3d/audit.webp','icons/3d/biz.webp','icons/3d/buy.webp','icons/3d/cart-new.webp','icons/3d/cash.webp','icons/3d/chq.webp','icons/3d/disc.webp','icons/3d/exp.webp','icons/3d/h-alert.webp','icons/3d/h-bt.webp','icons/3d/h-close.webp','icons/3d/h-cloud.webp','icons/3d/h-cust.webp','icons/3d/h-debts.webp','icons/3d/h-find.webp','icons/3d/h-item.webp','icons/3d/h-low.webp','icons/3d/h-print.webp','icons/3d/h-profit.webp','icons/3d/h-ret.webp','icons/3d/h-sales.webp','icons/3d/h-shield.webp','icons/3d/h-sub.webp','icons/3d/h-wa.webp','icons/3d/inv.webp','icons/3d/lab.webp','icons/3d/log.webp','icons/3d/loy.webp','icons/3d/n-debts.webp','icons/3d/n-home.webp','icons/3d/n-items.webp','icons/3d/n-more.webp','icons/3d/n-rep.webp','icons/3d/n-sell.webp','icons/3d/n-staff.webp','icons/3d/p-app.webp','icons/3d/p-cash.webp','icons/3d/p-debt.webp','icons/3d/p-split.webp','icons/3d/payroll.webp','icons/3d/pdf.webp','icons/3d/pexp.webp','icons/3d/rep.webp','icons/3d/s-cam.webp','icons/3d/s-phone.webp','icons/3d/s-wedge.webp','icons/3d/set.webp','icons/3d/sup.webp','icons/3d/support.webp','icons/3d/tour.webp','icons/3d/wh.webp'];
/* المتصفح ما بيقبل يفتح صفحة محفوظة جاية من تحويل (redirect) وقت ما في نت، فبنحفظها دايمًا كنسخة نظيفة */
const clean=async res=>res&&res.redirected?new Response(await res.blob(),{status:200,headers:res.headers}):res;
async function savePage(c,res){ if(res&&res.ok&&(res.headers.get('content-type')||'').includes('text/html')) await c.put(PAGE,await clean(res.clone())) }
self.addEventListener('install',e=>{e.waitUntil((async()=>{
  const c=await caches.open(CACHE);
  await savePage(c,await fetch(PAGE,{cache:'reload'}));
  await Promise.all(FILES.map(f=>fetch(f,{cache:'reload'}).then(r=>r.ok&&c.put(f,r)).catch(()=>{})));
  await self.skipWaiting() })())});
self.addEventListener('activate',e=>{e.waitUntil((async()=>{
  /* الصفحة المحفوظة بتضل موجودة دايمًا: إذا النسخة الجديدة ما قدرت تحفظها، بنرجّعها من القديمة قبل ما نحذفها */
  const c=await caches.open(CACHE);
  if(!(await c.match(PAGE))) for(const k of await caches.keys()){ if(k===CACHE) continue; const o=await caches.open(k); const p=(await o.match(PAGE))||(await o.match('index.html')); if(p){await c.put(PAGE,await clean(p));break} }
  for(const k of await caches.keys()) if(k!==CACHE&&k.startsWith('kashirak-')) await caches.delete(k);
  await self.clients.claim();
  /* إصدار جديد: أي نسخة قديمة مفتوحة بالخلفية بتتحدّث لحالها، والسلة محفوظة */
  const cs=await self.clients.matchAll({type:'window'}); await Promise.all(cs.filter(x=>x.visibilityState==='hidden'&&'navigate' in x).map(x=>x.navigate(x.url).catch(()=>{}))) })())});
self.addEventListener('fetch',e=>{
  const r=e.request; if(r.method!=='GET') return;
  const u=new URL(r.url);
  if(/\/(pay|catalog)\.html$/.test(u.pathname)) return; /* صفحة الدفع للزبون: من الشبكة دايمًا، وما بتنحفظ مكان التطبيق */
  if(r.mode==='navigate'){ /* الصفحة: من الشبكة إن وُجدت (بمهلة قصيرة إذا النت ضعيف)، وإلا من النسخة المحفوظة على الجهاز */
    e.respondWith((async()=>{
      const c=await caches.open(CACHE);
      const net=fetch(r).then(async res=>{ await savePage(c,res); return res });
      const cached=async()=>{ const p=(await c.match(PAGE))||(await caches.match(PAGE))||(await caches.match('index.html',{ignoreSearch:true})); return p?clean(p):null };
      try{ const res=await Promise.race([net,new Promise((_,rej)=>setTimeout(()=>rej('slow'),5000))]); if(res&&res.ok) return res; const p=await cached(); return p||res }
      catch(err){ const p=await cached(); if(p) return p; try{return await net}catch(e2){ return new Response('<meta charset=utf-8><body style="font-family:sans-serif;text-align:center;padding:40px" dir=rtl><h2>افتح التطبيق مرة وحدة وإنت متصل بالنت</h2><p>بعدها بيشتغل بدون نت.</p></body>',{headers:{'content-type':'text/html; charset=utf-8'}}) } }
    })()); return }
  if(u.origin===location.origin&&u.searchParams.has('u')) return; /* فحص التحديثات: من الشبكة دايمًا */
  /* صور أصناف القوالب: بتنحفظ مرة وحدة بمخزن خاص بيضل مع كل التحديثات، وبتطلع بدون نت */
  if(/\/kashirak-tpl\/[a-z]+\/[a-z0-9-]+\.jpg$/.test(u.pathname)||(u.origin===location.origin&&/\/icons\/veg\/[a-z0-9-]+\.jpg$/.test(u.pathname))||(u.origin===location.origin&&/\/kashirak\/help\/[a-z0-9_]+\.webp$/.test(u.pathname))){
    e.respondWith((async()=>{ const c=await caches.open(IMGC), k=u.origin+u.pathname; const hit=await c.match(k); if(hit) return hit;
      try{ const res=await fetch(k,{mode:'cors'}); if(res.ok&&/^image\//.test(res.headers.get('content-type')||'')) await c.put(k,res.clone()); return res }catch(err){ return new Response('',{status:504}) } })()); return }
  if(u.origin===location.origin||/fonts\.(googleapis|gstatic)\.com|unpkg\.com|cdn\.jsdelivr\.net/.test(u.host)){ /* الخطوط والملفات: المحفوظ أولًا */
    e.respondWith(caches.match(r,{ignoreSearch:u.origin===location.origin&&/\.(png|jpg|svg|webmanifest|bin|json)$/.test(u.pathname)}).then(hit=>hit||fetch(r).then(res=>{if((res.ok&&(!/\.(png|jpe?g|svg)$/.test(u.pathname)||/^image\//.test(res.headers.get('content-type')||'')))||res.type==='opaque'){const cp=res.clone();caches.open(CACHE).then(c=>c.put(r,cp))}return res})));
  }
});
/* إشعارات كاشيرك: السيرفر بيبعت تنبيه فاضي، وإحنا بنسأله عن نص الإشعار المناسب لهالمحل وهالساعة */
const KAPI='https://academy.marketingmiddleeast.com/kashirak-api';
self.addEventListener('push',e=>{e.waitUntil((async()=>{
  let m={title:'كاشيرك الذكي',body:'افتح التطبيق وكمّل شغلك'};
  try{ const s=await self.registration.pushManager.getSubscription(); const r=await fetch(KAPI+'/push/msg?e='+encodeURIComponent(s?s.endpoint:''),{cache:'no-store'}); if(r.ok){const j=await r.json(); if(j&&j.title) m=j} }catch(err){}
  await self.registration.showNotification(m.title,{body:m.body,icon:'icons/icon-192-v2.png',badge:'icons/icon-192-v2.png',tag:'kashirak',renotify:true,dir:'rtl',lang:'ar',data:{url:'./'}});
})())});
self.addEventListener('notificationclick',e=>{e.notification.close(); e.waitUntil((async()=>{
  const cs=await self.clients.matchAll({type:'window',includeUncontrolled:true});
  for(const c of cs){ if('focus' in c) return c.focus() }
  return self.clients.openWindow('./');
})())});
