// «كاشيرك الذكي» — shop accounts, cloud backup and multi-device sync (Cloudflare Pages Function, D1 binding: DB)
// Routes live under /kashirak-api/*. Separate tables (ksr_*) inside the academy database.
// Model: one shop = one account (phone + password). One "main" device sells and uploads the shop
// snapshot (gzip, base64, chunked); every other signed-in device follows it read-only and can take over.

const PBKDF2_ITER = 100000;
const TOKEN_DAYS = 365;
const CHUNK = 900000; // D1 rows stay well under 2 MB
const MAX_STATE = 40e6;
const MAX_BLOB = 1.6e6;
const ACADEMY_OWNER = 'power.ai.m10@gmail.com';

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, PUT, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type, x-device',
  'access-control-max-age': '86400',
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS } });
const err = (msg, status = 400, extra = {}) => json({ error: msg, ...extra }, status);
const nowMs = () => Date.now();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const randomHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const b64u = (s) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => decodeURIComponent(escape(atob(s.replace(/-/g, '+').replace(/_/g, '/'))));
async function body(req) { try { return await req.json(); } catch { return {}; } }
const clean = (s, max = 200) => String(s ?? '').trim().slice(0, max);
const phoneOf = (p) => String(p ?? '').replace(/[^\d]/g, '').replace(/^00/, '').slice(-12);

async function hashSecret(secret, saltHex) {
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(secret)), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER }, key, 256);
  return hex(bits);
}
function same(a, b) {
  a = String(a || ''); b = String(b || '');
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg)));
}

// ---------- storage ----------
let ready = false;
async function ensure(env) {
  if (ready) return;
  await env.DB.batch([
    env.DB.prepare('CREATE TABLE IF NOT EXISTS ksr_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS ksr_shops (id TEXT PRIMARY KEY, phone TEXT UNIQUE NOT NULL, name TEXT, salt TEXT NOT NULL, hash TEXT NOT NULL, main TEXT, version INTEGER NOT NULL DEFAULT 0, size INTEGER NOT NULL DEFAULT 0, updated INTEGER, created INTEGER NOT NULL, devices TEXT NOT NULL DEFAULT \'{}\', meta TEXT NOT NULL DEFAULT \'{}\')'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS ksr_chunks (shop TEXT NOT NULL, i INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY (shop, i))'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS ksr_blobs (shop TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, t INTEGER NOT NULL, PRIMARY KEY (shop, id))'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS ksr_fail (ip TEXT NOT NULL, t INTEGER NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS ksr_codes (code TEXT PRIMARY KEY, plan TEXT NOT NULL, days INTEGER NOT NULL, price REAL NOT NULL DEFAULT 0, note TEXT, created INTEGER NOT NULL, status TEXT NOT NULL DEFAULT \'new\', used_at INTEGER, used_for TEXT, used_label TEXT, kind TEXT NOT NULL DEFAULT \'code\')'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS ksr_lic (id TEXT PRIMARY KEY, exp INTEGER NOT NULL, plan TEXT, updated INTEGER NOT NULL, label TEXT, note TEXT)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS ksr_dev (id TEXT PRIMARY KEY, shop TEXT, phone TEXT, first INTEGER NOT NULL, last INTEGER NOT NULL, trial_end INTEGER, sales INTEGER, items INTEGER, ver TEXT, account TEXT)'),
  ]);
  // columns added later: each ALTER fails harmlessly once the column exists
  for (const q of [
    'ALTER TABLE ksr_shops ADD COLUMN acct INTEGER', 'ALTER TABLE ksr_shops ADD COLUMN owner TEXT', 'ALTER TABLE ksr_shops ADD COLUMN trial_end INTEGER',
    'ALTER TABLE ksr_shops ADD COLUMN fp TEXT', 'ALTER TABLE ksr_shops ADD COLUMN ip TEXT',
    'ALTER TABLE ksr_codes ADD COLUMN acct INTEGER', 'ALTER TABLE ksr_codes ADD COLUMN owner TEXT',
    'CREATE UNIQUE INDEX IF NOT EXISTS ksr_shops_acct ON ksr_shops (acct)',
    'CREATE TABLE IF NOT EXISTS ksr_join (ip TEXT NOT NULL, t INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS ksr_hist (shop TEXT NOT NULL, ver INTEGER NOT NULL, t INTEGER NOT NULL, size INTEGER NOT NULL, meta TEXT, why TEXT, PRIMARY KEY (shop, ver))',
    'CREATE TABLE IF NOT EXISTS ksr_hist_chunks (shop TEXT NOT NULL, ver INTEGER NOT NULL, i INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY (shop, ver, i))',
    'ALTER TABLE ksr_shops ADD COLUMN restored INTEGER',
    'ALTER TABLE ksr_shops ADD COLUMN wa TEXT',
    'ALTER TABLE ksr_shops ADD COLUMN sellers TEXT',
    'ALTER TABLE ksr_shops ADD COLUMN multi INTEGER',
    'CREATE TABLE IF NOT EXISTS ksr_ops (shop TEXT NOT NULL, id TEXT NOT NULL, dev TEXT, t INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY (shop, id))',
    'CREATE TABLE IF NOT EXISTS ksr_sig (shop TEXT NOT NULL, k TEXT NOT NULL, v TEXT, t INTEGER NOT NULL, PRIMARY KEY (shop, k))',
    'CREATE TABLE IF NOT EXISTS ksr_scans (id INTEGER PRIMARY KEY AUTOINCREMENT, shop TEXT NOT NULL, code TEXT NOT NULL, t INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS ksr_push (endpoint TEXT PRIMARY KEY, shop TEXT NOT NULL, dev TEXT, t INTEGER NOT NULL, last INTEGER NOT NULL DEFAULT 0, bc TEXT)',
  ]) { try { await env.DB.prepare(q).run(); } catch {} }
  ready = true;
}
const TRIAL_MS = 5 * 864e5;
async function newAcct(env) {
  for (let k = 0; k < 20; k++) {
    const n = 100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000);
    if (!(await env.DB.prepare('SELECT 1 FROM ksr_shops WHERE acct = ?').bind(n).first())) return n;
  }
  throw new Error('ما قدرنا نطلّع رقم حساب');
}
async function ensureAcct(env, shop) { // shops from before account numbers get one the first time they are seen
  if (shop.acct) return shop;
  const n = await newAcct(env);
  await env.DB.prepare('UPDATE ksr_shops SET acct = ?, trial_end = COALESCE(trial_end, ?) WHERE id = ? AND acct IS NULL').bind(n, (shop.created || nowMs()) + TRIAL_MS, shop.id).run();
  return await env.DB.prepare('SELECT * FROM ksr_shops WHERE id = ?').bind(shop.id).first();
}
async function secret(env) {
  const r = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind('secret').first();
  if (r) return r.v;
  const s = randomHex(32);
  await env.DB.prepare('INSERT OR IGNORE INTO ksr_kv (k, v) VALUES (?, ?)').bind('secret', s).run();
  const again = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind('secret').first();
  return again ? again.v : s;
}
async function tooManyFails(env, ip) {
  const since = nowMs() - 15 * 60e3;
  await env.DB.prepare('DELETE FROM ksr_fail WHERE t < ?').bind(since).run();
  const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM ksr_fail WHERE ip = ?').bind(ip).first();
  return (r && r.n) >= 10;
}
async function noteFail(env, ip) { await env.DB.prepare('INSERT INTO ksr_fail (ip, t) VALUES (?, ?)').bind(ip, nowMs()).run(); }

// token = shop id + password salt (a password change logs every device out)
async function makeToken(env, shop) {
  const payload = b64u(JSON.stringify({ s: shop.id, v: shop.salt, exp: nowMs() + TOKEN_DAYS * 864e5 }));
  return payload + '.' + (await hmac(await secret(env), payload));
}
async function readShop(env, req) {
  const h = req.headers.get('authorization') || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  const [payload, sig] = tok.split('.');
  if (!payload || !sig) return null;
  if (!same(sig, await hmac(await secret(env), payload))) return null;
  let p; try { p = JSON.parse(unb64u(payload)); } catch { return null; }
  if (!p || p.exp < nowMs()) return null;
  const shop = await env.DB.prepare('SELECT * FROM ksr_shops WHERE id = ?').bind(p.s).first();
  if (!shop || shop.salt !== p.v) return null;
  return shop;
}
const waOf = (w) => { const d = String(w || '').replace(/\D/g, '').replace(/^00/, ''); return /^97[02]5\d{8}$/.test(d) ? d : ''; };
// البيع من جوالين: الجهاز الأساسي + جوال بائع ثاني واحد. والحساب كله بينفتح على 3 أجهزة بالكثير (بائعين + جهاز متابعة)
const MAX_DEV = 3, DEV_ACTIVE = 30 * 864e5;
const sellersOf = (s) => { try { const a = JSON.parse(s.sellers || '[]'); return Array.isArray(a) ? a.filter((x) => x && x !== s.main).slice(0, 1) : []; } catch { return []; } };
const devsOf = (s) => { try { return JSON.parse(s.devices || '{}') || {}; } catch { return {}; } };
const activeDevs = (s) => Object.entries(devsOf(s)).filter(([k, v]) => k === s.main || (v && v.last > nowMs() - DEV_ACTIVE && !/طلب دخول/.test(v.label || ''))).map(([k, v]) => ({ id: k, label: (v.label || 'جهاز').replace(/ \(طلب دخول\)$/, ''), last: v.last, main: k === s.main, seller: sellersOf(s).includes(k) }));
const pubShop = (s) => ({ multi: !!s.multi, sellers: s.multi ? sellersOf(s) : [], restored: s.restored || 0, wa: s.wa || '', id: s.id, acct: s.acct, owner: s.owner, phone: s.phone, name: s.name, main: s.main, version: s.version, updated: s.updated, size: s.size, haspass: !!s.hash });
async function seen(env, shop, device, label) {
  if (!device) return;
  let d = {}; try { d = JSON.parse(shop.devices || '{}'); } catch {}
  const prev = d[device] || {};
  d[device] = { label: clean(label || prev.label || '', 60), first: prev.first || nowMs(), last: nowMs() };
  const keys = Object.keys(d).sort((a, b) => d[b].last - d[a].last).slice(0, 12);
  const out = {}; for (const k of keys) out[k] = d[k];
  await env.DB.prepare('UPDATE ksr_shops SET devices = ? WHERE id = ?').bind(JSON.stringify(out), shop.id).run();
}
async function dropDev(env, shop, dev) {
  const d = devsOf(shop); delete d[dev];
  await env.DB.prepare('UPDATE ksr_shops SET devices = ?, sellers = ? WHERE id = ?').bind(JSON.stringify(d), JSON.stringify(sellersOf(shop).filter((x) => x !== dev)), shop.id).run();
}
// ---------- version history: every shop keeps its recent cloud copies, so nothing can be lost by one bad upload ----------
const HIST_KEEP = 20, HIST_EVERY = 6 * 3600e3;
function snapStmts(env, shop, why, prune = true) { // copy the CURRENT cloud copy into history (same batch as the overwrite = atomic)
  return [
    env.DB.prepare('INSERT OR REPLACE INTO ksr_hist (shop, ver, t, size, meta, why) VALUES (?, ?, ?, ?, ?, ?)').bind(shop.id, shop.version, shop.updated || nowMs(), shop.size || 0, shop.meta || '{}', why),
    env.DB.prepare('DELETE FROM ksr_hist_chunks WHERE shop = ? AND ver = ?').bind(shop.id, shop.version),
    env.DB.prepare('INSERT INTO ksr_hist_chunks (shop, ver, i, data) SELECT shop, ?, i, data FROM ksr_chunks WHERE shop = ?').bind(shop.version, shop.id),
  ].concat(prune ? [
    env.DB.prepare('DELETE FROM ksr_hist WHERE shop = ? AND ver NOT IN (SELECT ver FROM ksr_hist WHERE shop = ? ORDER BY ver DESC LIMIT ?)').bind(shop.id, shop.id, HIST_KEEP),
    env.DB.prepare('DELETE FROM ksr_hist_chunks WHERE shop = ? AND ver NOT IN (SELECT ver FROM ksr_hist WHERE shop = ?)').bind(shop.id, shop.id),
  ] : []);
}
async function needSnap(env, shop, newSize) {
  if (!shop.version || !shop.size) return null;
  if (newSize < shop.size * 0.6) return 'shrink'; // a much smaller upload than before: always keep the previous copy
  const r = await env.DB.prepare('SELECT MAX(t) AS t FROM ksr_hist WHERE shop = ?').bind(shop.id).first();
  return !r || !r.t || nowMs() - r.t > HIST_EVERY ? 'auto' : null;
}
async function readState(env, id) {
  const r = await env.DB.prepare('SELECT data FROM ksr_chunks WHERE shop = ? ORDER BY i').bind(id).all();
  return (r.results || []).map((x) => x.data).join('');
}
// ---------- licences: ECDSA P-256. The private key lives only in D1; the app embeds the public key ----------
const LIC_EPOCH = Date.UTC(2026, 0, 1);
const DAYMS = 864e5;
const LIFETIME = 29200; // ~80 years, shown as «مفتوح»
const todayDay = () => Math.floor((Date.now() - LIC_EPOCH) / DAYMS);
const PLANS = { m1: ['شهر', 30], m2: ['شهرين', 60], m3: ['3 شهور', 90], m6: ['6 شهور', 182], y1: ['سنة', 365], life: ['مفتوح', 0] };
const b64uBytes = (u8) => { let s = ''; for (const b of u8) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
async function signKey(env) {
  let r = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind('sign_priv').first();
  if (!r) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const priv = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
    const pub = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.publicKey));
    await env.DB.batch([
      env.DB.prepare('INSERT OR IGNORE INTO ksr_kv (k, v) VALUES (?, ?)').bind('sign_priv', priv),
      env.DB.prepare('INSERT OR IGNORE INTO ksr_kv (k, v) VALUES (?, ?)').bind('sign_pub', pub),
    ]);
    r = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind('sign_priv').first();
  }
  return crypto.subtle.importKey('jwk', JSON.parse(r.v), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}
async function signLicense(env, row) {
  const [t, id] = row.id.split(':');
  const payload = b64u(JSON.stringify({ t, id, e: row.exp, p: row.plan || '', i: Date.now() }));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, await signKey(env), new TextEncoder().encode(payload)));
  return payload + '.' + b64uBytes(sig);
}
// the one certificate the app trusts: account + the ONE device allowed to sell + paid-until day + trial end
async function signShop(env, shop) {
  shop = await ensureAcct(env, shop);
  const L = await env.DB.prepare('SELECT * FROM ksr_lic WHERE id = ?').bind('shop:' + shop.id).first();
  const payload = b64u(JSON.stringify({ t: 'shop', id: shop.id, a: shop.acct, d: shop.main, s: shop.multi ? sellersOf(shop) : [], e: L ? L.exp : -1, tr: shop.trial_end || 0, p: L ? (L.plan || '') : 'trial', i: Date.now() }));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, await signKey(env), new TextEncoder().encode(payload)));
  return payload + '.' + b64uBytes(sig);
}
async function extendLic(env, id, days, plan, label) {
  const cur = await env.DB.prepare('SELECT * FROM ksr_lic WHERE id = ?').bind(id).first();
  const base = Math.max(todayDay(), cur ? cur.exp : 0);
  const exp = days === 0 ? LIFETIME : Math.min(LIFETIME, (cur && cur.exp >= LIFETIME ? LIFETIME : base + days));
  await env.DB.prepare('INSERT INTO ksr_lic (id, exp, plan, updated, label) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET exp = excluded.exp, plan = excluded.plan, updated = excluded.updated, label = COALESCE(excluded.label, ksr_lic.label)')
    .bind(id, exp, plan, nowMs(), label || null).run();
  return { id, exp, plan };
}
const CODE_ABC = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function newCode() { const b = crypto.getRandomValues(new Uint8Array(8)); let s = ''; for (const x of b) s += CODE_ABC[x % CODE_ABC.length]; return 'KSR-' + s.slice(0, 4) + '-' + s.slice(4); }
const normCode = (c) => { const s = String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '').replace(/^KSR/, ''); return s.length === 8 ? 'KSR-' + s.slice(0, 4) + '-' + s.slice(4) : ''; };

async function isAcademyOwner(env, req) {
  const c = req.headers.get('cookie') || '';
  const m = c.match(/(?:^|;\s*)mme_s=([^;]+)/);
  if (!m) return false;
  try {
    const th = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(decodeURIComponent(m[1]))));
    const u = await env.DB.prepare('SELECT u.email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?')
      .bind(th, Math.floor(Date.now() / 1000)).first();
    return !!u && String(u.email || '').toLowerCase() === ACADEMY_OWNER;
  } catch { return false; }
}


// ---------- إشعارات الجوال (Web Push + VAPID بدون محتوى: الـ service worker بيسأل السيرفر عن نص الإشعار) ----------
// نفس مفاتيح VAPID تبعت الأكاديمية (جدول settings)، فمفتاح واحد للموقع كله.
const pB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function pSetting(env, k) { try { const r = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(k).first(); return r ? r.value : null; } catch { return null; } }
async function pKeys(env) {
  let pub = await pSetting(env, 'vapid_pub'), priv = await pSetting(env, 'vapid_priv');
  if (!pub || !priv) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)').run();
    await env.DB.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('vapid_pub', ?)").bind(pB64(await crypto.subtle.exportKey('raw', kp.publicKey))).run();
    await env.DB.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('vapid_priv', ?)").bind(JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey))).run();
    pub = await pSetting(env, 'vapid_pub'); priv = await pSetting(env, 'vapid_priv');
  }
  return { pub, priv };
}
async function pAuth(env, endpoint) {
  const { pub, priv } = await pKeys(env);
  const key = await crypto.subtle.importKey('jwk', JSON.parse(priv), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const enc = (o) => pB64(new TextEncoder().encode(JSON.stringify(o)));
  const head = enc({ typ: 'JWT', alg: 'ES256' }), bodyP = enc({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'mailto:info@marketingmiddleeast.com' });
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(head + '.' + bodyP));
  return 'vapid t=' + head + '.' + bodyP + '.' + pB64(sig) + ', k=' + pub;
}
async function pSend(env, endpoint) {
  try {
    const r = await fetch(endpoint, { method: 'POST', headers: { TTL: '7200', Urgency: 'normal', Authorization: await pAuth(env, endpoint), 'Content-Length': '0' } });
    if (r.status === 404 || r.status === 410) { await env.DB.prepare('DELETE FROM ksr_push WHERE endpoint = ?').bind(endpoint).run(); return false; }
    return r.ok;
  } catch { return false; }
}
const gazaHour = () => parseInt(new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Gaza', hour: '2-digit', hour12: false }).format(new Date()), 10) % 24;
// نص الإشعار حسب الساعة ووضع المحل (تجربة، قرب الانتهاء، خلص الاشتراك)
async function pMessage(env, shopId) {
  const sh = await env.DB.prepare('SELECT * FROM ksr_shops WHERE id = ?').bind(shopId).first();
  if (!sh) return null;
  const L = await env.DB.prepare('SELECT * FROM ksr_lic WHERE id = ?').bind('shop:' + sh.id).first();
  const paidEnd = L && L.exp >= 0 ? LIC_EPOCH + (L.exp + 1) * DAYMS : 0, end = Math.max(sh.trial_end || 0, paidEnd), paid = paidEnd > (sh.trial_end || 0);
  const left = Math.ceil((end - nowMs()) / DAYMS), first = String(sh.owner || '').trim().split(/\s+/)[0] || '';
  const ya = first ? ' يا ' + first : '', h = gazaHour(), slot = Math.floor(h / 2) * 2;
  if (left <= 0 && [10, 16].includes(slot)) return { title: paid ? '⚠️ اشتراكك خلص' : '⚠️ انتهت التجربة المجانية', body: 'بياناتك كلها محفوظة. اشترك من التطبيق وكمّل شغلك بدون ما تخسر ولا إشي' };
  if (left > 0 && left <= (paid ? 3 : 5) && [12, 18].includes(slot)) return { title: paid ? `⏳ اشتراكك بينتهي بعد ${left} يوم` : `🎁 باقي ${left} ${left === 1 ? 'يوم' : 'أيام'} على تجربتك`, body: 'اشترك الآن من «اشترك الآن» داخل التطبيق، وكمّل شغلك بدون توقف' };
  const M = {
    6: ['صباح الخير' + ya + ' ☀️', 'افتح كاشيرك وابدأ يومك، أول بيعة على بركة الله'],
    8: ['صباح الخير' + ya + ' ☀️', 'افتح كاشيرك وابدأ يومك، أول بيعة على بركة الله'],
    10: ['يلا' + ya + ' 💪', 'سجّل كل بيعة أول بأول، وخلي حسابك مضبوط بالقرش'],
    12: ['نص النهار 📊', 'شوف قديش بعت لهلأ وكم ربحت، كله بكاشيرك'],
    14: ['دفتر الديون 📒', 'في زبون عليه دين؟ ابعتله كشف حسابه على الواتساب بضغطة'],
    16: ['شيك على المخزون 📦', 'شوف الأصناف اللي قرّبت تخلص قبل ما تنقطع عندك'],
    18: ['مساء الخير' + ya + ' 🌙', 'كيف كانت مبيعات اليوم؟ افتح التقارير وشوف ربحك'],
    20: ['قبل ما تسكّر المحل 💰', 'اقفل الصندوق وشوف صافي ربح اليوم'],
  };
  const [title, body] = M[slot] || M[18];
  return { title, body };
}

export async function onRequest({ request, env, params }) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (!env.DB) return err('قاعدة البيانات غير مربوطة', 500);
  await ensure(env);
  const parts = [].concat(params.path || []).filter(Boolean);
  const [a, b] = parts;
  const m = request.method;
  const ip = request.headers.get('cf-connecting-ip') || 'x';
  const url = new URL(request.url);

  try {
    if (a === 'ping') return json({ ok: true, t: nowMs() });

    // ----- first start on a device: every shop gets ONE account (by phone), bound to this device -----
    if (a === 'join' && m === 'POST') {
      const q = await body(request);
      const phone = phoneOf(q.phone), device = clean(q.device, 40), owner = clean(q.owner, 60), name = clean(q.shop, 80), fp = clean(q.fp, 64);
      if (!/^(0?5[69]\d{7}|97[02]5[69]\d{7})$/.test(phone)) return err('رقم الجوال مش صحيح. اكتبه هيك: 059xxxxxxx أو 056xxxxxxx', 400, { code: 'phone' });
      if (owner.length < 2) return err('اكتب اسم صاحب المحل');
      if (!name) return err('اكتب اسم المحل');
      const wa = waOf(q.wa); if (q.wa && String(q.wa).replace(/\D/g, '').length > 3 && !wa) return err('رقم الواتساب مش صحيح. اختار 970 أو 972 واكتب الرقم بدون صفر: 59xxxxxxx', 400, { code: 'wa' });
      if (!device) return err('رقم الجهاز ناقص');
      let shop = await env.DB.prepare('SELECT * FROM ksr_shops WHERE phone = ?').bind(phone).first();
      if (shop) {
        if (shop.main !== device) {
          await seen(env, shop, device, clean(q.label, 60) + ' (طلب دخول)');
          return err('هذا الرقم مسجّل على جهاز ثاني', 409, { code: 'other_device', acct: (await ensureAcct(env, shop)).acct, haspass: !!shop.hash });
        }
        await env.DB.prepare('UPDATE ksr_shops SET owner = COALESCE(owner, ?), name = COALESCE(name, ?), wa = COALESCE(?, wa) WHERE id = ?').bind(owner, name, wa || null, shop.id).run();
        shop = await ensureAcct(env, await env.DB.prepare('SELECT * FROM ksr_shops WHERE id = ?').bind(shop.id).first());
      } else {
        const day = nowMs() - 864e5;
        await env.DB.prepare('DELETE FROM ksr_join WHERE t < ?').bind(day).run();
        const j = await env.DB.prepare('SELECT COUNT(*) AS n FROM ksr_join WHERE ip = ?').bind(ip).first();
        if ((j && j.n) >= 25) return err('انعمل محلات كثير من نفس الشبكة اليوم. تواصل مع الدعم', 429);
        const since = Number(q.since) || 0; // installs from before accounts keep their original trial start (never a longer trial)
        const t0 = since > nowMs() - 180 * 864e5 && since < nowMs() ? since : nowMs();
        const salt = randomHex(16), id = randomHex(10), acct = await newAcct(env);
        await env.DB.prepare('INSERT INTO ksr_shops (id, phone, name, salt, hash, main, version, size, updated, created, devices, meta, acct, owner, trial_end, fp, ip, wa) VALUES (?, ?, ?, ?, \'\', ?, 0, 0, NULL, ?, ?, \'{}\', ?, ?, ?, ?, ?, ?)')
          .bind(id, phone, name, salt, device, nowMs(), JSON.stringify({ [device]: { label: clean(q.label, 60), first: nowMs(), last: nowMs() } }), acct, owner, t0 + TRIAL_MS, fp || null, ip, wa || null).run();
        await env.DB.prepare('INSERT INTO ksr_join (ip, t) VALUES (?, ?)').bind(ip, nowMs()).run();
        shop = await env.DB.prepare('SELECT * FROM ksr_shops WHERE id = ?').bind(id).first();
      }
      return json({ token: await makeToken(env, shop), shop: pubShop(shop), license: await signShop(env, shop) });
    }

    // ----- create a shop account -----
    if (a === 'register' && m === 'POST') {
      const q = await body(request);
      const phone = phoneOf(q.phone), password = String(q.password || ''), device = clean(q.device, 40);
      if (phone.length < 8) return err('اكتب رقم جوال صحيح');
      if (password.length < 6) return err('كلمة السر لازم تكون 6 أحرف أو أرقام على الأقل');
      if (!device) return err('رقم الجهاز ناقص');
      if (await tooManyFails(env, ip)) return err('محاولات كثيرة. جرّب بعد ربع ساعة', 429);
      const exists = await env.DB.prepare('SELECT * FROM ksr_shops WHERE phone = ?').bind(phone).first();
      if (exists && !exists.hash && exists.main === device) { // the shop sets a password so it can open from other devices
        const salt2 = randomHex(16);
        await env.DB.prepare('UPDATE ksr_shops SET salt = ?, hash = ? WHERE id = ?').bind(salt2, await hashSecret(password, salt2), exists.id).run();
        const sh2 = { ...exists, salt: salt2, hash: 'x' };
        return json({ token: await makeToken(env, sh2), shop: pubShop(sh2) });
      }
      if (exists) { await noteFail(env, ip); return err('هذا الرقم عليه حساب. ادخل بكلمة السر بدل إنشاء حساب جديد', 409); }
      const salt = randomHex(16);
      const shop = { id: randomHex(10), phone, name: clean(q.name, 80), salt, hash: await hashSecret(password, salt), main: device, version: 0, size: 0, updated: null, created: nowMs(), acct: await newAcct(env), owner: clean(q.owner, 60) || null, trial_end: nowMs() + TRIAL_MS };
      await env.DB.prepare('INSERT INTO ksr_shops (id, phone, name, salt, hash, main, version, size, updated, created, devices, meta, acct, owner, trial_end, ip) VALUES (?, ?, ?, ?, ?, ?, 0, 0, NULL, ?, ?, ?, ?, ?, ?, ?)')
        .bind(shop.id, phone, shop.name, salt, shop.hash, device, shop.created, JSON.stringify({ [device]: { label: clean(q.label, 60), first: nowMs(), last: nowMs() } }), '{}', shop.acct, shop.owner, shop.trial_end, ip).run();
      // a subscription bought on this device before the account existed now belongs to the shop
      const dl = await env.DB.prepare('SELECT * FROM ksr_lic WHERE id = ?').bind('dev:' + device).first();
      if (dl) await env.DB.batch([
        env.DB.prepare('INSERT OR REPLACE INTO ksr_lic (id, exp, plan, updated, label, note) VALUES (?, ?, ?, ?, ?, ?)').bind('shop:' + shop.id, dl.exp, dl.plan, nowMs(), shop.name || dl.label, dl.note),
        env.DB.prepare('DELETE FROM ksr_lic WHERE id = ?').bind('dev:' + device),
        env.DB.prepare('UPDATE ksr_codes SET used_for = ? WHERE used_for = ?').bind('shop:' + shop.id, 'dev:' + device),
      ]);
      return json({ token: await makeToken(env, shop), shop: pubShop(shop) });
    }

    // ----- sign in from any device -----
    if (a === 'login' && m === 'POST') {
      const q = await body(request);
      if (await tooManyFails(env, ip)) return err('محاولات كثيرة. جرّب بعد ربع ساعة', 429);
      const phone = phoneOf(q.phone);
      const shop = await env.DB.prepare('SELECT * FROM ksr_shops WHERE phone = ?').bind(phone).first();
      if (shop && !shop.hash) { return err('هذا الحساب لسا ما إله كلمة سر. حدّدها من الجهاز الأساسي: الإعدادات ← حساب المحل', 401, { code: 'nopass' }); }
      if (!shop || !same(shop.hash, await hashSecret(String(q.password || ''), shop.salt))) { await noteFail(env, ip); return err('رقم الجوال أو كلمة السر غلط', 401); }
      const ldev = clean(q.device, 40), act = activeDevs(shop);
      if (ldev && !act.some((x) => x.id === ldev) && act.length >= MAX_DEV) {
        const rp = clean(q.replace, 40);
        if (!rp || !act.some((x) => x.id === rp)) return err(`الحساب مفتوح على ${MAX_DEV} أجهزة، وهذا الحد. اختار جهاز تطلّعه من الحساب`, 409, { code: 'limit', devices: act });
        await dropDev(env, shop, rp); shop.devices = (await env.DB.prepare('SELECT devices FROM ksr_shops WHERE id = ?').bind(shop.id).first()).devices;
      }
      await seen(env, shop, ldev, q.label);
      return json({ token: await makeToken(env, shop), shop: pubShop(shop) });
    }

    if (a === 'pubkey') {
      await signKey(env);
      const r = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind('sign_pub').first();
      return json({ jwk: JSON.parse(r.v) });
    }

    // ----- redeem an activation code: only on the shop's own main device, only if the code was made for this account -----
    if (a === 'redeem' && m === 'POST') {
      const q = await body(request);
      if (await tooManyFails(env, ip)) return err('محاولات كثيرة. جرّب بعد ربع ساعة', 429);
      const code = normCode(q.code), device = clean(q.device, 40);
      if (!code) { await noteFail(env, ip); return err('الكود لازم يكون بالشكل KSR-XXXX-XXXX'); }
      let shopRow = await readShop(env, request);
      if (!shopRow) return err('لازم المحل يكون مسجّل أول. افتح التطبيق وهو متصل بالنت', 401, { code: 'noacct' });
      shopRow = await ensureAcct(env, shopRow);
      if (!device || device !== shopRow.main) return err('التفعيل بيصير بس من الجهاز الأساسي للمحل', 403, { code: 'not_main' });
      const row = await env.DB.prepare('SELECT * FROM ksr_codes WHERE code = ?').bind(code).first();
      if (!row) { await noteFail(env, ip); return err('الكود غير صحيح', 404); }
      if (row.status === 'void') return err('هذا الكود ملغي. تواصل مع الدعم', 410);
      if (row.acct && Number(row.acct) !== Number(shopRow.acct)) { await noteFail(env, ip); return err('هذا الكود مش لحسابك. الكود بيشتغل بس على رقم الحساب اللي انعمل إله', 403, { code: 'wrong_acct' }); }
      const target = 'shop:' + shopRow.id;
      if (row.status === 'used' && row.used_for !== target) return err('هذا الكود مستعمل على محل ثاني', 409);
      if (row.status !== 'used') {
        const label = shopRow.owner ? shopRow.owner + ' · ' + (shopRow.name || '') : (shopRow.name || shopRow.phone);
        await extendLic(env, target, row.days, row.plan, label);
        await env.DB.prepare("UPDATE ksr_codes SET status = 'used', used_at = ?, used_for = ?, used_label = ? WHERE code = ? AND status = 'new'").bind(nowMs(), target, label, code).run();
      }
      const L = await env.DB.prepare('SELECT * FROM ksr_lic WHERE id = ?').bind(target).first();
      return json({ license: await signShop(env, shopRow), exp: L ? L.exp : -1, plan: L ? L.plan : '' });
    }

    // ----- the app asks for its latest certificate whenever it is online (installs without an account just check in) -----
    if (a === 'license' && m === 'GET') {
      const shopRow = await readShop(env, request);
      const device = clean(url.searchParams.get('device') || '', 40);
      if (device && !/HeadlessChrome|Playwright|bot|crawler/i.test(request.headers.get('user-agent') || '')) {
        const sp = url.searchParams, t = nowMs();
        await env.DB.prepare('INSERT INTO ksr_dev (id, shop, phone, first, last, trial_end, sales, items, ver, account) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET shop = COALESCE(excluded.shop, ksr_dev.shop), phone = COALESCE(excluded.phone, ksr_dev.phone), last = excluded.last, sales = excluded.sales, items = excluded.items, ver = excluded.ver, account = COALESCE(excluded.account, ksr_dev.account)')
          .bind(device, clean(sp.get('shop') || '', 80) || null, clean(sp.get('phone') || '', 20) || null, t, t, null, parseInt(sp.get('sales'), 10) || 0, parseInt(sp.get('items'), 10) || 0, clean(sp.get('v') || '', 10) || null, shopRow ? shopRow.id : null).run().catch(() => {});
        if (shopRow && (devsOf(shopRow)[device] || activeDevs(shopRow).length < MAX_DEV)) await seen(env, shopRow, device);
      }
      if (!shopRow) return json({ license: null });
      return json({ license: await signShop(env, shopRow), main: shopRow.main });
    }


    // ----- إشعارات: مفتاح VAPID، ونص الإشعار للـ service worker، والتشغيل الدوري -----
    if (a === 'push' && b === 'key' && m === 'GET') return json({ key: (await pKeys(env)).pub });
    if (a === 'push' && b === 'msg' && m === 'GET') {
      const e = clean(url.searchParams.get('e') || '', 1000);
      const sub = e ? await env.DB.prepare('SELECT * FROM ksr_push WHERE endpoint = ?').bind(e).first() : null;
      if (!sub) return json({ title: 'كاشيرك الذكي', body: 'افتح التطبيق وكمّل شغلك' });
      let bc = null; try { bc = JSON.parse((await env.DB.prepare("SELECT v FROM ksr_kv WHERE k = 'push_bc'").first() || {}).v || 'null'); } catch {}
      if (bc && bc.id && sub.bc !== bc.id && nowMs() - bc.t < 12 * 3600e3) {
        await env.DB.prepare('UPDATE ksr_push SET bc = ? WHERE endpoint = ?').bind(bc.id, e).run();
        return json({ title: bc.title, body: bc.body });
      }
      return json((await pMessage(env, sub.shop)) || { title: 'كاشيرك الذكي', body: 'افتح التطبيق وكمّل شغلك' });
    }
    if (a === 'cron' && b === 'push') { // GitHub Actions كل ساعتين. آمن لو انطلب أكثر: كل جهاز إشعار وحد بالساعتين بالكثير، وبس بين 8 الصبح و 9 المسا
      const h = gazaHour();
      if (h < 7 || h > 21) return json({ ok: true, skipped: 'night', hour: h });
      const subs = (await env.DB.prepare('SELECT endpoint FROM ksr_push WHERE last < ?').bind(nowMs() - 100 * 60e3).all()).results || [];
      let sent = 0;
      for (const x of subs) { await env.DB.prepare('UPDATE ksr_push SET last = ? WHERE endpoint = ?').bind(nowMs(), x.endpoint).run(); if (await pSend(env, x.endpoint)) sent++; }
      return json({ ok: true, hour: h, subs: subs.length, sent });
    }

    // ----- everything below needs a shop token -----
    const shop = await readShop(env, request);
    if (a === 'admin') return admin(env, request, b);
    if (!shop) return err('سجّل دخول من جديد', 401);
    const device = clean(url.searchParams.get('device') || request.headers.get('x-device') || '', 40);
    if (a === 'push' && b === 'sub' && m === 'POST') {
      const q = await body(request), e = clean(q.endpoint, 1000);
      if (!/^https:\/\//.test(e)) return err('اشتراك الإشعارات مش صحيح');
      await env.DB.prepare('INSERT INTO ksr_push (endpoint, shop, dev, t, last) VALUES (?, ?, ?, ?, 0) ON CONFLICT(endpoint) DO UPDATE SET shop = excluded.shop, dev = excluded.dev, t = excluded.t').bind(e, shop.id, device || null, nowMs()).run();
      return json({ ok: true });
    }
    if (a === 'push' && b === 'off' && m === 'POST') {
      const q = await body(request); await env.DB.prepare('DELETE FROM ksr_push WHERE endpoint = ? AND shop = ?').bind(clean(q.endpoint, 1000), shop.id).run(); return json({ ok: true });
    }

    if (a === 'state' && m === 'GET') {
      if (device && !devsOf(shop)[device] && activeDevs(shop).length >= MAX_DEV) return err('هذا الجهاز انطلع من حساب المحل. ادخل من جديد', 401, { code: 'dropped' });
      await seen(env, shop, device);
      const have = parseInt(url.searchParams.get('have') || '-1', 10);
      const out = { shop: pubShop(shop) };
      if (shop.version > have && shop.version > 0) out.data = await readState(env, shop.id);
      const ops = (await env.DB.prepare('SELECT data FROM ksr_ops WHERE shop = ? ORDER BY t LIMIT 800').bind(shop.id).all()).results || [];
      if (ops.length) out.ops = ops.map((x) => { try { return JSON.parse(x.data); } catch { return null; } }).filter(Boolean);
      return json(out);
    }

    if (a === 'state' && m === 'PUT') {
      const q = await body(request);
      const dev = clean(q.device, 40);
      if (dev !== shop.main) return err('جهاز ثاني صار هو الأساسي', 409, { code: 'not_main', shop: pubShop(shop) });
      if (Number(q.base) !== shop.version) return err('في نسخة أحدث على الحساب', 409, { code: 'stale', shop: pubShop(shop) });
      const data = String(q.data || '');
      if (!data || data.length > MAX_STATE) return err('حجم البيانات غير مقبول', 413);
      if (!/^(g:|p:\{)/.test(data) || data.length < 40) return err('نسخة البيانات ناقصة أو تالفة، ما انحفظت', 422);
      const meta = JSON.stringify(q.meta && typeof q.meta === 'object' ? q.meta : {}).slice(0, 4000);
      const t = nowMs();
      const upd = await env.DB.prepare('UPDATE ksr_shops SET version = version + 1, updated = ?, size = ?, meta = ?, name = COALESCE(?, name) WHERE id = ? AND version = ? AND main = ?')
        .bind(t, data.length, meta, q.name ? clean(q.name, 80) : null, shop.id, shop.version, dev).run();
      if (!upd.meta || !upd.meta.changes) return err('في نسخة أحدث على الحساب', 409, { code: 'stale' });
      const why = await needSnap(env, shop, data.length);
      const stmts = [...(why ? snapStmts(env, shop, why) : []), env.DB.prepare('DELETE FROM ksr_chunks WHERE shop = ?').bind(shop.id)];
      for (let i = 0, k = 0; i < data.length; i += CHUNK, k++) stmts.push(env.DB.prepare('INSERT INTO ksr_chunks (shop, i, data) VALUES (?, ?, ?)').bind(shop.id, k, data.slice(i, i + CHUNK)));
      try { await env.DB.batch(stmts); }
      catch (e) { // the write failed as a whole: put the version back so the device simply retries, the old copy is untouched
        await env.DB.prepare('UPDATE ksr_shops SET version = ?, updated = ?, size = ?, meta = ? WHERE id = ? AND version = ?').bind(shop.version, shop.updated, shop.size, shop.meta, shop.id, shop.version + 1).run();
        throw e;
      }
      await seen(env, shop, dev);
      const done = Array.isArray(q.done) ? q.done.map((x) => clean(x, 40)).filter(Boolean).slice(0, 800) : [];
      for (let i = 0; i < done.length; i += 90) { const part = done.slice(i, i + 90); await env.DB.prepare(`DELETE FROM ksr_ops WHERE shop = ? AND id IN (${part.map(() => '?').join(',')})`).bind(shop.id, ...part).run(); }
      return json({ version: shop.version + 1, updated: t });
    }

    if (a === 'main' && m === 'POST') {
      const q = await body(request);
      if (!same(shop.hash, await hashSecret(String(q.password || ''), shop.salt))) { await noteFail(env, ip); return err('كلمة السر غلط', 401); }
      const dev = clean(q.device, 40);
      if (!dev) return err('رقم الجهاز ناقص');
      const sl = sellersOf(shop).filter((x) => x !== dev);
      await env.DB.prepare('UPDATE ksr_shops SET main = ?, sellers = ? WHERE id = ?').bind(dev, JSON.stringify(sl), shop.id).run();
      await seen(env, shop, dev, q.label);
      const sh2 = { ...shop, main: dev, sellers: JSON.stringify(sl) };
      return json({ shop: pubShop(sh2), license: await signShop(env, sh2) });
    }

    // ----- البيع من جوالين -----
    if (a === 'devices' && m === 'GET') return json({ devices: activeDevs(shop), max: MAX_DEV, multi: !!shop.multi });
    if (a === 'multi' && m === 'POST') { // الجهاز الأساسي بيشغّل/بيطفي البيع من جوالين
      const q = await body(request);
      if (device !== shop.main) return err('هذا بيتفعّل من الجهاز الأساسي للمحل', 403, { code: 'not_main' });
      const on = q.on ? 1 : 0;
      await env.DB.prepare('UPDATE ksr_shops SET multi = ?, sellers = ? WHERE id = ?').bind(on, on ? (shop.sellers || '[]') : '[]', shop.id).run();
      const sh2 = { ...shop, multi: on, sellers: on ? shop.sellers : '[]' };
      return json({ shop: pubShop(sh2), license: await signShop(env, sh2), devices: activeDevs(sh2) });
    }
    if (a === 'seller' && m === 'POST') { // جوال يصير بائع ثاني (من الجهاز الأساسي، أو الجوال نفسه) أو يرجع للمتابعة
      const q = await body(request), dev = clean(q.dev, 40) || device;
      if (device !== shop.main && device !== dev) return err('هذا بيصير من الجهاز الأساسي', 403);
      if (!dev || dev === shop.main) return err('الجهاز الأساسي بيبيع أصلًا');
      let sl = sellersOf(shop).filter((x) => x !== dev);
      if (q.on) {
        if (!shop.multi) return err('شغّل «البيع من جوالين» من الإعدادات بالجهاز الأساسي أول', 403, { code: 'multi_off' });
        if (!activeDevs(shop).some((x) => x.id === dev)) return err('هذا الجهاز مش داخل على الحساب');
        if (sl.length && device !== shop.main) return err('في جوال بائع ثاني مفعّل. بدّله من الجهاز الأساسي', 409, { code: 'seller_taken' });
        sl = [dev]; // من الجهاز الأساسي: بيبدّل البائع القديم بالجديد
      }
      await env.DB.prepare('UPDATE ksr_shops SET sellers = ? WHERE id = ?').bind(JSON.stringify(sl), shop.id).run();
      const sh2 = { ...shop, sellers: JSON.stringify(sl) };
      return json({ shop: pubShop(sh2), license: await signShop(env, sh2), devices: activeDevs(sh2) });
    }
    if (a === 'devdrop' && m === 'POST') { // الجهاز الأساسي بيطلّع جهاز من الحساب
      const q = await body(request), dev = clean(q.dev, 40);
      if (device !== shop.main) return err('هذا بيصير من الجهاز الأساسي', 403);
      if (!dev || dev === shop.main) return err('ما بتقدر تطلّع الجهاز الأساسي');
      await dropDev(env, shop, dev);
      const sh2 = await env.DB.prepare('SELECT * FROM ksr_shops WHERE id = ?').bind(shop.id).first();
      return json({ shop: pubShop(sh2), license: await signShop(env, sh2), devices: activeDevs(sh2) });
    }
    if (a === 'ops' && m === 'POST') { // عمليات الجوال البائع الثاني (بيع، دفعة، مصروف): بتستنى هون لحد ما الجهاز الأساسي يضيفها للمحل
      const q = await body(request);
      if (!shop.multi || !sellersOf(shop).includes(device)) return err('هذا الجوال مش مفعّل كبائع', 403, { code: 'not_seller', shop: pubShop(shop) });
      const list = Array.isArray(q.ops) ? q.ops.slice(0, 200) : [];
      const stmts = [];
      for (const o of list) {
        const id = clean(o && o.id, 40), txt = JSON.stringify(o);
        if (!id || txt.length > 200000 || !['sale', 'pay', 'exp'].includes(o.k)) continue;
        stmts.push(env.DB.prepare('INSERT OR IGNORE INTO ksr_ops (shop, id, dev, t, data) VALUES (?, ?, ?, ?, ?)').bind(shop.id, id, device, nowMs(), txt));
      }
      if (stmts.length) await env.DB.batch(stmts);
      await seen(env, shop, device);
      return json({ ok: true, n: stmts.length });
    }

    if (a === 'password' && m === 'POST') {
      const q = await body(request);
      if (!same(shop.hash, await hashSecret(String(q.old || ''), shop.salt))) { await noteFail(env, ip); return err('كلمة السر الحالية غلط', 401); }
      if (String(q.password || '').length < 6) return err('كلمة السر الجديدة لازم تكون 6 أحرف أو أرقام على الأقل');
      const salt = randomHex(16);
      await env.DB.prepare('UPDATE ksr_shops SET salt = ?, hash = ? WHERE id = ?').bind(salt, await hashSecret(String(q.password), salt), shop.id).run();
      return json({ token: await makeToken(env, { ...shop, salt }) });
    }

    // ----- phone as a wireless scanner for the laptop: tiny pairing mailbox (WebRTC offer/answer) + fallback relay -----
    if (a === 'sig' && m === 'POST') {
      const q = await body(request); const k = q.k === 'offer' ? 'offer' : q.k === 'answer' ? 'answer' : null;
      if (!k) return err('مفتاح غير معروف');
      await env.DB.prepare('INSERT OR REPLACE INTO ksr_sig (shop, k, v, t) VALUES (?, ?, ?, ?)').bind(shop.id, k, String(q.v || '').slice(0, 20000), nowMs()).run();
      return json({ ok: true });
    }
    if (a === 'sig' && m === 'GET') {
      const k = url.searchParams.get('k') === 'answer' ? 'answer' : 'offer';
      const r = await env.DB.prepare('SELECT v, t FROM ksr_sig WHERE shop = ? AND k = ?').bind(shop.id, k).first();
      return json(r && r.v && nowMs() - r.t < 15 * 60e3 ? { v: r.v, t: r.t } : { v: null });
    }
    if (a === 'scan' && m === 'POST') {
      const q = await body(request); const code = clean(q.code, 64);
      if (!code) return err('الباركود فاضي');
      await env.DB.batch([
        env.DB.prepare('INSERT INTO ksr_scans (shop, code, t) VALUES (?, ?, ?)').bind(shop.id, code, nowMs()),
        env.DB.prepare('DELETE FROM ksr_scans WHERE t < ?').bind(nowMs() - 10 * 60e3),
      ]);
      return json({ ok: true });
    }
    if (a === 'scans' && m === 'GET') {
      const after = parseInt(url.searchParams.get('after') || '0', 10) || 0;
      const r = await env.DB.prepare('SELECT id, code FROM ksr_scans WHERE shop = ? AND id > ? AND t > ? ORDER BY id LIMIT 20').bind(shop.id, after, nowMs() - 2 * 60e3).all();
      return json({ list: r.results || [] });
    }

    if (a === 'blobs' && m === 'GET') {
      const r = await env.DB.prepare('SELECT id FROM ksr_blobs WHERE shop = ?').bind(shop.id).all();
      return json({ ids: (r.results || []).map((x) => x.id) });
    }
    if (a === 'blob' && b && m === 'PUT') {
      if (device !== shop.main && !(shop.multi && sellersOf(shop).includes(device))) return err('جهاز ثاني صار هو الأساسي', 409, { code: 'not_main' });
      const q = await body(request);
      const data = String(q.data || '');
      if (!data.startsWith('data:image/') || data.length > MAX_BLOB) return err('صورة غير مقبولة', 413);
      await env.DB.prepare('INSERT OR REPLACE INTO ksr_blobs (shop, id, data, t) VALUES (?, ?, ?, ?)').bind(shop.id, clean(b, 60), data, nowMs()).run();
      return json({ ok: true });
    }
    if (a === 'blob' && b && m === 'GET') {
      const r = await env.DB.prepare('SELECT data FROM ksr_blobs WHERE shop = ? AND id = ?').bind(shop.id, clean(b, 60)).first();
      if (!r) return err('مش موجودة', 404);
      return json({ data: r.data });
    }
    return err('مسار غير معروف', 404);
  } catch (e) {
    return err('صار خطأ بالسيرفر: ' + (e && e.message ? e.message : e), 500);
  }
}

// ---------- the owner's control panel API (academy owner session only) ----------
async function admin(env, request, b) {
  const m = request.method;
  if (!(await isAcademyOwner(env, request))) {
    if (!b) return new Response(null, { status: 302, headers: { location: '/kashirak-admin/' } });
    return err('لازم تسجّل دخول بحساب الأدمن بالأكاديمية', 403, { code: 'login' });
  }
  if (!b) return new Response(null, { status: 302, headers: { location: '/kashirak-admin/' } });
  const q = m === 'POST' ? await body(request) : {};

  if (b === 'push' && m === 'POST') { // رسالة من الإدارة لكل المحلات (أو محل واحد)
    const title = clean(q.title, 80), text = clean(q.body, 240);
    if (!title || !text) return err('اكتب عنوان ونص الإشعار');
    if (q.shop) { const subs = (await env.DB.prepare('SELECT endpoint FROM ksr_push WHERE shop = ?').bind(clean(q.shop, 40)).all()).results || [];
      const id = 'bc' + nowMs(); await env.DB.prepare("INSERT INTO ksr_kv (k, v) VALUES ('push_bc', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(JSON.stringify({ id, t: nowMs(), title, body: text })).run();
      await env.DB.prepare("UPDATE ksr_push SET bc = ? WHERE shop <> ?").bind(id, clean(q.shop, 40)).run();
      let sent = 0; for (const x of subs) if (await pSend(env, x.endpoint)) sent++; return json({ ok: true, subs: subs.length, sent }); }
    const id = 'bc' + nowMs();
    await env.DB.prepare("INSERT INTO ksr_kv (k, v) VALUES ('push_bc', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(JSON.stringify({ id, t: nowMs(), title, body: text })).run();
    const subs = (await env.DB.prepare('SELECT endpoint FROM ksr_push').all()).results || [];
    let sent = 0; for (const x of subs) { if (await pSend(env, x.endpoint)) sent++; }
    return json({ ok: true, subs: subs.length, sent });
  }
  if (b === 'pushstats' && m === 'GET') {
    const r = await env.DB.prepare('SELECT COUNT(*) AS n, COUNT(DISTINCT shop) AS shops FROM ksr_push').first();
    return json({ subs: r ? r.n : 0, shops: r ? r.shops : 0 });
  }

  if (b === 'summary' && m === 'GET') {
    const [shopsR, licR, codesR, devR] = await Promise.all([
      env.DB.prepare("SELECT id, phone, name, main, version, size, updated, created, devices, meta, acct, owner, trial_end, fp, ip, wa, (hash <> '') AS haspass FROM ksr_shops ORDER BY created DESC LIMIT 3000").all(),
      env.DB.prepare('SELECT * FROM ksr_lic').all(),
      env.DB.prepare('SELECT * FROM ksr_codes ORDER BY created DESC LIMIT 3000').all(),
      env.DB.prepare('SELECT * FROM ksr_dev ORDER BY last DESC LIMIT 3000').all(),
    ]);
    const devs = {}; for (const d of devR.results || []) devs[d.id] = d;
    const lic = {}; for (const l of licR.results || []) lic[l.id] = l;
    const shops = (shopsR.results || []).map((s) => {
      let d = {}, meta = {}; try { d = JSON.parse(s.devices || '{}'); } catch {} try { meta = JSON.parse(s.meta || '{}'); } catch {}
      const L = lic['shop:' + s.id];
      const lastSeen = Math.max(0, ...Object.values(d).map((x) => x.last || 0));
      return { kind: 'shop', id: s.id, acct: s.acct, owner: s.owner || '', wa: s.wa || '', haspass: !!s.haspass, fp: s.fp || '', phone: s.phone, name: s.name || meta.shop || '', created: s.created, updated: s.updated, lastSeen, devices: Object.entries(d).map(([k, v]) => ({ id: k, label: v.label, last: v.last, main: k === s.main })), sales: meta.sales || 0, items: meta.items || 0, trialEnds: s.trial_end || meta.trialEnds || null, legacyExp: null, lic: L ? { exp: L.exp, plan: L.plan, updated: L.updated } : null, size: s.size, note: L && L.note || '' };
    });
    // same phone/browser fingerprint behind several accounts = probably the same person repeating the free trial
    const fpN = {}; for (const s of shops) if (s.fp) fpN[s.fp] = (fpN[s.fp] || 0) + 1;
    for (const s of shops) { s.dup = s.fp && fpN[s.fp] > 1 ? shops.filter((x) => x.fp === s.fp && x.id !== s.id).map((x) => x.acct + ' ' + (x.owner || x.name)).slice(0, 4) : []; }
    // installs without a shop account (trial, or activated with a code on this device only)
    const inShop = new Set(); for (const s of shops) for (const d of s.devices) inShop.add(d.id);
    const devIds = new Set([...Object.keys(devs), ...(licR.results || []).filter((l) => l.id.startsWith('dev:')).map((l) => l.id.slice(4))]);
    for (const id of devIds) {
      const d = devs[id] || {}, l = lic['dev:' + id];
      if (inShop.has(id) && !l) continue;
      shops.push({ kind: 'device', id, visit: !d.shop && !l, demo: false, phone: d.phone || '', name: d.shop || (l && l.label) || 'زائر · لسا ما جهّز المحل', created: d.first || (l && l.updated), lastSeen: d.last || null, devices: [{ id, label: 'جهاز', last: d.last, main: true }], sales: d.sales || 0, items: d.items || 0, trialEnds: d.trial_end || null, lic: l ? { exp: l.exp, plan: l.plan, updated: l.updated } : null, note: (l && l.note) || '', ver: d.ver || '' });
    }
    return json({ today: todayDay(), epoch: LIC_EPOCH, lifetime: LIFETIME, plans: PLANS, shops, codes: codesR.results || [] });
  }

  if (b === 'codes' && m === 'POST') {
    const plan = PLANS[q.plan] ? q.plan : null;
    const days = plan ? PLANS[plan][1] : Math.max(1, Math.min(3650, parseInt(q.days, 10) || 0));
    if (!plan && !q.days) return err('اختار مدة الكود');
    const acct = parseInt(q.acct, 10);
    const sh = acct ? await env.DB.prepare('SELECT * FROM ksr_shops WHERE acct = ?').bind(acct).first() : null;
    if (!sh) return err('رقم الحساب مش موجود. الزبون بيلاقيه بالتطبيق بصفحة التفعيل');
    const owner = clean(q.owner, 60) || sh.owner || '';
    if (owner.length < 2) return err('اكتب اسم صاحب المحل');
    if (!sh.owner) await env.DB.prepare('UPDATE ksr_shops SET owner = ? WHERE id = ?').bind(owner, sh.id).run();
    const count = Math.max(1, Math.min(5, parseInt(q.count, 10) || 1));
    const price = Math.max(0, Number(q.price) || 0), note = clean(q.note, 120) || (owner + ' · ' + (sh.name || '')), t = nowMs();
    const out = [];
    for (let i = 0; i < count; i++) {
      let code; for (let k = 0; k < 5; k++) { code = newCode(); const ex = await env.DB.prepare('SELECT 1 FROM ksr_codes WHERE code = ?').bind(code).first(); if (!ex) break; }
      await env.DB.prepare('INSERT INTO ksr_codes (code, plan, days, price, note, created, status, kind, acct, owner) VALUES (?, ?, ?, ?, ?, ?, \'new\', \'code\', ?, ?)').bind(code, plan || ('d' + days), days, price, note || null, t, acct, owner).run();
      out.push(code);
    }
    return json({ codes: out, acct, owner, shop: sh.name || '', phone: sh.phone, wa: sh.wa || '' });
  }
  if (b === 'acct' && m === 'GET') {
    const url = new URL(request.url); const n = parseInt(url.searchParams.get('n'), 10);
    const sh = n ? await env.DB.prepare('SELECT acct, owner, name, phone, wa FROM ksr_shops WHERE acct = ?').bind(n).first() : null;
    return sh ? json({ shop: sh }) : err('رقم الحساب مش موجود', 404);
  }
  if (b === 'move' && m === 'POST') { // the owner moves a shop to a new device (old one stops selling)
    const sh = await env.DB.prepare('SELECT * FROM ksr_shops WHERE id = ?').bind(clean(q.id, 40)).first();
    const dev = clean(q.device, 40);
    if (!sh || !dev) return err('بيانات ناقصة');
    await env.DB.prepare('UPDATE ksr_shops SET main = ? WHERE id = ?').bind(dev, sh.id).run();
    return json({ ok: true });
  }
  // ----- full control of an account from the owner panel -----
  if (['setpass', 'edit', 'trial', 'delete'].includes(b) && m === 'POST') {
    const sh = await env.DB.prepare('SELECT * FROM ksr_shops WHERE id = ?').bind(clean(q.id, 40)).first();
    if (!sh) return err('الحساب مش موجود', 404);
    if (b === 'setpass') { // new password; every device signs in again (the selling device reconnects by itself)
      const pw = String(q.password || '');
      if (pw.length < 6) return err('كلمة السر لازم تكون 6 أحرف أو أرقام على الأقل');
      const salt = randomHex(16);
      await env.DB.prepare('UPDATE ksr_shops SET salt = ?, hash = ? WHERE id = ?').bind(salt, await hashSecret(pw, salt), sh.id).run();
      return json({ ok: true });
    }
    if (b === 'edit') {
      const owner = clean(q.owner, 60), name = clean(q.name, 80), phone = q.phone ? phoneOf(q.phone) : sh.phone;
      if (phone.length < 9) return err('رقم الجوال مش صحيح');
      if (phone !== sh.phone && (await env.DB.prepare('SELECT 1 FROM ksr_shops WHERE phone = ? AND id <> ?').bind(phone, sh.id).first())) return err('هذا الرقم عليه حساب ثاني');
      const wa = q.wa === '' ? '' : (waOf(q.wa) || sh.wa || '');
      if (q.wa && !waOf(q.wa)) return err('رقم الواتساب مش صحيح. مثال: 970599123456');
      await env.DB.prepare('UPDATE ksr_shops SET owner = ?, name = ?, phone = ?, wa = ? WHERE id = ?').bind(owner || sh.owner, name || sh.name, phone, wa || null, sh.id).run();
      return json({ ok: true });
    }
    if (b === 'trial') {
      const days = Math.max(-60, Math.min(90, parseInt(q.days, 10) || 0));
      const base = q.fresh ? nowMs() : Math.max(nowMs(), sh.trial_end || 0);
      await env.DB.prepare('UPDATE ksr_shops SET trial_end = ? WHERE id = ?').bind(base + days * 864e5, sh.id).run();
      return json({ ok: true });
    }
    if (b === 'delete') {
      if (String(q.confirm || '') !== String(sh.acct)) return err('اكتب رقم الحساب للتأكيد');
      await env.DB.batch([
        env.DB.prepare('DELETE FROM ksr_chunks WHERE shop = ?').bind(sh.id),
        env.DB.prepare('DELETE FROM ksr_blobs WHERE shop = ?').bind(sh.id),
        env.DB.prepare('DELETE FROM ksr_hist WHERE shop = ?').bind(sh.id),
        env.DB.prepare('DELETE FROM ksr_hist_chunks WHERE shop = ?').bind(sh.id),
        env.DB.prepare('DELETE FROM ksr_lic WHERE id = ?').bind('shop:' + sh.id),
        env.DB.prepare('DELETE FROM ksr_shops WHERE id = ?').bind(sh.id),
      ]);
      return json({ ok: true });
    }
  }
  if (b === 'history' && m === 'GET') {
    const id = clean(new URL(request.url).searchParams.get('id'), 40);
    const sh = await env.DB.prepare('SELECT id, version, updated, size, meta FROM ksr_shops WHERE id = ?').bind(id).first();
    if (!sh) return err('الحساب مش موجود', 404);
    const r = await env.DB.prepare('SELECT ver, t, size, meta, why FROM ksr_hist WHERE shop = ? ORDER BY ver DESC').bind(id).all();
    return json({ current: sh, list: r.results || [] });
  }
  if (b === 'restore' && m === 'POST') { // bring a shop back to an earlier cloud copy (the current one is kept in history too)
    const sh = await env.DB.prepare('SELECT * FROM ksr_shops WHERE id = ?').bind(clean(q.id, 40)).first();
    const ver = parseInt(q.ver, 10);
    const h = sh && await env.DB.prepare('SELECT * FROM ksr_hist WHERE shop = ? AND ver = ?').bind(sh.id, ver).first();
    if (!sh || !h) return err('النسخة مش موجودة', 404);
    const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM ksr_hist_chunks WHERE shop = ? AND ver = ?').bind(sh.id, ver).first();
    if (!n || !n.n) return err('النسخة فاضية', 422);
    const nv = sh.version + 1, t = nowMs();
    await env.DB.batch([
      ...snapStmts(env, sh, 'before-restore', false),
      env.DB.prepare('DELETE FROM ksr_chunks WHERE shop = ?').bind(sh.id),
      env.DB.prepare('INSERT INTO ksr_chunks (shop, i, data) SELECT shop, i, data FROM ksr_hist_chunks WHERE shop = ? AND ver = ?').bind(sh.id, ver),
      env.DB.prepare('UPDATE ksr_shops SET version = ?, updated = ?, size = ?, meta = ?, restored = ? WHERE id = ? AND version = ?').bind(nv, t, h.size, h.meta, nv, sh.id, sh.version),
    ]);
    return json({ ok: true, version: nv });
  }
  if (b === 'void' && m === 'POST') {
    const code = normCode(q.code);
    const r = await env.DB.prepare("UPDATE ksr_codes SET status = 'void' WHERE code = ? AND status = 'new'").bind(code).run();
    if (!r.meta || !r.meta.changes) return err('ما بنقدر نلغي كود مستعمل أو مش موجود');
    return json({ ok: true });
  }
  if (b === 'extend' && m === 'POST') {
    const target = q.kind === 'device' ? 'dev:' + clean(q.id, 40) : 'shop:' + clean(q.id, 40);
    const plan = PLANS[q.plan] ? q.plan : null;
    const days = plan ? PLANS[plan][1] : Math.max(1, Math.min(3650, parseInt(q.days, 10) || 0));
    if (!plan && !q.days) return err('اختار المدة');
    const lic = await extendLic(env, target, days, plan || ('d' + days), clean(q.label, 80));
    const t = nowMs();
    await env.DB.prepare("INSERT INTO ksr_codes (code, plan, days, price, note, created, status, used_at, used_for, used_label, kind) VALUES (?, ?, ?, ?, ?, ?, 'used', ?, ?, ?, 'direct')")
      .bind('DIR-' + randomHex(4).toUpperCase(), plan || ('d' + days), days, Math.max(0, Number(q.price) || 0), clean(q.note, 120) || null, t, t, target, clean(q.label, 80) || null).run();
    return json({ lic });
  }
  if (b === 'setexp' && m === 'POST') {
    const target = q.kind === 'device' ? 'dev:' + clean(q.id, 40) : 'shop:' + clean(q.id, 40);
    const exp = Math.max(0, Math.min(LIFETIME, parseInt(q.exp, 10)));
    await env.DB.prepare('INSERT INTO ksr_lic (id, exp, plan, updated) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET exp = excluded.exp, updated = excluded.updated').bind(target, exp, 'manual', nowMs()).run();
    return json({ ok: true });
  }
  if (b === 'note' && m === 'POST') {
    const target = q.kind === 'device' ? 'dev:' + clean(q.id, 40) : 'shop:' + clean(q.id, 40);
    await env.DB.prepare('INSERT INTO ksr_lic (id, exp, plan, updated, note) VALUES (?, 0, NULL, ?, ?) ON CONFLICT(id) DO UPDATE SET note = excluded.note').bind(target, nowMs(), clean(q.note, 300)).run();
    return json({ ok: true });
  }
  return err('مسار غير معروف', 404);
}
