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
    'ALTER TABLE ksr_shops ADD COLUMN stopped INTEGER',
    'CREATE TABLE IF NOT EXISTS ksr_scan (id INTEGER PRIMARY KEY AUTOINCREMENT, shop TEXT NOT NULL, code TEXT NOT NULL, dev TEXT, t INTEGER NOT NULL)',
    'CREATE INDEX IF NOT EXISTS ksr_scan_shop ON ksr_scan (shop, id)',
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
const sellersOf = (s) => activeDevs(s).map((x) => x.id).filter((x) => x && x !== s.main).slice(0, MAX_DEV - 1);
const devsOf = (s) => { try { return JSON.parse(s.devices || '{}') || {}; } catch { return {}; } };
const activeDevs = (s) => Object.entries(devsOf(s)).filter(([k, v]) => k === s.main || (v && v.last > nowMs() - DEV_ACTIVE && !/طلب دخول/.test(v.label || ''))).map(([k, v]) => ({ id: k, label: (v.label || 'جهاز').replace(/ \(طلب دخول\)$/, ''), last: v.last, main: k === s.main, seller: k !== s.main }));
// كل الأجهزة المفعّلة للحساب (الأساسي + الباقي) صلاحيتها واحدة: تبيع وتعدّل وتزامن
const isBoss = (s, dev) => !!dev && (dev === s.main || activeDevs(s).some((x) => x.id === dev));
const pubShop = (s) => ({ multi: true, sellers: sellersOf(s), restored: s.restored || 0, wa: s.wa || '', id: s.id, acct: s.acct, owner: s.owner, phone: s.phone, name: s.name, main: s.main, version: s.version, updated: s.updated, size: s.size, haspass: !!s.hash });
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
async function stateText(raw) { // بيفك نسخة المحل للقراءة بس
  if (!raw) return '';
  if (raw.startsWith('p:')) return raw.slice(2);
  const bin = atob(raw.slice(2)), u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return await new Response(new Blob([u]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
}
const TPL_DEFAULT = {"meat":[{"n":"دجاج كامل","b":"","p":0,"u":"كيلو","f":"meat/ch-whole.jpg"},{"n":"صدر دجاج","b":"","p":0,"u":"كيلو","f":"meat/ch-breast.jpg"},{"n":"فخاد دجاج","b":"","p":0,"u":"كيلو","f":"meat/ch-thigh.jpg"},{"n":"دبابيس دجاج","b":"","p":0,"u":"كيلو","f":"meat/ch-drum.jpg"},{"n":"جوانح دجاج","b":"","p":0,"u":"كيلو","f":"meat/ch-wings.jpg"},{"n":"فخاد دجاج بدون عظم","b":"","p":0,"u":"كيلو","f":"meat/ch-thigh-bl.jpg"},{"n":"كبدة دجاج","b":"","p":0,"u":"كيلو","f":"meat/ch-liver.jpg"},{"n":"قوانص دجاج","b":"","p":0,"u":"كيلو","f":"meat/ch-gizzard.jpg"},{"n":"قلوب دجاج","b":"","p":0,"u":"كيلو","f":"meat/ch-heart.jpg"},{"n":"فيليه دجاج (ستربس)","b":"","p":0,"u":"كيلو","f":"meat/ch-fillet.jpg"},{"n":"دجاج مفروم","b":"","p":0,"u":"كيلو","f":"meat/ch-mince.jpg"},{"n":"شاورما دجاج متبلة","b":"","p":0,"u":"كيلو","f":"meat/ch-shawarma.jpg"},{"n":"أرباع دجاج","b":"","p":0,"u":"كيلو","f":"meat/ch-quarter.jpg"},{"n":"دجاج مشقوق","b":"","p":0,"u":"كيلو","f":"meat/ch-butterfly.jpg"},{"n":"دجاج بلدي","b":"","p":0,"u":"كيلو","f":"meat/ch-baladi.jpg"},{"n":"شيش طاووق","b":"","p":0,"u":"كيلو","f":"meat/ch-tawook.jpg"},{"n":"ستيك عجل","b":"","p":0,"u":"كيلو","f":"meat/bf-steak.jpg"},{"n":"لحمة عجل مفرومة","b":"","p":0,"u":"كيلو","f":"meat/bf-mince.jpg"},{"n":"لحمة عجل مكعبات","b":"","p":0,"u":"كيلو","f":"meat/bf-cubes.jpg"},{"n":"فيليه عجل","b":"","p":0,"u":"كيلو","f":"meat/bf-fillet.jpg"},{"n":"ريش عجل","b":"","p":0,"u":"كيلو","f":"meat/bf-ribs.jpg"},{"n":"موزات عجل","b":"","p":0,"u":"كيلو","f":"meat/bf-shank.jpg"},{"n":"كبدة عجل","b":"","p":0,"u":"كيلو","f":"meat/bf-liver.jpg"},{"n":"كفتة","b":"","p":0,"u":"كيلو","f":"meat/bf-kofta.jpg"},{"n":"صدر عجل","b":"","p":0,"u":"كيلو","f":"meat/bf-brisket.jpg"},{"n":"ريب آي (أنتركوت)","b":"","p":0,"u":"كيلو","f":"meat/bf-ribeye.jpg"},{"n":"عظم نخاع","b":"","p":0,"u":"كيلو","f":"meat/bf-bones.jpg"},{"n":"برجر لحمة طازج","b":"","p":0,"u":"كيلو","f":"meat/bf-burger.jpg"},{"n":"لسان عجل","b":"","p":0,"u":"كيلو","f":"meat/bf-tongue.jpg"},{"n":"نقانق لحمة","b":"","p":0,"u":"كيلو","f":"meat/bf-sausage.jpg"},{"n":"شاورما لحمة متبلة","b":"","p":0,"u":"كيلو","f":"meat/bf-shawarma.jpg"},{"n":"كرشة","b":"","p":0,"u":"كيلو","f":"meat/bf-tripe.jpg"},{"n":"فخذ خروف","b":"","p":0,"u":"كيلو","f":"meat/lb-leg.jpg"},{"n":"ريش خروف","b":"","p":0,"u":"كيلو","f":"meat/lb-chops.jpg"},{"n":"كتف خروف","b":"","p":0,"u":"كيلو","f":"meat/lb-shoulder.jpg"},{"n":"موزات خروف","b":"","p":0,"u":"كيلو","f":"meat/lb-shank.jpg"},{"n":"لحمة خروف مفرومة","b":"","p":0,"u":"كيلو","f":"meat/lb-mince.jpg"},{"n":"لحمة خروف مكعبات","b":"","p":0,"u":"كيلو","f":"meat/lb-cubes.jpg"},{"n":"كبدة خروف","b":"","p":0,"u":"كيلو","f":"meat/lb-liver.jpg"},{"n":"نص خروف","b":"","p":0,"u":"كيلو","f":"meat/lb-half.jpg"},{"n":"حبش كامل","b":"","p":0,"u":"كيلو","f":"meat/tk-whole.jpg"},{"n":"صدر حبش","b":"","p":0,"u":"كيلو","f":"meat/tk-breast.jpg"},{"n":"فخذ حبش","b":"","p":0,"u":"كيلو","f":"meat/tk-thigh.jpg"},{"n":"حبش مفروم","b":"","p":0,"u":"كيلو","f":"meat/tk-mince.jpg"},{"n":"بط كامل","b":"","p":0,"u":"كيلو","f":"meat/dk-whole.jpg"},{"n":"صدر بط","b":"","p":0,"u":"كيلو","f":"meat/dk-breast.jpg"},{"n":"أفخاذ بط","b":"","p":0,"u":"كيلو","f":"meat/dk-legs.jpg"},{"n":"وز كامل","b":"","p":0,"u":"كيلو","f":"meat/goose.jpg"},{"n":"دجاج مجمد كامل","b":"","p":0,"u":"حبة","f":"meat/fz-ch-whole.jpg"},{"n":"صدر دجاج مجمد","b":"","p":0,"u":"كيس","f":"meat/fz-ch-breast.jpg"},{"n":"جوانح دجاج مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-ch-wings.jpg"},{"n":"فخاد دجاج مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-ch-thigh.jpg"},{"n":"ناجتس مجمد","b":"","p":0,"u":"كيس","f":"meat/fz-nuggets.jpg"},{"n":"ستربس كرسبي مجمد","b":"","p":0,"u":"كيس","f":"meat/fz-strips.jpg"},{"n":"برجر دجاج مجمد","b":"","p":0,"u":"كيس","f":"meat/fz-ch-burger.jpg"},{"n":"برجر لحمة مجمد","b":"","p":0,"u":"كيس","f":"meat/fz-bf-burger.jpg"},{"n":"لحمة مفرومة مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-bf-mince.jpg"},{"n":"لحمة مكعبات مجمدة","b":"","p":0,"u":"كيلو","f":"meat/fz-bf-cubes.jpg"},{"n":"لحمة خروف مجمدة","b":"","p":0,"u":"كيلو","f":"meat/fz-lamb.jpg"},{"n":"كبدة دجاج مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-liver.jpg"},{"n":"نقانق مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-sausage.jpg"},{"n":"كفتة مجمدة","b":"","p":0,"u":"علبة","f":"meat/fz-kofta.jpg"},{"n":"شاورما مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-shawarma.jpg"},{"n":"حبش مجمد كامل","b":"","p":0,"u":"حبة","f":"meat/fz-turkey.jpg"},{"n":"فيليه سمك مجمد","b":"","p":0,"u":"كيس","f":"meat/fz-fish-fillet.jpg"},{"n":"سمك مجمد كامل","b":"","p":0,"u":"كيلو","f":"meat/fz-fish.jpg"},{"n":"جمبري مجمد","b":"","p":0,"u":"كيلو","f":"meat/fz-shrimp.jpg"},{"n":"حلقات كاليماري مجمدة","b":"","p":0,"u":"كيلو","f":"meat/fz-calamari.jpg"},{"n":"خضار مشكلة مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-mixveg.jpg"},{"n":"بازيلاء مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-peas.jpg"},{"n":"بامية مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-okra.jpg"},{"n":"ملوخية مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-molokhia.jpg"},{"n":"بطاطا مقلية مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-fries.jpg"},{"n":"سبانخ مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-spinach.jpg"},{"n":"ذرة مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-corn.jpg"},{"n":"سمبوسك مجمد","b":"","p":0,"u":"كيس","f":"meat/fz-sambousek.jpg"},{"n":"سبرينج رول مجمد","b":"","p":0,"u":"كيس","f":"meat/fz-springroll.jpg"},{"n":"بيتزا مجمدة","b":"","p":0,"u":"حبة","f":"meat/fz-pizza.jpg"},{"n":"كبة مجمدة","b":"","p":0,"u":"كيس","f":"meat/fz-kibbeh.jpg"},{"n":"عجينة بف باستري","b":"","p":0,"u":"علبة","f":"meat/fz-puff.jpg"},{"n":"سمك دنيس","b":"","p":0,"u":"كيلو","f":"meat/sea-bream.jpg"},{"n":"سمك لقز (قاروص)","b":"","p":0,"u":"كيلو","f":"meat/sea-bass.jpg"},{"n":"سلطان إبراهيم","b":"","p":0,"u":"كيلو","f":"meat/red-mullet.jpg"},{"n":"سردين","b":"","p":0,"u":"كيلو","f":"meat/sardine.jpg"},{"n":"ماكريل","b":"","p":0,"u":"كيلو","f":"meat/mackerel.jpg"},{"n":"تونا طازجة","b":"","p":0,"u":"كيلو","f":"meat/tuna.jpg"},{"n":"سمك لوكس (هامور)","b":"","p":0,"u":"كيلو","f":"meat/grouper.jpg"},{"n":"بلطي","b":"","p":0,"u":"كيلو","f":"meat/tilapia.jpg"},{"n":"فيليه سلمون","b":"","p":0,"u":"كيلو","f":"meat/salmon.jpg"},{"n":"جمبري طازج","b":"","p":0,"u":"كيلو","f":"meat/shrimp.jpg"},{"n":"سلطعون (كابوريا)","b":"","p":0,"u":"كيلو","f":"meat/crab.jpg"},{"n":"حبار (كاليماري)","b":"","p":0,"u":"كيلو","f":"meat/squid.jpg"},{"n":"بوري","b":"","p":0,"u":"كيلو","f":"meat/mullet.jpg"},{"n":"أنشوجة","b":"","p":0,"u":"كيلو","f":"meat/anchovy.jpg"},{"n":"لوبستر","b":"","p":0,"u":"كيلو","f":"meat/lobster.jpg"},{"n":"سمك موسى","b":"","p":0,"u":"كيلو","f":"meat/sole.jpg"}],"deli":[{"n":"مرتديلا سادة","b":"","p":0,"u":"كيلو","f":"deli/mortadella.jpg"},{"n":"مرتديلا بالزيتون","b":"","p":0,"u":"كيلو","f":"deli/mortadella-olive.jpg"},{"n":"لانشون لحمة","b":"","p":0,"u":"كيلو","f":"deli/luncheon-beef.jpg"},{"n":"لانشون دجاج","b":"","p":0,"u":"كيلو","f":"deli/luncheon-chicken.jpg"},{"n":"سلامي لحمة","b":"","p":0,"u":"كيلو","f":"deli/salami-beef.jpg"},{"n":"سلامي دجاج","b":"","p":0,"u":"كيلو","f":"deli/salami-chicken.jpg"},{"n":"صدر حبش مدخن شرائح","b":"","p":0,"u":"كيلو","f":"deli/turkey-slices.jpg"},{"n":"صدر دجاج مدخن","b":"","p":0,"u":"كيلو","f":"deli/chicken-smoked.jpg"},{"n":"بسطرمة","b":"","p":0,"u":"كيلو","f":"deli/basterma.jpg"},{"n":"نقانق هوت دوج","b":"","p":0,"u":"كيلو","f":"deli/hotdog.jpg"},{"n":"نقانق كوكتيل","b":"","p":0,"u":"كيلو","f":"deli/cocktail.jpg"},{"n":"فرانكفورتر دجاج","b":"","p":0,"u":"كيلو","f":"deli/frankfurter.jpg"},{"n":"بيبروني","b":"","p":0,"u":"كيلو","f":"deli/pepperoni.jpg"},{"n":"لحمة مدخنة شرائح","b":"","p":0,"u":"كيلو","f":"deli/beef-smoked.jpg"},{"n":"روست بيف","b":"","p":0,"u":"كيلو","f":"deli/roastbeef.jpg"},{"n":"سلمون مدخن","b":"","p":0,"u":"كيلو","f":"deli/salmon-smoked.jpg"},{"n":"حليب طازج","b":"","p":0,"u":"علبة","f":"deli/milk.jpg"},{"n":"لبن","b":"","p":0,"u":"علبة","f":"deli/laban.jpg"},{"n":"لبنة","b":"","p":0,"u":"كيلو","f":"deli/labneh.jpg"},{"n":"لبن رايب (زبادي)","b":"","p":0,"u":"علبة","f":"deli/yogurt.jpg"},{"n":"جبنة بيضاء","b":"","p":0,"u":"كيلو","f":"deli/white-cheese.jpg"},{"n":"جبنة فيتا","b":"","p":0,"u":"كيلو","f":"deli/feta.jpg"},{"n":"جبنة حلوم","b":"","p":0,"u":"كيلو","f":"deli/halloumi.jpg"},{"n":"جبنة موتزاريلا","b":"","p":0,"u":"كيلو","f":"deli/mozzarella.jpg"},{"n":"جبنة شيدر","b":"","p":0,"u":"كيلو","f":"deli/cheddar.jpg"},{"n":"جبنة مجدولة","b":"","p":0,"u":"كيلو","f":"deli/majdouleh.jpg"},{"n":"جبنة عكاوي","b":"","p":0,"u":"كيلو","f":"deli/akkawi.jpg"},{"n":"جبنة كريمية","b":"","p":0,"u":"علبة","f":"deli/cream-cheese.jpg"},{"n":"زبدة","b":"","p":0,"u":"حبة","f":"deli/butter.jpg"},{"n":"قشطة","b":"","p":0,"u":"علبة","f":"deli/cream.jpg"},{"n":"بيض","b":"","p":0,"u":"طبق","f":"deli/eggs.jpg"},{"n":"سمنة بلدي","b":"","p":0,"u":"علبة","f":"deli/ghee.jpg"}],"bake":[{"n":"خبز عربي","b":"","p":0,"u":"ربطة","f":"bake/pita.jpg"},{"n":"خبز طابون","b":"","p":0,"u":"حبة","f":"bake/taboon.jpg"},{"n":"خبز توست أبيض","b":"","p":0,"u":"حبة","f":"bake/toast-white.jpg"},{"n":"خبز توست أسمر","b":"","p":0,"u":"حبة","f":"bake/toast-brown.jpg"},{"n":"كعك القدس بالسمسم","b":"","p":0,"u":"حبة","f":"bake/kaak.jpg"},{"n":"كرواسون","b":"","p":0,"u":"حبة","f":"bake/croissant.jpg"},{"n":"خبز برجر","b":"","p":0,"u":"حبة","f":"bake/burger-bun.jpg"},{"n":"خبز هوت دوج","b":"","p":0,"u":"حبة","f":"bake/hotdog-bun.jpg"},{"n":"خبز فرنسي (باجيت)","b":"","p":0,"u":"حبة","f":"bake/baguette.jpg"},{"n":"مناقيش زعتر","b":"","p":0,"u":"حبة","f":"bake/manakish.jpg"},{"n":"فطاير جبنة","b":"","p":0,"u":"حبة","f":"bake/fatayer-cheese.jpg"},{"n":"صفيحة لحمة","b":"","p":0,"u":"حبة","f":"bake/sfiha.jpg"},{"n":"فطاير سبانخ","b":"","p":0,"u":"حبة","f":"bake/fatayer-spinach.jpg"},{"n":"دونات","b":"","p":0,"u":"حبة","f":"bake/donut.jpg"},{"n":"مافن","b":"","p":0,"u":"حبة","f":"bake/muffin.jpg"},{"n":"خبز حليب","b":"","p":0,"u":"حبة","f":"bake/milk-bread.jpg"},{"n":"كنافة نابلسية","b":"","p":0,"u":"كيلو","f":"bake/knafeh.jpg"},{"n":"بقلاوة","b":"","p":0,"u":"كيلو","f":"bake/baklava.jpg"},{"n":"بسبوسة","b":"","p":0,"u":"كيلو","f":"bake/basbousa.jpg"},{"n":"هريسة","b":"","p":0,"u":"كيلو","f":"bake/harissa.jpg"},{"n":"قطايف","b":"","p":0,"u":"كيلو","f":"bake/qatayef.jpg"},{"n":"وربات بالقشطة","b":"","p":0,"u":"كيلو","f":"bake/warbat.jpg"},{"n":"عش البلبل","b":"","p":0,"u":"كيلو","f":"bake/ush-bulbul.jpg"},{"n":"معمول بالتمر","b":"","p":0,"u":"كيلو","f":"bake/maamoul.jpg"},{"n":"حلاوة طحينية","b":"","p":0,"u":"كيلو","f":"bake/halawa.jpg"},{"n":"راحة (ملبن)","b":"","p":0,"u":"كيلو","f":"bake/malban.jpg"},{"n":"عوامة","b":"","p":0,"u":"كيلو","f":"bake/awameh.jpg"},{"n":"مبرومة","b":"","p":0,"u":"كيلو","f":"bake/mabrouma.jpg"},{"n":"غريبة","b":"","p":0,"u":"كيلو","f":"bake/ghraybeh.jpg"},{"n":"برازق","b":"","p":0,"u":"كيلو","f":"bake/barazek.jpg"},{"n":"كول وشكور","b":"","p":0,"u":"كيلو","f":"bake/kol-wshkor.jpg"},{"n":"نمورة","b":"","p":0,"u":"كيلو","f":"bake/namoura.jpg"}],"dry":[{"n":"رز طويل","b":"","p":0,"u":"كيلو","f":"dry/rice-long.jpg"},{"n":"رز مصري","b":"","p":0,"u":"كيلو","f":"dry/rice-short.jpg"},{"n":"برغل خشن","b":"","p":0,"u":"كيلو","f":"dry/bulgur-coarse.jpg"},{"n":"برغل ناعم","b":"","p":0,"u":"كيلو","f":"dry/bulgur-fine.jpg"},{"n":"عدس أحمر","b":"","p":0,"u":"كيلو","f":"dry/lentil-red.jpg"},{"n":"عدس بني (مجروش)","b":"","p":0,"u":"كيلو","f":"dry/lentil-brown.jpg"},{"n":"حمص حب","b":"","p":0,"u":"كيلو","f":"dry/chickpeas.jpg"},{"n":"فول حب","b":"","p":0,"u":"كيلو","f":"dry/fava.jpg"},{"n":"فاصوليا بيضاء","b":"","p":0,"u":"كيلو","f":"dry/white-beans.jpg"},{"n":"فريكة","b":"","p":0,"u":"كيلو","f":"dry/freekeh.jpg"},{"n":"سكر","b":"","p":0,"u":"كيلو","f":"dry/sugar.jpg"},{"n":"طحين","b":"","p":0,"u":"كيلو","f":"dry/flour.jpg"},{"n":"شوفان","b":"","p":0,"u":"كيلو","f":"dry/oats.jpg"},{"n":"مفتول","b":"","p":0,"u":"كيلو","f":"dry/maftoul.jpg"},{"n":"بازيلاء مجروشة","b":"","p":0,"u":"كيلو","f":"dry/split-peas.jpg"},{"n":"لوبيا ناشفة","b":"","p":0,"u":"كيلو","f":"dry/blackeye.jpg"},{"n":"كمون","b":"","p":0,"u":"كيلو","f":"dry/cumin.jpg"},{"n":"فلفل أسود","b":"","p":0,"u":"كيلو","f":"dry/pepper-black.jpg"},{"n":"كركم","b":"","p":0,"u":"كيلو","f":"dry/turmeric.jpg"},{"n":"بابريكا (فلفل حلو)","b":"","p":0,"u":"كيلو","f":"dry/paprika.jpg"},{"n":"قرفة عيدان","b":"","p":0,"u":"كيلو","f":"dry/cinnamon.jpg"},{"n":"هيل","b":"","p":0,"u":"كيلو","f":"dry/cardamom.jpg"},{"n":"قرنفل","b":"","p":0,"u":"كيلو","f":"dry/cloves.jpg"},{"n":"زعتر","b":"","p":0,"u":"كيلو","f":"dry/zaatar.jpg"},{"n":"سماق","b":"","p":0,"u":"كيلو","f":"dry/sumac.jpg"},{"n":"شطة مجروشة","b":"","p":0,"u":"كيلو","f":"dry/chili-flakes.jpg"},{"n":"بهارات مشكلة (سبع بهارات)","b":"","p":0,"u":"كيلو","f":"dry/7spices.jpg"},{"n":"نعنع ناشف","b":"","p":0,"u":"كيلو","f":"dry/mint-dry.jpg"},{"n":"ورق غار","b":"","p":0,"u":"كيلو","f":"dry/bay.jpg"},{"n":"جوزة الطيب","b":"","p":0,"u":"كيلو","f":"dry/nutmeg.jpg"},{"n":"زنجبيل مطحون","b":"","p":0,"u":"كيلو","f":"dry/ginger.jpg"},{"n":"يانسون نجمي","b":"","p":0,"u":"كيلو","f":"dry/anise.jpg"},{"n":"زيتون أخضر مرصوص","b":"","p":0,"u":"كيلو","f":"dry/olive-cracked.jpg"},{"n":"زيتون أخضر","b":"","p":0,"u":"كيلو","f":"dry/olive-green.jpg"},{"n":"زيتون أسود","b":"","p":0,"u":"كيلو","f":"dry/olive-black.jpg"},{"n":"زيتون محشي","b":"","p":0,"u":"كيلو","f":"dry/olive-stuffed.jpg"},{"n":"خيار مخلل","b":"","p":0,"u":"كيلو","f":"dry/pickle-cucumber.jpg"},{"n":"لفت مخلل","b":"","p":0,"u":"كيلو","f":"dry/pickle-turnip.jpg"},{"n":"فلفل حار مخلل","b":"","p":0,"u":"كيلو","f":"dry/pickle-pepper.jpg"},{"n":"مكدوس","b":"","p":0,"u":"كيلو","f":"dry/makdous.jpg"},{"n":"زهرة مخللة","b":"","p":0,"u":"كيلو","f":"dry/pickle-cauli.jpg"},{"n":"جزر مخلل","b":"","p":0,"u":"كيلو","f":"dry/pickle-carrot.jpg"},{"n":"مخلل مشكل","b":"","p":0,"u":"كيلو","f":"dry/pickle-mix.jpg"},{"n":"ليمون مخلل","b":"","p":0,"u":"كيلو","f":"dry/pickle-lemon.jpg"},{"n":"ترمس","b":"","p":0,"u":"كيلو","f":"dry/lupini.jpg"},{"n":"طحينة","b":"","p":0,"u":"علبة","f":"dry/tahini.jpg"},{"n":"زيت زيتون","b":"","p":0,"u":"حبة","f":"dry/olive-oil.jpg"},{"n":"حمص بالطحينة","b":"","p":0,"u":"كيلو","f":"dry/hummus.jpg"},{"n":"بهار سمك","b":"","p":0,"u":"كيلو","f":"dry/sp-fish.jpg"},{"n":"بهار كبسة","b":"","p":0,"u":"كيلو","f":"dry/sp-kabsa.jpg"},{"n":"بهار شاورما","b":"","p":0,"u":"كيلو","f":"dry/sp-shawarma.jpg"},{"n":"بهار رز قدرة","b":"","p":0,"u":"كيلو","f":"dry/sp-maqluba.jpg"},{"n":"بهار دجاج","b":"","p":0,"u":"كيلو","f":"dry/sp-chicken.jpg"},{"n":"بهار مشاوي","b":"","p":0,"u":"كيلو","f":"dry/sp-grill.jpg"},{"n":"بهار مندي","b":"","p":0,"u":"كيلو","f":"dry/sp-mandi.jpg"},{"n":"بهار شيش","b":"","p":0,"u":"كيلو","f":"dry/sp-shish.jpg"},{"n":"بهار محشي","b":"","p":0,"u":"كيلو","f":"dry/sp-mahshi.jpg"},{"n":"بهار بيتزا","b":"","p":0,"u":"كيلو","f":"dry/sp-pizza.jpg"},{"n":"بهار تايلندي","b":"","p":0,"u":"كيلو","f":"dry/sp-thai.jpg"},{"n":"بهار مدخن","b":"","p":0,"u":"كيلو","f":"dry/sp-smoked.jpg"},{"n":"بهار بني","b":"","p":0,"u":"كيلو","f":"dry/sp-brown.jpg"},{"n":"بهار أوزي","b":"","p":0,"u":"كيلو","f":"dry/sp-ouzi.jpg"},{"n":"بهارات خشنة","b":"","p":0,"u":"كيلو","f":"dry/sp-coarse.jpg"},{"n":"كلفت فلافل","b":"","p":0,"u":"كيلو","f":"dry/sp-falafel.jpg"},{"n":"قزحة (حبة البركة)","b":"","p":0,"u":"كيلو","f":"dry/nigella.jpg"},{"n":"شومر","b":"","p":0,"u":"كيلو","f":"dry/fennel.jpg"},{"n":"سمسم محمص","b":"","p":0,"u":"كيلو","f":"dry/sesame-toasted.jpg"},{"n":"سمسم ني","b":"","p":0,"u":"كيلو","f":"dry/sesame-raw.jpg"},{"n":"حلبة","b":"","p":0,"u":"كيلو","f":"dry/fenugreek.jpg"},{"n":"كركديه","b":"","p":0,"u":"كيلو","f":"dry/hibiscus.jpg"},{"n":"لومي","b":"","p":0,"u":"كيلو","f":"dry/loomi.jpg"},{"n":"مرمية","b":"","p":0,"u":"كيلو","f":"dry/sage.jpg"},{"n":"أوريجانو","b":"","p":0,"u":"كيلو","f":"dry/oregano.jpg"},{"n":"كزبرة حب","b":"","p":0,"u":"كيلو","f":"dry/coriander-seeds.jpg"},{"n":"سماق حب","b":"","p":0,"u":"كيلو","f":"dry/sumac-whole.jpg"},{"n":"دقة غزاوية","b":"","p":0,"u":"كيلو","f":"dry/dukkah.jpg"},{"n":"كلفة كعك","b":"","p":0,"u":"كيلو","f":"dry/kaak-spice.jpg"},{"n":"ثوم بودرة","b":"","p":0,"u":"كيلو","f":"dry/garlic-powder.jpg"},{"n":"بصل بودرة","b":"","p":0,"u":"كيلو","f":"dry/onion-powder.jpg"},{"n":"شطة مطحونة","b":"","p":0,"u":"كيلو","f":"dry/chili-powder.jpg"},{"n":"كربونة","b":"","p":0,"u":"كيلو","f":"dry/baking-soda.jpg"},{"n":"بقسماط","b":"","p":0,"u":"كيلو","f":"dry/breadcrumbs.jpg"},{"n":"جوز هند مبشور","b":"","p":0,"u":"كيلو","f":"dry/coconut.jpg"},{"n":"ذرة فشار","b":"","p":0,"u":"كيلو","f":"dry/popcorn.jpg"},{"n":"فستق مبشور","b":"","p":0,"u":"كيلو","f":"dry/pistachio-ground.jpg"},{"n":"لوز مطحون","b":"","p":0,"u":"كيلو","f":"dry/almond-ground.jpg"},{"n":"لوز نصاص","b":"","p":0,"u":"كيلو","f":"dry/almond-halves.jpg"},{"n":"لوز مبشور","b":"","p":0,"u":"كيلو","f":"dry/almond-slivered.jpg"},{"n":"زبيب","b":"","p":0,"u":"كيلو","f":"dry/raisins.jpg"},{"n":"تمر عنقود","b":"","p":0,"u":"كيلو","f":"dry/dates-cluster.jpg"},{"n":"جلي مشكل","b":"","p":0,"u":"كيلو","f":"dry/jelly.jpg"},{"n":"كاكاو بودرة","b":"","p":0,"u":"كيلو","f":"dry/cocoa.jpg"},{"n":"نشا","b":"","p":0,"u":"كيلو","f":"dry/starch.jpg"},{"n":"سكر بودرة","b":"","p":0,"u":"كيلو","f":"dry/icing-sugar.jpg"},{"n":"فانيلا","b":"","p":0,"u":"كيلو","f":"dry/vanilla.jpg"},{"n":"خميرة فورية","b":"","p":0,"u":"كيلو","f":"dry/yeast.jpg"}],"nuts":[{"n":"بزر بطيخ","b":"","p":0,"u":"كيلو","f":"nuts/watermelon-seeds.jpg"},{"n":"بزر قرع","b":"","p":0,"u":"كيلو","f":"nuts/pumpkin-seeds.jpg"},{"n":"بزر شمس","b":"","p":0,"u":"كيلو","f":"nuts/sunflower-seeds.jpg"},{"n":"فستق حلبي محمص","b":"","p":0,"u":"كيلو","f":"nuts/pistachio-shell.jpg"},{"n":"فستق مقشر","b":"","p":0,"u":"كيلو","f":"nuts/pistachio-peeled.jpg"},{"n":"قضامة","b":"","p":0,"u":"كيلو","f":"nuts/qdameh.jpg"},{"n":"ذرة حمراء محمصة","b":"","p":0,"u":"كيلو","f":"nuts/red-corn.jpg"},{"n":"فول سوداني بقشره","b":"","p":0,"u":"كيلو","f":"nuts/peanuts-shell.jpg"},{"n":"مياسي شطة","b":"","p":0,"u":"كيلو","f":"nuts/mayasi-chili.jpg"},{"n":"مياسي ذرة","b":"","p":0,"u":"كيلو","f":"nuts/mayasi-corn.jpg"},{"n":"مياسي جبنة","b":"","p":0,"u":"كيلو","f":"nuts/mayasi-cheese.jpg"},{"n":"مكاديميا","b":"","p":0,"u":"كيلو","f":"nuts/macadamia.jpg"},{"n":"كاجو","b":"","p":0,"u":"كيلو","f":"nuts/cashew.jpg"},{"n":"لوز","b":"","p":0,"u":"كيلو","f":"nuts/almond.jpg"},{"n":"جوز","b":"","p":0,"u":"كيلو","f":"nuts/walnut.jpg"},{"n":"بندق","b":"","p":0,"u":"كيلو","f":"nuts/hazelnut.jpg"}],"veg":[{"n":"تفاح أحمر","b":"","p":0,"u":"كيلو","iu":"icons/veg/apple-red.jpg","f":"veg/apple-red.jpg"},{"n":"تفاح أخضر","b":"","p":0,"u":"كيلو","iu":"icons/veg/apple-green.jpg","f":"veg/apple-green.jpg"},{"n":"موز","b":"","p":0,"u":"كيلو","iu":"icons/veg/banana.jpg","f":"veg/banana.jpg"},{"n":"برتقال","b":"","p":0,"u":"كيلو","iu":"icons/veg/orange.jpg","f":"veg/orange.jpg"},{"n":"يوسفي (مندلينا)","b":"","p":0,"u":"كيلو","iu":"icons/veg/mandarin.jpg","f":"veg/mandarin.jpg"},{"n":"ليمون","b":"","p":0,"u":"كيلو","iu":"icons/veg/lemon.jpg","f":"veg/lemon.jpg"},{"n":"عنب أبيض","b":"","p":0,"u":"كيلو","iu":"icons/veg/grapes-green.jpg","f":"veg/grapes-green.jpg"},{"n":"عنب أحمر","b":"","p":0,"u":"كيلو","iu":"icons/veg/grapes-red.jpg","f":"veg/grapes-red.jpg"},{"n":"فراولة","b":"","p":0,"u":"كيلو","iu":"icons/veg/strawberry.jpg","f":"veg/strawberry.jpg"},{"n":"بطيخ","b":"","p":0,"u":"كيلو","iu":"icons/veg/watermelon.jpg","f":"veg/watermelon.jpg"},{"n":"شمام","b":"","p":0,"u":"كيلو","iu":"icons/veg/cantaloupe.jpg","f":"veg/cantaloupe.jpg"},{"n":"مانجا","b":"","p":0,"u":"كيلو","iu":"icons/veg/mango.jpg","f":"veg/mango.jpg"},{"n":"رمان","b":"","p":0,"u":"كيلو","iu":"icons/veg/pomegranate.jpg","f":"veg/pomegranate.jpg"},{"n":"جوافة","b":"","p":0,"u":"كيلو","iu":"icons/veg/guava.jpg","f":"veg/guava.jpg"},{"n":"دراق","b":"","p":0,"u":"كيلو","iu":"icons/veg/peach.jpg","f":"veg/peach.jpg"},{"n":"إجاص","b":"","p":0,"u":"كيلو","iu":"icons/veg/pear.jpg","f":"veg/pear.jpg"},{"n":"مشمش","b":"","p":0,"u":"كيلو","iu":"icons/veg/apricot.jpg","f":"veg/apricot.jpg"},{"n":"برقوق","b":"","p":0,"u":"كيلو","iu":"icons/veg/plum.jpg","f":"veg/plum.jpg"},{"n":"كيوي","b":"","p":0,"u":"كيلو","iu":"icons/veg/kiwi.jpg","f":"veg/kiwi.jpg"},{"n":"أناناس","b":"","p":0,"u":"حبة","iu":"icons/veg/pineapple.jpg","f":"veg/pineapple.jpg"},{"n":"أفوكادو","b":"","p":0,"u":"كيلو","iu":"icons/veg/avocado.jpg","f":"veg/avocado.jpg"},{"n":"تين","b":"","p":0,"u":"كيلو","iu":"icons/veg/fig.jpg","f":"veg/fig.jpg"},{"n":"تمر","b":"","p":0,"u":"كيلو","iu":"icons/veg/dates.jpg","f":"veg/dates.jpg"},{"n":"كرز","b":"","p":0,"u":"كيلو","iu":"icons/veg/cherry.jpg","f":"veg/cherry.jpg"},{"n":"جريب فروت","b":"","p":0,"u":"كيلو","iu":"icons/veg/grapefruit.jpg","f":"veg/grapefruit.jpg"},{"n":"كاكا","b":"","p":0,"u":"كيلو","iu":"icons/veg/persimmon.jpg","f":"veg/persimmon.jpg"},{"n":"صبر","b":"","p":0,"u":"صندوق","iu":"icons/veg/prickly-pear.jpg","f":"veg/prickly-pear.jpg"},{"n":"أكدنيا","b":"","p":0,"u":"كيلو","iu":"icons/veg/loquat.jpg","f":"veg/loquat.jpg"},{"n":"جوز هند","b":"","p":0,"u":"حبة","iu":"icons/veg/coconut.jpg","f":"veg/coconut.jpg"},{"n":"توت","b":"","p":0,"u":"كيلو","iu":"icons/veg/mulberry.jpg","f":"veg/mulberry.jpg"},{"n":"سفرجل","b":"","p":0,"u":"كيلو","iu":"icons/veg/quince.jpg","f":"veg/quince.jpg"},{"n":"نكتارين","b":"","p":0,"u":"كيلو","iu":"icons/veg/nectarine.jpg","f":"veg/nectarine.jpg"},{"n":"بندورة","b":"","p":0,"u":"كيلو","iu":"icons/veg/tomato.jpg","f":"veg/tomato.jpg"},{"n":"خيار","b":"","p":0,"u":"كيلو","iu":"icons/veg/cucumber.jpg","f":"veg/cucumber.jpg"},{"n":"بطاطا","b":"","p":0,"u":"كيلو","iu":"icons/veg/potato.jpg","f":"veg/potato.jpg"},{"n":"بصل","b":"","p":0,"u":"كيلو","iu":"icons/veg/onion.jpg","f":"veg/onion.jpg"},{"n":"ثوم","b":"","p":0,"u":"كيلو","iu":"icons/veg/garlic.jpg","f":"veg/garlic.jpg"},{"n":"جزر","b":"","p":0,"u":"كيلو","iu":"icons/veg/carrot.jpg","f":"veg/carrot.jpg"},{"n":"باذنجان","b":"","p":0,"u":"كيلو","iu":"icons/veg/eggplant.jpg","f":"veg/eggplant.jpg"},{"n":"كوسا","b":"","p":0,"u":"كيلو","iu":"icons/veg/zucchini.jpg","f":"veg/zucchini.jpg"},{"n":"فلفل حلو أخضر","b":"","p":0,"u":"كيلو","iu":"icons/veg/pepper-green.jpg","f":"veg/pepper-green.jpg"},{"n":"فلفل حار","b":"","p":0,"u":"كيلو","iu":"icons/veg/chili-green.jpg","f":"veg/chili-green.jpg"},{"n":"ملفوف","b":"","p":0,"u":"حبة","iu":"icons/veg/cabbage.jpg","f":"veg/cabbage.jpg"},{"n":"زهرة (قرنبيط)","b":"","p":0,"u":"حبة","iu":"icons/veg/cauliflower.jpg","f":"veg/cauliflower.jpg"},{"n":"خس","b":"","p":0,"u":"حبة","iu":"icons/veg/lettuce.jpg","f":"veg/lettuce.jpg"},{"n":"بقدونس","b":"","p":0,"u":"ربطة","iu":"icons/veg/parsley.jpg","f":"veg/parsley.jpg"},{"n":"نعنع","b":"","p":0,"u":"ربطة","iu":"icons/veg/mint.jpg","f":"veg/mint.jpg"},{"n":"بامية","b":"","p":0,"u":"كيلو","iu":"icons/veg/okra.jpg","f":"veg/okra.jpg"},{"n":"فاصوليا خضراء","b":"","p":0,"u":"كيلو","iu":"icons/veg/green-beans.jpg","f":"veg/green-beans.jpg"},{"n":"بازيلاء","b":"","p":0,"u":"كيلو","iu":"icons/veg/peas.jpg","f":"veg/peas.jpg"},{"n":"سبانخ","b":"","p":0,"u":"ربطة","iu":"icons/veg/spinach.jpg","f":"veg/spinach.jpg"},{"n":"كزبرة","b":"","p":0,"u":"ربطة","iu":"icons/veg/coriander.jpg","f":"veg/coriander.jpg"},{"n":"شبت","b":"","p":0,"u":"ربطة","iu":"icons/veg/dill.jpg","f":"veg/dill.jpg"},{"n":"فجل","b":"","p":0,"u":"ربطة","iu":"icons/veg/radish.jpg","f":"veg/radish.jpg"},{"n":"شمندر","b":"","p":0,"u":"كيلو","iu":"icons/veg/beetroot.jpg","f":"veg/beetroot.jpg"},{"n":"بطاطا حلوة","b":"","p":0,"u":"كيلو","iu":"icons/veg/sweet-potato.jpg","f":"veg/sweet-potato.jpg"},{"n":"قرع","b":"","p":0,"u":"كيلو","iu":"icons/veg/pumpkin.jpg","f":"veg/pumpkin.jpg"},{"n":"ذرة","b":"","p":0,"u":"حبة","iu":"icons/veg/corn.jpg","f":"veg/corn.jpg"},{"n":"فطر (مشروم)","b":"","p":0,"u":"كيلو","iu":"icons/veg/mushroom.jpg","f":"veg/mushroom.jpg"},{"n":"بصل أحمر","b":"","p":0,"u":"كيلو","iu":"icons/veg/onion-red.jpg","f":"veg/onion-red.jpg"},{"n":"ملوخية","b":"","p":0,"u":"ربطة","iu":"icons/veg/molokhia.jpg","f":"veg/molokhia.jpg"},{"n":"جرجير","b":"","p":0,"u":"ربطة","iu":"icons/veg/arugula.jpg","f":"veg/arugula.jpg"},{"n":"كرفس","b":"","p":0,"u":"ربطة","iu":"icons/veg/celery.jpg","f":"veg/celery.jpg"}],"falafel":[{"n":"ساندويش فلافل","b":"","p":0,"u":"ساندويش","c":"fl_sand","f":"falafel/sand-falafel.jpg"},{"n":"ساندويش فلافل كبير","b":"","p":0,"u":"ساندويش","c":"fl_sand","f":"falafel/sand-falafel-big.jpg"},{"n":"ساندويش فلافل صاج","b":"","p":0,"u":"ساندويش","c":"fl_sand","f":"falafel/sand-falafel-saj.jpg"},{"n":"ساندويش فلافل وبطاطا","b":"","p":0,"u":"ساندويش","c":"fl_sand","f":"falafel/sand-falafel-fries.jpg"},{"n":"ساندويش بطاطا","b":"","p":0,"u":"ساندويش","c":"fl_sand","f":"falafel/sand-fries.jpg"},{"n":"ساندويش باذنجان مقلي","b":"","p":0,"u":"ساندويش","c":"fl_sand","f":"falafel/sand-eggplant.jpg"},{"n":"ساندويش فلافل محشي","b":"","p":0,"u":"ساندويش","c":"fl_sand","f":"falafel/sand-stuffed.jpg"},{"n":"ساندويش حمص","b":"","p":0,"u":"ساندويش","c":"fl_sand","f":"falafel/sand-hummus.jpg"},{"n":"صحن حمص","b":"","p":0,"u":"صحن","c":"fl_plate","f":"falafel/plate-hummus.jpg"},{"n":"صحن فول","b":"","p":0,"u":"صحن","c":"fl_plate","f":"falafel/plate-foul.jpg"},{"n":"صحن مسبحة","b":"","p":0,"u":"صحن","c":"fl_plate","f":"falafel/plate-msabaha.jpg"},{"n":"صحن فتة حمص","b":"","p":0,"u":"صحن","c":"fl_plate","f":"falafel/plate-fatteh.jpg"},{"n":"صحن فلافل","b":"","p":0,"u":"صحن","c":"fl_plate","f":"falafel/plate-falafel.jpg"},{"n":"صحن بطاطا مقلية","b":"","p":0,"u":"صحن","c":"fl_plate","f":"falafel/plate-fries.jpg"},{"n":"صحن دقة غزاوية","b":"","p":0,"u":"صحن","c":"fl_plate","f":"falafel/plate-dagga.jpg"},{"n":"صحن مخلل مشكل","b":"","p":0,"u":"صحن","c":"fl_plate","f":"falafel/plate-pickles.jpg"},{"n":"دزينة فلافل","b":"","p":0,"u":"دزينة","c":"fl_piece","f":"falafel/dozen-falafel.jpg"},{"n":"حبة فلافل","b":"","p":0,"u":"حبة","c":"fl_piece","f":"falafel/piece-falafel.jpg"},{"n":"كيلو عجينة فلافل","b":"","p":0,"u":"كيلو","c":"fl_piece","f":"falafel/kg-dough.jpg"},{"n":"كيلو حمص مطحون","b":"","p":0,"u":"كيلو","c":"fl_piece","f":"falafel/kg-hummus.jpg"},{"n":"ربطة خبز","b":"","p":0,"u":"ربطة","c":"fl_ext","s":1,"f":"falafel/bread.jpg"},{"n":"زيادة طحينة","b":"","p":0,"u":"حبة","c":"fl_ext","f":"falafel/extra-tahini.jpg"},{"n":"زيادة بطاطا","b":"","p":0,"u":"حبة","c":"fl_ext","f":"falafel/extra-fries.jpg"},{"n":"شطة","b":"","p":0,"u":"حبة","c":"fl_ext","f":"falafel/chili.jpg"},{"n":"كولا علبة","b":"","p":0,"u":"علبة","c":"fl_drink","s":1,"f":"falafel/cola.jpg"},{"n":"سبرايت علبة","b":"","p":0,"u":"علبة","c":"fl_drink","s":1,"f":"falafel/sprite.jpg"},{"n":"ماء صغير","b":"","p":0,"u":"قنينة","c":"fl_drink","s":1,"f":"falafel/water.jpg"},{"n":"عصير علبة","b":"","p":0,"u":"علبة","c":"fl_drink","s":1,"f":"falafel/juice.jpg"}],"shawarma":[{"n":"ساندويش شاورما دجاج","b":"","p":0,"u":"ساندويش","c":"sh_sand","f":"shawarma/sand-chicken.jpg"},{"n":"ساندويش شاورما دجاج دبل","b":"","p":0,"u":"ساندويش","c":"sh_sand","f":"shawarma/sand-chicken-double.jpg"},{"n":"ساندويش شاورما لحمة","b":"","p":0,"u":"ساندويش","c":"sh_sand","f":"shawarma/sand-meat.jpg"},{"n":"ساندويش زنجر","b":"","p":0,"u":"ساندويش","c":"sh_sand","f":"shawarma/sand-zinger.jpg"},{"n":"ساندويش كرسبي","b":"","p":0,"u":"ساندويش","c":"sh_sand","f":"shawarma/sand-crispy.jpg"},{"n":"ساندويش سكالوب","b":"","p":0,"u":"ساندويش","c":"sh_sand","f":"shawarma/sand-escalope.jpg"},{"n":"ساندويش كباب","b":"","p":0,"u":"ساندويش","c":"sh_sand","f":"shawarma/sand-kebab.jpg"},{"n":"ساندويش شاورما صاج","b":"","p":0,"u":"ساندويش","c":"sh_sand","f":"shawarma/sand-saj.jpg"},{"n":"وجبة شاورما عربي","b":"","p":0,"u":"وجبة","c":"sh_meal","f":"shawarma/meal-arabi.jpg"},{"n":"وجبة شاورما عربي دبل","b":"","p":0,"u":"وجبة","c":"sh_meal","f":"shawarma/meal-arabi-double.jpg"},{"n":"صحن شاورما دجاج","b":"","p":0,"u":"صحن","c":"sh_meal","f":"shawarma/plate-chicken.jpg"},{"n":"فتة شاورما","b":"","p":0,"u":"صحن","c":"sh_meal","f":"shawarma/fatteh-shawarma.jpg"},{"n":"وجبة بروستد 4 قطع","b":"","p":0,"u":"وجبة","c":"sh_meal","f":"shawarma/broasted-4.jpg"},{"n":"وجبة بروستد 8 قطع","b":"","p":0,"u":"وجبة","c":"sh_meal","f":"shawarma/broasted-8.jpg"},{"n":"وجبة زنجر","b":"","p":0,"u":"وجبة","c":"sh_meal","f":"shawarma/meal-zinger.jpg"},{"n":"وجبة كرسبي","b":"","p":0,"u":"وجبة","c":"sh_meal","f":"shawarma/meal-crispy.jpg"},{"n":"بطاطا مقلية صغير","b":"","p":0,"u":"حبة","c":"sh_side","f":"shawarma/fries-small.jpg"},{"n":"بطاطا مقلية كبير","b":"","p":0,"u":"حبة","c":"sh_side","f":"shawarma/fries-big.jpg"},{"n":"ثومية","b":"","p":0,"u":"حبة","c":"sh_side","f":"shawarma/garlic.jpg"},{"n":"سلطة كول سلو","b":"","p":0,"u":"حبة","c":"sh_side","f":"shawarma/coleslaw.jpg"},{"n":"مخلل","b":"","p":0,"u":"حبة","c":"sh_side","f":"shawarma/pickles.jpg"},{"n":"حمص","b":"","p":0,"u":"حبة","c":"sh_side","f":"shawarma/hummus.jpg"},{"n":"زيادة جبنة","b":"","p":0,"u":"حبة","c":"sh_ext","f":"shawarma/extra-cheese.jpg"},{"n":"زيادة ثومية","b":"","p":0,"u":"حبة","c":"sh_ext","f":"shawarma/extra-garlic.jpg"},{"n":"كولا علبة","b":"","p":0,"u":"علبة","c":"sh_drink","s":1,"f":"shawarma/cola.jpg"},{"n":"سبرايت علبة","b":"","p":0,"u":"علبة","c":"sh_drink","s":1,"f":"shawarma/sprite.jpg"},{"n":"ماء صغير","b":"","p":0,"u":"قنينة","c":"sh_drink","s":1,"f":"shawarma/water.jpg"},{"n":"لبن عيران","b":"","p":0,"u":"علبة","c":"sh_drink","s":1,"f":"shawarma/ayran.jpg"}],"cafe":[{"n":"قهوة تركي","b":"","p":0,"u":"فنجان","c":"cf_hot","f":"cafe/turkish.jpg"},{"n":"قهوة تركي دبل","b":"","p":0,"u":"فنجان","c":"cf_hot","f":"cafe/turkish-double.jpg"},{"n":"إسبريسو","b":"","p":0,"u":"فنجان","c":"cf_hot","f":"cafe/espresso.jpg"},{"n":"إسبريسو دبل","b":"","p":0,"u":"فنجان","c":"cf_hot","f":"cafe/espresso-double.jpg"},{"n":"أمريكانو","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/americano.jpg"},{"n":"كابتشينو","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/cappuccino.jpg"},{"n":"لاتيه","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/latte.jpg"},{"n":"موكا","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/mocha.jpg"},{"n":"نسكافيه","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/nescafe.jpg"},{"n":"شاي","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/tea.jpg"},{"n":"شاي بالنعنع","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/tea-mint.jpg"},{"n":"شاي بالمرمية","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/tea-sage.jpg"},{"n":"هوت شوكلت","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/hot-choc.jpg"},{"n":"سحلب","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/sahlab.jpg"},{"n":"زهورات","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/herbal.jpg"},{"n":"يانسون","b":"","p":0,"u":"كاسة","c":"cf_hot","f":"cafe/anise.jpg"},{"n":"آيس كوفي","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/iced-coffee.jpg"},{"n":"آيس لاتيه","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/iced-latte.jpg"},{"n":"فرابيه","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/frappe.jpg"},{"n":"ميلك شيك شوكولاتة","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/shake-choc.jpg"},{"n":"ميلك شيك فراولة","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/shake-straw.jpg"},{"n":"ميلك شيك فانيلا","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/shake-vanilla.jpg"},{"n":"موهيتو","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/mojito.jpg"},{"n":"ليمون ونعنع","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/lemon-mint.jpg"},{"n":"عصير برتقال طبيعي","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/orange.jpg"},{"n":"عصير مانجا","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/mango.jpg"},{"n":"كوكتيل فواكه","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/cocktail.jpg"},{"n":"سموذي","b":"","p":0,"u":"كاسة","c":"cf_cold","f":"cafe/smoothie.jpg"},{"n":"قطعة كيك","b":"","p":0,"u":"قطعة","c":"cf_sweet","f":"cafe/cake.jpg"},{"n":"تشيز كيك","b":"","p":0,"u":"قطعة","c":"cf_sweet","f":"cafe/cheesecake.jpg"},{"n":"وافل","b":"","p":0,"u":"حبة","c":"cf_sweet","f":"cafe/waffle.jpg"},{"n":"كريب نوتيلا","b":"","p":0,"u":"حبة","c":"cf_sweet","f":"cafe/crepe.jpg"},{"n":"بان كيك","b":"","p":0,"u":"صحن","c":"cf_sweet","f":"cafe/pancake.jpg"},{"n":"براونيز","b":"","p":0,"u":"قطعة","c":"cf_sweet","f":"cafe/brownie.jpg"},{"n":"كرواسون","b":"","p":0,"u":"حبة","c":"cf_sweet","f":"cafe/croissant.jpg"},{"n":"كنافة","b":"","p":0,"u":"صحن","c":"cf_sweet","f":"cafe/knafeh.jpg"},{"n":"ماء صغير","b":"","p":0,"u":"قنينة","c":"cf_drink","s":1,"f":"cafe/water.jpg"},{"n":"مشروب غازي","b":"","p":0,"u":"علبة","c":"cf_drink","s":1,"f":"cafe/soda.jpg"},{"n":"مشروب طاقة","b":"","p":0,"u":"علبة","c":"cf_drink","s":1,"f":"cafe/energy.jpg"},{"n":"عصير علبة","b":"","p":0,"u":"علبة","c":"cf_drink","s":1,"f":"cafe/juice.jpg"}],"nylon":[{"n":"أكياس شيالة صغير","b":"","p":0,"u":"باكيت","c":"ny_bags","f":"nylon/bag-small.jpg"},{"n":"أكياس شيالة وسط","b":"","p":0,"u":"باكيت","c":"ny_bags","f":"nylon/bag-medium.jpg"},{"n":"أكياس شيالة كبير","b":"","p":0,"u":"باكيت","c":"ny_bags","f":"nylon/bag-large.jpg"},{"n":"أكياس شيالة بالكيلو","b":"","p":0,"u":"كيلو","c":"ny_bags","f":"nylon/bag-kg.jpg"},{"n":"أكياس شفافة (فواكه وخضار)","b":"","p":0,"u":"رول","c":"ny_bags","f":"nylon/bag-clear.jpg"},{"n":"أكياس زبالة كبير","b":"","p":0,"u":"رول","c":"ny_bags","f":"nylon/trash-large.jpg"},{"n":"أكياس زبالة صغير","b":"","p":0,"u":"رول","c":"ny_bags","f":"nylon/trash-small.jpg"},{"n":"أكياس فريزر","b":"","p":0,"u":"علبة","c":"ny_bags","f":"nylon/freezer.jpg"},{"n":"أكياس ثلج","b":"","p":0,"u":"باكيت","c":"ny_bags","f":"nylon/ice.jpg"},{"n":"أكياس خبز","b":"","p":0,"u":"باكيت","c":"ny_bags","f":"nylon/bread.jpg"},{"n":"أكياس سحاب (زيب لوك)","b":"","p":0,"u":"باكيت","c":"ny_bags","f":"nylon/zip.jpg"},{"n":"رول نايلون سميك","b":"","p":0,"u":"رول","c":"ny_bags","f":"nylon/roll-thick.jpg"},{"n":"نايلون لاصق (سلوفان)","b":"","p":0,"u":"رول","c":"ny_food","f":"nylon/cling.jpg"},{"n":"ورق ألمنيوم","b":"","p":0,"u":"رول","c":"ny_food","f":"nylon/foil.jpg"},{"n":"ورق زبدة","b":"","p":0,"u":"رول","c":"ny_food","f":"nylon/baking.jpg"},{"n":"علب فلين للأكل","b":"","p":0,"u":"كرتونة","c":"ny_food","f":"nylon/foam-box.jpg"},{"n":"علب بلاستيك بغطا","b":"","p":0,"u":"باكيت","c":"ny_food","f":"nylon/plastic-box.jpg"},{"n":"علب ألمنيوم بغطا","b":"","p":0,"u":"باكيت","c":"ny_food","f":"nylon/alu-box.jpg"},{"n":"علب بيتزا","b":"","p":0,"u":"حبة","c":"ny_food","f":"nylon/pizza.jpg"},{"n":"علب كيك وحلويات","b":"","p":0,"u":"حبة","c":"ny_food","f":"nylon/cake-box.jpg"},{"n":"أكياس ساندويش ورق","b":"","p":0,"u":"باكيت","c":"ny_food","f":"nylon/sand-bag.jpg"},{"n":"علب سلطة صغيرة بغطا","b":"","p":0,"u":"باكيت","c":"ny_food","f":"nylon/sauce-cup.jpg"},{"n":"كاسات بلاستيك","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/cup-plastic.jpg"},{"n":"كاسات ورق للقهوة","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/cup-paper.jpg"},{"n":"أغطية كاسات","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/cup-lid.jpg"},{"n":"كاسات شفافة للعصير","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/cup-clear.jpg"},{"n":"صحون بلاستيك","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/plate-plastic.jpg"},{"n":"صحون ورق","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/plate-paper.jpg"},{"n":"صحون فلين","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/plate-foam.jpg"},{"n":"ملاعق بلاستيك","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/spoon.jpg"},{"n":"شوك بلاستيك","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/fork.jpg"},{"n":"سكاكين بلاستيك","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/knife.jpg"},{"n":"شفاطات","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/straw.jpg"},{"n":"أعواد تحريك","b":"","p":0,"u":"باكيت","c":"ny_cups","f":"nylon/stirrer.jpg"},{"n":"محارم سفرة","b":"","p":0,"u":"باكيت","c":"ny_paper","f":"nylon/napkin.jpg"},{"n":"محارم جيب","b":"","p":0,"u":"باكيت","c":"ny_paper","f":"nylon/pocket-tissue.jpg"},{"n":"محارم علبة","b":"","p":0,"u":"علبة","c":"ny_paper","f":"nylon/tissue-box.jpg"},{"n":"ورق مطبخ","b":"","p":0,"u":"رول","c":"ny_paper","f":"nylon/kitchen-roll.jpg"},{"n":"ورق تواليت","b":"","p":0,"u":"باكيت","c":"ny_paper","f":"nylon/toilet.jpg"},{"n":"سفرة نايلون (مفرش)","b":"","p":0,"u":"رول","c":"ny_paper","f":"nylon/table-cover.jpg"},{"n":"شريط لاصق شفاف","b":"","p":0,"u":"حبة","c":"ny_pack","f":"nylon/tape.jpg"},{"n":"شريط لاصق بني","b":"","p":0,"u":"حبة","c":"ny_pack","f":"nylon/tape-brown.jpg"},{"n":"كرتون تغليف","b":"","p":0,"u":"حبة","c":"ny_pack","f":"nylon/carton.jpg"},{"n":"نايلون فقاعات","b":"","p":0,"u":"رول","c":"ny_pack","f":"nylon/bubble.jpg"},{"n":"ستريتش تغليف كبير","b":"","p":0,"u":"رول","c":"ny_pack","f":"nylon/stretch.jpg"},{"n":"قفازات نايلون","b":"","p":0,"u":"باكيت","c":"ny_pack","f":"nylon/gloves.jpg"},{"n":"ربطات مطاط","b":"","p":0,"u":"باكيت","c":"ny_pack","f":"nylon/rubber.jpg"},{"n":"أكياس هدايا","b":"","p":0,"u":"حبة","c":"ny_pack","f":"nylon/gift-bag.jpg"}],"clean":[{"n":"صابون جلي","b":"","p":0,"u":"قنينة","c":"cl_dish","s":1,"f":"clean/dish-soap.jpg"},{"n":"مسحوق غسيل","b":"","p":0,"u":"كيس","c":"cl_laundry","s":1,"f":"clean/powder.jpg"},{"n":"سائل غسيل","b":"","p":0,"u":"قنينة","c":"cl_laundry","s":1,"f":"clean/liquid.jpg"},{"n":"منعّم ملابس","b":"","p":0,"u":"قنينة","c":"cl_laundry","s":1,"f":"clean/softener.jpg"},{"n":"كلور","b":"","p":0,"u":"قنينة","c":"cl_house","s":1,"f":"clean/bleach.jpg"},{"n":"معطر أرضيات","b":"","p":0,"u":"قنينة","c":"cl_house","s":1,"f":"clean/floor.jpg"},{"n":"منظف حمامات","b":"","p":0,"u":"قنينة","c":"cl_house","s":1,"f":"clean/bathroom.jpg"},{"n":"منظف زجاج","b":"","p":0,"u":"قنينة","c":"cl_house","s":1,"f":"clean/glass.jpg"},{"n":"معطر جو","b":"","p":0,"u":"علبة","c":"cl_house","s":1,"f":"clean/air.jpg"},{"n":"مبيد حشرات","b":"","p":0,"u":"علبة","c":"cl_house","s":1,"f":"clean/insect.jpg"},{"n":"صابون يد سائل","b":"","p":0,"u":"قنينة","c":"cl_body","s":1,"f":"clean/handsoap.jpg"},{"n":"صابون قالب","b":"","p":0,"u":"حبة","c":"cl_body","s":1,"f":"clean/bar-soap.jpg"},{"n":"شامبو","b":"","p":0,"u":"قنينة","c":"cl_body","s":1,"f":"clean/shampoo.jpg"},{"n":"معجون أسنان","b":"","p":0,"u":"حبة","c":"cl_body","s":1,"f":"clean/toothpaste.jpg"},{"n":"فرشاة أسنان","b":"","p":0,"u":"حبة","c":"cl_body","s":1,"f":"clean/toothbrush.jpg"},{"n":"مناديل مبللة","b":"","p":0,"u":"باكيت","c":"cl_body","s":1,"f":"clean/wipes.jpg"},{"n":"مكنسة","b":"","p":0,"u":"حبة","c":"cl_tools","s":1,"f":"clean/broom.jpg"},{"n":"ممسحة (مساحة)","b":"","p":0,"u":"حبة","c":"cl_tools","s":1,"f":"clean/mop.jpg"},{"n":"سطل","b":"","p":0,"u":"حبة","c":"cl_tools","s":1,"f":"clean/bucket.jpg"},{"n":"كاشطة مياه","b":"","p":0,"u":"حبة","c":"cl_tools","s":1,"f":"clean/squeegee.jpg"},{"n":"إسفنج جلي","b":"","p":0,"u":"باكيت","c":"cl_tools","s":1,"f":"clean/sponge.jpg"},{"n":"سلك جلي","b":"","p":0,"u":"باكيت","c":"cl_tools","s":1,"f":"clean/steel-wool.jpg"},{"n":"قفازات مطاط","b":"","p":0,"u":"زوج","c":"cl_tools","s":1,"f":"clean/gloves.jpg"},{"n":"فوط تنظيف","b":"","p":0,"u":"باكيت","c":"cl_tools","s":1,"f":"clean/cloth.jpg"},{"n":"لكن بلاستيك","b":"","p":0,"u":"حبة","c":"cl_kitchen","s":1,"f":"clean/basin.jpg"},{"n":"سلة غسيل","b":"","p":0,"u":"حبة","c":"cl_kitchen","s":1,"f":"clean/laundry-basket.jpg"},{"n":"علب حفظ طعام","b":"","p":0,"u":"طقم","c":"cl_kitchen","s":1,"f":"clean/containers.jpg"},{"n":"جالون مي","b":"","p":0,"u":"حبة","c":"cl_kitchen","s":1,"f":"clean/jerrycan.jpg"},{"n":"مشاطب غسيل","b":"","p":0,"u":"باكيت","c":"cl_kitchen","s":1,"f":"clean/pegs.jpg"},{"n":"حبل غسيل","b":"","p":0,"u":"حبة","c":"cl_kitchen","s":1,"f":"clean/rope.jpg"},{"n":"سلة زبالة","b":"","p":0,"u":"حبة","c":"cl_kitchen","s":1,"f":"clean/trash-bin.jpg"},{"n":"ولاعة","b":"","p":0,"u":"حبة","c":"cl_kitchen","s":1,"f":"clean/lighter.jpg"}],"juice":[{"n":"عصير برتقال","b":"","p":0,"u":"كاسة","c":"ju_fresh","f":"juice/orange.jpg"},{"n":"عصير ليمون ونعنع","b":"","p":0,"u":"كاسة","c":"ju_fresh","f":"juice/lemon-mint.jpg"},{"n":"عصير جزر","b":"","p":0,"u":"كاسة","c":"ju_fresh","f":"juice/carrot.jpg"},{"n":"عصير رمان","b":"","p":0,"u":"كاسة","c":"ju_fresh","f":"juice/pomegranate.jpg"},{"n":"عصير فراولة","b":"","p":0,"u":"كاسة","c":"ju_fresh","f":"juice/strawberry.jpg"},{"n":"عصير مانجا","b":"","p":0,"u":"كاسة","c":"ju_fresh","f":"juice/mango.jpg"},{"n":"عصير موز وحليب","b":"","p":0,"u":"كاسة","c":"ju_fresh","f":"juice/banana.jpg"},{"n":"عصير بطيخ","b":"","p":0,"u":"كاسة","c":"ju_fresh","f":"juice/watermelon.jpg"},{"n":"كوكتيل طبقات","b":"","p":0,"u":"كاسة","c":"ju_cock","f":"juice/cocktail.jpg"},{"n":"كوكتيل أفوكادو","b":"","p":0,"u":"كاسة","c":"ju_cock","f":"juice/avocado.jpg"},{"n":"كوكتيل فواكه مقطعة","b":"","p":0,"u":"كاسة","c":"ju_cock","f":"juice/fruit-cup.jpg"},{"n":"سلطة فواكه بالقشطة","b":"","p":0,"u":"صحن","c":"ju_cock","f":"juice/fruit-salad.jpg"},{"n":"سلَش","b":"","p":0,"u":"كاسة","c":"ju_cock","f":"juice/slush.jpg"},{"n":"ميلك شيك","b":"","p":0,"u":"كاسة","c":"ju_cock","f":"juice/shake.jpg"},{"n":"تمر هندي","b":"","p":0,"u":"كاسة","c":"ju_cock","f":"juice/tamarind.jpg"},{"n":"خروب","b":"","p":0,"u":"كاسة","c":"ju_cock","f":"juice/carob.jpg"},{"n":"بوظة كورة وحدة","b":"","p":0,"u":"كاسة","c":"ju_ice","f":"juice/ice-1.jpg"},{"n":"بوظة كورتين","b":"","p":0,"u":"كاسة","c":"ju_ice","f":"juice/ice-2.jpg"},{"n":"بوظة 3 كورات","b":"","p":0,"u":"كاسة","c":"ju_ice","f":"juice/ice-3.jpg"},{"n":"بوظة بالكيلو","b":"","p":0,"u":"كيلو","c":"ju_ice","f":"juice/ice-kg.jpg"},{"n":"بوظة بالبسكوت (كون)","b":"","p":0,"u":"حبة","c":"ju_ice","f":"juice/cone.jpg"},{"n":"بوظة عربية بالفستق","b":"","p":0,"u":"صحن","c":"ju_ice","f":"juice/arabic-ice.jpg"},{"n":"آيس كريم سنداي","b":"","p":0,"u":"كاسة","c":"ju_ice","f":"juice/sundae.jpg"},{"n":"بوظة عصا","b":"","p":0,"u":"حبة","c":"ju_ice","s":1,"f":"juice/stick.jpg"}],"sweets":[{"n":"كنافة نابلسية","b":"","p":0,"u":"كيلو","c":"sw_kn","s":1,"f":"sweets/knafeh.jpg"},{"n":"كنافة خشنة","b":"","p":0,"u":"كيلو","c":"sw_kn","s":1,"f":"sweets/knafeh-coarse.jpg"},{"n":"كنافة ناعمة","b":"","p":0,"u":"كيلو","c":"sw_kn","s":1,"f":"sweets/knafeh-fine.jpg"},{"n":"كنافة بالقشطة","b":"","p":0,"u":"كيلو","c":"sw_kn","s":1,"f":"sweets/knafeh-cream.jpg"},{"n":"صحن كنافة","b":"","p":0,"u":"صحن","c":"sw_kn","f":"sweets/knafeh-plate.jpg"},{"n":"بسبوسة","b":"","p":0,"u":"كيلو","c":"sw_tray","s":1,"f":"sweets/basbousa.jpg"},{"n":"هريسة","b":"","p":0,"u":"كيلو","c":"sw_tray","s":1,"f":"sweets/harissa.jpg"},{"n":"نمورة بالقشطة","b":"","p":0,"u":"كيلو","c":"sw_tray","s":1,"f":"sweets/namoura.jpg"},{"n":"بقلاوة","b":"","p":0,"u":"كيلو","c":"sw_bak","s":1,"f":"sweets/baklava.jpg"},{"n":"أصابع زينب","b":"","p":0,"u":"كيلو","c":"sw_bak","s":1,"f":"sweets/fingers.jpg"},{"n":"بلورية","b":"","p":0,"u":"كيلو","c":"sw_bak","s":1,"f":"sweets/balloria.jpg"},{"n":"عش البلبل","b":"","p":0,"u":"كيلو","c":"sw_bak","s":1,"f":"sweets/nest.jpg"},{"n":"كول وشكور","b":"","p":0,"u":"كيلو","c":"sw_bak","s":1,"f":"sweets/kol-shkor.jpg"},{"n":"وربات بالقشطة","b":"","p":0,"u":"حبة","c":"sw_bak","s":1,"f":"sweets/warbat.jpg"},{"n":"قطايف بالجوز","b":"","p":0,"u":"كيلو","c":"sw_other","s":1,"f":"sweets/qatayef-nut.jpg"},{"n":"قطايف بالقشطة","b":"","p":0,"u":"كيلو","c":"sw_other","s":1,"f":"sweets/qatayef-cream.jpg"},{"n":"معمول تمر","b":"","p":0,"u":"كيلو","c":"sw_other","s":1,"f":"sweets/maamoul-date.jpg"},{"n":"معمول جوز","b":"","p":0,"u":"كيلو","c":"sw_other","s":1,"f":"sweets/maamoul-nut.jpg"},{"n":"غريبة","b":"","p":0,"u":"كيلو","c":"sw_other","s":1,"f":"sweets/ghraibeh.jpg"},{"n":"كعك بالسمسم","b":"","p":0,"u":"كيلو","c":"sw_other","s":1,"f":"sweets/kaak.jpg"},{"n":"عوامة (زلابية)","b":"","p":0,"u":"كيلو","c":"sw_other","s":1,"f":"sweets/awameh.jpg"},{"n":"مهلبية","b":"","p":0,"u":"حبة","c":"sw_other","s":1,"f":"sweets/muhallabia.jpg"},{"n":"أرز بحليب","b":"","p":0,"u":"حبة","c":"sw_other","s":1,"f":"sweets/rice-pudding.jpg"},{"n":"صينية مشكل","b":"","p":0,"u":"صينية","c":"sw_other","s":1,"f":"sweets/mix-tray.jpg"}],"clothes":[{"n":"قميص رجالي","b":"","p":0,"u":"حبة","c":"ct_men","s":1,"f":"clothes/shirt.jpg"},{"n":"بنطلون جينز رجالي","b":"","p":0,"u":"حبة","c":"ct_men","s":1,"f":"clothes/jeans.jpg"},{"n":"بنطلون قماش","b":"","p":0,"u":"حبة","c":"ct_men","s":1,"f":"clothes/trousers.jpg"},{"n":"تيشيرت","b":"","p":0,"u":"حبة","c":"ct_men","s":1,"f":"clothes/tshirt.jpg"},{"n":"جاكيت","b":"","p":0,"u":"حبة","c":"ct_men","s":1,"f":"clothes/jacket.jpg"},{"n":"بيجامة رجالي","b":"","p":0,"u":"طقم","c":"ct_men","s":1,"f":"clothes/pajama-men.jpg"},{"n":"ترينينغ","b":"","p":0,"u":"طقم","c":"ct_men","s":1,"f":"clothes/tracksuit.jpg"},{"n":"جلابية رجالي","b":"","p":0,"u":"حبة","c":"ct_men","s":1,"f":"clothes/jalabiya.jpg"},{"n":"عباية","b":"","p":0,"u":"حبة","c":"ct_women","s":1,"f":"clothes/abaya.jpg"},{"n":"جلباب نسائي","b":"","p":0,"u":"حبة","c":"ct_women","s":1,"f":"clothes/jilbab.jpg"},{"n":"فستان","b":"","p":0,"u":"حبة","c":"ct_women","s":1,"f":"clothes/dress.jpg"},{"n":"بلوزة","b":"","p":0,"u":"حبة","c":"ct_women","s":1,"f":"clothes/blouse.jpg"},{"n":"تنورة","b":"","p":0,"u":"حبة","c":"ct_women","s":1,"f":"clothes/skirt.jpg"},{"n":"حجاب","b":"","p":0,"u":"حبة","c":"ct_women","s":1,"f":"clothes/hijab.jpg"},{"n":"إسدال صلاة","b":"","p":0,"u":"حبة","c":"ct_women","s":1,"f":"clothes/prayer.jpg"},{"n":"بيجامة نسائي","b":"","p":0,"u":"طقم","c":"ct_women","s":1,"f":"clothes/pajama-women.jpg"},{"n":"طقم ولادي","b":"","p":0,"u":"طقم","c":"ct_kids","s":1,"f":"clothes/kids-boy.jpg"},{"n":"فستان بناتي","b":"","p":0,"u":"حبة","c":"ct_kids","s":1,"f":"clothes/kids-dress.jpg"},{"n":"ملابس مواليد","b":"","p":0,"u":"طقم","c":"ct_kids","s":1,"f":"clothes/baby.jpg"},{"n":"زي مدرسي","b":"","p":0,"u":"طقم","c":"ct_kids","s":1,"f":"clothes/uniform.jpg"},{"n":"ملابس داخلية","b":"","p":0,"u":"حبة","c":"ct_under","s":1,"f":"clothes/underwear.jpg"},{"n":"جرابات","b":"","p":0,"u":"زوج","c":"ct_under","s":1,"f":"clothes/socks.jpg"},{"n":"فانيلا","b":"","p":0,"u":"حبة","c":"ct_under","s":1,"f":"clothes/undershirt.jpg"},{"n":"شال","b":"","p":0,"u":"حبة","c":"ct_under","s":1,"f":"clothes/scarf.jpg"},{"n":"حذاء رجالي","b":"","p":0,"u":"زوج","c":"ct_shoes","s":1,"f":"clothes/shoes-men.jpg"},{"n":"حذاء رياضي","b":"","p":0,"u":"زوج","c":"ct_shoes","s":1,"f":"clothes/sneakers.jpg"},{"n":"حذاء نسائي","b":"","p":0,"u":"زوج","c":"ct_shoes","s":1,"f":"clothes/shoes-women.jpg"},{"n":"حذاء أطفال","b":"","p":0,"u":"زوج","c":"ct_shoes","s":1,"f":"clothes/shoes-kids.jpg"},{"n":"شبشب","b":"","p":0,"u":"زوج","c":"ct_shoes","s":1,"f":"clothes/slippers.jpg"},{"n":"صندل","b":"","p":0,"u":"زوج","c":"ct_shoes","s":1,"f":"clothes/sandals.jpg"},{"n":"شنطة نسائية","b":"","p":0,"u":"حبة","c":"ct_shoes","s":1,"f":"clothes/handbag.jpg"},{"n":"حزام","b":"","p":0,"u":"حبة","c":"ct_shoes","s":1,"f":"clothes/belt.jpg"}],"salon":[{"n":"حلاقة شعر","b":"","p":0,"u":"خدمة","c":"sa_men","f":"salon/haircut.jpg"},{"n":"حلاقة دقن","b":"","p":0,"u":"خدمة","c":"sa_men","f":"salon/beard.jpg"},{"n":"حلاقة شعر ودقن","b":"","p":0,"u":"خدمة","c":"sa_men","f":"salon/hair-beard.jpg"},{"n":"حلاقة أطفال","b":"","p":0,"u":"خدمة","c":"sa_men","f":"salon/kids-cut.jpg"},{"n":"تحديد دقن","b":"","p":0,"u":"خدمة","c":"sa_men","f":"salon/beard-line.jpg"},{"n":"حلاقة على الموس","b":"","p":0,"u":"خدمة","c":"sa_men","f":"salon/razor.jpg"},{"n":"حلاقة عريس","b":"","p":0,"u":"خدمة","c":"sa_men","f":"salon/groom.jpg"},{"n":"سشوار","b":"","p":0,"u":"خدمة","c":"sa_men","f":"salon/blowdry.jpg"},{"n":"صبغة شعر","b":"","p":0,"u":"خدمة","c":"sa_care","f":"salon/dye.jpg"},{"n":"صبغة دقن","b":"","p":0,"u":"خدمة","c":"sa_care","f":"salon/beard-dye.jpg"},{"n":"بروتين وفرد","b":"","p":0,"u":"خدمة","c":"sa_care","f":"salon/keratin.jpg"},{"n":"تنظيف بشرة","b":"","p":0,"u":"خدمة","c":"sa_care","f":"salon/facial.jpg"},{"n":"ماسك وجه","b":"","p":0,"u":"خدمة","c":"sa_care","f":"salon/mask.jpg"},{"n":"خيط (فتلة)","b":"","p":0,"u":"خدمة","c":"sa_care","f":"salon/threading.jpg"},{"n":"شمع","b":"","p":0,"u":"خدمة","c":"sa_care","f":"salon/wax.jpg"},{"n":"غسيل شعر","b":"","p":0,"u":"خدمة","c":"sa_care","f":"salon/wash.jpg"},{"n":"جل شعر","b":"","p":0,"u":"علبة","c":"sa_prod","s":1,"f":"salon/gel.jpg"},{"n":"واكس شعر","b":"","p":0,"u":"علبة","c":"sa_prod","s":1,"f":"salon/wax-jar.jpg"},{"n":"كولونيا بعد الحلاقة","b":"","p":0,"u":"قنينة","c":"sa_prod","s":1,"f":"salon/cologne.jpg"},{"n":"زيت دقن","b":"","p":0,"u":"قنينة","c":"sa_prod","s":1,"f":"salon/beard-oil.jpg"},{"n":"شفرات حلاقة","b":"","p":0,"u":"باكيت","c":"sa_prod","s":1,"f":"salon/blades.jpg"},{"n":"مشط","b":"","p":0,"u":"حبة","c":"sa_prod","s":1,"f":"salon/comb.jpg"},{"n":"بخاخ شعر","b":"","p":0,"u":"علبة","c":"sa_prod","s":1,"f":"salon/spray.jpg"},{"n":"كريم شعر","b":"","p":0,"u":"علبة","c":"sa_prod","s":1,"f":"salon/cream.jpg"}],"stat":[{"n":"دفتر 40 ورقة","b":"","p":0,"u":"حبة","c":"st_note","s":1,"f":"stat/notebook-40.jpg"},{"n":"دفتر 100 ورقة","b":"","p":0,"u":"حبة","c":"st_note","s":1,"f":"stat/notebook-100.jpg"},{"n":"دفتر سلك","b":"","p":0,"u":"حبة","c":"st_note","s":1,"f":"stat/spiral.jpg"},{"n":"دفتر رسم","b":"","p":0,"u":"حبة","c":"st_note","s":1,"f":"stat/sketch.jpg"},{"n":"رزمة ورق A4","b":"","p":0,"u":"رزمة","c":"st_note","s":1,"f":"stat/a4.jpg"},{"n":"ملف بلاستيك","b":"","p":0,"u":"حبة","c":"st_note","s":1,"f":"stat/folder.jpg"},{"n":"كرتون ملون","b":"","p":0,"u":"حبة","c":"st_note","s":1,"f":"stat/color-paper.jpg"},{"n":"بطاقات ملاحظات لاصقة","b":"","p":0,"u":"باكيت","c":"st_note","s":1,"f":"stat/sticky.jpg"},{"n":"قلم حبر أزرق","b":"","p":0,"u":"حبة","c":"st_pen","s":1,"f":"stat/pen-blue.jpg"},{"n":"قلم رصاص","b":"","p":0,"u":"حبة","c":"st_pen","s":1,"f":"stat/pencil.jpg"},{"n":"ألوان خشبية","b":"","p":0,"u":"علبة","c":"st_pen","s":1,"f":"stat/colors.jpg"},{"n":"ألوان فلوماستر","b":"","p":0,"u":"علبة","c":"st_pen","s":1,"f":"stat/markers.jpg"},{"n":"ألوان مائية","b":"","p":0,"u":"علبة","c":"st_pen","s":1,"f":"stat/watercolor.jpg"},{"n":"قلم تخطيط (هايلايتر)","b":"","p":0,"u":"حبة","c":"st_pen","s":1,"f":"stat/highlighter.jpg"},{"n":"قلم سبورة","b":"","p":0,"u":"حبة","c":"st_pen","s":1,"f":"stat/board-marker.jpg"},{"n":"مصحح (طمس)","b":"","p":0,"u":"حبة","c":"st_pen","s":1,"f":"stat/correction.jpg"},{"n":"محّاية","b":"","p":0,"u":"حبة","c":"st_tool","s":1,"f":"stat/eraser.jpg"},{"n":"برّاية","b":"","p":0,"u":"حبة","c":"st_tool","s":1,"f":"stat/sharpener.jpg"},{"n":"مسطرة","b":"","p":0,"u":"حبة","c":"st_tool","s":1,"f":"stat/ruler.jpg"},{"n":"مقص","b":"","p":0,"u":"حبة","c":"st_tool","s":1,"f":"stat/scissors.jpg"},{"n":"صمغ (غرّاء)","b":"","p":0,"u":"حبة","c":"st_tool","s":1,"f":"stat/glue.jpg"},{"n":"شريط لاصق","b":"","p":0,"u":"حبة","c":"st_tool","s":1,"f":"stat/tape.jpg"},{"n":"دبّاسة","b":"","p":0,"u":"حبة","c":"st_tool","s":1,"f":"stat/stapler.jpg"},{"n":"آلة حاسبة","b":"","p":0,"u":"حبة","c":"st_tool","s":1,"f":"stat/calculator.jpg"},{"n":"شنطة مدرسية","b":"","p":0,"u":"حبة","c":"st_bag","s":1,"f":"stat/backpack.jpg"},{"n":"مقلمة","b":"","p":0,"u":"حبة","c":"st_bag","s":1,"f":"stat/pencil-case.jpg"},{"n":"زمزمية مي","b":"","p":0,"u":"حبة","c":"st_bag","s":1,"f":"stat/bottle.jpg"},{"n":"علبة سندويش","b":"","p":0,"u":"حبة","c":"st_bag","s":1,"f":"stat/lunchbox.jpg"},{"n":"تصوير ورقة","b":"","p":0,"u":"ورقة","c":"st_serv","f":"stat/copy.jpg"},{"n":"طباعة ورقة","b":"","p":0,"u":"ورقة","c":"st_serv","f":"stat/print.jpg"},{"n":"تغليف (تجليد)","b":"","p":0,"u":"حبة","c":"st_serv","f":"stat/laminate.jpg"},{"n":"قرطاسية مشكلة","b":"","p":0,"u":"طقم","c":"st_serv","s":1,"f":"stat/set.jpg"}],"mobile":[{"n":"شاحن سريع","b":"","p":0,"u":"حبة","c":"mb_charge","s":1,"f":"mobile/charger.jpg"},{"n":"كابل تايب سي","b":"","p":0,"u":"حبة","c":"mb_charge","s":1,"f":"mobile/cable-c.jpg"},{"n":"كابل آيفون","b":"","p":0,"u":"حبة","c":"mb_charge","s":1,"f":"mobile/cable-ip.jpg"},{"n":"كابل مايكرو","b":"","p":0,"u":"حبة","c":"mb_charge","s":1,"f":"mobile/cable-micro.jpg"},{"n":"باور بانك 10000","b":"","p":0,"u":"حبة","c":"mb_charge","s":1,"f":"mobile/powerbank-10.jpg"},{"n":"باور بانك 20000","b":"","p":0,"u":"حبة","c":"mb_charge","s":1,"f":"mobile/powerbank-20.jpg"},{"n":"شاحن سيارة","b":"","p":0,"u":"حبة","c":"mb_charge","s":1,"f":"mobile/car-charger.jpg"},{"n":"شاحن لاسلكي","b":"","p":0,"u":"حبة","c":"mb_charge","s":1,"f":"mobile/wireless.jpg"},{"n":"سماعة سلكية","b":"","p":0,"u":"حبة","c":"mb_audio","s":1,"f":"mobile/earphones.jpg"},{"n":"سماعة بلوتوث","b":"","p":0,"u":"حبة","c":"mb_audio","s":1,"f":"mobile/earbuds.jpg"},{"n":"سماعة رأس","b":"","p":0,"u":"حبة","c":"mb_audio","s":1,"f":"mobile/headphones.jpg"},{"n":"سبيكر بلوتوث","b":"","p":0,"u":"حبة","c":"mb_audio","s":1,"f":"mobile/speaker.jpg"},{"n":"كفر جوال","b":"","p":0,"u":"حبة","c":"mb_protect","s":1,"f":"mobile/case.jpg"},{"n":"اسكرينة حماية","b":"","p":0,"u":"حبة","c":"mb_protect","s":1,"f":"mobile/screen.jpg"},{"n":"اسكرينة كاميرا","b":"","p":0,"u":"حبة","c":"mb_protect","s":1,"f":"mobile/camera-lens.jpg"},{"n":"ستاند جوال","b":"","p":0,"u":"حبة","c":"mb_protect","s":1,"f":"mobile/stand.jpg"},{"n":"ذاكرة 32 جيجا","b":"","p":0,"u":"حبة","c":"mb_store","s":1,"f":"mobile/sd-32.jpg"},{"n":"ذاكرة 64 جيجا","b":"","p":0,"u":"حبة","c":"mb_store","s":1,"f":"mobile/sd-64.jpg"},{"n":"فلاشة","b":"","p":0,"u":"حبة","c":"mb_store","s":1,"f":"mobile/flash.jpg"},{"n":"قارئ ذاكرة","b":"","p":0,"u":"حبة","c":"mb_store","s":1,"f":"mobile/reader.jpg"},{"n":"جوال مستعمل","b":"","p":0,"u":"حبة","c":"mb_phone","s":1,"f":"mobile/phone-used.jpg"},{"n":"جوال جديد","b":"","p":0,"u":"حبة","c":"mb_phone","s":1,"f":"mobile/phone-new.jpg"},{"n":"جوال كبسة","b":"","p":0,"u":"حبة","c":"mb_phone","s":1,"f":"mobile/feature-phone.jpg"},{"n":"بطارية جوال","b":"","p":0,"u":"حبة","c":"mb_phone","s":1,"f":"mobile/battery.jpg"},{"n":"شحن جوال (بالمرة)","b":"","p":0,"u":"مرة","c":"mb_serv","f":"mobile/charge-service.jpg"},{"n":"تركيب اسكرينة","b":"","p":0,"u":"خدمة","c":"mb_serv","f":"mobile/install-screen.jpg"},{"n":"تصليح جوال","b":"","p":0,"u":"خدمة","c":"mb_serv","f":"mobile/repair.jpg"},{"n":"تنزيل برامج","b":"","p":0,"u":"خدمة","c":"mb_serv","f":"mobile/software.jpg"},{"n":"كرت شحن جوال","b":"","p":0,"u":"حبة","c":"mb_serv","s":1,"f":"mobile/topup-jawwal.jpg"},{"n":"كرت شحن أوريدو","b":"","p":0,"u":"حبة","c":"mb_serv","s":1,"f":"mobile/topup-ooredoo.jpg"},{"n":"حزمة إنترنت","b":"","p":0,"u":"حبة","c":"mb_serv","s":1,"f":"mobile/data.jpg"},{"n":"شريحة جديدة","b":"","p":0,"u":"حبة","c":"mb_serv","s":1,"f":"mobile/sim.jpg"}]};
const VEG_DEFAULT = TPL_DEFAULT.veg;
const TPL_KEYS = { market: 'سوبر ماركت', pharm: 'صيدلية', veg: 'فواكه وخضروات', meat: 'لحوم ومجمدات وأسماك', deli: 'لحوم باردة وألبان وأجبان', bake: 'مخبوزات وحلويات', dry: 'حبوب وبهارات ومخللات', nuts: 'مكسرات وبزر', falafel: 'فلافل وحمص وفول', shawarma: 'شاورما ووجبات سريعة', cafe: 'كافيه ومشروبات', nylon: 'نايلون ومستلزمات تغليف', clean: 'منظفات وأدوات منزلية', juice: 'مرطبات وعصائر وبوظة', sweets: 'حلويات عربية', clothes: 'ملابس وأحذية', salon: 'حلاقة وصالونات', stat: 'مكتبة وقرطاسية', mobile: 'جوالات وإكسسوارات' };
/* أقسام السوبر ماركت: بتنحسب من اسم الصنف (ما بتغيّر إشي بالقالب المحفوظ) */
const MCATS = [
  ['baby', 'أطفال', /بمبز|حفاض|نيدو|سيريلاك|بيبي(?! دول)|جونسون/],
  ['clean', 'منظفات', /غسيل|سائل جلي|ليفة جلي|سلكة جلي|مطر جو|أوكسي|كلنس(?! لفاف)|ماء زجاج|هاربك|فلاش|مياه نار|مياء نار|مزيل|سنفرة|معطر|معر بلاط|بخاخ بعوض|ليفة(?! جسم)|سلكة|فوط مسح|كلور|فنيش|سائل/],
  ['care', 'عناية شخصية', /شامبو|شابو|بلسم|صبونة|صابون|دوف|مسك|مرطب|كريم جونسون|سنان|إسنان|أسنان|معجون|شفرات|جل شعر|نكشات|سبريه|سوري|أدم|فوط(?! مسح)|ليفة جسم|مرهم/],
  ['home', 'أدوات منزلية وبلاستيك', /مكنس|عصى|مجرود|قشاطة|لمامة|ممسحة|فرشاتة مرحاض|كياس|كيس|سلفان|ورق زبدة|ورق عنب(?!)|مفرش|صحون|معالق|شوكة|كسات|فنجان|فحم|لسقة|كلنس لفاف|ولاعة/],
  ['snack', 'شيبس وتسالي', /شبس|شبسي|ليون|دريتوس|تاتس|برنجز|ليزي|بيكرولز|قسمان|فلتز|كراكر|كروكر|(?<!ب)قسماط|مياسي|شبفوكس|بزر عين/],
  ['sweet', 'شوكولاتة وبسكويت وسكاكر', /شوكو|شوكل|بسكو|يسكت|كيك|كندر|سنكرز|توكس|مارس|كت كات|كيت كات|ميلكا|جلكسي|ببلي|دري ملك|mms|فيرو|فرايرو|مكنتوش|لارش|هدايا|حلو|جلي|مصاص|ليدن|مينتوس|نمبر ون|نبر ون|بليزو|عدسيم|مرشملو|بونتي|تورن|بليني|لوك مي|كوكيز|رولانة|بوظا|برك ريزو|لوغو|لفيفا|كردينيا|قردينة|جاردينيا|سرنتا|سرناتا|أمراتي|إيمراتي|ديدو|ملينيوم|ميلينيوم|تويلر|توينز|مترو|سكيتلز|مخدات|حلقوم|سوسو|هوبي|ريتر|كدبري|فري بري|سنقرط|سرلا|سولار|زبدة لوتس|نتلا|حلبي لفيفا|ألبينيو|فيب|كرسبي|مندولين|أورجنل|بريتلي|قوفرت|يارا|أباشا|فلاك|مجدولين|تايم أوت|تب$|أمير صاروخ/],
  ['hot', 'شاي وقهوة', /قهوة|^بن |بنك العميد|نسكافي|نسكافية|شاي(?! بسكوت)|مبيض|هوت شوكلت|CAFE|لتي كرمل|سحلب|كابتشينو/],
  ['drink', 'مشروبات وعصائر', /عصير|كابي|كولا|سفن|شوبس|بلو|راني|سما |سما$|مياه|ميه|مشروب|شراب|فور يو|^V|بيتي|دومتي|دمتي|مراعي (موز|تفاح|فراولة)|شوكو مراعي|فيمتو|بيريل|سوبر عنب/],
  ['dairy', 'ألبان وأجبان وبيض', /جبنة|جبن|لبنة|لبن|حليب|قشطة|زبدة(?! لوتس)|كريمة|بيض$|مثلثات|شرائح توست|ممراح|سمنة/],
  ['spice', 'بهارات ومكسرات', /بهار|فلفل أسود|فلفل اسود|كمون|كركم|زنجبيل|شطة|ثوم بودرة|بصل بودرة|سمسم|حبهان|قزحة|شومر|كلفة|كلفت|كركديه|حلبة|دقة|زعتر|ورق غار|قرفة|جوز الطيب|لومي|بقسماط|زبيب|ذرة فشار|سماق|كزبرة|أوريقانو|فبركة|مندي|قرنفل|تمر|فاخر|بزر|ذرة حمراء|زلط|مكديمية|مياسي|قضامة|فستق|لوز|جوز هند|كربونة|مرمية|جرادة/],
  ['food', 'مواد غذائية ومعلبات', /رز|سكر|ملح|طحين|سميد|معكرونة|مفتول|اشعرية|شعرية|أندمي|اندومي|صلصة|كتشب|مايونيز|ثومية|طحينة|خل|دبس|مربى|زيتون|طرشي|مكبوس|فطر|ذرة|بامية|فول|حمص|متبل|سلطة|تونة|لحمة|بسطرما|أناناس|أناس|فواكه صغيرة|ماجي|خميره|خميرة|كريم كرمل|دريم جلي|زيت|ورق عنب|فلفل أحمر/],
];
function catOf(n) { n = String(n || ''); if (/أندمي|اندومي|إندومي/.test(n)) return 'food'; for (const [k, , re] of MCATS) if (re.test(n)) return k; return 'other'; }
const PIC_CAT = { veg: 'veg', meat: 'meat', deli: 'deli', bake: 'bake', dry: 'dry', nuts: 'nuts' };
async function tplImgs(env, request, items) { // الصور من ملفات القوالب على نفس السيرفر، بتنبعت جوّا القالب
  if (!env.ASSETS) return items;
  return Promise.all(items.map(async (x) => {
    if (x.img || !x.f || !/^[a-z]+\/[a-z0-9-]+\.jpg$/.test(x.f)) return x;
    try { const r = await env.ASSETS.fetch(new URL('/kashirak-tpl/' + x.f, request.url)); if (!r.ok || !/^image\//.test(r.headers.get('content-type') || '')) return x;
      const u = new Uint8Array(await r.arrayBuffer()); let bin = ''; for (let i = 0; i < u.length; i += 0x8000) bin += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
      return { ...x, img: 'data:image/jpeg;base64,' + btoa(bin) }; } catch { return x; }
  }));
}
/* صور منتجات السوبر ماركت: (1) بالاسم من صور القوالب الجاهزة (2) بالباركود من Open Food Facts، محفوظة بـ ksr_kv تحت pimg:<باركود> */
const nmKey = (t) => String(t || '').replace(/[\u064B-\u0652\u0640]/g, '').replace(/[أإآ]/g, 'ا').replace(/ة/g, 'ه').replace(/ى/g, 'ي').replace(/[^\u0600-\u06FFa-z0-9]/gi, '');
/* صور عامة لأصناف السوبر ماركت حسب نوع الصنف (بالترتيب: الأدق أول) */
const MK_RULES = [["choc-gift",/^هدايا/],["choc-spread",/نتلا|زبدة لوتس/],["hot-choc",/هوت شوكلت|سحلب/],["bleach",/مياه نار|مياء نار|فلاش|هاربك|مزيل|كلور/],["glass-cleaner",/ماء زجاج/],["air-freshener",/^معطر|مطر جو|معر بلاط/],["insect",/بخاخ بعوض/],["dish-soap",/جلي (فيري|بريل|لازو)|سائل جلي|سائل أوكسي جلي/],["detergent",/بودرة غسيل|دواء غسيل|سائل غسيل|ABC|أوكسي/],["cooking-cream",/^كريمة/],["dessert-mix",/كريم كرمل|دريم جلي/],["milk-powder",/حليب بودرة|نيدو/],["milk",/^حليب(?!.*بودرة)|شوكو مراعي/],["juice",/عصير|كابي|بيتي|راني|دومتي|دمتي|(?<!جبنة )مراعي/],["syrup",/^شراب|فيمتو/],["water",/^(مياه معدنية|مياه 0|ميه)/],["cola",/(?<!شو)كولا|بيبسي|سفن|سبرايت|شوبس|^سما|^بلو|فور يو|^V|مشروب|كيكو/],["instant-coffee",/نسكافي|CAFE|كفي ميت|سرلا|(^|\s)لتي/],["coffee",/قهوة|^بن |بنك/],["tea",/^شاي/],["noodles",/أندمي|اندومي|أندومي/],["chips",/شبس|شبسي|ليون|ليزي|برنجز|دريتوس|تاتس|ويز|كرنشي|قسمان|بيكرولز|مياسي|فوكس|بلبري/],["biscuits",/بسكوت|بسكوتة|كوكيز|قسماط|كراكر|كروكر|كيك|بليزو|نمبر ون|لفرز|رولانة|ويفر|لوغو|لوكر|اولكر|أولكر|توركو|لوك مي|ليه/],["chocolate",/شوكولا|شوكلا|شوكلت|ششوكل|كت كات|كيت كات|سنكرز|مارس|ميلكا|(?<!سبريه )جلكسي|كندر|بونتي|توكس|دري ملك|تويلر|ريتر|فيروري|ببلي|mms|مترو|توينز|هرم|تورن|بليني|لفيفا|فلاك|قوفرت|كردينيا|قردينة|جاردينيا|تايم أوت/],["gum",/ليدن|علكة/],["candy",/^حلو|مصاص|^جلي|سكيتلز|مينتوس|مرشملو|حلقوم|نوجا|بوظا|عدسيم|سوسو/],["sugar",/^سكر/],["salt",/ملح/],["flour",/^طحين(?!ة)/],["semolina",/سميد/],["rice",/^(رز|أرز)/],["maftoul",/مفتول/],["pasta",/معكرونة/],["vermicelli",/شعرية|اشعرية/],["eggs",/^بيض$/],["olives",/(?<!زيت )زيتون/],["pickles",/طرشي|مكبوس|مخلل/],["grape-leaves",/ورق عنب/],["tahini",/طحينة/],["vinegar",/^خل/],["molasses",/دبس/],["jam",/مربى/],["qishta",/قشطة/],["labneh",/لبنة/],["butter",/^زبدة (?!لوتس)/],["cheese",/جبنة|شيدر|مثلثات/],["luncheon",/^لحمة/],["pastrami",/بسطرما/],["tuna",/تونة/],["beans-can",/^فول/],["tomato-paste",/صلصة/],["corn-can",/^ذرة (إسر|اسر)/],["mushroom",/فطر/],["okra-can",/^بامية/],["hummus-can",/حمص|متبل/],["canned-fruit",/أناناس قطع|أناس شرائح|فواكه صغيرة/],["yeast",/خميره|خميرة|كربونة/],["mayo",/مايونيز|ثومية/],["ketchup",/^كتشب|^ماجي|مايونيز وكتشب/],["shampoo",/شامبو|شابو|بلسم/],["soap",/صبونة|صابون|دوف/],["toothpaste",/معجون/],["toothbrush",/فرشاة (إسنان|سنان)/],["razor",/شفرات/],["hair-gel",/جل شعر/],["deodorant",/سبريه|سوريه|سورية|أدم/],["diapers",/بمبز/],["tissues",/كلنس|ورق نت/],["pads",/فوط (يومية|ألوز|بيونير)/],["sponge",/ليفة|سلكة|سنفرة/],["broom",/مكنسة|مكنسه|مجرود|لمامة|قشاطة|ممسحة/],["trash-bags",/كياس قمامة/],["disposables",/شوكة|معالق|صحون|كسات|فنجان/],["cling-film",/سلفان|ورق زبدة|كيس حراري/],["charcoal",/فحم/],["ghee",/سمنة/],["oil",/زيت (نباتي|ذرة|دوار)|^زيت/],["dates",/^تمر/],["popcorn",/فشار/],["cosmetics",/مسك|مرطب|كريم جونسون|مرهم/]];
const mkPic = (n) => { const s = String(n || '').trim(); for (const [k, re] of MK_RULES) if (re.test(s)) return 'market/' + k + '.jpg'; return null; };
let PICIDX = null;
function picIdx() { if (PICIDX) return PICIDX; PICIDX = {}; for (const k of Object.keys(PIC_CAT)) for (const x of TPL_DEFAULT[k] || []) if (x.f) { const kk = nmKey(x.n); if (kk && !PICIDX[kk]) PICIDX[kk] = x.f; } return PICIDX; }
async function offImg(bc) { // صورة المنتج من Open Food Facts (قاعدة مفتوحة للمنتجات بالباركود)
  const H = { 'User-Agent': 'Kashirak/1.0 (marketingmiddleeast.com)' };
  for (const host of ['world.openfoodfacts.org', 'world.openbeautyfacts.org', 'world.openproductsfacts.org']) {
    try { const r = await fetch(`https://${host}/api/v2/product/${encodeURIComponent(bc)}.json?fields=image_front_small_url,image_small_url`, { headers: H }); if (!r.ok) continue;
      const j = await r.json(); const u = j && j.product && (j.product.image_front_small_url || j.product.image_small_url); if (!u) continue;
      const g = await fetch(u, { headers: H }); const ct = g.headers.get('content-type') || ''; if (!g.ok || !/^image\//.test(ct)) continue;
      const a = new Uint8Array(await g.arrayBuffer()); if (a.length > 90000) continue; let bin = ''; for (let i = 0; i < a.length; i += 0x8000) bin += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000));
      return 'data:' + ct.split(';')[0] + ';base64,' + btoa(bin); } catch {}
  }
  return '';
}
async function tplBackup(env, k) { // نسخة من القالب قبل أي حفظ. النسخ ما بتنمسح
  try { const r = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind('tpl:' + k).first(); if (r && r.v) await env.DB.prepare('INSERT INTO ksr_kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO NOTHING').bind('tplbak:' + k + ':' + nowMs(), r.v).run(); } catch {}
}
async function tplStamp(env, k, items) { // الصنف الجديد بالقالب بياخد وقت إضافته (a)، عشان المحلات المفعّلة تنزّله لحالها
  let prev = []; try { const r = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind('tpl:' + k).first(); prev = r ? (JSON.parse(r.v).items || []) : (TPL_DEFAULT[k] || []); } catch {}
  const old = new Map(prev.map((x) => [x.b || ('n:' + x.n), x.a || 0])), now = nowMs(), first = !prev.length;
  return items.map((x) => { const key = x.b || ('n:' + x.n); if (old.has(key)) { const a = old.get(key); const y = { ...x }; delete y.a; return a ? { ...y, a } : y; } return first ? x : { ...x, a: now }; });
}
function tplClean(list) {
  const out = [], seen = new Set();
  for (const x of Array.isArray(list) ? list : []) {
    const n = clean(x && (x.n ?? x.name), 120), bc = clean(x && (x.b ?? x.barcode), 40).replace(/\s/g, ''), pr = Math.max(0, Math.round((parseFloat(x && (x.p ?? x.price)) || 0) * 100) / 100), u = clean(x && x.u, 20), img = typeof (x && x.img) === 'string' && /^data:image\/(jpeg|png|webp);base64,/.test(x.img) && x.img.length < 60000 ? x.img : '';
    if (!n) continue; const key = bc || ('n:' + n); if (seen.has(key)) continue; seen.add(key);
    const iu = typeof (x && x.iu) === 'string' && /^icons\/veg\/[a-z0-9-]+\.jpg$/.test(x.iu) ? x.iu : '';
    const f = typeof (x && x.f) === 'string' && /^[a-z]+\/[a-z0-9-]+\.jpg$/.test(x.f) ? x.f : '';
    const at = +(x && x.a) > 0 ? +x.a : 0, cc = /^[a-z_]{2,12}$/.test(String(x && x.c || '')) ? x.c : '', st = x && x.s ? 1 : 0;
    out.push({ n, b: bc, p: pr, ...(u ? { u } : {}), ...(img ? { img } : {}), ...(iu ? { iu } : {}), ...(f ? { f } : {}), ...(at ? { a: at } : {}), ...(cc ? { c: cc } : {}), ...(st ? { s: 1 } : {}) });
  }
  return out;
}
async function kvJson(env, k) { try { const r = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind(k).first(); return r ? JSON.parse(r.v) : {}; } catch { return {}; } }
async function cfgFor(env, shop) { // إعدادات لوحة الكاشير: العامة + الخاصة بهذا المحل (الخاص بيغلب)
  const g = await kvJson(env, 'cfg'), sh = shop ? await kvJson(env, 'cfg:' + shop.id) : {};
  return { ...g, feat: { ...(g.feat || {}), ...(sh.feat || {}) }, ...(sh.notice ? { notice: sh.notice } : {}), t: Math.max(g.t || 0, sh.t || 0) };
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
  const off = !!shop.stopped;
  const payload = b64u(JSON.stringify({ t: 'shop', id: shop.id, a: shop.acct, d: shop.main, s: sellersOf(shop), e: off ? -1 : (L ? L.exp : -1), tr: off ? 0 : (shop.trial_end || 0), p: off ? 'stopped' : (L ? (L.plan || '') : 'trial'), i: Date.now() }));
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
    if (a === 'ad') { const r = await env.DB.prepare("SELECT v FROM ksr_kv WHERE k = 'app_ad'").first(); let v = {}; try { v = JSON.parse((r && r.v) || '{}'); } catch {} return json(v.on ? v : { on: false }); }

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
      if (password.length < 4) return err('كلمة السر لازم تكون 4 أحرف أو أرقام على الأقل');
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
      if (shop.stopped) return err('هذا الحساب موقوف حاليًا. تواصل مع الدعم، وبياناتك كلها محفوظة', 403, { code: 'stopped' });
      const ldev = clean(q.device, 40), act = activeDevs(shop);
      if (ldev && !act.some((x) => x.id === ldev) && act.length >= MAX_DEV) {
        const rp = clean(q.replace, 40);
        if (!rp || !act.some((x) => x.id === rp)) return err(`الحساب مفتوح على ${MAX_DEV} أجهزة، وهذا الحد. اختار جهاز تطلّعه من الحساب`, 409, { code: 'limit', devices: act });
        await dropDev(env, shop, rp); shop.devices = (await env.DB.prepare('SELECT devices FROM ksr_shops WHERE id = ?').bind(shop.id).first()).devices;
      }
      const oldLbl = (devsOf(shop)[ldev] || {}).label || '';
      await seen(env, shop, ldev, (q.label ? clean(q.label, 60) : oldLbl).replace(/ \(طلب دخول\)$/, ''));
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
      // كود المالك السري: اشتراك دائم لأي حساب (محفوظ كبصمة فقط، الكود نفسه مش موجود بالسيرفر ولا بالتطبيق)
      const rawC = String(q.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
      if (rawC && hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rawC))) === 'eb7d9a8451fcfdadc680830cb3ae6fbce3afd6b2c19c70d4d123c4281853fb1e') {
        let sr = await readShop(env, request);
        if (!sr) return err('لازم المحل يكون مسجّل أول. افتح التطبيق وهو متصل بالنت', 401, { code: 'noacct' });
        sr = await ensureAcct(env, sr);
        if (!device || !isBoss(sr, device)) return err('التفعيل بيصير من أي جهاز مفعّل على الحساب', 403, { code: 'not_main' });
        const tg = 'shop:' + sr.id, lbl = sr.owner ? sr.owner + ' · ' + (sr.name || '') : (sr.name || sr.phone);
        await extendLic(env, tg, 0, 'life', lbl);
        try { await env.DB.prepare("INSERT INTO ksr_codes (code, plan, days, price, status, acct, owner, kind, note, created, used_for, used_at, used_label) VALUES (?, 'life', 0, 0, 'used', ?, ?, 'master', 'كود المالك', ?, ?, ?, ?)").bind('OWN-' + sr.acct + '-' + nowMs().toString(36).toUpperCase(), sr.acct, sr.owner || '', nowMs(), tg, nowMs(), lbl).run(); } catch {}
        const L = await env.DB.prepare('SELECT * FROM ksr_lic WHERE id = ?').bind(tg).first();
        return json({ license: await signShop(env, sr), exp: L ? L.exp : -1, plan: L ? L.plan : '' });
      }
      if (!code) { await noteFail(env, ip); return err('الكود لازم يكون بالشكل KSR-XXXX-XXXX'); }
      let shopRow = await readShop(env, request);
      if (!shopRow) return err('لازم المحل يكون مسجّل أول. افتح التطبيق وهو متصل بالنت', 401, { code: 'noacct' });
      shopRow = await ensureAcct(env, shopRow);
      if (!device || !isBoss(shopRow, device)) return err('التفعيل بيصير من أي جهاز مفعّل على الحساب', 403, { code: 'not_main' });
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
      const cfg = await cfgFor(env, shopRow);
      if (!shopRow) return json({ license: null, cfg });
      return json({ license: await signShop(env, shopRow), main: shopRow.main, cfg });
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
    if (a === 'tplv' && m === 'GET') { const out = {}; const r = await env.DB.prepare("SELECT k, json_extract(v,'$.t') AS t FROM ksr_kv WHERE k LIKE 'tpl:%'").all(); for (const x of r.results || []) out[x.k.slice(4)] = +x.t || 0; return json(out); }
    if (a === 'cfgx' && m === 'GET') { const x = await kvJson(env, 'cfgx'); return json({ v: x.v || 0, pay: x.pay || {}, ic: x.ic || {} }); }
    if (a === 'pimgs' && m === 'POST') { // صور منتجات بالباركود (قراءة فقط)
      if (!(await readShop(env, request))) return err('سجّل الدخول أول', 401);
      const q = await body(request); const bs = [...new Set((Array.isArray(q.b) ? q.b : []).map((x) => clean(x, 40).replace(/\s/g, '')).filter(Boolean))].slice(0, 40);
      const out = {}; if (bs.length) { const r = await env.DB.prepare(`SELECT k, v FROM ksr_kv WHERE k IN (${bs.map(() => '?').join(',')})`).bind(...bs.map((x) => 'pimg:' + x)).all();
        for (const x of r.results || []) if (x.v && x.v.startsWith('data:image/')) out[x.k.slice(5)] = x.v; }
      return json({ map: out });
    }
    if (a === 'tpl' && m === 'GET') { // قالب أصناف عام حسب مجال العمل (منفصل عن بيانات أي محل)
      const k = clean(url.searchParams.get('k') || '', 20);
      if (!TPL_KEYS[k]) return err('مجال غير معروف');
      if (!(await readShop(env, request))) return err('سجّل الدخول أول', 401);
      const r = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind('tpl:' + k).first();
      let o = { t: 0, items: [] }; try { if (r) o = JSON.parse(r.v); } catch {}
      if (TPL_DEFAULT[k] && !(o.items || []).length) o = { t: 1, items: TPL_DEFAULT[k] };
      const pi = PIC_CAT[k] ? null : picIdx();
      const its = (o.items || []).map((x) => ({ ...x, c: x.c || PIC_CAT[k] || catOf(x.n), ...(pi && !x.f && !x.img && pi[nmKey(x.n)] ? { f: pi[nmKey(x.n)] } : (k === 'market' && !x.f && !x.img && !x.iu && mkPic(x.n) ? { f: mkPic(x.n) } : {})) }));
      return json({ k, name: TPL_KEYS[k], t: o.t || 0, cats: MCATS.map(([ck, cl]) => [ck, cl]).concat([['other', 'أصناف ثانية']]), items: await tplImgs(env, request, its) });
    }
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
      const dq = url.searchParams.get('dirty');
      if (device && device === shop.main && (dq === '1' || dq === '0')) {
        await env.DB.prepare("INSERT INTO ksr_sig (shop, k, v, t) VALUES (?, 'dirty', ?, ?) ON CONFLICT(shop, k) DO UPDATE SET v = excluded.v, t = excluded.t").bind(shop.id, dq === '1' ? device : '', nowMs()).run().catch(() => {});
      }
      const have = parseInt(url.searchParams.get('have') || '-1', 10);
      const out = { shop: pubShop(shop) };
      if (shop.version > have && shop.version > 0) out.data = await readState(env, shop.id);
      const ops = (await env.DB.prepare('SELECT data FROM ksr_ops WHERE shop = ? ORDER BY t LIMIT 800').bind(shop.id).all()).results || [];
      if (ops.length) out.ops = ops.map((x) => { try { return JSON.parse(x.data); } catch { return null; } }).filter(Boolean);
      // اللابتوب طالب جوال يصير ماسح باركود: الجوالات بتشوف الطلب مع التحديث العادي
      try {
        const sg = await env.DB.prepare("SELECT v, t FROM ksr_sig WHERE shop = ? AND k = 'offer'").bind(shop.id).first();
        if (sg && sg.v && nowMs() - sg.t < 15 * 60e3) { const o = JSON.parse(sg.v); if (o && o.n) out.scanReq = { n: String(o.n).slice(0, 20), dev: String(o.dev || '').slice(0, 40), label: String(o.label || '').slice(0, 40), t: sg.t }; }
      } catch { /* الجدول لسا ما انعمل أو الطلب مش JSON */ }
      return json(out);
    }

    if (a === 'state' && m === 'PUT') {
      const q = await body(request);
      const dev = clean(q.device, 40);
      if (!isBoss(shop, dev)) return err('الجهاز مش مفعّل على الحساب', 409, { code: 'not_main', shop: pubShop(shop) });
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
      await env.DB.prepare("INSERT INTO ksr_sig (shop, k, v, t) VALUES (?, 'dirty', '', ?) ON CONFLICT(shop, k) DO UPDATE SET v = '', t = excluded.t").bind(shop.id, t).run().catch(() => {});
      const done = Array.isArray(q.done) ? q.done.map((x) => clean(x, 40)).filter(Boolean).slice(0, 800) : [];
      for (let i = 0; i < done.length; i += 90) { const part = done.slice(i, i + 90); await env.DB.prepare(`DELETE FROM ksr_ops WHERE shop = ? AND id IN (${part.map(() => '?').join(',')})`).bind(shop.id, ...part).run(); }
      return json({ version: shop.version + 1, updated: t });
    }

    if (a === 'main' && m === 'POST') {
      const q = await body(request);
      const dev = clean(q.device, 40);
      if (!(dev && dev === device && isBoss(shop, dev)) && !same(shop.hash, await hashSecret(String(q.password || ''), shop.salt))) { await noteFail(env, ip); return err('كلمة السر غلط', 401); }
      if (!dev) return err('رقم الجهاز ناقص');
      if (shop.main && shop.main !== dev && !q.force && !q.password) {
        const dg = await env.DB.prepare("SELECT v, t FROM ksr_sig WHERE shop = ? AND k = 'dirty'").bind(shop.id).first().catch(() => null);
        if (dg && dg.v && dg.v === shop.main) return err('الجهاز الثاني عنده شغل لسا ما انرفع', 409, { code: 'main_dirty', label: (devsOf(shop)[shop.main] || {}).label || '' });
      }
      const sl = sellersOf(shop).filter((x) => x !== dev);
      await env.DB.prepare('UPDATE ksr_shops SET main = ?, sellers = ? WHERE id = ?').bind(dev, JSON.stringify(sl), shop.id).run();
      await seen(env, shop, dev, q.label);
      const sh2 = { ...shop, main: dev, sellers: JSON.stringify(sl) };
      return json({ shop: pubShop(sh2), license: await signShop(env, sh2) });
    }

    // ----- الجوال ماسح باركود لجهاز ثاني (لابتوب) -----
    if (a === 'scan' && m === 'POST') {
      const q = await body(request), code = clean(q.code, 64);
      if (!code) return err('الباركود فاضي');
      await env.DB.batch([
        env.DB.prepare('INSERT INTO ksr_scan (shop, code, dev, t) VALUES (?, ?, ?, ?)').bind(shop.id, code, device, nowMs()),
        env.DB.prepare('DELETE FROM ksr_scan WHERE shop = ? AND t < ?').bind(shop.id, nowMs() - 600e3),
      ]);
      return json({ ok: true });
    }
    if (a === 'scan' && m === 'GET') {
      const raw = url.searchParams.get('after');
      if (raw === null) { const r = await env.DB.prepare('SELECT MAX(id) AS id FROM ksr_scan WHERE shop = ?').bind(shop.id).first(); return json({ last: (r && r.id) || 0, codes: [] }); }
      const after = Math.max(0, parseInt(raw, 10) || 0);
      const r = await env.DB.prepare('SELECT id, code FROM ksr_scan WHERE shop = ? AND id > ? AND t > ? ORDER BY id LIMIT 50').bind(shop.id, after, nowMs() - 120e3).all();
      const codes = r.results || [];
      return json({ last: codes.length ? codes[codes.length - 1].id : after, codes: codes.map((x) => x.code) });
    }
    // ----- مسح كل بيانات المحل (من الجهاز الأساسي): بتنمسح من السحابة كمان، وبتضل نسخة بسجل الإدارة للطوارئ. الاشتراك والحساب ما بيتغيّروا -----
    if (a === 'reset' && m === 'POST') {
      const q = await body(request);
      if (!isBoss(shop, device)) return err('مسح البيانات بيصير من جهاز مفعّل على الحساب', 403, { code: 'not_main' });
      if (String(q.confirm || '') !== 'مسح') return err('اكتب كلمة مسح للتأكيد');
      await env.DB.batch([
        ...(shop.version > 0 ? snapStmts(env, shop, 'قبل مسح كل البيانات من التطبيق') : []),
        env.DB.prepare('DELETE FROM ksr_chunks WHERE shop = ?').bind(shop.id),
        env.DB.prepare('DELETE FROM ksr_ops WHERE shop = ?').bind(shop.id),
        env.DB.prepare('UPDATE ksr_shops SET version = 0, size = 0, meta = ?, updated = ? WHERE id = ?').bind('{}', nowMs(), shop.id),
      ]);
      return json({ ok: true });
    }

    // ----- البيع من جوالين -----
    if (a === 'devices' && m === 'GET') return json({ devices: activeDevs(shop), max: MAX_DEV, multi: !!shop.multi });
    if (a === 'multi' && m === 'POST') { // الجهاز الأساسي بيشغّل/بيطفي البيع من جوالين
      const q = await body(request);
      if (!isBoss(shop, device)) return err('هذا بيتفعّل من جهاز مفعّل على الحساب', 403, { code: 'not_main' });
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
        if (sl.length >= MAX_DEV - 1) return err('في جوالين بائعين مفعّلين (الحد). رجّع واحد للمتابعة من الجهاز الأساسي', 409, { code: 'seller_taken' });
        sl = [...sl, dev];
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
      if (!isBoss(shop, device)) return err('هذا الجوال مش مفعّل على الحساب', 403, { code: 'not_seller', shop: pubShop(shop) });
      const list = Array.isArray(q.ops) ? q.ops.slice(0, 200) : [];
      const stmts = [];
      for (const o of list) {
        const id = clean(o && o.id, 40), txt = JSON.stringify(o);
        if (!id || txt.length > 200000 || !['sale', 'pay', 'exp', 'item'].includes(o.k)) continue;
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
      // المسح من الجوال بينحفظ بجدول ksr_scan (من POST /scan فوق)
      const after = parseInt(url.searchParams.get('after') || '0', 10) || 0;
      if (!after) { const r0 = await env.DB.prepare('SELECT MAX(id) AS id FROM ksr_scan WHERE shop = ?').bind(shop.id).first(); return json({ list: r0 && r0.id ? [{ id: r0.id, code: '' }] : [] }); }
      const r = await env.DB.prepare('SELECT id, code FROM ksr_scan WHERE shop = ? AND id > ? AND t > ? ORDER BY id LIMIT 20').bind(shop.id, after, nowMs() - 2 * 60e3).all();
      return json({ list: r.results || [] });
    }

    if (a === 'blobs' && m === 'GET') {
      const r = await env.DB.prepare('SELECT id FROM ksr_blobs WHERE shop = ?').bind(shop.id).all();
      return json({ ids: (r.results || []).map((x) => x.id) });
    }
    if (a === 'blob' && b && m === 'PUT') {
      if (!isBoss(shop, device)) return err('الجهاز مش مفعّل على الحساب', 409, { code: 'not_main' });
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
  if (b === 'tpl' && m === 'GET') {
    const out = {};
    for (const k of Object.keys(TPL_KEYS)) { const r = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind('tpl:' + k).first(); let o = {}; try { o = r ? JSON.parse(r.v) : {}; } catch {} if (TPL_DEFAULT[k] && !(o.items || []).length) o = { t: 1, src: 'القالب الجاهز بالتطبيق', items: TPL_DEFAULT[k] }; out[k] = { name: TPL_KEYS[k], n: (o.items || []).length, t: o.t || 0, src: o.src || '', items: new URL(request.url).searchParams.get('k') === k ? (o.items || []) : undefined }; }
    return json(out);
  }
  if (b === 'tpl' && m === 'POST') { // بيحفظ القالب العام بس. ما بيلمس أي محل، وما بيأثر على أصناف نزلت قبل عند المحلات
    const k = clean(q.k, 20); if (!TPL_KEYS[k]) return err('مجال غير معروف');
    const items = await tplStamp(env, k, tplClean(q.items)); const v = JSON.stringify({ t: nowMs(), src: clean(q.src || 'لوحة الكاشير', 80), items });
    if (v.length > 1800000) return err('القالب كبير كثير (' + items.length + ' صنف). قسّمه أو خفّف الصور');
    await tplBackup(env, k);
    await env.DB.prepare('INSERT INTO ksr_kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind('tpl:' + k, v).run();
    return json({ ok: true, n: items.length });
  }
  if (b === 'pimgfetch' && m === 'POST') { // جلب صور منتجات القالب بالباركود. بيضيف بس صور بجدول منفصل، ما بيلمس أي محل ولا القالب
    const k = clean(q.k, 20) || 'market'; if (!TPL_KEYS[k]) return err('مجال غير معروف');
    const r = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind('tpl:' + k).first(); let o = {}; try { o = r ? JSON.parse(r.v) : {}; } catch {}
    const items = (o.items && o.items.length ? o.items : TPL_DEFAULT[k] || []).filter((x) => x.b && /^\d{6,14}$/.test(x.b) && !x.img && !x.f);
    const have = new Map(); const hr = await env.DB.prepare("SELECT k, substr(v,1,1) AS v FROM ksr_kv WHERE k LIKE 'pimg:%'").all(); for (const x of hr.results || []) have.set(x.k.slice(5), x.v);
    if (q.retry) for (const [bc, v] of have) if (v === '-') have.delete(bc);
    const todo = items.filter((x) => !have.has(x.b)).slice(0, Math.min(12, Math.max(1, +q.n || 8)));
    let found = 0; for (const x of todo) { const d = await offImg(x.b); if (d) found++;
      await env.DB.prepare('INSERT INTO ksr_kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind('pimg:' + x.b, d || '-').run(); have.set(x.b, d ? 'd' : '-'); }
    const left = items.filter((x) => !have.has(x.b)).length, ok = items.filter((x) => have.get(x.b) === 'd').length;
    return json({ ok: true, total: items.length, done: items.length - left, found: ok, now: found, left, miss: left ? [] : items.filter((x) => have.get(x.b) === '-').map((x) => x.n) });
  }
  if (b === 'tplfromshop' && m === 'POST') { // نسخ أصناف محل (الاسم، الباركود، السعر) لقالب عام. قراءة فقط من المحل
    const k = clean(q.k, 20) || 'market'; if (!TPL_KEYS[k]) return err('مجال غير معروف');
    const ph = phoneOf(q.phone); if (!ph) return err('اكتب رقم جوال المحل');
    const snap = async () => {
      const sh = await env.DB.prepare('SELECT id, name, version, updated, size FROM ksr_shops WHERE phone = ?').bind(ph).first();
      if (!sh) return null; const raw = await readState(env, sh.id); const txt = await stateText(raw); let st = {}; try { st = JSON.parse(txt); } catch {}
      const h = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw)));
      const L = (x) => Array.isArray(st[x]) ? st[x].length : 0;
      const debt = Math.round((st.customers || []).reduce((a, c) => a + (c.ledger || []).reduce((b2, l) => b2 + (l.cur && l.cur !== 'ILS' ? 0 : +l.amt || 0), 0), 0) * 100) / 100;
      return { sh, st, h, counts: { items: L('items'), customers: L('customers'), suppliers: L('suppliers'), sales: L('sales'), purchases: L('purchases'), debt } };
    };
    const before = await snap(); if (!before) return err('ما في محل بهذا الرقم', 404);
    /* بالإضافة فقط: أصناف القالب الموجودة بتضل، وبينضاف عليها أصناف المحل الجديدة بس */
    let old = []; try { const r0 = await env.DB.prepare('SELECT v FROM ksr_kv WHERE k = ?').bind('tpl:' + k).first(); old = r0 ? (JSON.parse(r0.v).items || []) : []; } catch {}
    const have = new Set(old.map((x) => x.b || ('n:' + x.n))), haveN = new Set(old.map((x) => x.n));
    const fresh = tplClean((before.st.items || []).map((i) => ({ n: i.name, b: i.barcode, p: i.price }))).filter((x) => !have.has(x.b || ('n:' + x.n)) && !haveN.has(x.n));
    const items = await tplStamp(env, k, [...old, ...fresh]);
    const v = JSON.stringify({ t: nowMs(), src: (before.sh.name || '') + ' · ' + ph, items });
    await tplBackup(env, k);
    if (v.length > 1800000) return err('الأصناف كثيرة كثير (' + items.length + ')');
    await env.DB.prepare('INSERT INTO ksr_kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind('tpl:' + k, v).run();
    const after = await snap();
    const same = after && after.h === before.h && after.sh.version === before.sh.version && after.sh.updated === before.sh.updated && JSON.stringify(after.counts) === JSON.stringify(before.counts);
    return json({ ok: true, copied: fresh.length, total: items.length, shop: before.sh.name || '', before: { ...before.counts, version: before.sh.version }, after: after ? { ...after.counts, version: after.sh.version } : null, unchanged: !!same,
      note: same ? 'حساب المحل ما تغيّر فيه ولا إشي (نفس البصمة ونفس النسخة ونفس الأعداد)' : 'المحل عمل تعديل أثناء النسخ (بيع مثلًا) من جهازه. النسخ نفسه ما كتب على المحل' });
  }
  if (b === 'cfgx') { // صور التخصيص (شعارات الدفع والأيقونات). منفصلة عشان ما تنبعت مع كل فحص اشتراك
    if (m === 'GET') return json(await kvJson(env, 'cfgx'));
    const ok = (d) => typeof d === 'string' && /^data:image\/(png|jpeg|webp);base64,/.test(d) && d.length < 40000;
    const x = await kvJson(env, 'cfgx'); for (const g of ['pay', 'ic']) { x[g] = x[g] || {}; const inp = (q[g] && typeof q[g] === 'object') ? q[g] : {};
      for (const [k, d] of Object.entries(inp)) { const kk = clean(k, 40); if (!kk) continue; if (d === null || d === '') delete x[g][kk]; else if (ok(d)) x[g][kk] = d; } }
    const xv = nowMs(); x.v = xv; const txt = JSON.stringify(x); if (txt.length > 900000) return err('الصور كثيرة أو كبيرة');
    await env.DB.prepare('INSERT INTO ksr_kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind('cfgx', txt).run();
    const c = { ...(await kvJson(env, 'cfg')), xv, t: nowMs() }; await env.DB.prepare('INSERT INTO ksr_kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind('cfg', JSON.stringify(c)).run();
    return json({ ok: true, xv });
  }
  if (b === 'cfg') { // الإعدادات العامة لتطبيق الكاشير. الحفظ بيدمج: الحقل اللي ما انبعت بيضل زي ما هو
    if (m === 'GET') return json(await kvJson(env, 'cfg'));
    const v = { ...(await kvJson(env, 'cfg')), t: nowMs() };
    if (q.feat) { const feat = {}; for (const [k, x] of Object.entries(q.feat || {})) if (/^[a-z]{2,10}$/.test(k)) feat[k] = x ? 1 : 0; v.feat = feat; }
    if ('curOff' in q) v.curOff = (Array.isArray(q.curOff) ? q.curOff : []).filter((x) => ['USD', 'JOD'].includes(x));
    if ('wa' in q) v.wa = String(q.wa || '').replace(/\D/g, '').slice(0, 15);
    if ('notice' in q) v.notice = clean(q.notice, 300);
    if (q.land) v.land = { title: clean(q.land.title, 60), desc: clean(q.land.desc, 300) };
    if (q.tx && typeof q.tx === 'object') { const tx = {}; for (const [k, x] of Object.entries(q.tx).slice(0, 300)) { const a = clean(k, 120), b2 = clean(x, 160); if (a) tx[a] = b2; } v.tx = tx; }
    if (q.col && typeof q.col === 'object') { const col = {}; for (const k of ['gold', 'navy', 'bg']) if (/^#[0-9a-fA-F]{6}$/.test(q.col[k] || '')) col[k] = q.col[k]; v.col = col; }
    if (Array.isArray(q.pay)) v.pay = q.pay.slice(0, 10).map((x) => ({ n: clean(x && x.n, 30), c: /^#[0-9a-fA-F]{6}$/.test((x && x.c) || '') ? x.c : '#5E6A7E' })).filter((x) => x.n);
    if (Array.isArray(q.cards)) v.cards = q.cards.slice(0, 8).map((x) => ({ t: clean(x && x.t, 60), d: clean(x && x.d, 200), u: /^(https:\/\/|\d{9,15}$)/.test(String((x && x.u) || '')) ? clean(x.u, 300) : '', ic: clean(x && x.ic, 4) })).filter((x) => x.t);
    if (q.prices && typeof q.prices === 'object') { const pr = {}; for (const k of Object.keys(PLANS)) if (+q.prices[k] >= 0) pr[k] = Math.round(+q.prices[k]); v.prices = pr; }
    if (Array.isArray(q.hide)) v.hide = q.hide.filter((x) => /^[a-z0-9-]{2,12}$/.test(x)).slice(0, 60);
    return json(v);
  }
  if (b === 'shopcfg') { // ميزات محل معيّن (بتخفي بس، ما بتحذف إشي)
    const id = clean(q.id || new URL(request.url).searchParams.get('id'), 40); if (!id) return err('المحل ناقص');
    if (m === 'GET') return json(await kvJson(env, 'cfg:' + id));
    const feat = {}; for (const [k, v] of Object.entries(q.feat || {})) if (/^[a-z]{2,10}$/.test(k) && v !== null && v !== '') feat[k] = v ? 1 : 0;
    const v = { t: nowMs(), feat, notice: clean(q.notice, 300) };
    await env.DB.prepare('INSERT INTO ksr_kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind('cfg:' + id, JSON.stringify(v)).run();
    return json(v);
  }
  if (b === 'stop' && m === 'POST') { // إيقاف/تفعيل محل: بيمنع الدخول والإضافة بس، وبياناته كلها بتضل
    const sh = await env.DB.prepare('SELECT id FROM ksr_shops WHERE id = ?').bind(clean(q.id, 40)).first(); if (!sh) return err('الحساب مش موجود', 404);
    await env.DB.prepare('UPDATE ksr_shops SET stopped = ? WHERE id = ?').bind(q.on ? nowMs() : null, sh.id).run();
    return json({ ok: true, stopped: !!q.on });
  }
  if (b === 'pushstats' && m === 'GET') {
    const r = await env.DB.prepare('SELECT COUNT(*) AS n, COUNT(DISTINCT shop) AS shops FROM ksr_push').first();
    return json({ subs: r ? r.n : 0, shops: r ? r.shops : 0 });
  }

  if (b === 'summary' && m === 'GET') {
    const [shopsR, licR, codesR, devR] = await Promise.all([
      env.DB.prepare("SELECT id, phone, name, main, version, size, updated, created, devices, meta, acct, owner, trial_end, fp, ip, wa, stopped, (hash <> '') AS haspass FROM ksr_shops ORDER BY created DESC LIMIT 3000").all(),
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
      return { kind: 'shop', id: s.id, stopped: s.stopped || 0, acct: s.acct, owner: s.owner || '', wa: s.wa || '', haspass: !!s.haspass, fp: s.fp || '', phone: s.phone, name: s.name || meta.shop || '', created: s.created, updated: s.updated, lastSeen, devices: Object.entries(d).map(([k, v]) => ({ id: k, label: v.label, last: v.last, main: k === s.main })), sales: meta.sales || 0, items: meta.items || 0, trialEnds: s.trial_end || meta.trialEnds || null, legacyExp: null, lic: L ? { exp: L.exp, plan: L.plan, updated: L.updated } : null, size: s.size, note: L && L.note || '' };
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
      // ما في حذف نهائي: الحساب بينقل للأرشيف (موقوف) وكل بياناته بتضل وبترجع بضغطة «تفعيل»
      await env.DB.prepare('UPDATE ksr_shops SET stopped = ? WHERE id = ?').bind(nowMs(), sh.id).run();
      return json({ ok: true, archived: true });
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
  if (b === 'ad') { // الإعلان اللي بيظهر داخل التطبيق لكل المحلات
    if (m === 'GET') { const r = await env.DB.prepare("SELECT v FROM ksr_kv WHERE k = 'app_ad'").first(); let v = {}; try { v = JSON.parse((r && r.v) || '{}'); } catch {} return json(v); }
    if (m === 'POST') { const img = String((q && q.img) || ''); if (img && !/^data:image\/(jpeg|png|webp);base64,/.test(img)) return err('الصورة مش صالحة'); if (img.length > 700000) return err('الصورة كبيرة');
      const v = { on: !!(q && q.on), title: clean((q && q.title) || '', 80), text: clean((q && q.text) || '', 300), btn: clean((q && q.btn) || '', 30), link: clean((q && q.link) || '', 300), img, v: nowMs() };
      if (v.link && !/^(https:\/\/|tel:|https:\/\/wa\.me\/)/.test(v.link)) return err('الرابط لازم يبدأ بـ https://');
      await env.DB.prepare("INSERT INTO ksr_kv (k, v) VALUES ('app_ad', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(JSON.stringify(v)).run(); return json(v); }
  }
  if (b === 'books') { // دفتر المالك: تعديل مبالغ الاشتراكات (أو استثناؤها) + مصروفات الشركة
    if (m === 'GET') { const r = await env.DB.prepare("SELECT v FROM ksr_kv WHERE k = 'admin_books'").first(); let v = { adj: {}, exp: [] }; try { v = Object.assign(v, JSON.parse((r && r.v) || '{}')); } catch {} return json(v); }
    if (m === 'POST') {
      const adj = {}; for (const [k, v] of Object.entries((q && q.adj) || {}).slice(0, 5000)) { const kk = clean(k, 40); if (!kk || !v) continue; const o = {}; if (v.p !== undefined && v.p !== null && v.p !== '') o.p = Math.max(0, Math.min(1e7, +v.p || 0)); if (v.on !== undefined) o.on = !!v.on; if (v.n) o.n = clean(v.n, 120); adj[kk] = o; }
      const exp = (Array.isArray(q && q.exp) ? q.exp : []).slice(0, 5000).map((e) => ({ id: clean(String(e.id || ''), 30) || String(nowMs()), ts: +e.ts || nowMs(), amt: Math.max(0, Math.min(1e7, +e.amt || 0)), note: clean(e.note || '', 120), cat: clean(e.cat || '', 40) })).filter((e) => e.amt > 0);
      const v = JSON.stringify({ adj, exp });
      await env.DB.prepare("INSERT INTO ksr_kv (k, v) VALUES ('admin_books', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(v).run();
      return json({ ok: true, adj, exp });
    }
  }
  if (b === 'note' && m === 'POST') {
    const target = q.kind === 'device' ? 'dev:' + clean(q.id, 40) : 'shop:' + clean(q.id, 40);
    await env.DB.prepare('INSERT INTO ksr_lic (id, exp, plan, updated, note) VALUES (?, 0, NULL, ?, ?) ON CONFLICT(id) DO UPDATE SET note = excluded.note').bind(target, nowMs(), clean(q.note, 300)).run();
    return json({ ok: true });
  }
  return err('مسار غير معروف', 404);
}
