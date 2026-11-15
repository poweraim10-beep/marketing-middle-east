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
const pubShop = (s) => ({ id: s.id, acct: s.acct, owner: s.owner, phone: s.phone, name: s.name, main: s.main, version: s.version, updated: s.updated, size: s.size, haspass: !!s.hash });
async function seen(env, shop, device, label) {
  if (!device) return;
  let d = {}; try { d = JSON.parse(shop.devices || '{}'); } catch {}
  const prev = d[device] || {};
  d[device] = { label: clean(label || prev.label || '', 60), first: prev.first || nowMs(), last: nowMs() };
  const keys = Object.keys(d).sort((a, b) => d[b].last - d[a].last).slice(0, 12);
  const out = {}; for (const k of keys) out[k] = d[k];
  await env.DB.prepare('UPDATE ksr_shops SET devices = ? WHERE id = ?').bind(JSON.stringify(out), shop.id).run();
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
  const payload = b64u(JSON.stringify({ t: 'shop', id: shop.id, a: shop.acct, d: shop.main, e: L ? L.exp : -1, tr: shop.trial_end || 0, p: L ? (L.plan || '') : 'trial', i: Date.now() }));
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
      if (phone.length < 9) return err('اكتب رقم جوال صحيح');
      if (owner.length < 2) return err('اكتب اسم صاحب المحل');
      if (!name) return err('اكتب اسم المحل');
      if (!device) return err('رقم الجهاز ناقص');
      let shop = await env.DB.prepare('SELECT * FROM ksr_shops WHERE phone = ?').bind(phone).first();
      if (shop) {
        if (shop.main !== device) {
          await seen(env, shop, device, clean(q.label, 60) + ' (طلب دخول)');
          return err('هذا الرقم مسجّل على جهاز ثاني', 409, { code: 'other_device', acct: (await ensureAcct(env, shop)).acct, haspass: !!shop.hash });
        }
        await env.DB.prepare('UPDATE ksr_shops SET owner = COALESCE(owner, ?), name = COALESCE(name, ?) WHERE id = ?').bind(owner, name, shop.id).run();
        shop = await ensureAcct(env, await env.DB.prepare('SELECT * FROM ksr_shops WHERE id = ?').bind(shop.id).first());
      } else {
        const day = nowMs() - 864e5;
        await env.DB.prepare('DELETE FROM ksr_join WHERE t < ?').bind(day).run();
        const j = await env.DB.prepare('SELECT COUNT(*) AS n FROM ksr_join WHERE ip = ?').bind(ip).first();
        if ((j && j.n) >= 25) return err('انعمل محلات كثير من نفس الشبكة اليوم. تواصل مع الدعم', 429);
        const since = Number(q.since) || 0; // installs from before accounts keep their original trial start (never a longer trial)
        const t0 = since > nowMs() - 180 * 864e5 && since < nowMs() ? since : nowMs();
        const salt = randomHex(16), id = randomHex(10), acct = await newAcct(env);
        await env.DB.prepare('INSERT INTO ksr_shops (id, phone, name, salt, hash, main, version, size, updated, created, devices, meta, acct, owner, trial_end, fp, ip) VALUES (?, ?, ?, ?, \'\', ?, 0, 0, NULL, ?, ?, \'{}\', ?, ?, ?, ?, ?)')
          .bind(id, phone, name, salt, device, nowMs(), JSON.stringify({ [device]: { label: clean(q.label, 60), first: nowMs(), last: nowMs() } }), acct, owner, t0 + TRIAL_MS, fp || null, ip).run();
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
      if (shop && !shop.hash) { await noteFail(env, ip); return err('هذا الحساب لسا ما إله كلمة سر. حدّدها من الجهاز الأساسي: الإعدادات ← حساب المحل', 401, { code: 'nopass' }); }
      if (!shop || !same(shop.hash, await hashSecret(String(q.password || ''), shop.salt))) { await noteFail(env, ip); return err('رقم الجوال أو كلمة السر غلط', 401); }
      await seen(env, shop, clean(q.device, 40), q.label);
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
      if (device) {
        const sp = url.searchParams, t = nowMs();
        await env.DB.prepare('INSERT INTO ksr_dev (id, shop, phone, first, last, trial_end, sales, items, ver, account) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET shop = COALESCE(excluded.shop, ksr_dev.shop), phone = COALESCE(excluded.phone, ksr_dev.phone), last = excluded.last, sales = excluded.sales, items = excluded.items, ver = excluded.ver, account = COALESCE(excluded.account, ksr_dev.account)')
          .bind(device, clean(sp.get('shop') || '', 80) || null, clean(sp.get('phone') || '', 20) || null, t, t, null, parseInt(sp.get('sales'), 10) || 0, parseInt(sp.get('items'), 10) || 0, clean(sp.get('v') || '', 10) || null, shopRow ? shopRow.id : null).run().catch(() => {});
        if (shopRow) await seen(env, shopRow, device);
      }
      if (!shopRow) return json({ license: null });
      return json({ license: await signShop(env, shopRow), main: shopRow.main });
    }

    // ----- everything below needs a shop token -----
    const shop = await readShop(env, request);
    if (a === 'admin') return admin(env, request, b);
    if (!shop) return err('سجّل دخول من جديد', 401);
    const device = clean(url.searchParams.get('device') || request.headers.get('x-device') || '', 40);

    if (a === 'state' && m === 'GET') {
      await seen(env, shop, device);
      const have = parseInt(url.searchParams.get('have') || '-1', 10);
      const out = { shop: pubShop(shop) };
      if (shop.version > have && shop.version > 0) out.data = await readState(env, shop.id);
      return json(out);
    }

    if (a === 'state' && m === 'PUT') {
      const q = await body(request);
      const dev = clean(q.device, 40);
      if (dev !== shop.main) return err('جهاز ثاني صار هو الأساسي', 409, { code: 'not_main', shop: pubShop(shop) });
      if (Number(q.base) !== shop.version) return err('في نسخة أحدث على الحساب', 409, { code: 'stale', shop: pubShop(shop) });
      const data = String(q.data || '');
      if (!data || data.length > MAX_STATE) return err('حجم البيانات غير مقبول', 413);
      const meta = JSON.stringify(q.meta && typeof q.meta === 'object' ? q.meta : {}).slice(0, 4000);
      const t = nowMs();
      const upd = await env.DB.prepare('UPDATE ksr_shops SET version = version + 1, updated = ?, size = ?, meta = ?, name = COALESCE(?, name) WHERE id = ? AND version = ? AND main = ?')
        .bind(t, data.length, meta, q.name ? clean(q.name, 80) : null, shop.id, shop.version, dev).run();
      if (!upd.meta || !upd.meta.changes) return err('في نسخة أحدث على الحساب', 409, { code: 'stale' });
      const stmts = [env.DB.prepare('DELETE FROM ksr_chunks WHERE shop = ?').bind(shop.id)];
      for (let i = 0, k = 0; i < data.length; i += CHUNK, k++) stmts.push(env.DB.prepare('INSERT INTO ksr_chunks (shop, i, data) VALUES (?, ?, ?)').bind(shop.id, k, data.slice(i, i + CHUNK)));
      await env.DB.batch(stmts);
      await seen(env, shop, dev);
      return json({ version: shop.version + 1, updated: t });
    }

    if (a === 'main' && m === 'POST') {
      const q = await body(request);
      if (!same(shop.hash, await hashSecret(String(q.password || ''), shop.salt))) { await noteFail(env, ip); return err('كلمة السر غلط', 401); }
      const dev = clean(q.device, 40);
      if (!dev) return err('رقم الجهاز ناقص');
      await env.DB.prepare('UPDATE ksr_shops SET main = ? WHERE id = ?').bind(dev, shop.id).run();
      await seen(env, shop, dev, q.label);
      return json({ shop: { ...pubShop(shop), main: dev } });
    }

    if (a === 'password' && m === 'POST') {
      const q = await body(request);
      if (!same(shop.hash, await hashSecret(String(q.old || ''), shop.salt))) { await noteFail(env, ip); return err('كلمة السر الحالية غلط', 401); }
      if (String(q.password || '').length < 6) return err('كلمة السر الجديدة لازم تكون 6 أحرف أو أرقام على الأقل');
      const salt = randomHex(16);
      await env.DB.prepare('UPDATE ksr_shops SET salt = ?, hash = ? WHERE id = ?').bind(salt, await hashSecret(String(q.password), salt), shop.id).run();
      return json({ token: await makeToken(env, { ...shop, salt }) });
    }

    if (a === 'blobs' && m === 'GET') {
      const r = await env.DB.prepare('SELECT id FROM ksr_blobs WHERE shop = ?').bind(shop.id).all();
      return json({ ids: (r.results || []).map((x) => x.id) });
    }
    if (a === 'blob' && b && m === 'PUT') {
      if (device !== shop.main) return err('جهاز ثاني صار هو الأساسي', 409, { code: 'not_main' });
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

  if (b === 'summary' && m === 'GET') {
    const [shopsR, licR, codesR, devR] = await Promise.all([
      env.DB.prepare("SELECT id, phone, name, main, version, size, updated, created, devices, meta, acct, owner, trial_end, fp, ip, (hash <> '') AS haspass FROM ksr_shops ORDER BY created DESC LIMIT 3000").all(),
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
      return { kind: 'shop', id: s.id, acct: s.acct, owner: s.owner || '', haspass: !!s.haspass, fp: s.fp || '', phone: s.phone, name: s.name || meta.shop || '', created: s.created, updated: s.updated, lastSeen, devices: Object.entries(d).map(([k, v]) => ({ id: k, label: v.label, last: v.last, main: k === s.main })), sales: meta.sales || 0, items: meta.items || 0, trialEnds: s.trial_end || meta.trialEnds || null, legacyExp: null, lic: L ? { exp: L.exp, plan: L.plan, updated: L.updated } : null, size: s.size, note: L && L.note || '' };
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
    return json({ codes: out, acct, owner, shop: sh.name || '', phone: sh.phone });
  }
  if (b === 'acct' && m === 'GET') {
    const url = new URL(request.url); const n = parseInt(url.searchParams.get('n'), 10);
    const sh = n ? await env.DB.prepare('SELECT acct, owner, name, phone FROM ksr_shops WHERE acct = ?').bind(n).first() : null;
    return sh ? json({ shop: sh }) : err('رقم الحساب مش موجود', 404);
  }
  if (b === 'move' && m === 'POST') { // the owner moves a shop to a new device (old one stops selling)
    const sh = await env.DB.prepare('SELECT * FROM ksr_shops WHERE id = ?').bind(clean(q.id, 40)).first();
    const dev = clean(q.device, 40);
    if (!sh || !dev) return err('بيانات ناقصة');
    await env.DB.prepare('UPDATE ksr_shops SET main = ? WHERE id = ?').bind(dev, sh.id).run();
    return json({ ok: true });
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
