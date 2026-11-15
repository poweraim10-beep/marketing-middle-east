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
  'access-control-allow-headers': 'authorization, content-type',
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
  ]);
  ready = true;
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
const pubShop = (s) => ({ id: s.id, phone: s.phone, name: s.name, main: s.main, version: s.version, updated: s.updated, size: s.size });
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

    // ----- create a shop account -----
    if (a === 'register' && m === 'POST') {
      const q = await body(request);
      const phone = phoneOf(q.phone), password = String(q.password || ''), device = clean(q.device, 40);
      if (phone.length < 8) return err('اكتب رقم جوال صحيح');
      if (password.length < 6) return err('كلمة السر لازم تكون 6 أحرف أو أرقام على الأقل');
      if (!device) return err('رقم الجهاز ناقص');
      if (await tooManyFails(env, ip)) return err('محاولات كثيرة. جرّب بعد ربع ساعة', 429);
      const exists = await env.DB.prepare('SELECT id FROM ksr_shops WHERE phone = ?').bind(phone).first();
      if (exists) { await noteFail(env, ip); return err('هذا الرقم عليه حساب. ادخل بكلمة السر بدل إنشاء حساب جديد', 409); }
      const salt = randomHex(16);
      const shop = { id: randomHex(10), phone, name: clean(q.name, 80), salt, hash: await hashSecret(password, salt), main: device, version: 0, size: 0, updated: null, created: nowMs() };
      await env.DB.prepare('INSERT INTO ksr_shops (id, phone, name, salt, hash, main, version, size, updated, created, devices, meta) VALUES (?, ?, ?, ?, ?, ?, 0, 0, NULL, ?, ?, ?)')
        .bind(shop.id, phone, shop.name, salt, shop.hash, device, shop.created, JSON.stringify({ [device]: { label: clean(q.label, 60), first: nowMs(), last: nowMs() } }), '{}').run();
      return json({ token: await makeToken(env, shop), shop: pubShop(shop) });
    }

    // ----- sign in from any device -----
    if (a === 'login' && m === 'POST') {
      const q = await body(request);
      if (await tooManyFails(env, ip)) return err('محاولات كثيرة. جرّب بعد ربع ساعة', 429);
      const phone = phoneOf(q.phone);
      const shop = await env.DB.prepare('SELECT * FROM ksr_shops WHERE phone = ?').bind(phone).first();
      if (!shop || !same(shop.hash, await hashSecret(String(q.password || ''), shop.salt))) { await noteFail(env, ip); return err('رقم الجوال أو كلمة السر غلط', 401); }
      await seen(env, shop, clean(q.device, 40), q.label);
      return json({ token: await makeToken(env, shop), shop: pubShop(shop) });
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

// ---------- the seller's dashboard (academy owner session only) ----------
async function admin(env, request, b) {
  if (!(await isAcademyOwner(env, request))) {
    if (b === 'shops') return err('لازم تسجّل دخول بحساب الأدمن بالأكاديمية', 403);
    return new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui;direction:rtl;padding:24px;background:#0B1F3A;color:#F7F1E1">
<h2>لوحة مشتركين كاشيرك</h2><p>سجّل دخول بحسابك (الأدمن) على <a style="color:#F0CF7A" href="/">academy.marketingmiddleeast.com</a> بنفس المتصفح، وبعدها افتح هالصفحة من جديد.</p></body>`, { status: 403, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }
  const r = await env.DB.prepare('SELECT id, phone, name, main, version, size, updated, created, devices, meta FROM ksr_shops ORDER BY COALESCE(updated, created) DESC LIMIT 1000').all();
  const shops = (r.results || []).map((s) => {
    let d = {}, meta = {}; try { d = JSON.parse(s.devices || '{}'); } catch {} try { meta = JSON.parse(s.meta || '{}'); } catch {}
    const last = Math.max(0, ...Object.values(d).map((x) => x.last || 0));
    return { phone: s.phone, name: s.name || meta.shop || '', created: s.created, updated: s.updated, version: s.version, size: s.size, devices: Object.keys(d).length, lastSeen: last, lic: meta.lic || null, sales: meta.sales || 0, items: meta.items || 0, trialEnds: meta.trialEnds || null, device: s.main };
  });
  if (b === 'shops') return json({ shops });
  const rows = shops.map((s) => {
    const day = (t) => t ? new Date(t).toLocaleDateString('ar-u-nu-latn', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
    const ago = s.lastSeen ? Math.floor((Date.now() - s.lastSeen) / 864e5) : null;
    const lic = s.lic ? (s.lic > Date.now() ? `مفعّل لـ ${day(s.lic)}` : `منتهي ${day(s.lic)}`) : (s.trialEnds ? (s.trialEnds > Date.now() ? `تجربة لـ ${day(s.trialEnds)}` : 'انتهت التجربة') : '—');
    const esc = (x) => String(x ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    return `<tr><td><b>${esc(s.name)}</b><br><span style="opacity:.7">${esc(s.phone)}</span></td><td>${lic}</td><td>${s.sales}</td><td>${s.devices}</td><td>${ago == null ? '—' : ago === 0 ? 'اليوم' : `قبل ${ago} يوم`}</td><td>${day(s.created)}</td><td>${Math.round(s.size / 1024)} KB</td></tr>`;
  }).join('');
  const active = shops.filter((s) => s.lastSeen && Date.now() - s.lastSeen < 7 * 864e5).length;
  return new Response(`<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>مشتركين كاشيرك</title>
<style>body{font-family:system-ui,'IBM Plex Sans Arabic',sans-serif;margin:0;background:#F5F1E8;color:#0B1F3A}header{background:linear-gradient(150deg,#16325A,#0B1F3A);color:#F7F1E1;padding:22px 18px;border-bottom:3px solid #C8A24A}h1{margin:0;font-size:22px}.k{display:flex;gap:10px;flex-wrap:wrap;padding:14px}.k div{background:#fff;border-radius:14px;padding:12px 16px;box-shadow:0 2px 8px rgba(0,0,0,.06)}.k b{display:block;font-size:24px}table{width:calc(100% - 28px);margin:0 14px 30px;border-collapse:collapse;background:#fff;border-radius:14px;overflow:hidden;font-size:14px}th,td{padding:10px;text-align:right;border-bottom:1px solid #eee}th{background:#0B1F3A;color:#F0CF7A;font-weight:600}</style>
<header><h1>لوحة مشتركين «كاشيرك الذكي»</h1></header>
<div class="k"><div>كل المحلات<b>${shops.length}</b></div><div>شغّالين آخر 7 أيام<b>${active}</b></div></div>
<div style="overflow-x:auto"><table><tr><th>المحل</th><th>الاشتراك</th><th>الفواتير</th><th>الأجهزة</th><th>آخر ظهور</th><th>من</th><th>الحجم</th></tr>${rows || '<tr><td colspan="7">ما في محلات لسا</td></tr>'}</table></div></html>`, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}
