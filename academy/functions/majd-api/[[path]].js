// «المجد لمكافحة الحشرات» — orders & delivery API (Cloudflare Pages Function, D1 binding: DB)
// Routes live under /majd-api/*. Separate tables (majd_*) inside the academy database.
// Roles: admin (one password) and drivers (one PIN each). Drivers only ever receive their own orders.

const PBKDF2_ITER = 100000;
const TOKEN_DAYS = 60;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
const err = (msg, status = 400) => json({ error: msg }, status);
const nowMs = () => Date.now();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const randomHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const b64u = (s) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => decodeURIComponent(escape(atob(s.replace(/-/g, '+').replace(/_/g, '/'))));
async function body(req) { try { return await req.json(); } catch { return {}; } }
const clean = (s, max = 300) => String(s ?? '').trim().slice(0, max);
const num = (v) => { const n = parseFloat(v); return Number.isFinite(n) ? n : 0; };

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
    env.DB.prepare('CREATE TABLE IF NOT EXISTS majd_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS majd_orders (id TEXT PRIMARY KEY, driver TEXT, created_by TEXT, data TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS majd_products (id TEXT PRIMARY KEY, data TEXT NOT NULL, updated INTEGER NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS majd_receipts (id TEXT PRIMARY KEY, driver TEXT, img TEXT NOT NULL, t INTEGER NOT NULL)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS majd_fail (ip TEXT NOT NULL, t INTEGER NOT NULL)'),
  ]);
  ready = true;
}
async function kvGet(env, k) {
  const r = await env.DB.prepare('SELECT v FROM majd_kv WHERE k = ?').bind(k).first();
  if (!r) return null;
  try { return JSON.parse(r.v); } catch { return null; }
}
async function kvSet(env, k, v) {
  await env.DB.prepare('INSERT INTO majd_kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind(k, JSON.stringify(v)).run();
}
async function secret(env) {
  let s = await kvGet(env, 'secret');
  if (!s) { s = randomHex(32); await kvSet(env, 'secret', s); }
  return s;
}

// First run: the store's own starting data (name, delivery zones, the two captains, the four products).
const DEFAULT_SETTINGS = {
  storeName: 'شركة المجد لمكافحة الحشرات',
  storeTagline: 'بيع منتجات مكافحة الحشرات',
  adminName: 'د. محمود نصرالله (أبو عمر)',
  countryCode: '970',
  feeIncluded: true,
  areas: [{ name: 'غزة والشمال', fee: 10 }, { name: 'الجنوب', fee: 12 }],
  drivers: [
    { id: 'gaza', name: 'محمد مطر (أبو أنس)', short: 'أبو أنس', zone: 'غزة والشمال', phone: '' },
    { id: 'south', name: 'أبو إسلام مطر', short: 'أبو إسلام', zone: 'الجنوب', phone: '' },
  ],
  staff: [
    { id: 'amona', name: 'أمونة' },
    { id: 'abuayman', name: 'محمد أبو أيمن' },
    { id: 'ahmad', name: 'أحمد أبو إسلام' },
  ],
};
const DEFAULT_PRODUCTS = [
  { id: 'df-spray', name: 'سائل البعوض والبراغيث', unit: 'لتر', price: 45, img: 'img/spray.jpg', available: true, order: 1 },
  { id: 'df-gel', name: 'عجينة صراصير', unit: 'D.F', price: 50, img: 'img/gel.jpg', available: true, order: 2 },
  { id: 'rodent-choc', name: 'سم شوكولاتة للقوارض', unit: '', price: 0, img: 'img/choc.jpg', available: true, order: 3 },
  { id: 'ratimon-red', name: 'سم أحمر للقوارض', unit: 'رطيمون 60 مل', price: 50, img: 'img/red.jpg', available: true, order: 4 },
];
async function settings(env) {
  let s = await kvGet(env, 'settings');
  if (!s) {
    s = DEFAULT_SETTINGS;
    await kvSet(env, 'settings', s);
    const t = nowMs();
    await env.DB.batch(DEFAULT_PRODUCTS.map((p) => {
      const { id, ...d } = p;
      return env.DB.prepare('INSERT OR IGNORE INTO majd_products (id, data, updated) VALUES (?, ?, ?)').bind(id, JSON.stringify({ ...d, createdAt: t }), t);
    }));
  }
  return s;
}
// what clients may see: PIN hashes never leave the server
function publicSettings(s) {
  return {
    ...s,
    drivers: (s.drivers || []).map(({ pinHash, pinSalt, pinVer, ...d }) => ({ ...d, hasPin: !!pinHash })),
    staff: (s.staff || []).map(({ pinHash, pinSalt, ...d }) => ({ ...d, hasPin: !!pinHash })),
  };
}
function driverForArea(s, area) { return (s.drivers || []).find((d) => d.zone === area) || null; }

// ---------- auth ----------
// Creating or resetting the admin password needs the academy owner's own signed-in session (cookie mme_s).
const ACADEMY_OWNER = 'power.ai.m10@gmail.com';
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
async function makeToken(env, role, driverId, ver) {
  const payload = b64u(JSON.stringify({ r: role, d: driverId || '', v: ver || '', exp: nowMs() + TOKEN_DAYS * 864e5 }));
  return payload + '.' + (await hmac(await secret(env), payload));
}
async function readToken(env, req) {
  const h = req.headers.get('authorization') || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  const [payload, sig] = tok.split('.');
  if (!payload || !sig) return null;
  if (!same(sig, await hmac(await secret(env), payload))) return null;
  let p; try { p = JSON.parse(unb64u(payload)); } catch { return null; }
  if (!p || p.exp < nowMs()) return null;
  // a password / PIN change logs out every older session
  if (p.r === 'admin') {
    const a = await kvGet(env, 'admin');
    if (!a || a.salt !== p.v) return null;
    return { role: 'admin' };
  }
  if (p.r === 'driver') {
    const s = await settings(env);
    const d = (s.drivers || []).find((x) => x.id === p.d);
    if (!d || !d.pinHash || d.pinSalt !== p.v) return null;
    return { role: 'driver', driverId: d.id };
  }
  if (p.r === 'staff') {
    const s = await settings(env);
    const d = (s.staff || []).find((x) => x.id === p.d);
    if (!d || !d.pinHash || d.pinSalt !== p.v) return null;
    return { role: 'staff', staffId: d.id, name: d.name };
  }
  return null;
}
async function tooManyFails(env, ip) {
  const since = nowMs() - 15 * 60e3;
  await env.DB.prepare('DELETE FROM majd_fail WHERE t < ?').bind(since).run();
  const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM majd_fail WHERE ip = ?').bind(ip).first();
  return (r && r.n) >= 8;
}
async function noteFail(env, ip) { await env.DB.prepare('INSERT INTO majd_fail (ip, t) VALUES (?, ?)').bind(ip, nowMs()).run(); }

// ---------- orders ----------
const DRIVER_FIELDS = ['status', 'history', 'deliveredAt', 'updatedAt', 'payMethod', 'transferShop', 'transferAmount', 'taskNote', 'deliverNote', 'hasReceipt', 'driverNote'];
const DRIVER_STATUSES = ['picked', 'onway', 'delivered', 'postponed', 'returned'];
const STAFF_FIELDS = ['customer', 'phone', 'address', 'notes', 'items', 'area', 'fee', 'feeOnCustomer', 'wholesale', 'payment', 'updatedAt'];
const rowToOrder = (r) => { let d = {}; try { d = JSON.parse(r.data); } catch {} return { ...d, id: r.id }; };
function sanitizeOrder(o) {
  const d = { ...o }; delete d.id;
  const s = JSON.stringify(d);
  if (s.length > 200000) throw new Error('الطلب كبير جداً');
  return d;
}

// ---------- router ----------
export async function onRequest({ request, env, params }) {
  if (!env.DB) return err('قاعدة البيانات غير مربوطة', 500);
  await ensure(env);
  const parts = [].concat(params.path || []).filter(Boolean);
  const [a, b] = parts;
  const m = request.method;
  const ip = request.headers.get('cf-connecting-ip') || 'x';

  try {
    // ----- public -----
    if (a === 'public' && m === 'GET') {
      const s = await settings(env);
      const admin = await kvGet(env, 'admin');
      return json({
        storeName: s.storeName, storeTagline: s.storeTagline, adminName: s.adminName || '', adminSet: !!admin,
        drivers: (s.drivers || []).map((d) => ({ id: d.id, name: d.name, short: d.short, zone: d.zone, hasPin: !!d.pinHash })),
        staff: (s.staff || []).map((d) => ({ id: d.id, name: d.name, hasPin: !!d.pinHash })),
      });
    }
    if (a === 'setup' && m === 'POST') {
      const { password, reset } = await body(request);
      if (!(await isAcademyOwner(env, request))) return err('لازم تكون مسجّل دخول بحسابك (الأدمن) بالأكاديمية على نفس الجوال. افتح academy.marketingmiddleeast.com وسجّل دخول، وبعدها ارجع لهون.', 403);
      if ((await kvGet(env, 'admin')) && !reset) return err('كلمة سر الأدمن موجودة', 409);
      if (String(password || '').length < 4) return err('كلمة السر لازم تكون 4 أحرف أو أرقام على الأقل');
      const salt = randomHex(16);
      await kvSet(env, 'admin', { salt, hash: await hashSecret(password, salt) });
      return json({ token: await makeToken(env, 'admin', '', salt), role: 'admin' });
    }
    if (a === 'login' && m === 'POST') {
      if (await tooManyFails(env, ip)) return err('محاولات كثيرة، استنى ربع ساعة وجرّب', 429);
      const bd = await body(request);
      if (bd.role === 'admin') {
        const ad = await kvGet(env, 'admin');
        if (!ad) return err('ما في كلمة سر للأدمن بعد', 409);
        if (!same(await hashSecret(bd.password || '', ad.salt), ad.hash)) { await noteFail(env, ip); return err('كلمة السر غلط', 401); }
        return json({ token: await makeToken(env, 'admin', '', ad.salt), role: 'admin' });
      }
      if (bd.role === 'driver') {
        const s = await settings(env);
        const d = (s.drivers || []).find((x) => x.id === bd.driverId);
        if (!d) return err('الحساب مش موجود', 404);
        if (!d.pinHash) return err('ما في رقم سري لحسابك لسا، اطلب من الأدمن يحدده', 409);
        if (!same(await hashSecret(bd.pin || '', d.pinSalt), d.pinHash)) { await noteFail(env, ip); return err('الرقم السري غلط', 401); }
        return json({ token: await makeToken(env, 'driver', d.id, d.pinSalt), role: 'driver', driverId: d.id });
      }
      if (bd.role === 'staff') {
        const s = await settings(env);
        const d = (s.staff || []).find((x) => x.id === bd.staffId);
        if (!d) return err('الحساب مش موجود', 404);
        if (!d.pinHash) return err('ما في رقم سري لحسابك لسا، اطلب من الإدارة تحدده', 409);
        if (!same(await hashSecret(bd.pin || '', d.pinSalt), d.pinHash)) { await noteFail(env, ip); return err('الرقم السري غلط', 401); }
        return json({ token: await makeToken(env, 'staff', d.id, d.pinSalt), role: 'staff', staffId: d.id });
      }
      return err('طلب غير صحيح');
    }

    // ----- signed in -----
    const me = await readToken(env, request);
    if (!me) return err('سجّل دخول من جديد', 401);
    const isAdmin = me.role === 'admin';
    const isStaff = me.role === 'staff';

    if (a === 'me' && m === 'GET') return json(me);

    if (a === 'state' && m === 'GET') {
      const s = await settings(env);
      const prods = (await env.DB.prepare('SELECT id, data FROM majd_products').all()).results.map(rowToOrder);
      const q = isAdmin
        ? env.DB.prepare('SELECT id, data FROM majd_orders ORDER BY created DESC LIMIT 800')
        : isStaff
          ? env.DB.prepare('SELECT id, data FROM majd_orders WHERE created_by = ? ORDER BY created DESC LIMIT 400').bind(me.staffId)
          : env.DB.prepare('SELECT id, data FROM majd_orders WHERE driver = ? ORDER BY created DESC LIMIT 400').bind(me.driverId);
      const orders = (await q.all()).results.map(rowToOrder);
      return json({ me, settings: publicSettings(s), products: prods, orders });
    }

    if (a === 'settings' && m === 'PUT') {
      if (!isAdmin) return err('للأدمن فقط', 403);
      const { settings: ns } = await body(request);
      if (!ns || typeof ns !== 'object') return err('طلب غير صحيح');
      const old = await settings(env);
      const oldDrivers = Object.fromEntries((old.drivers || []).map((d) => [d.id, d]));
      const drivers = (Array.isArray(ns.drivers) ? ns.drivers : old.drivers || []).slice(0, 20).map((d) => {
        const o = oldDrivers[d.id] || {};
        return {
          id: clean(d.id, 40) || randomHex(4), name: clean(d.name, 80), short: clean(d.short, 40), zone: clean(d.zone, 80), phone: clean(d.phone, 30),
          ...(o.pinHash ? { pinHash: o.pinHash, pinSalt: o.pinSalt } : {}),
        };
      });
      const oldStaff = Object.fromEntries((old.staff || []).map((d) => [d.id, d]));
      const staff = (Array.isArray(ns.staff) ? ns.staff : old.staff || []).slice(0, 30).map((d) => {
        const o = oldStaff[d.id] || {};
        return { id: clean(d.id, 40) || randomHex(4), name: clean(d.name, 80), ...(o.pinHash ? { pinHash: o.pinHash, pinSalt: o.pinSalt } : {}) };
      }).filter((d) => d.name);
      const s = {
        adminName: clean(ns.adminName, 80) || old.adminName || '', staff,
        storeName: clean(ns.storeName, 80), storeTagline: clean(ns.storeTagline, 120), countryCode: clean(ns.countryCode, 4) || '970',
        feeIncluded: !!ns.feeIncluded, driverName: clean(ns.driverName, 60), driverPhone: clean(ns.driverPhone, 30),
        areas: (Array.isArray(ns.areas) ? ns.areas : []).slice(0, 40).map((x) => ({ name: clean(x.name, 80), fee: num(x.fee) })).filter((x) => x.name),
        drivers,
      };
      await kvSet(env, 'settings', s);
      return json({ ok: true, settings: publicSettings(s) });
    }
    if (a === 'driver-pin' && m === 'PUT') {
      if (!isAdmin) return err('للأدمن فقط', 403);
      const { driverId, staffId, pin } = await body(request);
      if (String(pin || '').length < 4) return err('الرقم السري لازم يكون 4 أرقام على الأقل');
      const s = await settings(env);
      const d = staffId ? (s.staff || []).find((x) => x.id === staffId) : (s.drivers || []).find((x) => x.id === driverId);
      if (!d) return err('الحساب مش موجود', 404);
      d.pinSalt = randomHex(16); d.pinHash = await hashSecret(pin, d.pinSalt);
      await kvSet(env, 'settings', s);
      return json({ ok: true });
    }
    if (a === 'admin-password' && m === 'PUT') {
      if (!isAdmin) return err('للأدمن فقط', 403);
      const { old, password } = await body(request);
      const ad = await kvGet(env, 'admin');
      if (!same(await hashSecret(old || '', ad.salt), ad.hash)) return err('كلمة السر الحالية غلط', 401);
      if (String(password || '').length < 4) return err('كلمة السر الجديدة قصيرة');
      const salt = randomHex(16);
      await kvSet(env, 'admin', { salt, hash: await hashSecret(password, salt) });
      return json({ token: await makeToken(env, 'admin', '', salt) });
    }

    // products
    if (a === 'products') {
      if (!isAdmin) return err('للأدمن فقط', 403);
      if (m === 'POST') {
        const { data } = await body(request);
        const id = 'p' + randomHex(5);
        const d = sanitizeOrder(data || {});
        await env.DB.prepare('INSERT INTO majd_products (id, data, updated) VALUES (?, ?, ?)').bind(id, JSON.stringify(d), nowMs()).run();
        return json({ id });
      }
      if (b && m === 'PUT') {
        const { data } = await body(request);
        await env.DB.prepare('INSERT INTO majd_products (id, data, updated) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated = excluded.updated')
          .bind(b, JSON.stringify(sanitizeOrder(data || {})), nowMs()).run();
        return json({ ok: true });
      }
      if (b && m === 'DELETE') { await env.DB.prepare('DELETE FROM majd_products WHERE id = ?').bind(b).run(); return json({ ok: true }); }
    }

    // orders
    if (a === 'orders') {
      const s = await settings(env);
      if (m === 'POST') {
        if (!isAdmin && !isStaff) return err('غير مسموح', 403);
        const { data } = await body(request);
        const d = sanitizeOrder(data || {});
        if (isStaff) { d.status = 'new'; d.settled = false; d.createdBy = me.staffId; d.createdByName = me.name; delete d.driverId; }
        else { d.createdBy = 'admin'; d.createdByName = s.adminName || 'الإدارة'; }
        if (!d.driverId) { const dr = driverForArea(s, d.area); d.driverId = dr ? dr.id : ''; }
        const last = await env.DB.prepare("SELECT MAX(CAST(json_extract(data, '$.num') AS INTEGER)) AS n FROM majd_orders").first();
        d.num = Math.max(1000, (last && last.n) || 1000) + 1;
        const id = 'o' + randomHex(6), t = nowMs();
        d.createdAt = d.createdAt || t;
        await env.DB.prepare('INSERT INTO majd_orders (id, driver, created_by, data, created, updated) VALUES (?, ?, ?, ?, ?, ?)').bind(id, d.driverId, d.createdBy, JSON.stringify(d), t, t).run();
        return json({ id, num: d.num });
      }
      if (!b) return err('طلب غير صحيح');
      const row = await env.DB.prepare('SELECT id, driver, created_by, data FROM majd_orders WHERE id = ?').bind(b).first();
      const staffOwn = isStaff && row && row.created_by === me.staffId && rowToOrder(row).status === 'new';
      if (m === 'DELETE') {
        if (!isAdmin && !staffOwn) return err('بتقدر تحذف طلباتك الجديدة بس', 403);
        await env.DB.batch([
          env.DB.prepare('DELETE FROM majd_orders WHERE id = ?').bind(b),
          env.DB.prepare('DELETE FROM majd_receipts WHERE id = ?').bind(b),
        ]);
        return json({ ok: true });
      }
      if (m === 'PUT') {
        const { data } = await body(request);
        if (!row) return err('الطلب مش موجود', 404);
        let d;
        if (isAdmin) {
          d = sanitizeOrder(data || {});
          if (!d.driverId) { const dr = driverForArea(s, d.area); d.driverId = dr ? dr.id : ''; }
        } else if (isStaff) {
          if (!staffOwn) return err('بتقدر تعدّل طلباتك الجديدة بس', 403);
          const cur = rowToOrder(row); delete cur.id;
          const inc = data || {};
          d = { ...cur };
          for (const k of STAFF_FIELDS) if (k in inc) d[k] = inc[k];
          if (d.area !== cur.area) { const dr = driverForArea(s, d.area); d.driverId = dr ? dr.id : ''; }
          d = sanitizeOrder(d);
        } else {
          if (row.driver !== me.driverId) return err('هذا الطلب مش إلك', 403);
          const cur = rowToOrder(row); delete cur.id;
          const inc = data || {};
          if (inc.status && !DRIVER_STATUSES.includes(inc.status)) return err('حالة غير مسموحة', 403);
          d = { ...cur };
          for (const k of DRIVER_FIELDS) if (k in inc) d[k] = inc[k];
          d = sanitizeOrder(d);
        }
        await env.DB.prepare('UPDATE majd_orders SET driver = ?, data = ?, updated = ? WHERE id = ?').bind(d.driverId || '', JSON.stringify(d), nowMs(), b).run();
        return json({ ok: true });
      }
    }

    // receipts (transfer notice photos)
    if (a === 'receipts' && b) {
      const row = await env.DB.prepare('SELECT driver FROM majd_orders WHERE id = ?').bind(b).first();
      if (!row) return err('الطلب مش موجود', 404);
      const own = isAdmin || (me.role === 'driver' && row.driver === me.driverId);
      const ownView = own || (isStaff && (await env.DB.prepare('SELECT created_by FROM majd_orders WHERE id = ?').bind(b).first()).created_by === me.staffId);
      if (!ownView) return err('هذا الطلب مش إلك', 403);
      if (m === 'PUT') {
        if (!own) return err('غير مسموح', 403);
        const { img } = await body(request);
        if (!/^data:image\/(jpeg|png|webp);base64,/.test(String(img || '')) || img.length > 400000) return err('الصورة غير صالحة أو كبيرة');
        await env.DB.prepare('INSERT INTO majd_receipts (id, driver, img, t) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET img = excluded.img, t = excluded.t').bind(b, row.driver, img, nowMs()).run();
        return json({ ok: true });
      }
      if (m === 'GET') {
        const r = await env.DB.prepare('SELECT img, t FROM majd_receipts WHERE id = ?').bind(b).first();
        return r ? json({ img: r.img, t: r.t }) : err('ما في صورة', 404);
      }
    }

    return err('غير موجود', 404);
  } catch (e) {
    return err(e && e.message ? e.message : 'خطأ بالسيرفر', 500);
  }
}
