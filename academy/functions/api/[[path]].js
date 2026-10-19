// MME Academy API — Cloudflare Pages Function backed by D1 (binding: DB)
// Routes live under /api/*

const SESSION_COOKIE = 'mme_s';
const SESSION_DAYS = 30;
const PBKDF2_ITER = 100000;
const OWNER_EMAIL = 'power.ai.m10@gmail.com'; // the only admin account
const roleFor = (email) => (String(email || '').toLowerCase() === OWNER_EMAIL ? 'admin' : 'student');

// ---------- helpers ----------
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });
const err = (msg, status = 400) => json({ error: msg }, status);
const now = () => Math.floor(Date.now() / 1000);

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const randomHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));

async function hashPassword(password, saltHex) {
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER }, key, 256);
  return b64(bits);
}
async function sha256(s) {
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function getCookie(req, name) {
  const c = req.headers.get('cookie') || '';
  const m = c.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}
function sessionCookie(token, maxAge) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
async function body(req) {
  try { return await req.json(); } catch { return {}; }
}
const clean = (s, max = 200) => String(s ?? '').trim().slice(0, max);
const publicUser = (u) => u && { id: u.id, name: u.name, email: u.email, phone: u.phone, role: roleFor(u.email) };

// ---------- referrals ----------
const REF_ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const DEFAULT_REF_PCT = 25;
function newRefCode() {
  const b = crypto.getRandomValues(new Uint8Array(6));
  return [...b].map((x) => REF_ALPHA[x % REF_ALPHA.length]).join('');
}
async function ensureRefCode(env, user) {
  if (user.ref_code) return user.ref_code;
  for (let i = 0; i < 6; i++) {
    const code = newRefCode();
    try {
      const r = await env.DB.prepare('UPDATE users SET ref_code = ? WHERE id = ? AND ref_code IS NULL').bind(code, user.id).run();
      if (r.meta.changes) { user.ref_code = code; return code; }
      const u = await env.DB.prepare('SELECT ref_code FROM users WHERE id = ?').bind(user.id).first();
      if (u && u.ref_code) { user.ref_code = u.ref_code; return u.ref_code; }
    } catch (e) { /* code collision, retry */ }
  }
  return null;
}
async function refPct(env) {
  const r = await env.DB.prepare("SELECT value FROM settings WHERE key = 'ref_pct'").first();
  const v = r ? Number(r.value) : NaN;
  return Number.isFinite(v) && v >= 0 && v <= 100 ? v : DEFAULT_REF_PCT;
}
// a referral counts once the invited friend has at least one approved (paid) enrollment
async function refStats(env, userId) {
  const r = await env.DB.prepare(`SELECT
      (SELECT COUNT(*) FROM users WHERE referred_by = ?) AS registered,
      (SELECT COUNT(*) FROM users u WHERE u.referred_by = ? AND EXISTS (SELECT 1 FROM enrollments e WHERE e.user_id = u.id AND e.status = 'approved')) AS paid`
  ).bind(userId, userId).first();
  const pct = await refPct(env);
  const discount = Math.min(100, (r.paid || 0) * pct);
  return { registered: r.registered || 0, paid: r.paid || 0, pct, discount };
}
const priceAfter = (price, discount) => Math.max(0, Math.round(Number(price || 0) * (100 - discount)) / 100);

async function currentUser(env, req) {
  const token = getCookie(req, SESSION_COOKIE);
  if (!token) return null;
  const th = await sha256(token);
  const u = await env.DB.prepare(
    'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?'
  ).bind(th, now()).first();
  if (!u) return null;
  u.role = roleFor(u.email);
  if (u.suspended && u.role !== 'admin') return null; // suspended accounts lose access immediately
  return u;
}
async function createSession(env, userId, req, isAdmin) {
  const token = randomHex(32);
  // one active device per student: a new sign-in ends every other session (stops password sharing)
  if (!isAdmin) await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId).run();
  if (req) {
    try {
      await env.DB.prepare('INSERT INTO logins (user_id, at, ip, country, ua) VALUES (?, ?, ?, ?, ?)')
        .bind(userId, now(), req.headers.get('cf-connecting-ip') || null, (req.cf && req.cf.country) || null,
          clean(req.headers.get('user-agent'), 300) || null).run();
    } catch (e) {}
  }
  await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(await sha256(token), userId, now() + SESSION_DAYS * 86400).run();
  // opportunistic cleanup
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now()).run();
  return token;
}

// ---------- signed video links ----------
// Every lesson video URL carries a short-lived signature tied to the viewer's account,
// so a copied link stops working for anyone else and expires on its own.
const VIDEO_TOKEN_SECONDS = 3 * 3600;
async function videoSecret(env) {
  let r = await env.DB.prepare("SELECT value FROM settings WHERE key = 'video_secret'").first();
  if (!r) {
    await env.DB.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('video_secret', ?)").bind(randomHex(32)).run();
    r = await env.DB.prepare("SELECT value FROM settings WHERE key = 'video_secret'").first();
  }
  return r.value;
}
async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg)));
}
async function videoToken(env, userId, lessonId) {
  const exp = now() + VIDEO_TOKEN_SECONDS;
  return exp + '.' + (await hmac(await videoSecret(env), `${userId}.${lessonId}.${exp}`));
}
async function videoTokenOk(env, t, userId, lessonId) {
  const m = String(t || '').match(/^(\d+)\.([0-9a-f]{64})$/);
  if (!m || Number(m[1]) < now()) return false;
  return timingSafeEqual(m[2], await hmac(await videoSecret(env), `${userId}.${lessonId}.${m[1]}`));
}

// ---------- handlers ----------
async function register(env, req) {
  const b = await body(req);
  const name = clean(b.name, 80), email = clean(b.email, 120).toLowerCase(), phone = clean(b.phone, 30);
  const password = String(b.password || '');
  if (name.length < 2) return err('اكتب اسمك الكامل');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('البريد الإلكتروني غير صحيح');
  if (phone.replace(/\D/g, '').length < 8) return err('اكتب رقم واتساب صحيح مع مقدمة الدولة');
  if (password.length < 6) return err('كلمة المرور لازم تكون 6 أحرف على الأقل');
  if (b.terms !== true) return err('لازم توافق على شروط الاشتراك وحماية المحتوى');
  const exists = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (exists) return err('هذا البريد مسجّل مسبقًا، سجّل دخول بدلًا من ذلك', 409);
  const salt = randomHex(16);
  const pass_hash = await hashPassword(password, salt);
  let referredBy = null;
  const refCode = clean(b.ref, 20).toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (refCode) {
    const ref = await env.DB.prepare('SELECT id FROM users WHERE ref_code = ?').bind(refCode).first();
    if (ref) referredBy = ref.id;
  }
  const r = await env.DB.prepare(
    'INSERT INTO users (name, email, phone, pass_hash, salt, role, created_at, last_login, terms_at, referred_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(name, email, phone, pass_hash, salt, roleFor(email), now(), now(), now(), referredBy).run();
  const id = r.meta.last_row_id;
  try { await env.DB.prepare('UPDATE users SET notif_seen = (SELECT COALESCE(MAX(id), 0) FROM notifications) WHERE id = ?').bind(id).run(); } catch (e) {}
  await ensureRefCode(env, { id });
  if (roleFor(email) !== 'admin') await alertAdmin(env, `👤 حساب جديد: ${name}`, `${phone} · ${email}${referredBy ? ' · جاي بدعوة من صديق' : ''}`, `#/admin?u=${id}`);
  const token = await createSession(env, id, req, roleFor(email) === 'admin');
  return json({ user: { id, name, email, phone, role: roleFor(email) } }, 200, { 'set-cookie': sessionCookie(token, SESSION_DAYS * 86400) });
}

async function login(env, req) {
  const b = await body(req);
  const email = clean(b.email, 120).toLowerCase();
  const password = String(b.password || '');
  const u = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (!u) return err('البريد أو كلمة المرور غير صحيحة', 401);
  const h = await hashPassword(password, u.salt);
  if (!timingSafeEqual(h, u.pass_hash)) return err('البريد أو كلمة المرور غير صحيحة', 401);
  if (u.suspended && roleFor(u.email) !== 'admin') return err('حسابك موقوف. تواصل مع إدارة الأكاديمية على واتساب', 403);
  await env.DB.prepare('UPDATE users SET last_login = ? WHERE id = ?').bind(now(), u.id).run();
  const token = await createSession(env, u.id, req, roleFor(u.email) === 'admin');
  return json({ user: publicUser(u) }, 200, { 'set-cookie': sessionCookie(token, SESSION_DAYS * 86400) });
}

async function logout(env, req) {
  const token = getCookie(req, SESSION_COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(await sha256(token)).run();
  return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
}

// enrollments.welcomed_at: when the student saw the "you're enrolled" message (shown once per activation)
let welcomeColReady = false;
async function ensureWelcomeCol(env) {
  if (welcomeColReady) return;
  try { await env.DB.prepare('ALTER TABLE enrollments ADD COLUMN welcomed_at INTEGER').run(); } catch (e) { /* column already exists */ }
  welcomeColReady = true;
}

async function me(env, user) {
  await ensureWelcomeCol(env);
  const base = `SELECT e.id, e.course_id, e.status, e.created_at, e.decided_at, c.title, c.price
     FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.user_id = ? ORDER BY e.created_at DESC`;
  let results;
  try {
    ({ results } = await env.DB.prepare(base.replace('e.decided_at,', 'e.decided_at, e.welcomed_at,')).bind(user.id).all());
  } catch (e) {
    ({ results } = await env.DB.prepare(base).bind(user.id).all()); // never break the account page over the welcome flag
  }
  // "last seen" drives the daily reminders; written at most every 10 minutes
  if (!user.last_seen || user.last_seen < now() - 600) {
    try { await env.DB.prepare('UPDATE users SET last_seen = ? WHERE id = ?').bind(now(), user.id).run(); } catch (e) {}
  }
  // backup trigger for the daily reminders in case the scheduled call did not run
  if (env.__wait) env.__wait(runDaily(env, false).catch(() => {}));
  const code = await ensureRefCode(env, user);
  const rs = await refStats(env, user.id);
  const friends = await env.DB.prepare(
    `SELECT u.name, u.created_at, EXISTS (SELECT 1 FROM enrollments e WHERE e.user_id = u.id AND e.status = 'approved') AS paid
     FROM users u WHERE u.referred_by = ? ORDER BY u.created_at DESC LIMIT 50`
  ).bind(user.id).all();
  const enrollments = results.map((e) => ({ ...e, final_price: e.status === 'pending' ? priceAfter(e.price, rs.discount) : e.price }));
  return json({
    user: publicUser(user),
    enrollments,
    referral: { code, ...rs, friends: friends.results.map((f) => ({ name: String(f.name || '').trim().split(/\s+/)[0], created_at: f.created_at, paid: !!f.paid })) },
  });
}

async function markWelcomed(env, req, user) {
  const b = await body(req);
  await ensureWelcomeCol(env);
  await env.DB.prepare("UPDATE enrollments SET welcomed_at = ? WHERE id = ? AND user_id = ? AND status = 'approved'")
    .bind(now(), Number(b.enrollment_id) || 0, user.id).run();
  return json({ ok: true });
}

async function listCourses(env) {
  const { results } = await env.DB.prepare(
    `SELECT c.id, c.title, c.title_en, c.description, c.price, c.old_price,
       (SELECT COUNT(*) FROM lessons l WHERE l.course_id = c.id) AS lessons
     FROM courses c WHERE c.published = 1 ORDER BY c.sort`
  ).all();
  return json({ courses: results });
}

async function enroll(env, req, user) {
  const b = await body(req);
  const course = await env.DB.prepare('SELECT * FROM courses WHERE id = ? AND published = 1').bind(clean(b.course_id, 60)).first();
  if (!course) return err('الدورة غير موجودة', 404);
  let e = await env.DB.prepare('SELECT * FROM enrollments WHERE user_id = ? AND course_id = ?').bind(user.id, course.id).first();
  if (!e) {
    await env.DB.prepare('INSERT INTO enrollments (user_id, course_id, status, created_at) VALUES (?, ?, ?, ?)')
      .bind(user.id, course.id, 'pending', now()).run();
    e = await env.DB.prepare('SELECT * FROM enrollments WHERE user_id = ? AND course_id = ?').bind(user.id, course.id).first();
    await alertAdmin(env, `🆕 طلب جديد #${e.id}: ${user.name}`, `طلب دورة «${course.title}» ($${course.price}). تواصل معه وفعّل الطلب.`, '#/admin?t=orders');
  } else if (e.status === 'rejected') {
    await env.DB.prepare("UPDATE enrollments SET status = 'pending', decided_at = NULL, created_at = ? WHERE id = ?").bind(now(), e.id).run();
    e.status = 'pending';
    await alertAdmin(env, `🆕 طلب جديد #${e.id}: ${user.name}`, `قدّم طلب دورة «${course.title}» من جديد ($${course.price}).`, '#/admin?t=orders');
  }
  return json({ enrollment: { id: e.id, status: e.status, course_id: course.id, title: course.title, price: course.price } });
}

async function getCourse(env, user, id) {
  const course = await env.DB.prepare('SELECT * FROM courses WHERE id = ?').bind(id).first();
  if (!course) return err('الدورة غير موجودة', 404);
  const isAdmin = user && user.role === 'admin';
  let status = null;
  if (user) {
    const e = await env.DB.prepare('SELECT status FROM enrollments WHERE user_id = ? AND course_id = ?').bind(user.id, id).first();
    status = e ? e.status : null;
  }
  const access = isAdmin || status === 'approved';
  const { results } = await env.DB.prepare(
    'SELECT id, title, minutes, sort, video_url, notes, video_key, video_size FROM lessons WHERE course_id = ? ORDER BY sort, id'
  ).bind(id).all();
  const lessons = [];
  for (const l of results) {
    const has_video = !!l.video_key;
    if (!access) { lessons.push({ id: l.id, title: l.title, minutes: l.minutes, sort: l.sort, has_video }); continue; }
    const { video_key, ...rest } = l;
    lessons.push({ ...rest, has_video, vt: has_video ? await videoToken(env, user.id, l.id) : undefined,
      video_size: isAdmin ? l.video_size : undefined });
  }
  let done = [];
  if (user && access) {
    const p = await env.DB.prepare(
      'SELECT p.lesson_id FROM progress p JOIN lessons l ON l.id = p.lesson_id WHERE p.user_id = ? AND l.course_id = ?'
    ).bind(user.id, id).all();
    done = p.results.map((r) => r.lesson_id);
  }
  return json({ course, status, access, lessons, done });
}

async function markProgress(env, req, user) {
  const b = await body(req);
  const lesson = await env.DB.prepare('SELECT course_id FROM lessons WHERE id = ?').bind(Number(b.lesson_id) || 0).first();
  if (!lesson) return err('الدرس غير موجود', 404);
  const e = await env.DB.prepare("SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ? AND status = 'approved'").bind(user.id, lesson.course_id).first();
  if (!e && user.role !== 'admin') return err('غير مسموح', 403);
  if (b.done === false) {
    await env.DB.prepare('DELETE FROM progress WHERE user_id = ? AND lesson_id = ?').bind(user.id, Number(b.lesson_id)).run();
  } else {
    await env.DB.prepare('INSERT OR IGNORE INTO progress (user_id, lesson_id, done_at) VALUES (?, ?, ?)').bind(user.id, Number(b.lesson_id), now()).run();
  }
  return json({ ok: true });
}

// ---------- comments (moderated) ----------
// Nothing a student writes is public until the admin approves it. Public lists never carry the
// full email: only its first 3 characters, the rest hidden.
const maskEmail = (e) => {
  const local = String(e || '').split('@')[0];
  return (local.slice(0, Math.min(3, Math.max(1, local.length - 1))) || '•') + '•••••';
};
async function listComments(env, user, courseId) {
  const { results } = await env.DB.prepare(
    `SELECT c.id, c.body, c.created_at, COALESCE(u.email, c.guest_email) AS email,
       EXISTS(SELECT 1 FROM enrollments e WHERE e.user_id = c.user_id AND e.course_id = c.course_id AND e.status = 'approved') AS subscriber
     FROM comments c LEFT JOIN users u ON u.id = c.user_id
     WHERE c.course_id = ? AND c.status = 'approved' ORDER BY c.created_at DESC LIMIT 200`
  ).bind(courseId).all();
  const comments = results.map((r) => ({ id: r.id, body: r.body, created_at: r.created_at, who: maskEmail(r.email), subscriber: !!r.subscriber }));
  let mine = [];
  if (user) {
    const m = await env.DB.prepare(
      "SELECT id, body, status, created_at FROM comments WHERE course_id = ? AND user_id = ? AND status != 'approved' ORDER BY created_at DESC LIMIT 10"
    ).bind(courseId, user.id).all();
    mine = m.results;
  }
  return json({ comments, mine });
}
// anyone can comment (visitor or account); everything waits for admin approval
async function addComment(env, req, user, courseId) {
  const course = await env.DB.prepare('SELECT id FROM courses WHERE id = ?').bind(courseId).first();
  if (!course) return err('الدورة غير موجودة', 404);
  const b = await body(req);
  if (b.website) return json({ ok: true }); // bot trap: a hidden field people never fill
  const text = String(b.body ?? '').replace(/\r/g, '').replace(/\n{3,}/g, '\n\n').trim().slice(0, 1000);
  if (text.length < 3) return err('اكتب تعليقك أولًا');
  const ip = req.headers.get('cf-connecting-ip') || null;
  let guestName = null, guestEmail = null;
  if (!user) {
    guestName = clean(b.name, 60);
    guestEmail = clean(b.email, 120).toLowerCase();
    if (guestName.length < 2) return err('اكتب اسمك');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(guestEmail)) return err('اكتب بريد إلكتروني صحيح');
  }
  const p = user
    ? await env.DB.prepare("SELECT COUNT(*) AS n FROM comments WHERE user_id = ? AND status = 'pending'").bind(user.id).first()
    : await env.DB.prepare("SELECT COUNT(*) AS n FROM comments WHERE status = 'pending' AND (ip = ? OR guest_email = ?) AND created_at > ?").bind(ip, guestEmail, now() - 86400).first();
  if (p && p.n >= 3) return err('عندك تعليقات بانتظار الموافقة، استنى لحتى نراجعها');
  await env.DB.prepare("INSERT INTO comments (course_id, user_id, guest_name, guest_email, ip, body, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)")
    .bind(courseId, user ? user.id : null, guestName, guestEmail, ip, text, now()).run();
  return json({ ok: true });
}
async function adminComments(env, url) {
  const status = url.searchParams.get('status');
  let sql = `SELECT c.id, c.body, c.status, c.created_at, c.decided_at, c.course_id, co.title,
               u.id AS user_id, COALESCE(u.name, c.guest_name) AS name, COALESCE(u.email, c.guest_email) AS email, u.phone,
               CASE WHEN c.user_id IS NULL THEN 1 ELSE 0 END AS guest
             FROM comments c LEFT JOIN users u ON u.id = c.user_id JOIN courses co ON co.id = c.course_id`;
  const args = [];
  if (status) { sql += ' WHERE c.status = ?'; args.push(status); }
  sql += " ORDER BY CASE c.status WHEN 'pending' THEN 0 ELSE 1 END, c.created_at DESC LIMIT 1000";
  const { results } = await env.DB.prepare(sql).bind(...args).all();
  return json({ comments: results.map((r) => ({ ...r, who: maskEmail(r.email) })) });
}
async function adminDecideComment(env, req, id) {
  const b = await body(req);
  if (!['approved', 'rejected', 'pending'].includes(b.status)) return err('حالة غير صحيحة');
  await env.DB.prepare('UPDATE comments SET status = ?, decided_at = ? WHERE id = ?').bind(b.status, now(), id).run();
  return json({ ok: true });
}
async function adminDeleteComment(env, id) {
  await env.DB.prepare('DELETE FROM comments WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ---------- admin ----------
async function adminStats(env) {
  const t = now(), week = t - 7 * 86400;
  const s = await env.DB.prepare(`SELECT
      (SELECT COUNT(*) FROM users WHERE role = 'student') AS students,
      (SELECT COUNT(*) FROM users WHERE role = 'student' AND created_at > ?) AS students_week,
      (SELECT COUNT(*) FROM enrollments WHERE status = 'pending') AS pending,
      (SELECT COUNT(*) FROM enrollments WHERE status = 'approved') AS approved,
      (SELECT COUNT(*) FROM enrollments WHERE status = 'rejected') AS rejected,
      (SELECT COALESCE(SUM(COALESCE(e.paid, c.price)), 0) FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.status = 'approved') AS revenue,
      (SELECT COALESCE(SUM(COALESCE(e.paid, c.price)), 0) FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.status = 'approved' AND e.decided_at > ?) AS revenue_week,
      (SELECT COALESCE(SUM(c.price), 0) FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.status = 'pending') AS pending_value`
  ).bind(week, week).first();
  const courses = await env.DB.prepare(`SELECT c.id, c.title, c.price,
      (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id AND e.status = 'approved') AS approved,
      (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id AND e.status = 'pending') AS pending,
      (SELECT COUNT(*) FROM lessons l WHERE l.course_id = c.id) AS lessons
    FROM courses c ORDER BY c.sort`).all();
  const recent = await env.DB.prepare(`SELECT e.id, e.status, e.created_at, c.title, c.price, u.id AS user_id, u.name, u.phone
    FROM enrollments e JOIN users u ON u.id = e.user_id JOIN courses c ON c.id = e.course_id
    ORDER BY e.created_at DESC LIMIT 6`).all();
  return json({ stats: s, courses: courses.results, recent: recent.results });
}
async function adminEnrollments(env, url) {
  const status = url.searchParams.get('status');
  let sql = `SELECT e.id, e.status, e.created_at, e.decided_at, e.note, e.paid, e.course_id, c.title, c.price,
               u.id AS user_id, u.name, u.email, u.phone,
               (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.id AND EXISTS (SELECT 1 FROM enrollments x WHERE x.user_id = r.id AND x.status = 'approved')) AS ref_paid,
               (SELECT name FROM users r WHERE r.id = u.referred_by) AS referrer
             FROM enrollments e JOIN users u ON u.id = e.user_id JOIN courses c ON c.id = e.course_id`;
  const args = [];
  if (status) { sql += ' WHERE e.status = ?'; args.push(status); }
  sql += " ORDER BY CASE e.status WHEN 'pending' THEN 0 ELSE 1 END, e.created_at DESC LIMIT 1000";
  const { results } = await env.DB.prepare(sql).bind(...args).all();
  const pct = await refPct(env);
  results.forEach((e) => { e.ref_discount = Math.min(100, e.ref_paid * pct); e.final_price = priceAfter(e.price, e.ref_discount); });
  return json({ enrollments: results, ref_pct: pct });
}
async function adminDecide(env, req, id) {
  const b = await body(req);
  if (!['approved', 'rejected', 'pending'].includes(b.status)) return err('حالة غير صحيحة');
  const e = await env.DB.prepare('SELECT e.*, c.price FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.id = ?').bind(id).first();
  if (!e) return err('الطلب غير موجود', 404);
  let def = e.paid ?? e.price;
  if (b.status === 'approved' && e.paid == null) def = priceAfter(e.price, (await refStats(env, e.user_id)).discount);
  const paid = b.status === 'approved' ? (b.paid !== undefined && b.paid !== '' ? Number(b.paid) || 0 : def) : e.paid;
  const note = b.note !== undefined ? clean(b.note, 500) || null : e.note;
  await env.DB.prepare('UPDATE enrollments SET status = ?, decided_at = ?, paid = ?, note = ? WHERE id = ?').bind(b.status, now(), paid, note, id).run();
  return json({ ok: true });
}
async function adminUpdateEnrollment(env, req, id) {
  const b = await body(req);
  await env.DB.prepare('UPDATE enrollments SET note = ?, paid = ? WHERE id = ?')
    .bind(clean(b.note, 500) || null, b.paid === '' || b.paid == null ? null : Number(b.paid) || 0, id).run();
  return json({ ok: true });
}
async function adminDeleteEnrollment(env, id) {
  await env.DB.prepare('DELETE FROM enrollments WHERE id = ?').bind(id).run();
  return json({ ok: true });
}
async function adminUsers(env) {
  const { results } = await env.DB.prepare(
    `SELECT u.id, u.name, u.email, u.phone, u.role, u.created_at, MAX(COALESCE(u.last_login, 0), COALESCE(u.last_seen, 0)) AS last_login, u.admin_note, u.suspended,
       (SELECT COUNT(*) FROM enrollments e WHERE e.user_id = u.id AND e.status = 'approved') AS active,
       (SELECT COUNT(*) FROM enrollments e WHERE e.user_id = u.id AND e.status = 'pending') AS pending,
       (SELECT COUNT(*) FROM enrollments e WHERE e.user_id = u.id AND e.status = 'rejected') AS rejected,
       (SELECT COALESCE(SUM(COALESCE(e.paid, c.price)),0) FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.user_id = u.id AND e.status = 'approved') AS paid,
       (SELECT COUNT(*) FROM progress p WHERE p.user_id = u.id) AS done,
       (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.id) AS refs,
       (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.id AND EXISTS (SELECT 1 FROM enrollments x WHERE x.user_id = r.id AND x.status = 'approved')) AS ref_paid
     FROM users u ORDER BY u.created_at DESC LIMIT 5000`
  ).all();
  return json({ users: results });
}
async function adminSuspend(env, req, id) {
  const b = await body(req);
  const u = await env.DB.prepare('SELECT email FROM users WHERE id = ?').bind(id).first();
  if (!u) return err('المستخدم غير موجود', 404);
  if (roleFor(u.email) === 'admin') return err('ما بتقدر توقف حساب الإدارة');
  await env.DB.prepare('UPDATE users SET suspended = ? WHERE id = ?').bind(b.suspended ? 1 : 0, id).run();
  if (b.suspended) await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
  return json({ ok: true });
}
async function adminLogoutAll(env, id) {
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
  return json({ ok: true });
}
async function adminUser(env, id) {
  const u = await env.DB.prepare('SELECT id, name, email, phone, role, created_at, MAX(COALESCE(last_login, 0), COALESCE(last_seen, 0)) AS last_login, admin_note, suspended, terms_at, ref_code, referred_by FROM users WHERE id = ?').bind(id).first();
  if (!u) return err('المستخدم غير موجود', 404);
  const referrer = u.referred_by ? await env.DB.prepare('SELECT id, name FROM users WHERE id = ?').bind(u.referred_by).first() : null;
  const refs = await env.DB.prepare(
    `SELECT u.id, u.name, u.created_at, EXISTS (SELECT 1 FROM enrollments e WHERE e.user_id = u.id AND e.status = 'approved') AS paid
     FROM users u WHERE u.referred_by = ? ORDER BY u.created_at DESC`
  ).bind(id).all();
  const referral = { ...(await refStats(env, id)), code: u.ref_code, referrer, friends: refs.results };
  const { results } = await env.DB.prepare(
    `SELECT e.id, e.course_id, e.status, e.created_at, e.decided_at, e.note, e.paid, c.title, c.price,
       (SELECT COUNT(*) FROM lessons l WHERE l.course_id = c.id) AS lessons,
       (SELECT COUNT(*) FROM progress p JOIN lessons l ON l.id = p.lesson_id WHERE p.user_id = e.user_id AND l.course_id = c.id) AS done
     FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.user_id = ? ORDER BY e.created_at DESC`
  ).bind(id).all();
  const logins = await env.DB.prepare('SELECT at, ip, country, ua FROM logins WHERE user_id = ? ORDER BY at DESC LIMIT 15').bind(id).all();
  const countries = await env.DB.prepare('SELECT COUNT(DISTINCT country) AS n FROM logins WHERE user_id = ? AND at > ?').bind(id, now() - 86400).first();
  return json({ user: u, enrollments: results, logins: logins.results, countries_24h: countries ? countries.n : 0, referral });
}
async function adminUpdateUser(env, req, id, me) {
  const b = await body(req);
  const u = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
  if (!u) return err('المستخدم غير موجود', 404);
  const name = b.name !== undefined ? clean(b.name, 80) : u.name;
  const email = b.email !== undefined ? clean(b.email, 120).toLowerCase() : u.email;
  const phone = b.phone !== undefined ? clean(b.phone, 30) : u.phone;
  if (roleFor(u.email) === 'admin' && email !== u.email) return err('ما بتقدر تغيّر إيميل حساب الإدارة');
  if (roleFor(email) === 'admin' && roleFor(u.email) !== 'admin') return err('هذا الإيميل محجوز لحساب الإدارة');
  const role = roleFor(email);
  if (name.length < 2) return err('الاسم قصير');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('البريد الإلكتروني غير صحيح');
  if (email !== u.email) {
    const ex = await env.DB.prepare('SELECT id FROM users WHERE email = ? AND id != ?').bind(email, id).first();
    if (ex) return err('هذا البريد مستخدم لحساب ثاني', 409);
  }
  const note = b.admin_note !== undefined ? clean(b.admin_note, 2000) || null : u.admin_note;
  await env.DB.prepare('UPDATE users SET name = ?, email = ?, phone = ?, role = ?, admin_note = ? WHERE id = ?').bind(name, email, phone, role, note, id).run();
  return json({ ok: true });
}
async function adminDeleteUser(env, id, me) {
  if (id === me.id) return err('ما بتقدر تحذف حسابك');
  await env.DB.prepare('DELETE FROM progress WHERE user_id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM enrollments WHERE user_id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
  await env.DB.prepare('UPDATE users SET referred_by = NULL WHERE referred_by = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
  return json({ ok: true });
}
async function adminEnrollUser(env, req, id) {
  const b = await body(req);
  const status = b.status === 'pending' ? 'pending' : 'approved';
  const course = await env.DB.prepare('SELECT * FROM courses WHERE id = ?').bind(clean(b.course_id, 60)).first();
  const u = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(id).first();
  if (!course || !u) return err('غير موجود', 404);
  const ex = await env.DB.prepare('SELECT id FROM enrollments WHERE user_id = ? AND course_id = ?').bind(id, course.id).first();
  const paid = status === 'approved' ? (b.paid !== undefined && b.paid !== '' ? Number(b.paid) || 0 : course.price) : null;
  if (ex) {
    await env.DB.prepare('UPDATE enrollments SET status = ?, decided_at = ?, paid = ?, note = COALESCE(?, note) WHERE id = ?').bind(status, now(), paid, clean(b.note, 500) || null, ex.id).run();
  } else {
    await env.DB.prepare('INSERT INTO enrollments (user_id, course_id, status, created_at, decided_at, paid, note) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(id, course.id, status, now(), status === 'approved' ? now() : null, paid, clean(b.note, 500) || null).run();
  }
  return json({ ok: true });
}
async function adminResetPassword(env, req, id) {
  const b = await body(req);
  const password = String(b.password || '');
  if (password.length < 6) return err('كلمة المرور لازم تكون 6 أحرف على الأقل');
  const salt = randomHex(16);
  await env.DB.prepare('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?').bind(await hashPassword(password, salt), salt, id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
  return json({ ok: true });
}
async function adminSaveLesson(env, req, id) {
  const b = await body(req);
  const title = clean(b.title, 200);
  if (!title) return err('اكتب عنوان الدرس');
  const vals = [title, clean(b.video_url, 1000) || null, clean(b.notes, 4000) || null, Number(b.sort) || 0, Number(b.minutes) || null];
  if (id) {
    await env.DB.prepare('UPDATE lessons SET title = ?, video_url = ?, notes = ?, sort = ?, minutes = ? WHERE id = ?').bind(...vals, id).run();
  } else {
    const course = await env.DB.prepare('SELECT id FROM courses WHERE id = ?').bind(clean(b.course_id, 60)).first();
    if (!course) return err('الدورة غير موجودة', 404);
    const r = await env.DB.prepare('INSERT INTO lessons (title, video_url, notes, sort, minutes, course_id) VALUES (?, ?, ?, ?, ?, ?)').bind(...vals, course.id).run();
    if (vals[1]) await notifyLesson(env, r.meta.last_row_id);
    return json({ ok: true, id: r.meta.last_row_id });
  }
  if (vals[1]) await notifyLesson(env, id);
  return json({ ok: true, id });
}
async function adminDeleteLesson(env, id) {
  const l = await env.DB.prepare('SELECT video_key FROM lessons WHERE id = ?').bind(id).first();
  if (l && l.video_key && env.VIDEOS) { try { await env.VIDEOS.delete(l.video_key); } catch (e) {} }
  await env.DB.prepare('DELETE FROM progress WHERE lesson_id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM lessons WHERE id = ?').bind(id).run();
  return json({ ok: true });
}
async function adminSaveCourse(env, req, id) {
  const b = await body(req);
  await env.DB.prepare('UPDATE courses SET title = ?, description = ?, price = ?, old_price = ?, published = ? WHERE id = ?')
    .bind(clean(b.title, 200), clean(b.description, 4000), Number(b.price) || 0, b.old_price ? Number(b.old_price) : null, b.published ? 1 : 0, id).run();
  if (b.published) await notifyCourse(env, id);
  return json({ ok: true });
}
async function adminCreateCourse(env, req) {
  const b = await body(req);
  const title = clean(b.title, 200);
  if (title.length < 3) return err('اكتب اسم الدورة');
  let base = clean(b.slug, 40).toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '') || 'course';
  let cid = base, i = 2;
  while (await env.DB.prepare('SELECT 1 FROM courses WHERE id = ?').bind(cid).first()) cid = `${base}-${i++}`;
  const sort = (await env.DB.prepare('SELECT COALESCE(MAX(sort), 0) + 1 AS s FROM courses').first()).s;
  await env.DB.prepare('INSERT INTO courses (id, title, description, price, old_price, published, sort) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(cid, title, clean(b.description, 4000) || null, Number(b.price) || 0, b.old_price ? Number(b.old_price) : null, b.published ? 1 : 0, sort).run();
  if (b.published) await notifyCourse(env, cid);
  return json({ ok: true, id: cid });
}

// ---------- notifications: new course for everyone, new lecture for that course's students ----------
async function ensureNotifTables(env) {
  try {
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, ref TEXT, title TEXT NOT NULL, body TEXT, link TEXT, course_id TEXT, audience TEXT NOT NULL DEFAULT 'all', created_at INTEGER NOT NULL)").run();
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS notif_wa (notif_id INTEGER NOT NULL, user_id INTEGER NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(notif_id, user_id))').run();
  } catch (e) {}
}
async function addNotif(env, n) {
  await ensureNotifTables(env);
  if (n.ref) {
    const ex = await env.DB.prepare('SELECT id FROM notifications WHERE kind = ? AND ref = ?').bind(n.kind, n.ref).first();
    if (ex) return ex.id;
  }
  const r = await env.DB.prepare('INSERT INTO notifications (kind, ref, title, body, link, course_id, audience, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(n.kind, n.ref || null, n.title, n.body || null, n.link || null, n.course_id || null, n.audience || 'all', now()).run();
  const job = pushNotif(env, { ...n, id: r.meta.last_row_id }).catch(() => {});
  if (env.__wait) env.__wait(job); else await job;
  return r.meta.last_row_id;
}

// ---------- phone push notifications (Web Push + VAPID, no payload: the service worker fetches the text) ----------
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uStr = (str) => b64u(new TextEncoder().encode(str));
async function ensurePushTables(env) {
  try { await env.DB.prepare('CREATE TABLE IF NOT EXISTS push_subs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, endpoint TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL)').run(); } catch (e) {}
}
async function vapidKeys(env) {
  let pub = await getSetting(env, 'vapid_pub'), priv = await getSetting(env, 'vapid_priv');
  if (!pub || !priv) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    pub = b64u(await crypto.subtle.exportKey('raw', kp.publicKey));
    priv = JSON.stringify(await crypto.subtle.exportKey('jwk', kp.privateKey));
    // first writer wins so two parallel requests can't end up with different keys
    await env.DB.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('vapid_pub', ?)").bind(pub).run();
    await env.DB.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('vapid_priv', ?)").bind(priv).run();
    pub = await getSetting(env, 'vapid_pub'); priv = await getSetting(env, 'vapid_priv');
  }
  return { pub, priv };
}
async function vapidAuth(env, endpoint) {
  const { pub, priv } = await vapidKeys(env);
  const key = await crypto.subtle.importKey('jwk', JSON.parse(priv), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const head = b64uStr(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const body = b64uStr(JSON.stringify({ aud: new URL(endpoint).origin, exp: now() + 12 * 3600, sub: 'mailto:info@marketingmiddleeast.com' }));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(`${head}.${body}`));
  return `vapid t=${head}.${body}.${b64u(sig)}, k=${pub}`;
}
async function pushNotif(env, n) {
  await ensurePushTables(env);
  const sql = n.audience === 'course'
    ? "SELECT s.id, s.endpoint FROM push_subs s JOIN enrollments e ON e.user_id = s.user_id AND e.course_id = ? AND e.status = 'approved'"
    : 'SELECT s.id, s.endpoint FROM push_subs s';
  const { results } = n.audience === 'course' ? await env.DB.prepare(sql).bind(n.course_id).all() : await env.DB.prepare(sql).all();
  await sendPushes(env, results);
}
async function sendPushes(env, subs) {
  for (const sub of subs) {
    try {
      const r = await fetch(sub.endpoint, { method: 'POST', headers: { TTL: '172800', Urgency: 'high', Authorization: await vapidAuth(env, sub.endpoint), 'Content-Length': '0' } });
      if (r.status === 404 || r.status === 410) await env.DB.prepare('DELETE FROM push_subs WHERE id = ?').bind(sub.id).run();
    } catch (e) {}
  }
}

// ---------- daily «كمّل محاضراتك» reminders for activated students who did not open the academy today ----------
const NUDGES = [
  (x) => [`👋 مرحبا ${x.name}، ما تنسى تكمّل محاضراتك`, `المحاضرة الجاية: «${x.lesson}». عشر دقايق اليوم بتفرق!`],
  (x) => [`🔥 ${x.name}، كمّل سلسلتك اليوم`, `باقيلك ${x.left} ${x.left === 1 ? 'محاضرة' : 'محاضرات'} وبتخلص الدورة وبتاخذ شهادتك 🎓`],
  (x) => ['🎬 محاضرتك الجاية بتستناك', `«${x.lesson}»، يلا تعال نكمّل سوا.`],
  (x) => ['💪 خطوة صغيرة كل يوم', `كل محاضرة بتقرّبك من أول زبون إلك. ادخل كمّل «${x.lesson}».`],
  (x) => [`✨ ${x.name}، إنت قريب من الاحتراف`, `خلّصت ${x.done} من ${x.total}، كمّل «${x.lesson}» واقترب من شهادتك.`],
];
const LONG_AWAY = (x) => [`⏰ ${x.name}، صار إلك فترة ما دخلت!`, `احنا هون ومستنيينك 😊 كمّل من وين ما وقفت: «${x.lesson}».`];
async function runDaily(env, force) {
  const last = Number(await getSetting(env, 'cron_last')) || 0;
  if (!force && last > now() - 20 * 3600) return { skipped: true };
  const h = new Date().getUTCHours();
  if (!force && (h < 7 || h > 18)) return { skipped: 'night' }; // only between 10:00 and 21:59 Gaza time

  await setSetting(env, 'cron_last', String(now()));
  await ensurePushTables(env);
  const day = 20 * 3600;
  const { results } = await env.DB.prepare(
    `SELECT DISTINCT u.id, u.name, COALESCE(u.last_seen, u.last_login, 0) AS seen FROM users u
     JOIN enrollments e ON e.user_id = u.id AND e.status = 'approved'
     WHERE COALESCE(u.suspended, 0) = 0 AND u.role != 'admin'
       AND EXISTS (SELECT 1 FROM push_subs s WHERE s.user_id = u.id)
       AND COALESCE(u.last_seen, u.last_login, 0) < ? AND COALESCE(u.last_nudge, 0) < ?`
  ).bind(now() - day, now() - day).all();
  let sent = 0;
  for (const u of results) {
    const ens = await env.DB.prepare("SELECT e.course_id FROM enrollments e WHERE e.user_id = ? AND e.status = 'approved' ORDER BY e.decided_at DESC").bind(u.id).all();
    for (const e of ens.results) {
      const ls = await env.DB.prepare(
        `SELECT l.id, l.title, EXISTS (SELECT 1 FROM progress p WHERE p.user_id = ? AND p.lesson_id = l.id) AS done
         FROM lessons l WHERE l.course_id = ? AND (l.video_key IS NOT NULL OR l.video_url IS NOT NULL) ORDER BY l.sort, l.id`
      ).bind(u.id, e.course_id).all();
      const all = ls.results, next = all.find((l) => !l.done);
      if (!next) continue; // finished this course
      const x = { name: String(u.name || '').trim().split(/\s+/)[0] || 'صديقي', lesson: next.title, total: all.length, done: all.filter((l) => l.done).length };
      x.left = x.total - x.done;
      const away = now() - u.seen > 3 * 24 * 3600;
      let pick = (Math.floor(now() / 86400) + u.id) % NUDGES.length;
      if (pick === 4 && !x.done) pick = 0; // «خلّصت 0 من …» reads badly
      const [title, msg] = (away ? LONG_AWAY : NUDGES[pick])(x);
      await env.DB.prepare('UPDATE users SET last_nudge = ?, nudge_title = ?, nudge_body = ?, nudge_link = ? WHERE id = ?')
        .bind(now(), title, msg, `#/course/${e.course_id}?l=${next.id}`, u.id).run();
      const subs = await env.DB.prepare('SELECT id, endpoint FROM push_subs WHERE user_id = ?').bind(u.id).all();
      await sendPushes(env, subs.results);
      sent++;
      break;
    }
  }
  return { sent, candidates: results.length };
}
// phone alert for the admin (new account, new order); shown by the service worker like a personal reminder
async function alertAdmin(env, title, msg, link) {
  try {
    const a = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(OWNER_EMAIL).first();
    if (!a) return;
    await env.DB.prepare('UPDATE users SET last_nudge = ?, nudge_title = ?, nudge_body = ?, nudge_link = ? WHERE id = ?').bind(now(), title, msg, link, a.id).run();
    await ensurePushTables(env);
    const subs = await env.DB.prepare('SELECT id, endpoint FROM push_subs WHERE user_id = ?').bind(a.id).all();
    const job = sendPushes(env, subs.results).catch(() => {});
    if (env.__wait) env.__wait(job); else await job;
  } catch (e) {}
}
async function pushKey(env) { return json({ key: (await vapidKeys(env)).pub }); }
async function pushSubscribe(env, req, user) {
  const b = await body(req);
  const ep = clean(b.endpoint, 1000);
  if (!/^https:\/\//.test(ep)) return err('اشتراك غير صحيح');
  await ensurePushTables(env);
  await env.DB.prepare('INSERT INTO push_subs (user_id, endpoint, created_at) VALUES (?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id').bind(user.id, ep, now()).run();
  return json({ ok: true });
}
async function pushUnsubscribe(env, req) {
  const b = await body(req);
  await ensurePushTables(env);
  await env.DB.prepare('DELETE FROM push_subs WHERE endpoint = ?').bind(clean(b.endpoint, 1000)).run();
  return json({ ok: true });
}
// what the service worker shows: the newest notification this user can see
async function latestNotif(env, user) {
  await ensureNotifTables(env);
  const n = await env.DB.prepare(`SELECT n.id, n.kind, n.title, n.body, n.link, n.created_at FROM notifications n WHERE ${NOTIF_VISIBLE} ORDER BY n.id DESC LIMIT 1`).bind(user.id).first();
  // a personal daily reminder newer than the last announcement wins
  if (user.nudge_title && user.last_nudge && (!n || user.last_nudge >= n.created_at)) {
    return json({ item: { id: 'r' + user.last_nudge, kind: user.role === 'admin' ? 'admin' : 'nudge', title: user.nudge_title, body: user.nudge_body, link: user.nudge_link } });
  }
  return json({ item: n || null });
}
async function notifyCourse(env, cid) {
  const c = await env.DB.prepare('SELECT id, title, published FROM courses WHERE id = ?').bind(cid).first();
  if (!c || !c.published) return;
  await addNotif(env, { kind: 'course', ref: c.id, title: `🆕 دورة جديدة: ${c.title}`, body: 'نزلت دورة جديدة على أكاديمية MME. شوف التفاصيل واحجز مقعدك.', link: '#/course/' + c.id, course_id: c.id, audience: 'all' });
}
async function notifyLesson(env, lid) {
  const l = await env.DB.prepare('SELECT l.id, l.title, l.course_id, l.video_key, l.video_url, c.title AS ctitle FROM lessons l JOIN courses c ON c.id = l.course_id WHERE l.id = ?').bind(lid).first();
  if (!l || (!l.video_key && !l.video_url)) return;
  await addNotif(env, { kind: 'lesson', ref: String(l.id), title: `🎬 محاضرة جديدة: ${l.title}`, body: `نزلت محاضرة جديدة بدورة «${l.ctitle}». ادخل وشاهدها الآن.`, link: `#/course/${l.course_id}?l=${l.id}`, course_id: l.course_id, audience: 'course' });
}
// which notifications a user can see: everything for "all", course ones only for its activated students
const NOTIF_VISIBLE = `(n.audience = 'all' OR EXISTS (SELECT 1 FROM enrollments e WHERE e.user_id = ? AND e.course_id = n.course_id AND e.status = 'approved'))`;
async function myNotifs(env, user) {
  await ensureNotifTables(env);
  const { results } = await env.DB.prepare(`SELECT n.id, n.kind, n.title, n.body, n.link, n.created_at FROM notifications n WHERE ${NOTIF_VISIBLE} ORDER BY n.id DESC LIMIT 30`).bind(user.id).all();
  const seen = Number(user.notif_seen) || 0;
  return json({ items: results.map((x) => ({ ...x, unread: x.id > seen })), unread: results.filter((x) => x.id > seen).length });
}
async function markNotifsSeen(env, user) {
  await env.DB.prepare('UPDATE users SET notif_seen = (SELECT COALESCE(MAX(id), 0) FROM notifications) WHERE id = ?').bind(user.id).run();
  return json({ ok: true });
}
async function notifRecipients(env, n) {
  const sql = n.audience === 'course'
    ? "SELECT u.id, u.name, u.phone FROM users u JOIN enrollments e ON e.user_id = u.id AND e.course_id = ? AND e.status = 'approved' WHERE COALESCE(u.suspended,0) = 0 AND u.role != 'admin' ORDER BY u.name"
    : "SELECT u.id, u.name, u.phone FROM users u WHERE COALESCE(u.suspended,0) = 0 AND u.role != 'admin' ORDER BY u.created_at DESC";
  const { results } = n.audience === 'course' ? await env.DB.prepare(sql).bind(n.course_id).all() : await env.DB.prepare(sql).all();
  return results;
}
async function adminNotifs(env) {
  await ensureNotifTables(env);
  const { results } = await env.DB.prepare(`SELECT n.*, c.title AS course_title, (SELECT COUNT(*) FROM notif_wa w WHERE w.notif_id = n.id) AS wa_sent FROM notifications n LEFT JOIN courses c ON c.id = n.course_id ORDER BY n.id DESC LIMIT 100`).all();
  for (const n of results) n.recipients = (await notifRecipients(env, n)).length;
  return json({ notifications: results });
}
async function adminNotifDetail(env, id) {
  const n = await env.DB.prepare('SELECT * FROM notifications WHERE id = ?').bind(id).first();
  if (!n) return err('غير موجود', 404);
  const rec = await notifRecipients(env, n);
  const { results } = await env.DB.prepare('SELECT user_id FROM notif_wa WHERE notif_id = ?').bind(id).all();
  const sent = new Set(results.map((r) => r.user_id));
  return json({ notification: n, recipients: rec.map((u) => ({ ...u, wa_sent: sent.has(u.id) })) });
}
async function adminCreateNotif(env, req) {
  const b = await body(req);
  const title = clean(b.title, 200);
  if (title.length < 3) return err('اكتب عنوان الإشعار');
  const audience = b.audience === 'course' ? 'course' : 'all';
  let course_id = null;
  if (audience === 'course') {
    const c = await env.DB.prepare('SELECT id FROM courses WHERE id = ?').bind(clean(b.course_id, 60)).first();
    if (!c) return err('اختار الدورة');
    course_id = c.id;
  }
  const id = await addNotif(env, { kind: 'custom', title, body: clean(b.body, 1000) || null, link: clean(b.link, 300) || null, course_id, audience });
  return json({ ok: true, id });
}
async function adminMarkWa(env, req, id) {
  const b = await body(req);
  if (b.sent === false) await env.DB.prepare('DELETE FROM notif_wa WHERE notif_id = ? AND user_id = ?').bind(id, Number(b.user_id) || 0).run();
  else await env.DB.prepare('INSERT OR IGNORE INTO notif_wa (notif_id, user_id, at) VALUES (?, ?, ?)').bind(id, Number(b.user_id) || 0, now()).run();
  return json({ ok: true });
}
async function adminDeleteNotif(env, id) {
  await env.DB.prepare('DELETE FROM notif_wa WHERE notif_id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM notifications WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ---------- videos (R2) ----------
const noR2 = () => err('تخزين الفيديو غير مفعّل بعد (R2)', 503);
async function uploadStart(env, req) {
  if (!env.VIDEOS) return noR2();
  const b = await body(req);
  const type = /^video\//.test(String(b.type || '')) ? String(b.type) : 'video/mp4';
  const ext = (String(b.filename || '').match(/\.(mp4|m4v|mov|webm|mkv)$/i) || [, 'mp4'])[1].toLowerCase();
  let key;
  if (b.target === 'intro') key = `intro/${randomHex(8)}.${ext}`;
  else {
    const lesson = await env.DB.prepare('SELECT id FROM lessons WHERE id = ?').bind(Number(b.lesson_id) || 0).first();
    if (!lesson) return err('الدرس غير موجود', 404);
    key = `lessons/${lesson.id}/${randomHex(8)}.${ext}`;
  }
  const mpu = await env.VIDEOS.createMultipartUpload(key, { httpMetadata: { contentType: type } });
  return json({ key: mpu.key, uploadId: mpu.uploadId });
}
async function uploadPart(env, req, url) {
  if (!env.VIDEOS) return noR2();
  const key = url.searchParams.get('key'), uploadId = url.searchParams.get('uploadId'), n = Number(url.searchParams.get('part'));
  if (!key || !/^(lessons|intro)\//.test(key) || !uploadId || !(n >= 1 && n <= 10000)) return err('طلب غير صحيح');
  const mpu = env.VIDEOS.resumeMultipartUpload(key, uploadId);
  const part = await mpu.uploadPart(n, await req.arrayBuffer());
  return json({ partNumber: part.partNumber, etag: part.etag });
}
async function uploadComplete(env, req) {
  if (!env.VIDEOS) return noR2();
  const b = await body(req);
  if (b.target === 'intro') {
    if (!b.key || !String(b.key).startsWith('intro/') || !b.uploadId || !Array.isArray(b.parts)) return err('طلب غير صحيح');
    const mpu = env.VIDEOS.resumeMultipartUpload(b.key, b.uploadId);
    const obj = await mpu.complete(b.parts.map((p) => ({ partNumber: Number(p.partNumber), etag: String(p.etag) })));
    const old = await getSetting(env, 'intro_key');
    if (old && old !== b.key) { try { await env.VIDEOS.delete(old); } catch (e) {} }
    await setSetting(env, 'intro_key', b.key);
    await setSetting(env, 'intro_size', String(obj.size));
    await setSetting(env, 'intro_type', (obj.httpMetadata && obj.httpMetadata.contentType) || 'video/mp4');
    return json({ ok: true, size: obj.size });
  }
  if (!b.key || !String(b.key).startsWith('lessons/') || !b.uploadId || !Array.isArray(b.parts)) return err('طلب غير صحيح');
  const lesson = await env.DB.prepare('SELECT id, video_key FROM lessons WHERE id = ?').bind(Number(b.lesson_id) || 0).first();
  if (!lesson) return err('الدرس غير موجود', 404);
  const mpu = env.VIDEOS.resumeMultipartUpload(b.key, b.uploadId);
  const obj = await mpu.complete(b.parts.map((p) => ({ partNumber: Number(p.partNumber), etag: String(p.etag) })));
  if (lesson.video_key && lesson.video_key !== b.key) { try { await env.VIDEOS.delete(lesson.video_key); } catch (e) {} }
  await env.DB.prepare('UPDATE lessons SET video_key = ?, video_size = ?, video_type = ? WHERE id = ?')
    .bind(b.key, obj.size, (obj.httpMetadata && obj.httpMetadata.contentType) || 'video/mp4', lesson.id).run();
  await notifyLesson(env, lesson.id);
  return json({ ok: true, size: obj.size });
}
async function uploadAbort(env, req) {
  if (!env.VIDEOS) return noR2();
  const b = await body(req);
  try { await env.VIDEOS.resumeMultipartUpload(b.key, b.uploadId).abort(); } catch (e) {}
  return json({ ok: true });
}
async function deleteLessonVideo(env, id) {
  const l = await env.DB.prepare('SELECT video_key FROM lessons WHERE id = ?').bind(id).first();
  if (l && l.video_key && env.VIDEOS) { try { await env.VIDEOS.delete(l.video_key); } catch (e) {} }
  await env.DB.prepare('UPDATE lessons SET video_key = NULL, video_size = NULL, video_type = NULL WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// admin diagnostic: reads the MP4 box layout straight from R2 to say why a lesson video will not play
async function probeLessonVideo(env, id) {
  if (!env.VIDEOS) return noR2();
  const l = await env.DB.prepare('SELECT video_key, video_size, video_type FROM lessons WHERE id = ?').bind(id).first();
  if (!l || !l.video_key) return json({ ok: false, problem: 'missing', boxes: [] });
  const head = await env.VIDEOS.head(l.video_key);
  if (!head) return json({ ok: false, problem: 'missing', boxes: [] });
  const size = head.size;
  const boxes = [];
  let off = 0, moov = null, truncated = false;
  while (off + 8 <= size && boxes.length < 64) {
    const o = await env.VIDEOS.get(l.video_key, { range: { offset: off, length: Math.min(16, size - off) } });
    const b = new Uint8Array(await o.arrayBuffer());
    const dv = new DataView(b.buffer);
    let len = dv.getUint32(0);
    const type = String.fromCharCode(b[4], b[5], b[6], b[7]);
    if (!/^[\x20-\x7e]{4}$/.test(type)) { truncated = true; break; }
    if (len === 1 && b.length >= 16) len = dv.getUint32(8) * 4294967296 + dv.getUint32(12);
    else if (len === 0) len = size - off;
    if (len < 8) { truncated = true; break; }
    boxes.push({ type, offset: off, size: len });
    if (type === 'moov') moov = { offset: off, size: len };
    if (off + len > size) { truncated = true; break; }
    off += len;
  }
  let codec = null;
  if (moov && moov.size <= 32 * 1024 * 1024 && moov.offset + moov.size <= size) {
    const o = await env.VIDEOS.get(l.video_key, { range: { offset: moov.offset, length: moov.size } });
    const txt = new TextDecoder('latin1').decode(await o.arrayBuffer());
    for (const c of ['avc1', 'avc3', 'hvc1', 'hev1', 'av01', 'vp09', 'mp4v']) if (txt.includes(c)) { codec = c; break; }
  }
  const moovIdx = boxes.findIndex((x) => x.type === 'moov'), mdatIdx = boxes.findIndex((x) => x.type === 'mdat');
  let problem = null;
  if (!moov || truncated) problem = 'incomplete';
  else if (codec && /^(hvc1|hev1)$/.test(codec)) problem = 'hevc';
  else if (codec && !/^avc/.test(codec)) problem = 'codec';
  return json({ ok: !problem, problem, codec, size, stored_type: l.video_type, moov_at_end: moovIdx > mdatIdx && mdatIdx >= 0, truncated, boxes: boxes.slice(0, 12) });
}
async function streamVideo(env, req, user, id, url) {
  if (!user) return err('سجّل دخول أولًا', 401);
  if (!env.VIDEOS) return noR2();
  // only the lesson player may load the file: opening the link in a tab or a download request is refused
  const dest = req.headers.get('sec-fetch-dest');
  if (dest && !['video', 'audio', 'empty'].includes(dest)) return err('غير مسموح', 403);
  if (!(await videoTokenOk(env, url.searchParams.get('t'), user.id, id))) return err('انتهت صلاحية رابط الفيديو، حدّث الصفحة', 403);
  const l = await env.DB.prepare('SELECT course_id, video_key, video_type, video_size FROM lessons WHERE id = ?').bind(id).first();
  if (!l || !l.video_key) return err('الفيديو غير موجود', 404);
  if (user.role !== 'admin') {
    const e = await env.DB.prepare("SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ? AND status = 'approved'").bind(user.id, l.course_id).first();
    if (!e) return err('غير مسموح', 403);
  }
  // no conditional (onlyIf) here: a 304 answer to a media range request leaves the player blank.
  // The Range header is parsed here (not handed to R2) so open-ended requests like "bytes=0-",
  // which browsers send first for every video, always get a correct 206 answer.
  let size = Number(l.video_size) || 0;
  if (!size) { const hd = await env.VIDEOS.head(l.video_key); if (!hd) return err('الفيديو غير موجود', 404); size = hd.size; }
  const rh = req.headers.get('range');
  let start = 0, end = size - 1, partial = false;
  const rm = rh && /^bytes=(\d*)-(\d*)$/.exec(rh.trim());
  if (rm && (rm[1] !== '' || rm[2] !== '')) {
    if (rm[1] === '') { start = Math.max(0, size - Number(rm[2])); end = size - 1; }
    else { start = Number(rm[1]); end = rm[2] === '' ? size - 1 : Math.min(Number(rm[2]), size - 1); }
    if (start >= size || start > end) return new Response(null, { status: 416, headers: { 'content-range': `bytes */${size}`, 'accept-ranges': 'bytes' } });
    partial = true;
  }
  const obj = await env.VIDEOS.get(l.video_key, partial ? { range: { offset: start, length: end - start + 1 } } : undefined);
  if (!obj) return err('الفيديو غير موجود', 404);
  const h = new Headers();
  h.set('content-type', l.video_type || (obj.httpMetadata && obj.httpMetadata.contentType) || 'video/mp4');
  h.set('etag', obj.httpEtag);
  h.set('accept-ranges', 'bytes');
  h.set('cache-control', 'private, no-store');
  h.set('content-disposition', 'inline');
  h.set('x-content-type-options', 'nosniff');
  h.set('content-length', String(end - start + 1));
  if (partial) h.set('content-range', `bytes ${start}-${end}/${size}`);
  return new Response(req.method === 'HEAD' ? null : obj.body, { status: partial ? 206 : 200, headers: h });
}

// ---------- intro (promo) video on the academy home page: public, streamed from R2 ----------
async function getSetting(env, k) {
  const r = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(k).first();
  return r ? r.value : null;
}
async function setSetting(env, k, v) {
  if (v === null) return env.DB.prepare('DELETE FROM settings WHERE key = ?').bind(k).run();
  return env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(k, v).run();
}
async function getIntro(env) {
  const key = await getSetting(env, 'intro_key');
  return json({ video: !!key, v: key ? key.slice(6, 14) : null, size: Number(await getSetting(env, 'intro_size')) || null, url: (await getSetting(env, 'intro_url')) || null });
}
async function saveIntro(env, req) {
  const b = await body(req);
  if (b.url !== undefined) await setSetting(env, 'intro_url', clean(b.url, 1000) || null);
  return json({ ok: true });
}
async function deleteIntro(env) {
  const key = await getSetting(env, 'intro_key');
  if (key && env.VIDEOS) { try { await env.VIDEOS.delete(key); } catch (e) {} }
  for (const k of ['intro_key', 'intro_size', 'intro_type']) await setSetting(env, k, null);
  return json({ ok: true });
}
async function streamIntro(env, req) {
  if (!env.VIDEOS) return noR2();
  const key = await getSetting(env, 'intro_key');
  if (!key) return err('ما في فيديو تعريفي', 404);
  let size = Number(await getSetting(env, 'intro_size')) || 0;
  if (!size) { const hd = await env.VIDEOS.head(key); if (!hd) return err('الفيديو غير موجود', 404); size = hd.size; }
  const rh = req.headers.get('range');
  let start = 0, end = size - 1, partial = false;
  const rm = rh && /^bytes=(\d*)-(\d*)$/.exec(rh.trim());
  if (rm && (rm[1] !== '' || rm[2] !== '')) {
    if (rm[1] === '') { start = Math.max(0, size - Number(rm[2])); end = size - 1; }
    else { start = Number(rm[1]); end = rm[2] === '' ? size - 1 : Math.min(Number(rm[2]), size - 1); }
    if (start >= size || start > end) return new Response(null, { status: 416, headers: { 'content-range': `bytes */${size}`, 'accept-ranges': 'bytes' } });
    partial = true;
  }
  const obj = await env.VIDEOS.get(key, partial ? { range: { offset: start, length: end - start + 1 } } : undefined);
  if (!obj) return err('الفيديو غير موجود', 404);
  const h = new Headers();
  h.set('content-type', (await getSetting(env, 'intro_type')) || 'video/mp4');
  h.set('etag', obj.httpEtag);
  h.set('accept-ranges', 'bytes');
  h.set('cache-control', 'public, max-age=3600');
  h.set('content-length', String(end - start + 1));
  if (partial) h.set('content-range', `bytes ${start}-${end}/${size}`);
  return new Response(req.method === 'HEAD' ? null : obj.body, { status: partial ? 206 : 200, headers: h });
}

// ---------- settings (payment methods) ----------
const PAY_KEYS = ['bank_name', 'bank_holder', 'bank_account', 'bank_iban', 'palpay_number', 'palpay_holder', 'jawwal_number', 'jawwal_holder', 'pay_note', 'ref_pct'];
async function getSettings(env) {
  const { results } = await env.DB.prepare('SELECT key, value FROM settings').all();
  const s = {};
  results.forEach((r) => { if (PAY_KEYS.includes(r.key)) s[r.key] = r.value; });
  return json({ settings: s });
}
async function saveSettings(env, req) {
  const b = await body(req);
  if (b.ref_pct !== undefined) {
    const v = Number(b.ref_pct);
    if (!Number.isFinite(v) || v < 0 || v > 100) return err('نسبة الخصم لازم تكون بين 0 و 100');
    b.ref_pct = String(v);
  }
  for (const k of PAY_KEYS) {
    if (b[k] === undefined) continue;
    await env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(k, clean(b[k], 300)).run();
  }
  return json({ ok: true });
}

// ---------- router ----------
export async function onRequest(context) {
  const { request } = context;
  // bindings stay reachable through the prototype; __wait lets slow work (push sends) finish after the response
  const env = Object.assign(Object.create(context.env), { __wait: (p) => { try { context.waitUntil(p); } catch (e) {} } });
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api/, '').replace(/\/+$/, '') || '/';
  const method = request.method;

  if (!env.DB) return err('قاعدة البيانات غير مربوطة', 500);

  // CSRF guard: state-changing requests must be JSON from our own origin
  if (method !== 'GET' && method !== 'HEAD') {
    const ct = request.headers.get('content-type') || '';
    const origin = request.headers.get('origin');
    if (origin && new URL(origin).host !== url.host) return err('Forbidden', 403);
    const isPart = path === '/admin/upload/part' && method === 'PUT';
    if (isPart ? !origin : !ct.includes('application/json')) return err('Bad request', 415);
  }

  try {
    if (path === '/register' && method === 'POST') return await register(env, request);
    if (path === '/login' && method === 'POST') return await login(env, request);
    if (path === '/logout' && method === 'POST') return await logout(env, request);
    if (path === '/courses' && method === 'GET') return await listCourses(env);
    if (path === '/intro' && method === 'GET') return await getIntro(env);
    // called once a day by the scheduled GitHub workflow; safe to call publicly (runs at most every 20h)
    if (path === '/cron/daily' && (method === 'GET' || method === 'POST')) return json(await runDaily(env, false));
    if (path === '/intro/video' && (method === 'GET' || method === 'HEAD')) return await streamIntro(env, request);

    const user = await currentUser(env, request);
    // payment account details are no longer shown publicly; only the admin can read them
    if (path === '/settings' && method === 'GET') return user && user.role === 'admin' ? await getSettings(env) : json({ settings: { ref_pct: String(await refPct(env)) } });

    let m;
    if ((m = path.match(/^\/course\/([\w-]+)$/)) && method === 'GET') return await getCourse(env, user, m[1]);
    if ((m = path.match(/^\/course\/([\w-]+)\/comments$/)) && method === 'GET') return await listComments(env, user, m[1]);
    if ((m = path.match(/^\/course\/([\w-]+)\/comments$/)) && method === 'POST') return await addComment(env, request, user, m[1]);
    if ((m = path.match(/^\/video\/(\d+)$/)) && (method === 'GET' || method === 'HEAD')) return await streamVideo(env, request, user, Number(m[1]), url);

    if (!user) return err('سجّل دخول أولًا', 401);
    if (path === '/me' && method === 'GET') return await me(env, user);
    if (path === '/enroll' && method === 'POST') return await enroll(env, request, user);
    if (path === '/welcomed' && method === 'POST') return await markWelcomed(env, request, user);
    if (path === '/notifications' && method === 'GET') return await myNotifs(env, user);
    if (path === '/notifications/seen' && method === 'POST') return await markNotifsSeen(env, user);
    if (path === '/notifications/latest' && method === 'GET') return await latestNotif(env, user);
    if (path === '/push/key' && method === 'GET') return await pushKey(env);
    if (path === '/push/subscribe' && method === 'POST') return await pushSubscribe(env, request, user);
    if (path === '/push/unsubscribe' && method === 'POST') return await pushUnsubscribe(env, request);
    if (path === '/progress' && method === 'POST') return await markProgress(env, request, user);

    if (path.startsWith('/admin')) {
      if (user.role !== 'admin') return err('هذه الصفحة للإدارة فقط', 403);
      if (path === '/admin/stats' && method === 'GET') return await adminStats(env);
      if (path === '/admin/settings' && method === 'POST') return await saveSettings(env, request);
      if (path === '/admin/enrollments' && method === 'GET') return await adminEnrollments(env, url);
      if ((m = path.match(/^\/admin\/enrollments\/(\d+)$/))) {
        if (method === 'POST') return await adminDecide(env, request, Number(m[1]));
        if (method === 'DELETE') return await adminDeleteEnrollment(env, Number(m[1]));
      }
      if ((m = path.match(/^\/admin\/enrollments\/(\d+)\/meta$/)) && method === 'POST') return await adminUpdateEnrollment(env, request, Number(m[1]));
      if (path === '/admin/comments' && method === 'GET') return await adminComments(env, url);
      if ((m = path.match(/^\/admin\/comments\/(\d+)$/))) {
        if (method === 'POST') return await adminDecideComment(env, request, Number(m[1]));
        if (method === 'DELETE') return await adminDeleteComment(env, Number(m[1]));
      }
      if (path === '/admin/users' && method === 'GET') return await adminUsers(env);
      if ((m = path.match(/^\/admin\/users\/(\d+)$/))) {
        if (method === 'GET') return await adminUser(env, Number(m[1]));
        if (method === 'POST') return await adminUpdateUser(env, request, Number(m[1]), user);
        if (method === 'DELETE') return await adminDeleteUser(env, Number(m[1]), user);
      }
      if ((m = path.match(/^\/admin\/users\/(\d+)\/suspend$/)) && method === 'POST') return await adminSuspend(env, request, Number(m[1]));
      if ((m = path.match(/^\/admin\/users\/(\d+)\/logout-all$/)) && method === 'POST') return await adminLogoutAll(env, Number(m[1]));
      if ((m = path.match(/^\/admin\/users\/(\d+)\/password$/)) && method === 'POST') return await adminResetPassword(env, request, Number(m[1]));
      if ((m = path.match(/^\/admin\/users\/(\d+)\/enroll$/)) && method === 'POST') return await adminEnrollUser(env, request, Number(m[1]));
      if (path === '/admin/intro' && method === 'POST') return await saveIntro(env, request);
      if (path === '/admin/intro' && method === 'DELETE') return await deleteIntro(env);
      if (path === '/admin/upload/start' && method === 'POST') return await uploadStart(env, request);
      if (path === '/admin/upload/part' && method === 'PUT') return await uploadPart(env, request, url);
      if (path === '/admin/upload/complete' && method === 'POST') return await uploadComplete(env, request);
      if (path === '/admin/upload/abort' && method === 'POST') return await uploadAbort(env, request);
      if ((m = path.match(/^\/admin\/lessons\/(\d+)\/probe$/)) && method === 'GET') return await probeLessonVideo(env, Number(m[1]));
      if ((m = path.match(/^\/admin\/lessons\/(\d+)\/video$/)) && method === 'DELETE') return await deleteLessonVideo(env, Number(m[1]));
      if (path === '/admin/lessons' && method === 'POST') return await adminSaveLesson(env, request, null);
      if ((m = path.match(/^\/admin\/lessons\/(\d+)$/))) {
        if (method === 'POST') return await adminSaveLesson(env, request, Number(m[1]));
        if (method === 'DELETE') return await adminDeleteLesson(env, Number(m[1]));
      }
      if ((m = path.match(/^\/admin\/courses\/([\w-]+)$/)) && method === 'POST') return await adminSaveCourse(env, request, m[1]);
      if (path === '/admin/courses' && method === 'POST') return await adminCreateCourse(env, request);
      if (path === '/admin/notifications' && method === 'GET') return await adminNotifs(env);
      if (path === '/admin/reminders/run' && method === 'POST') return json(await runDaily(env, true));
      if (path === '/admin/notifications' && method === 'POST') return await adminCreateNotif(env, request);
      if ((m = path.match(/^\/admin\/notifications\/(\d+)$/))) {
        if (method === 'GET') return await adminNotifDetail(env, Number(m[1]));
        if (method === 'DELETE') return await adminDeleteNotif(env, Number(m[1]));
      }
      if ((m = path.match(/^\/admin\/notifications\/(\d+)\/wa$/)) && method === 'POST') return await adminMarkWa(env, request, Number(m[1]));
    }
    return err('Not found', 404);
  } catch (e) {
    return err('خطأ في السيرفر، حاول مرة ثانية', 500);
  }
}
