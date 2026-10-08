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

async function currentUser(env, req) {
  const token = getCookie(req, SESSION_COOKIE);
  if (!token) return null;
  const th = await sha256(token);
  const u = await env.DB.prepare(
    'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?'
  ).bind(th, now()).first();
  if (u) u.role = roleFor(u.email);
  return u;
}
async function createSession(env, userId) {
  const token = randomHex(32);
  await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(await sha256(token), userId, now() + SESSION_DAYS * 86400).run();
  // opportunistic cleanup
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now()).run();
  return token;
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
  const exists = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (exists) return err('هذا البريد مسجّل مسبقًا، سجّل دخول بدلًا من ذلك', 409);
  const salt = randomHex(16);
  const pass_hash = await hashPassword(password, salt);
  const r = await env.DB.prepare(
    'INSERT INTO users (name, email, phone, pass_hash, salt, role, created_at, last_login) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(name, email, phone, pass_hash, salt, roleFor(email), now(), now()).run();
  const id = r.meta.last_row_id;
  const token = await createSession(env, id);
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
  await env.DB.prepare('UPDATE users SET last_login = ? WHERE id = ?').bind(now(), u.id).run();
  const token = await createSession(env, u.id);
  return json({ user: publicUser(u) }, 200, { 'set-cookie': sessionCookie(token, SESSION_DAYS * 86400) });
}

async function logout(env, req) {
  const token = getCookie(req, SESSION_COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(await sha256(token)).run();
  return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
}

async function me(env, user) {
  const { results } = await env.DB.prepare(
    `SELECT e.id, e.course_id, e.status, e.created_at, e.decided_at, c.title, c.price
     FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.user_id = ? ORDER BY e.created_at DESC`
  ).bind(user.id).all();
  return json({ user: publicUser(user), enrollments: results });
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
  } else if (e.status === 'rejected') {
    await env.DB.prepare("UPDATE enrollments SET status = 'pending', decided_at = NULL, created_at = ? WHERE id = ?").bind(now(), e.id).run();
    e.status = 'pending';
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
  const lessons = results.map((l) => {
    const has_video = !!l.video_key;
    if (!access) return { id: l.id, title: l.title, minutes: l.minutes, sort: l.sort, has_video };
    const { video_key, ...rest } = l;
    return { ...rest, has_video, video_size: isAdmin ? l.video_size : undefined };
  });
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
               u.id AS user_id, u.name, u.email, u.phone
             FROM enrollments e JOIN users u ON u.id = e.user_id JOIN courses c ON c.id = e.course_id`;
  const args = [];
  if (status) { sql += ' WHERE e.status = ?'; args.push(status); }
  sql += " ORDER BY CASE e.status WHEN 'pending' THEN 0 ELSE 1 END, e.created_at DESC LIMIT 1000";
  const { results } = await env.DB.prepare(sql).bind(...args).all();
  return json({ enrollments: results });
}
async function adminDecide(env, req, id) {
  const b = await body(req);
  if (!['approved', 'rejected', 'pending'].includes(b.status)) return err('حالة غير صحيحة');
  const e = await env.DB.prepare('SELECT e.*, c.price FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.id = ?').bind(id).first();
  if (!e) return err('الطلب غير موجود', 404);
  const paid = b.status === 'approved' ? (b.paid !== undefined && b.paid !== '' ? Number(b.paid) || 0 : (e.paid ?? e.price)) : e.paid;
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
    `SELECT u.id, u.name, u.email, u.phone, u.role, u.created_at, u.last_login, u.admin_note,
       (SELECT COUNT(*) FROM enrollments e WHERE e.user_id = u.id AND e.status = 'approved') AS active,
       (SELECT COUNT(*) FROM enrollments e WHERE e.user_id = u.id AND e.status = 'pending') AS pending,
       (SELECT COUNT(*) FROM enrollments e WHERE e.user_id = u.id AND e.status = 'rejected') AS rejected,
       (SELECT COALESCE(SUM(COALESCE(e.paid, c.price)),0) FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.user_id = u.id AND e.status = 'approved') AS paid,
       (SELECT COUNT(*) FROM progress p WHERE p.user_id = u.id) AS done
     FROM users u ORDER BY u.created_at DESC LIMIT 5000`
  ).all();
  return json({ users: results });
}
async function adminUser(env, id) {
  const u = await env.DB.prepare('SELECT id, name, email, phone, role, created_at, last_login, admin_note FROM users WHERE id = ?').bind(id).first();
  if (!u) return err('المستخدم غير موجود', 404);
  const { results } = await env.DB.prepare(
    `SELECT e.id, e.course_id, e.status, e.created_at, e.decided_at, e.note, e.paid, c.title, c.price,
       (SELECT COUNT(*) FROM lessons l WHERE l.course_id = c.id) AS lessons,
       (SELECT COUNT(*) FROM progress p JOIN lessons l ON l.id = p.lesson_id WHERE p.user_id = e.user_id AND l.course_id = c.id) AS done
     FROM enrollments e JOIN courses c ON c.id = e.course_id WHERE e.user_id = ? ORDER BY e.created_at DESC`
  ).bind(id).all();
  return json({ user: u, enrollments: results });
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
    return json({ ok: true, id: r.meta.last_row_id });
  }
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
  return json({ ok: true });
}

// ---------- videos (R2) ----------
const noR2 = () => err('تخزين الفيديو غير مفعّل بعد (R2)', 503);
async function uploadStart(env, req) {
  if (!env.VIDEOS) return noR2();
  const b = await body(req);
  const lesson = await env.DB.prepare('SELECT id FROM lessons WHERE id = ?').bind(Number(b.lesson_id) || 0).first();
  if (!lesson) return err('الدرس غير موجود', 404);
  const type = /^video\//.test(String(b.type || '')) ? String(b.type) : 'video/mp4';
  const ext = (String(b.filename || '').match(/\.(mp4|m4v|mov|webm|mkv)$/i) || [, 'mp4'])[1].toLowerCase();
  const key = `lessons/${lesson.id}/${randomHex(8)}.${ext}`;
  const mpu = await env.VIDEOS.createMultipartUpload(key, { httpMetadata: { contentType: type } });
  return json({ key: mpu.key, uploadId: mpu.uploadId });
}
async function uploadPart(env, req, url) {
  if (!env.VIDEOS) return noR2();
  const key = url.searchParams.get('key'), uploadId = url.searchParams.get('uploadId'), n = Number(url.searchParams.get('part'));
  if (!key || !key.startsWith('lessons/') || !uploadId || !(n >= 1 && n <= 10000)) return err('طلب غير صحيح');
  const mpu = env.VIDEOS.resumeMultipartUpload(key, uploadId);
  const part = await mpu.uploadPart(n, await req.arrayBuffer());
  return json({ partNumber: part.partNumber, etag: part.etag });
}
async function uploadComplete(env, req) {
  if (!env.VIDEOS) return noR2();
  const b = await body(req);
  if (!b.key || !String(b.key).startsWith('lessons/') || !b.uploadId || !Array.isArray(b.parts)) return err('طلب غير صحيح');
  const lesson = await env.DB.prepare('SELECT id, video_key FROM lessons WHERE id = ?').bind(Number(b.lesson_id) || 0).first();
  if (!lesson) return err('الدرس غير موجود', 404);
  const mpu = env.VIDEOS.resumeMultipartUpload(b.key, b.uploadId);
  const obj = await mpu.complete(b.parts.map((p) => ({ partNumber: Number(p.partNumber), etag: String(p.etag) })));
  if (lesson.video_key && lesson.video_key !== b.key) { try { await env.VIDEOS.delete(lesson.video_key); } catch (e) {} }
  await env.DB.prepare('UPDATE lessons SET video_key = ?, video_size = ?, video_type = ? WHERE id = ?')
    .bind(b.key, obj.size, (obj.httpMetadata && obj.httpMetadata.contentType) || 'video/mp4', lesson.id).run();
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
async function streamVideo(env, req, user, id) {
  if (!user) return err('سجّل دخول أولًا', 401);
  if (!env.VIDEOS) return noR2();
  const l = await env.DB.prepare('SELECT course_id, video_key, video_type FROM lessons WHERE id = ?').bind(id).first();
  if (!l || !l.video_key) return err('الفيديو غير موجود', 404);
  if (user.role !== 'admin') {
    const e = await env.DB.prepare("SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ? AND status = 'approved'").bind(user.id, l.course_id).first();
    if (!e) return err('غير مسموح', 403);
  }
  const obj = await env.VIDEOS.get(l.video_key, { range: req.headers, onlyIf: req.headers });
  if (!obj) return err('الفيديو غير موجود', 404);
  const h = new Headers();
  obj.writeHttpMetadata(h);
  h.set('content-type', l.video_type || h.get('content-type') || 'video/mp4');
  h.set('etag', obj.httpEtag);
  h.set('accept-ranges', 'bytes');
  h.set('cache-control', 'private, no-store');
  h.set('content-disposition', 'inline');
  h.set('x-content-type-options', 'nosniff');
  if (!('body' in obj) || !obj.body) return new Response(null, { status: 304, headers: h });
  if (req.headers.get('range') && obj.range) {
    const size = obj.size;
    let start, end;
    if ('suffix' in obj.range) { start = size - obj.range.suffix; end = size - 1; }
    else { start = obj.range.offset || 0; end = obj.range.length != null ? start + obj.range.length - 1 : size - 1; }
    h.set('content-range', `bytes ${start}-${end}/${size}`);
    h.set('content-length', String(end - start + 1));
    return new Response(obj.body, { status: 206, headers: h });
  }
  h.set('content-length', String(obj.size));
  return new Response(obj.body, { status: 200, headers: h });
}

// ---------- settings (payment methods) ----------
const PAY_KEYS = ['bank_name', 'bank_holder', 'bank_account', 'bank_iban', 'palpay_number', 'palpay_holder', 'jawwal_number', 'jawwal_holder', 'pay_note'];
async function getSettings(env) {
  const { results } = await env.DB.prepare('SELECT key, value FROM settings').all();
  const s = {};
  results.forEach((r) => { if (PAY_KEYS.includes(r.key)) s[r.key] = r.value; });
  return json({ settings: s });
}
async function saveSettings(env, req) {
  const b = await body(req);
  for (const k of PAY_KEYS) {
    if (b[k] === undefined) continue;
    await env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(k, clean(b[k], 300)).run();
  }
  return json({ ok: true });
}

// ---------- router ----------
export async function onRequest({ request, env }) {
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
    if (path === '/settings' && method === 'GET') return await getSettings(env);

    const user = await currentUser(env, request);

    let m;
    if ((m = path.match(/^\/course\/([\w-]+)$/)) && method === 'GET') return await getCourse(env, user, m[1]);
    if ((m = path.match(/^\/video\/(\d+)$/)) && (method === 'GET' || method === 'HEAD')) return await streamVideo(env, request, user, Number(m[1]));

    if (!user) return err('سجّل دخول أولًا', 401);
    if (path === '/me' && method === 'GET') return await me(env, user);
    if (path === '/enroll' && method === 'POST') return await enroll(env, request, user);
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
      if (path === '/admin/users' && method === 'GET') return await adminUsers(env);
      if ((m = path.match(/^\/admin\/users\/(\d+)$/))) {
        if (method === 'GET') return await adminUser(env, Number(m[1]));
        if (method === 'POST') return await adminUpdateUser(env, request, Number(m[1]), user);
        if (method === 'DELETE') return await adminDeleteUser(env, Number(m[1]), user);
      }
      if ((m = path.match(/^\/admin\/users\/(\d+)\/password$/)) && method === 'POST') return await adminResetPassword(env, request, Number(m[1]));
      if ((m = path.match(/^\/admin\/users\/(\d+)\/enroll$/)) && method === 'POST') return await adminEnrollUser(env, request, Number(m[1]));
      if (path === '/admin/upload/start' && method === 'POST') return await uploadStart(env, request);
      if (path === '/admin/upload/part' && method === 'PUT') return await uploadPart(env, request, url);
      if (path === '/admin/upload/complete' && method === 'POST') return await uploadComplete(env, request);
      if (path === '/admin/upload/abort' && method === 'POST') return await uploadAbort(env, request);
      if ((m = path.match(/^\/admin\/lessons\/(\d+)\/video$/)) && method === 'DELETE') return await deleteLessonVideo(env, Number(m[1]));
      if (path === '/admin/lessons' && method === 'POST') return await adminSaveLesson(env, request, null);
      if ((m = path.match(/^\/admin\/lessons\/(\d+)$/))) {
        if (method === 'POST') return await adminSaveLesson(env, request, Number(m[1]));
        if (method === 'DELETE') return await adminDeleteLesson(env, Number(m[1]));
      }
      if ((m = path.match(/^\/admin\/courses\/([\w-]+)$/)) && method === 'POST') return await adminSaveCourse(env, request, m[1]);
    }
    return err('Not found', 404);
  } catch (e) {
    return err('خطأ في السيرفر، حاول مرة ثانية', 500);
  }
}
