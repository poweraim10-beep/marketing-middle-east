// Gate for /gift/* : only signed-in accounts with an activated course (or the admin) can download the student kit.
const SESSION_COOKIE = 'mme_s';

function getCookie(req, name) {
  const c = req.headers.get('cookie') || '';
  const m = c.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}
async function sha256(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function onRequest({ request, env }) {
  const token = getCookie(request, SESSION_COOKIE);
  let ok = false;
  if (token) {
    // the kit is a reward for students whose course is activated (or the admin)
    const row = await env.DB.prepare(
      `SELECT u.email,
         EXISTS (SELECT 1 FROM enrollments e WHERE e.user_id = u.id AND e.status = 'approved') AS active
       FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ? AND COALESCE(u.suspended, 0) = 0`
    ).bind(await sha256(token), Math.floor(Date.now() / 1000)).first();
    ok = !!row && (!!row.active || String(row.email).toLowerCase() === 'power.ai.m10@gmail.com');
    if (row && !ok) return Response.redirect(new URL('/#/my', request.url).toString(), 302);
  }
  if (!ok) return Response.redirect(new URL('/#/register', request.url).toString(), 302);
  const res = await env.ASSETS.fetch(request);
  const h = new Headers(res.headers);
  h.set('cache-control', 'private, no-store');
  h.set('content-disposition', 'attachment; filename="MME-Student-Kit.pdf"');
  return new Response(res.body, { status: res.status, headers: h });
}
