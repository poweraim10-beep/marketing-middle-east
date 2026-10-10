// Gate for /gift/* : only signed-in academy accounts can download the student kit.
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
    const row = await env.DB.prepare('SELECT 1 FROM sessions WHERE token = ? AND expires_at > ?')
      .bind(await sha256(token), Math.floor(Date.now() / 1000)).first();
    ok = !!row;
  }
  if (!ok) return Response.redirect(new URL('/#/register', request.url).toString(), 302);
  const res = await env.ASSETS.fetch(request);
  const h = new Headers(res.headers);
  h.set('cache-control', 'private, no-store');
  h.set('content-disposition', 'attachment; filename="MME-Student-Kit.pdf"');
  return new Response(res.body, { status: res.status, headers: h });
}
