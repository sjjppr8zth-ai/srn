import { json, badRequest, notFound } from '../../../_lib/response.js';
import { requireAuth, assertRole } from '../../../_lib/auth.js';
import { randomBytes, b64Encode, pbkdf2Hash, nowIso } from '../../../_lib/crypto.js';
import { logActivity } from '../../../_lib/log.js';

function normalizePassword(p) {
  if (typeof p !== 'string') return null;
  return p.trim();
}

export async function onRequest(context) {
  const { env, request, params } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }

  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  const deny = assertRole(auth.user, ['admin']);
  if (deny) return deny;

  const username = (params.username || '').toString().trim().toLowerCase();
  if (!username) return badRequest('نام کاربری نامعتبر است.');

  const user = await env.DB.prepare(
    `SELECT id, username, display_name, role, active FROM users WHERE username=? LIMIT 1`
  ).bind(username).first();

  if (!user) return notFound('کاربر پیدا نشد.');

  if (request.method === 'GET') {
    return json({ ok: true, user: { username: user.username, displayName: user.display_name, role: user.role, active: !!user.active } });
  }

  if (request.method !== 'PUT') return badRequest('روش درخواست نامعتبر است.');

  let body;
  try { body = await request.json(); } catch { return badRequest('بدنه درخواست باید JSON باشد.'); }

  const pass = normalizePassword(body.password);
  const setActive = (body.active === undefined || body.active === null) ? null : !!body.active;

  const now = nowIso();

  if (pass === null && setActive === null && body.displayName === undefined) {
    return badRequest('هیچ تغییری ارسال نشده است.');
  }

  const updates = [];
  const binds = [];

  let detail = [];

  if (body.displayName !== undefined) {
    const dn = String(body.displayName || '').trim();
    if (!dn) return badRequest('نام نمایشی نمی‌تواند خالی باشد.');
    updates.push('display_name=?');
    binds.push(dn);
    detail.push('displayName');
  }

  if (pass !== null) {
    if (!pass) {
      // disable user by clearing password
      updates.push('active=0');
      updates.push('pass_salt=NULL');
      updates.push('pass_hash=NULL');
      updates.push('pass_iters=NULL');
      detail.push('disable');
    } else {
      if (pass.length < 6) return badRequest('رمز عبور باید حداقل ۶ کاراکتر باشد.');
      const salt = randomBytes(16);
      const iters = 210000;
      const hashBytes = await pbkdf2Hash(pass, salt, iters, 256);
      updates.push('pass_salt=?');
      binds.push(b64Encode(salt));
      updates.push('pass_hash=?');
      binds.push(b64Encode(hashBytes));
      updates.push('pass_iters=?');
      binds.push(iters);
      updates.push('active=1');
      detail.push('password');
    }
  }

  if (setActive !== null && pass === null) {
    // allow toggling active only if password isn't being replaced in this request
    updates.push('active=?');
    binds.push(setActive ? 1 : 0);
    detail.push('active');
  }

  updates.push('updated_at=?');
  binds.push(now);

  binds.push(user.id);

  await env.DB.prepare(
    `UPDATE users SET ${updates.join(', ')} WHERE id=?`
  ).bind(...binds).run();

  await logActivity(env, {
    userId: auth.user.id,
    action: 'user_update',
    entity: 'users',
    entityId: user.id,
    detail: `${username}: ${detail.join(',')}`,
    ip: auth.ip || null,
    ua: auth.ua || null,
  });

  const updated = await env.DB.prepare(
    `SELECT username, display_name, role, active, updated_at FROM users WHERE id=?`
  ).bind(user.id).first();

  return json({ ok: true, user: { username: updated.username, displayName: updated.display_name, role: updated.role, active: !!updated.active, updatedAt: updated.updated_at } });
}
