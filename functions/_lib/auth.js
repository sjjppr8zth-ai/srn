import { sha256Hex, nowIso } from './crypto.js';
import { unauthorized, forbidden } from './response.js';

function getIp(request) {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';
}

export async function getAuth(context) {
  const { request, env } = context;
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const token = m[1].trim();
  if (!token) return null;

  const tokenHash = await sha256Hex(token);
  const now = nowIso();

  const row = await env.DB.prepare(
    `SELECT s.id as session_id, s.expires_at, u.id as user_id, u.username, u.display_name, u.role, u.active
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  ).bind(tokenHash, now).first();

  if (!row) return null;
  if (!row.active) return null;

  // Best-effort last_seen update (don't block auth).
  context.waitUntil?.(
    env.DB.prepare(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`)
      .bind(now, row.session_id)
      .run()
      .catch(() => {})
  );

  return {
    token,
    tokenHash,
    sessionId: row.session_id,
    user: {
      id: row.user_id,
      username: row.username,
      displayName: row.display_name,
      role: row.role,
      active: !!row.active,
    },
    ip: getIp(request),
    ua: request.headers.get('User-Agent') || '',
  };
}

export async function requireAuth(context) {
  const auth = await getAuth(context);
  if (!auth) return unauthorized('برای ادامه باید وارد شوید.');
  return auth;
}

export function assertRole(user, roles) {
  if (!roles.includes(user.role)) {
    return forbidden('شما اجازه انجام این عملیات را ندارید.');
  }
  return null;
}

export function canReadCustomers(user) {
  return user.role === 'admin' || user.role === 'accountant';
}
export function canWriteCustomers(user) {
  return user.role === 'admin' || user.role === 'accountant';
}
export function canReadProperties(user) {
  return true;
}
export function canWriteProperties(user) {
  return user.role === 'admin' || user.role === 'accountant';
}
export function canDeleteProperties(user) {
  return user.role === 'admin';
}
