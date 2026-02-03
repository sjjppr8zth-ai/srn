import { json, badRequest, unauthorized } from '../../_lib/response.js';
import { nowIso, randomBytes, b64urlEncode, b64DecodeToBytes, pbkdf2Hash, timingSafeEqual, sha256Hex } from '../../_lib/crypto.js';
import { logActivity } from '../../_lib/log.js';

function normUsername(u) {
  return (u || '').toString().trim().toLowerCase();
}

export async function onRequest({ env, request }) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }
  if (request.method !== 'POST') return badRequest('روش درخواست نامعتبر است.');

  const initRow = await env.DB.prepare(`SELECT value FROM meta WHERE key='initialized'`).first();
  if (initRow?.value !== '1') {
    return badRequest('سیستم هنوز راه‌اندازی نشده است. ابتدا راه‌اندازی اولیه را انجام دهید.');
  }

  let body;
  try { body = await request.json(); } catch { return badRequest('بدنه درخواست باید JSON باشد.'); }

  const username = normUsername(body.username);
  const password = (body.password || '').toString();

  if (!username || !password) return badRequest('نام کاربری و رمز عبور الزامی است.');

  const user = await env.DB.prepare(
    `SELECT id, username, display_name, role, active, pass_salt, pass_hash, pass_iters
     FROM users WHERE username = ? LIMIT 1`
  ).bind(username).first();

  if (!user || !user.active || !user.pass_hash || !user.pass_salt || !user.pass_iters) {
    return unauthorized('نام کاربری یا رمز عبور اشتباه است.');
  }

  const saltBytes = b64DecodeToBytes(user.pass_salt);
  const hashBytes = await pbkdf2Hash(password, saltBytes, user.pass_iters, 256);
  const storedHashBytes = b64DecodeToBytes(user.pass_hash);

  if (!timingSafeEqual(hashBytes, storedHashBytes)) {
    await logActivity(env, {
      userId: user.id,
      action: 'login_failed',
      entity: 'auth',
      entityId: null,
      detail: `username=${username}`,
      ip: request.headers.get('CF-Connecting-IP') || null,
      ua: request.headers.get('User-Agent') || null,
    });
    return unauthorized('نام کاربری یا رمز عبور اشتباه است.');
  }

  const token = b64urlEncode(randomBytes(32));
  const tokenHash = await sha256Hex(token);
  const sessionId = crypto.randomUUID();
  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at, ip, ua)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    sessionId,
    user.id,
    tokenHash,
    createdAt,
    expiresAt,
    createdAt,
    request.headers.get('CF-Connecting-IP') || null,
    request.headers.get('User-Agent') || null
  ).run();

  await logActivity(env, {
    userId: user.id,
    action: 'login_success',
    entity: 'auth',
    entityId: sessionId,
    detail: null,
    ip: request.headers.get('CF-Connecting-IP') || null,
    ua: request.headers.get('User-Agent') || null,
  });

  return json({
    ok: true,
    token,
    expiresAt,
    user: { username: user.username, displayName: user.display_name, role: user.role }
  });
}
