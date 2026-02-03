import { json, badRequest } from '../../_lib/response.js';
import { requireAuth } from '../../_lib/auth.js';
import { logActivity } from '../../_lib/log.js';

export async function onRequest(context) {
  const { env, request } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }
  if (request.method !== 'POST') return badRequest('روش درخواست نامعتبر است.');

  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  await env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(auth.sessionId).run();

  await logActivity(env, {
    userId: auth.user.id,
    action: 'logout',
    entity: 'auth',
    entityId: auth.sessionId,
    detail: null,
    ip: auth.ip || null,
    ua: auth.ua || null,
  });

  return json({ ok: true });
}
