import { json, badRequest } from '../../_lib/response.js';
import { requireAuth, assertRole } from '../../_lib/auth.js';

export async function onRequest(context) {
  const { env, request } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }

  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  const deny = assertRole(auth.user, ['admin']);
  if (deny) return deny;

  if (request.method === 'GET') {
    const url = new URL(request.url);
    const limit = Math.min(Number(url.searchParams.get('limit') || 200), 500);

    const res = await env.DB.prepare(
      `SELECT a.id, a.ts, a.action, a.entity, a.entity_id, a.detail, a.ip, a.ua,
              u.username, u.display_name
       FROM activity_log a
       LEFT JOIN users u ON u.id = a.user_id
       ORDER BY a.ts DESC
       LIMIT ?`
    ).bind(limit).all();

    return json({ ok: true, results: res.results || [] });
  }

  return badRequest('روش درخواست نامعتبر است.');
}
