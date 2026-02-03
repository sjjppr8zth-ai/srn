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
    const res = await env.DB.prepare(
      `SELECT username, display_name, role, active, created_at, updated_at
       FROM users
       ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'accountant' THEN 2 ELSE 3 END, username ASC`
    ).all();
    return json({ ok: true, results: res.results || [] });
  }

  return badRequest('روش درخواست نامعتبر است.');
}
