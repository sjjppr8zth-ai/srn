import { json } from '../../_lib/response.js';
import { requireAuth } from '../../_lib/auth.js';

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }

  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  return json({ ok: true, user: auth.user });
}
