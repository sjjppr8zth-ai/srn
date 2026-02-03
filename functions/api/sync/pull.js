import { json, badRequest } from '../../_lib/response.js';
import { requireAuth, canReadCustomers } from '../../_lib/auth.js';
import { nowIso } from '../../_lib/crypto.js';

export async function onRequest(context) {
  const { env, request } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }
  if (request.method !== 'GET') return badRequest('روش درخواست نامعتبر است.');

  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  const url = new URL(request.url);
  const since = url.searchParams.get('since') || '1970-01-01T00:00:00.000Z';
  const serverNow = nowIso();

  const props = await env.DB.prepare(
    `SELECT id, title, address, price, status, description, owner_name, owner_phone,
            created_at, updated_at, updated_by, deleted, version
     FROM properties
     WHERE updated_at > ?
     ORDER BY updated_at ASC`
  ).bind(since).all();

  let customers = { results: [] };
  if (canReadCustomers(auth.user)) {
    customers = await env.DB.prepare(
      `SELECT id, name, phone, notes, created_at, updated_at, updated_by, deleted, version
       FROM customers
       WHERE updated_at > ?
       ORDER BY updated_at ASC`
    ).bind(since).all();
  }

  return json({
    ok: true,
    serverNow,
    since,
    properties: props.results || [],
    customers: customers.results || [],
  });
}
