import { json, badRequest } from '../../_lib/response.js';
import { requireAuth, canReadCustomers } from '../../_lib/auth.js';

export async function onRequest(context) {
  const { env, request } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }
  if (request.method !== 'GET') return badRequest('روش درخواست نامعتبر است.');

  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  const url = new URL(request.url);
  const entity = String(url.searchParams.get('entity') || '').trim();
  const entityId = String(url.searchParams.get('entityId') || '').trim();

  if (!entity || !entityId) return badRequest('entity و entityId الزامی است.');

  if (entity === 'customers' && !canReadCustomers(auth.user)) {
    return json({ ok: false, error: 'forbidden', message: 'اجازه دسترسی به فایل‌های مشتریان را ندارید.' }, { status: 403 });
  }

  const res = await env.DB.prepare(
    `SELECT id, entity, entity_id, content_type, size, created_at
     FROM files
     WHERE entity=? AND entity_id=?
     ORDER BY created_at DESC`
  ).bind(entity, entityId).all();

  const results = (res.results || []).map(r => ({
    id: r.id,
    entity: r.entity,
    entityId: r.entity_id,
    contentType: r.content_type,
    size: r.size,
    createdAt: r.created_at,
    url: `/api/files/${r.id}`,
  }));

  return json({ ok: true, results });
}
