import { notFound, json } from '../../_lib/response.js';
import { requireAuth, canReadCustomers } from '../../_lib/auth.js';

export async function onRequest(context) {
  const { env, request, params } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }

  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  const id = params.id;

  const meta = await env.DB.prepare(
    `SELECT id, r2_key, entity, entity_id, content_type, size, created_at
     FROM files WHERE id=?`
  ).bind(id).first();

  if (!meta) return notFound('فایل پیدا نشد.');

  if (meta.entity === 'customers' && !canReadCustomers(auth.user)) {
    return json({ ok: false, error: 'forbidden', message: 'اجازه دسترسی به فایل‌های مشتریان را ندارید.' }, { status: 403 });
  }

  const obj = await env.BUCKET.get(meta.r2_key);
  if (!obj) return notFound('فایل در مخزن پیدا نشد.');

  const headers = new Headers();
  headers.set('Content-Type', meta.content_type || 'application/octet-stream');
  headers.set('Cache-Control', 'private, max-age=86400');
  headers.set('X-Content-Type-Options', 'nosniff');

  return new Response(obj.body, { headers });
}
