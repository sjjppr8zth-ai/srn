import { json, badRequest } from '../../_lib/response.js';
import { requireAuth, canWriteProperties, canWriteCustomers } from '../../_lib/auth.js';
import { nowIso } from '../../_lib/crypto.js';
import { logActivity } from '../../_lib/log.js';

function sanitizeFilename(name) {
  return String(name || 'file')
    .replace(/[^\w\d\.\-\u0600-\u06FF]+/g, '_')
    .slice(0, 80);
}

export async function onRequest(context) {
  const { env, request } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }
  if (request.method !== 'POST') return badRequest('روش درخواست نامعتبر است.');

  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  const ct = request.headers.get('Content-Type') || '';
  if (!ct.includes('multipart/form-data')) {
    return badRequest('فرمت آپلود باید multipart/form-data باشد.');
  }

  const form = await request.formData();
  const entity = String(form.get('entity') || '').trim();
  const entityId = String(form.get('entityId') || '').trim();

  if (!entity || !entityId) return badRequest('entity و entityId الزامی است.');

  if (entity === 'properties' && !canWriteProperties(auth.user)) {
    return json({ ok: false, error: 'forbidden', message: 'اجازه آپلود برای ملک ندارید.' }, { status: 403 });
  }
  if (entity === 'customers' && !canWriteCustomers(auth.user)) {
    return json({ ok: false, error: 'forbidden', message: 'اجازه آپلود برای مشتری ندارید.' }, { status: 403 });
  }

  const file = form.get('file');
  if (!file || typeof file === 'string') return badRequest('فایل ارسال نشده است.');

  const id = crypto.randomUUID();
  const name = sanitizeFilename(file.name);
  const r2Key = `${entity}/${entityId}/${id}-${name}`;
  const contentType = file.type || 'application/octet-stream';
  const size = file.size || null;

  await env.BUCKET.put(r2Key, file.stream(), {
    httpMetadata: { contentType },
  });

  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO files (id, r2_key, entity, entity_id, content_type, size, created_at, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, r2Key, entity, entityId, contentType, size, now, auth.user.id).run();

  await logActivity(env, { userId: auth.user.id, action: 'file_upload', entity: 'files', entityId: id, detail: `${entity}:${entityId}`, ip: auth.ip || null, ua: auth.ua || null });

  return json({ ok: true, file: { id, entity, entityId, contentType, size, url: `/api/files/${id}` } });
}
