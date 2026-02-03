import { json, badRequest, notFound } from '../../_lib/response.js';
import { requireAuth, canWriteProperties, canDeleteProperties } from '../../_lib/auth.js';
import { nowIso } from '../../_lib/crypto.js';
import { logActivity } from '../../_lib/log.js';

function asText(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s ? s : null;
}
function asInt(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return Math.round(n);
}

export async function onRequest(context) {
  const { env, request, params } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }
  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  const id = params.id;

  const existing = await env.DB.prepare(
    `SELECT id, title, address, price, status, description, owner_name, owner_phone,
            created_at, updated_at, updated_by, deleted, version
     FROM properties WHERE id=?`
  ).bind(id).first();

  if (!existing) return notFound('ملک پیدا نشد.');

  if (request.method === 'GET') {
    return json({ ok: true, record: existing });
  }

  if (request.method === 'PUT') {
    if (!canWriteProperties(auth.user)) return json({ ok: false, error: 'forbidden', message: 'اجازه ویرایش ملک ندارید.' }, { status: 403 });
    let body;
    try { body = await request.json(); } catch { return badRequest('بدنه درخواست باید JSON باشد.'); }

    const title = asText(body.title) || existing.title;
    if (!title) return badRequest('عنوان ملک الزامی است.');

    const now = nowIso();

    await env.DB.prepare(
      `UPDATE properties
       SET title=?, address=?, price=?, status=?, description=?, owner_name=?, owner_phone=?,
           updated_at=?, updated_by=?, deleted=0, version=version+1
       WHERE id=?`
    ).bind(
      title,
      asText(body.address),
      asInt(body.price),
      asText(body.status),
      asText(body.description),
      asText(body.owner_name),
      asText(body.owner_phone),
      now,
      auth.user.id,
      id
    ).run();

    await logActivity(env, { userId: auth.user.id, action: 'property_update', entity: 'properties', entityId: id, detail: null, ip: auth.ip || null, ua: auth.ua || null });

    const rec = await env.DB.prepare(
      `SELECT id, title, address, price, status, description, owner_name, owner_phone,
              created_at, updated_at, updated_by, deleted, version
       FROM properties WHERE id=?`
    ).bind(id).first();

    return json({ ok: true, record: rec });
  }

  if (request.method === 'DELETE') {
    if (!canDeleteProperties(auth.user)) return json({ ok: false, error: 'forbidden', message: 'فقط مدیر می‌تواند حذف کند.' }, { status: 403 });

    const now = nowIso();
    await env.DB.prepare(
      `UPDATE properties SET deleted=1, updated_at=?, updated_by=?, version=version+1 WHERE id=?`
    ).bind(now, auth.user.id, id).run();

    await logActivity(env, { userId: auth.user.id, action: 'property_delete', entity: 'properties', entityId: id, detail: null, ip: auth.ip || null, ua: auth.ua || null });

    return json({ ok: true });
  }

  return badRequest('روش درخواست نامعتبر است.');
}
