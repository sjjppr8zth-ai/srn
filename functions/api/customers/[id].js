import { json, badRequest, notFound } from '../../_lib/response.js';
import { requireAuth, canReadCustomers, canWriteCustomers } from '../../_lib/auth.js';
import { nowIso } from '../../_lib/crypto.js';
import { logActivity } from '../../_lib/log.js';

function asText(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s ? s : null;
}

export async function onRequest(context) {
  const { env, request, params } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }
  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  if (!canReadCustomers(auth.user)) {
    return json({ ok: false, error: 'forbidden', message: 'شما اجازه دسترسی به مشتریان را ندارید.' }, { status: 403 });
  }

  const id = params.id;

  const existing = await env.DB.prepare(
    `SELECT id, name, phone, notes, created_at, updated_at, updated_by, deleted, version
     FROM customers WHERE id=?`
  ).bind(id).first();

  if (!existing) return notFound('مشتری پیدا نشد.');

  if (request.method === 'GET') {
    return json({ ok: true, record: existing });
  }

  if (request.method === 'PUT') {
    if (!canWriteCustomers(auth.user)) return json({ ok: false, error: 'forbidden', message: 'اجازه ویرایش مشتری ندارید.' }, { status: 403 });

    let body;
    try { body = await request.json(); } catch { return badRequest('بدنه درخواست باید JSON باشد.'); }

    const name = asText(body.name) || existing.name;
    if (!name) return badRequest('نام مشتری الزامی است.');

    const now = nowIso();

    await env.DB.prepare(
      `UPDATE customers
       SET name=?, phone=?, notes=?, updated_at=?, updated_by=?, deleted=0, version=version+1
       WHERE id=?`
    ).bind(name, asText(body.phone), asText(body.notes), now, auth.user.id, id).run();

    await logActivity(env, { userId: auth.user.id, action: 'customer_update', entity: 'customers', entityId: id, detail: null, ip: auth.ip || null, ua: auth.ua || null });

    const rec = await env.DB.prepare(
      `SELECT id, name, phone, notes, created_at, updated_at, updated_by, deleted, version
       FROM customers WHERE id=?`
    ).bind(id).first();

    return json({ ok: true, record: rec });
  }

  if (request.method === 'DELETE') {
    if (auth.user.role !== 'admin') return json({ ok: false, error: 'forbidden', message: 'فقط مدیر می‌تواند حذف کند.' }, { status: 403 });

    const now = nowIso();
    await env.DB.prepare(
      `UPDATE customers SET deleted=1, updated_at=?, updated_by=?, version=version+1 WHERE id=?`
    ).bind(now, auth.user.id, id).run();

    await logActivity(env, { userId: auth.user.id, action: 'customer_delete', entity: 'customers', entityId: id, detail: null, ip: auth.ip || null, ua: auth.ua || null });

    return json({ ok: true });
  }

  return badRequest('روش درخواست نامعتبر است.');
}
