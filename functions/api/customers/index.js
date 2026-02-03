import { json, badRequest } from '../../_lib/response.js';
import { requireAuth, canReadCustomers, canWriteCustomers } from '../../_lib/auth.js';
import { nowIso } from '../../_lib/crypto.js';
import { logActivity } from '../../_lib/log.js';

function asText(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s ? s : null;
}

export async function onRequest(context) {
  const { env, request } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }
  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  if (!canReadCustomers(auth.user)) {
    return json({ ok: false, error: 'forbidden', message: 'شما اجازه دسترسی به مشتریان را ندارید.' }, { status: 403 });
  }

  if (request.method === 'GET') {
    const url = new URL(request.url);
    const q = (url.searchParams.get('q') || '').trim();
    const limit = Math.min(Number(url.searchParams.get('limit') || 200), 500);

    let stmt;
    if (q) {
      const like = `%${q}%`;
      stmt = env.DB.prepare(
        `SELECT id, name, phone, notes, created_at, updated_at, updated_by, deleted, version
         FROM customers
         WHERE deleted=0 AND (name LIKE ? OR phone LIKE ? OR notes LIKE ?)
         ORDER BY updated_at DESC
         LIMIT ?`
      ).bind(like, like, like, limit);
    } else {
      stmt = env.DB.prepare(
        `SELECT id, name, phone, notes, created_at, updated_at, updated_by, deleted, version
         FROM customers
         WHERE deleted=0
         ORDER BY updated_at DESC
         LIMIT ?`
      ).bind(limit);
    }

    const res = await stmt.all();
    return json({ ok: true, results: res.results || [] });
  }

  if (request.method === 'POST') {
    if (!canWriteCustomers(auth.user)) return json({ ok: false, error: 'forbidden', message: 'اجازه ثبت مشتری ندارید.' }, { status: 403 });
    let body;
    try { body = await request.json(); } catch { return badRequest('بدنه درخواست باید JSON باشد.'); }

    const name = asText(body.name) || '';
    if (!name) return badRequest('نام مشتری الزامی است.');

    const id = crypto.randomUUID();
    const now = nowIso();

    await env.DB.prepare(
      `INSERT INTO customers (id, name, phone, notes, created_at, updated_at, updated_by, deleted, version)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1)`
    ).bind(id, name, asText(body.phone), asText(body.notes), now, now, auth.user.id).run();

    await logActivity(env, { userId: auth.user.id, action: 'customer_create', entity: 'customers', entityId: id, detail: null, ip: auth.ip || null, ua: auth.ua || null });

    const rec = await env.DB.prepare(
      `SELECT id, name, phone, notes, created_at, updated_at, updated_by, deleted, version
       FROM customers WHERE id=?`
    ).bind(id).first();

    return json({ ok: true, record: rec });
  }

  return badRequest('روش درخواست نامعتبر است.');
}
