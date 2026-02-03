import { json, badRequest } from '../../_lib/response.js';
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
  const { env, request } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }
  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  if (request.method === 'GET') {
    const url = new URL(request.url);
    const q = (url.searchParams.get('q') || '').trim();
    const limit = Math.min(Number(url.searchParams.get('limit') || 200), 500);

    let stmt;
    if (q) {
      const like = `%${q}%`;
      stmt = env.DB.prepare(
        `SELECT id, title, address, price, status, description, owner_name, owner_phone,
                created_at, updated_at, updated_by, deleted, version
         FROM properties
         WHERE deleted=0 AND (title LIKE ? OR address LIKE ? OR owner_name LIKE ? OR owner_phone LIKE ?)
         ORDER BY updated_at DESC
         LIMIT ?`
      ).bind(like, like, like, like, limit);
    } else {
      stmt = env.DB.prepare(
        `SELECT id, title, address, price, status, description, owner_name, owner_phone,
                created_at, updated_at, updated_by, deleted, version
         FROM properties
         WHERE deleted=0
         ORDER BY updated_at DESC
         LIMIT ?`
      ).bind(limit);
    }

    const res = await stmt.all();
    return json({ ok: true, results: res.results || [] });
  }

  if (request.method === 'POST') {
    if (!canWriteProperties(auth.user)) return json({ ok: false, error: 'forbidden', message: 'اجازه ثبت ملک ندارید.' }, { status: 403 });
    let body;
    try { body = await request.json(); } catch { return badRequest('بدنه درخواست باید JSON باشد.'); }

    const title = asText(body.title) || '';
    if (!title) return badRequest('عنوان ملک الزامی است.');

    const id = crypto.randomUUID();
    const now = nowIso();

    await env.DB.prepare(
      `INSERT INTO properties
       (id, title, address, price, status, description, owner_name, owner_phone, created_at, updated_at, updated_by, deleted, version)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1)`
    ).bind(
      id, title, asText(body.address), asInt(body.price), asText(body.status), asText(body.description),
      asText(body.owner_name), asText(body.owner_phone),
      now, now, auth.user.id
    ).run();

    await logActivity(env, { userId: auth.user.id, action: 'property_create', entity: 'properties', entityId: id, detail: null, ip: auth.ip || null, ua: auth.ua || null });

    const rec = await env.DB.prepare(
      `SELECT id, title, address, price, status, description, owner_name, owner_phone,
              created_at, updated_at, updated_by, deleted, version
       FROM properties WHERE id=?`
    ).bind(id).first();

    return json({ ok: true, record: rec });
  }

  return badRequest('روش درخواست نامعتبر است.');
}
