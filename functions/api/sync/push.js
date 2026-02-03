import { json, badRequest } from '../../_lib/response.js';
import { requireAuth, canWriteProperties, canWriteCustomers, canDeleteProperties } from '../../_lib/auth.js';
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

function pickProperty(record) {
  return {
    id: asText(record?.id),
    title: asText(record?.title) || '',
    address: asText(record?.address),
    price: asInt(record?.price),
    status: asText(record?.status),
    description: asText(record?.description),
    owner_name: asText(record?.owner_name),
    owner_phone: asText(record?.owner_phone),
    updated_at: asText(record?.updated_at),
  };
}

function pickCustomer(record) {
  return {
    id: asText(record?.id),
    name: asText(record?.name) || '',
    phone: asText(record?.phone),
    notes: asText(record?.notes),
    updated_at: asText(record?.updated_at),
  };
}

export async function onRequest(context) {
  const { env, request } = context;
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }
  if (request.method !== 'POST') return badRequest('روش درخواست نامعتبر است.');

  const auth = await requireAuth(context);
  if (auth instanceof Response) return auth;

  let body;
  try { body = await request.json(); } catch { return badRequest('بدنه درخواست باید JSON باشد.'); }

  const changes = Array.isArray(body.changes) ? body.changes : [];
  if (!changes.length) return json({ ok: true, applied: [], conflicts: [], rejected: [] });

  const now = nowIso();

  const applied = [];
  const conflicts = [];
  const rejected = [];

  for (const ch of changes) {
    const entity = ch?.entity;
    const op = ch?.op;

    if (!['properties', 'customers'].includes(entity) || !['upsert', 'delete'].includes(op)) {
      rejected.push({ ch, reason: 'bad_change' });
      continue;
    }

    if (entity === 'properties') {
      if (!canWriteProperties(auth.user)) {
        rejected.push({ ch, reason: 'no_permission' });
        continue;
      }
      const rec = pickProperty(ch.record || {});

      if (op === 'delete') {
        if (!rec.id) {
          rejected.push({ ch, reason: 'id_required' });
          continue;
        }
        if (!canDeleteProperties(auth.user)) {
          rejected.push({ ch, reason: 'delete_not_allowed' });
          continue;
        }
        const existing = await env.DB.prepare(`SELECT id, updated_at, version FROM properties WHERE id=?`).bind(rec.id).first();
        if (!existing) {
          // nothing
          continue;
        }
        await env.DB.prepare(
          `UPDATE properties
           SET deleted=1, updated_at=?, updated_by=?, version=version+1
           WHERE id=?`
        ).bind(now, auth.user.id, rec.id).run();
        applied.push({ entity, op, id: rec.id, updated_at: now });
        await logActivity(env, {
          userId: auth.user.id,
          action: 'property_delete',
          entity: 'properties',
          entityId: rec.id,
          detail: null,
          ip: auth.ip || null,
          ua: auth.ua || null,
        });
        continue;
      }

      if (!rec.id) rec.id = crypto.randomUUID();
      if (!rec.title) {
        rejected.push({ ch, reason: 'title_required' });
        continue;
      }

      // upsert
      const existing = await env.DB.prepare(
        `SELECT id, updated_at, version
         FROM properties WHERE id=?`
      ).bind(rec.id).first();

      const clientUpdatedAt = rec.updated_at || ch.clientUpdatedAt || null;
      if (existing && clientUpdatedAt && existing.updated_at > clientUpdatedAt) {
        // conflict
        const serverRec = await env.DB.prepare(
          `SELECT id, title, address, price, status, description, owner_name, owner_phone,
                  created_at, updated_at, updated_by, deleted, version
           FROM properties WHERE id=?`
        ).bind(rec.id).first();
        conflicts.push({ entity, id: rec.id, server: serverRec });
        continue;
      }

      if (!existing) {
        await env.DB.prepare(
          `INSERT INTO properties
           (id, title, address, price, status, description, owner_name, owner_phone, created_at, updated_at, updated_by, deleted, version)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1)`
        ).bind(
          rec.id, rec.title, rec.address, rec.price, rec.status, rec.description, rec.owner_name, rec.owner_phone,
          now, now, auth.user.id
        ).run();
        applied.push({ entity, op, id: rec.id, updated_at: now });
        await logActivity(env, {
          userId: auth.user.id,
          action: 'property_create',
          entity: 'properties',
          entityId: rec.id,
          detail: null,
          ip: auth.ip || null,
          ua: auth.ua || null,
        });
      } else {
        await env.DB.prepare(
          `UPDATE properties
           SET title=?, address=?, price=?, status=?, description=?, owner_name=?, owner_phone=?,
               updated_at=?, updated_by=?, deleted=0, version=version+1
           WHERE id=?`
        ).bind(
          rec.title, rec.address, rec.price, rec.status, rec.description, rec.owner_name, rec.owner_phone,
          now, auth.user.id, rec.id
        ).run();
        applied.push({ entity, op, id: rec.id, updated_at: now });
        await logActivity(env, {
          userId: auth.user.id,
          action: 'property_update',
          entity: 'properties',
          entityId: rec.id,
          detail: null,
          ip: auth.ip || null,
          ua: auth.ua || null,
        });
      }
    }

    if (entity === 'customers') {
      if (!canWriteCustomers(auth.user)) {
        rejected.push({ ch, reason: 'no_permission' });
        continue;
      }
      const rec = pickCustomer(ch.record || {});

      if (op === 'delete') {
        if (!rec.id) {
          rejected.push({ ch, reason: 'id_required' });
          continue;
        }
        // allow delete only for admin for now
        if (auth.user.role !== 'admin') {
          rejected.push({ ch, reason: 'delete_not_allowed' });
          continue;
        }
        const existing = await env.DB.prepare(`SELECT id FROM customers WHERE id=?`).bind(rec.id).first();
        if (!existing) continue;
        await env.DB.prepare(
          `UPDATE customers SET deleted=1, updated_at=?, updated_by=?, version=version+1 WHERE id=?`
        ).bind(now, auth.user.id, rec.id).run();
        applied.push({ entity, op, id: rec.id, updated_at: now });
        await logActivity(env, {
          userId: auth.user.id,
          action: 'customer_delete',
          entity: 'customers',
          entityId: rec.id,
          detail: null,
          ip: auth.ip || null,
          ua: auth.ua || null,
        });
        continue;
      }

      if (!rec.id) rec.id = crypto.randomUUID();
      if (!rec.name) {
        rejected.push({ ch, reason: 'name_required' });
        continue;
      }

      const existing = await env.DB.prepare(`SELECT id, updated_at FROM customers WHERE id=?`).bind(rec.id).first();
      const clientUpdatedAt = rec.updated_at || ch.clientUpdatedAt || null;
      if (existing && clientUpdatedAt && existing.updated_at > clientUpdatedAt) {
        const serverRec = await env.DB.prepare(
          `SELECT id, name, phone, notes, created_at, updated_at, updated_by, deleted, version
           FROM customers WHERE id=?`
        ).bind(rec.id).first();
        conflicts.push({ entity, id: rec.id, server: serverRec });
        continue;
      }

      if (!existing) {
        await env.DB.prepare(
          `INSERT INTO customers (id, name, phone, notes, created_at, updated_at, updated_by, deleted, version)
           VALUES (?, ?, ?, ?, ?, ?, ?, 0, 1)`
        ).bind(rec.id, rec.name, rec.phone, rec.notes, now, now, auth.user.id).run();
        applied.push({ entity, op, id: rec.id, updated_at: now });
        await logActivity(env, {
          userId: auth.user.id,
          action: 'customer_create',
          entity: 'customers',
          entityId: rec.id,
          detail: null,
          ip: auth.ip || null,
          ua: auth.ua || null,
        });
      } else {
        await env.DB.prepare(
          `UPDATE customers
           SET name=?, phone=?, notes=?, updated_at=?, updated_by=?, deleted=0, version=version+1
           WHERE id=?`
        ).bind(rec.name, rec.phone, rec.notes, now, auth.user.id, rec.id).run();
        applied.push({ entity, op, id: rec.id, updated_at: now });
        await logActivity(env, {
          userId: auth.user.id,
          action: 'customer_update',
          entity: 'customers',
          entityId: rec.id,
          detail: null,
          ip: auth.ip || null,
          ua: auth.ua || null,
        });
      }
    }
  }

  return json({ ok: true, applied, conflicts, rejected, serverNow: now });
}
