import { nowIso } from './crypto.js';

export async function logActivity(env, { userId = null, action, entity = null, entityId = null, detail = null, ip = null, ua = null }) {
  const id = crypto.randomUUID();
  const ts = nowIso();
  await env.DB.prepare(
    `INSERT INTO activity_log (id, ts, user_id, action, entity, entity_id, detail, ip, ua)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, ts, userId, action, entity, entityId, detail, ip, ua).run();
}
