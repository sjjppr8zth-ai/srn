import { json, badRequest, conflict } from '../../_lib/response.js';
import { nowIso, randomBytes, b64Encode, pbkdf2Hash } from '../../_lib/crypto.js';
import { logActivity } from '../../_lib/log.js';

function normalizePassword(p) {
  if (typeof p !== 'string') return '';
  return p.trim();
}

async function makePassFields(password) {
  const pass = normalizePassword(password);
  if (!pass) return { active: 0, pass_salt: null, pass_hash: null, pass_iters: null };
  if (pass.length < 6) {
    // keep it lenient but not too short
    throw new Error('رمز عبور باید حداقل ۶ کاراکتر باشد.');
  }
  const salt = randomBytes(16);
  const iters = 210000;
  const hashBytes = await pbkdf2Hash(pass, salt, iters, 256);
  return { active: 1, pass_salt: b64Encode(salt), pass_hash: b64Encode(hashBytes), pass_iters: iters };
}

export async function onRequest({ env, request }) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }
  if (request.method !== 'POST') return badRequest('روش درخواست نامعتبر است.');

  const row = await env.DB.prepare(`SELECT value FROM meta WHERE key='initialized'`).first();
  const initialized = row?.value === '1';
  if (initialized) return conflict('سیستم قبلاً راه‌اندازی شده است.');

  let body;
  try {
    body = await request.json();
  } catch {
    return badRequest('بدنه درخواست باید JSON باشد.');
  }

  const orgName = (body.orgName || 'Saran').toString().trim() || 'Saran';

  const usersSpec = [
    { username: 'admin', role: 'admin', displayName: 'مدیر', password: body.adminPassword },
    { username: 'accountant', role: 'accountant', displayName: 'حسابدار', password: body.accountantPassword },
    { username: 'staff1', role: 'staff', displayName: 'کارمند ۱', password: body.staff1Password },
    { username: 'staff2', role: 'staff', displayName: 'کارمند ۲', password: body.staff2Password },
    { username: 'staff3', role: 'staff', displayName: 'کارمند ۳', password: body.staff3Password },
    { username: 'staff4', role: 'staff', displayName: 'کارمند ۴', password: body.staff4Password },
  ];

  // At least admin must be enabled.
  const adminPass = normalizePassword(body.adminPassword);
  if (!adminPass) return badRequest('رمز عبور مدیر (admin) الزامی است.');

  const now = nowIso();

  try {
    // meta
    await env.DB.prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES ('org_name', ?)`).bind(orgName).run();
    await env.DB.prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '1')`).run();

    // users
    for (const u of usersSpec) {
      const passFields = await makePassFields(u.password);
      const id = crypto.randomUUID();
      await env.DB.prepare(
        `INSERT INTO users (id, username, display_name, role, active, pass_salt, pass_hash, pass_iters, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        id, u.username, u.displayName, u.role, passFields.active,
        passFields.pass_salt, passFields.pass_hash, passFields.pass_iters,
        now, now
      ).run();
    }

    await env.DB.prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES ('initialized', '1')`).run();

    await logActivity(env, {
      userId: null,
      action: 'bootstrap_init',
      entity: 'system',
      entityId: null,
      detail: `org=${orgName}`,
      ip: request.headers.get('CF-Connecting-IP') || null,
      ua: request.headers.get('User-Agent') || null,
    });

    return json({ ok: true, initialized: true, orgName });
  } catch (err) {
    return badRequest(err?.message || 'خطا در راه‌اندازی سیستم.');
  }
}
