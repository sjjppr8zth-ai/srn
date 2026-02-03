import { json } from '../../_lib/response.js';

export async function onRequest({ env, request }) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' } });
  }

  const row = await env.DB.prepare(`SELECT value FROM meta WHERE key='initialized'`).first();
  const initialized = row?.value === '1';

  const orgRow = await env.DB.prepare(`SELECT value FROM meta WHERE key='org_name'`).first();
  const orgName = orgRow?.value || 'Saran';

  return json({ ok: true, initialized, orgName, appName: 'Saran' });
}
