import { json } from './_lib/response.js';

// Global middleware for Pages Functions:
// - Handles CORS preflight
// - Returns a clear JSON error if required bindings are missing
// - Converts unhandled exceptions to JSON (so the UI can show a useful message)

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
};

function jsonError(status, message, hint) {
  return json(
    { ok: false, error: 'config_error', message, hint },
    { status, headers: CORS_HEADERS }
  );
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  // CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  // Quick misconfiguration checks (most common reason for HTTP 500 here)
  if (url.pathname.startsWith('/api/')) {
    if (!env.DB) {
      return jsonError(
        500,
        'Missing D1 binding: DB',
        'Cloudflare Dashboard → Workers & Pages → (project) → Settings → Functions → D1 database bindings → Add binding name: DB (select your D1 database)'
      );
    }

    // Only needed for file endpoints
    if ((url.pathname.startsWith('/api/files') || url.pathname.includes('/files/')) && !env.BUCKET) {
      return jsonError(
        500,
        'Missing R2 binding: BUCKET',
        'Cloudflare Dashboard → Storage & databases → R2 → Create bucket, then Workers & Pages → (project) → Settings → Functions → R2 bindings → Add binding name: BUCKET'
      );
    }
  }

  try {
    const res = await context.next();
    // Add CORS headers to API responses
    if (url.pathname.startsWith('/api/')) {
      const headers = new Headers(res.headers);
      for (const [k, v] of Object.entries(CORS_HEADERS)) headers.set(k, v);
      return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
    }
    return res;
  } catch (err) {
    const msg = err?.message ? String(err.message) : String(err);
    return json(
      {
        ok: false,
        error: 'server_error',
        message: msg,
      },
      { status: 500, headers: CORS_HEADERS }
    );
  }
}
