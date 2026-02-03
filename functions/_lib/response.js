export function json(data, init = {}) {
  const headers = new Headers(init.headers || {});
  headers.set('Content-Type', 'application/json; charset=utf-8');
  // Basic CORS (same-origin is best, but keep it friendly for preview domains).
  headers.set('Access-Control-Allow-Origin', headers.get('Access-Control-Allow-Origin') || '*');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  headers.set('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  return new Response(JSON.stringify(data, null, 2), { ...init, headers });
}

export function text(body, init = {}) {
  const headers = new Headers(init.headers || {});
  headers.set('Content-Type', 'text/plain; charset=utf-8');
  return new Response(body, { ...init, headers });
}

export function badRequest(message, extra = {}) {
  return json({ ok: false, error: 'bad_request', message, ...extra }, { status: 400 });
}

export function unauthorized(message = 'Unauthorized') {
  return json({ ok: false, error: 'unauthorized', message }, { status: 401 });
}

export function forbidden(message = 'Forbidden') {
  return json({ ok: false, error: 'forbidden', message }, { status: 403 });
}

export function notFound(message = 'Not found') {
  return json({ ok: false, error: 'not_found', message }, { status: 404 });
}

export function conflict(message = 'Conflict') {
  return json({ ok: false, error: 'conflict', message }, { status: 409 });
}

export function serverError(message = 'Server error') {
  return json({ ok: false, error: 'server_error', message }, { status: 500 });
}
