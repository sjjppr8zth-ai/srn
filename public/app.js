// Saran PWA (Cloudflare Pages + Functions + D1 + R2)
// Front-end: vanilla JS, offline-first (IndexedDB) + sync.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const API = {
  bootstrapStatus: () => fetchJSON('/api/bootstrap/status'),
  bootstrapInit: (payload) => fetchJSON('/api/bootstrap/init', { method: 'POST', body: JSON.stringify(payload) }),

  login: (username, password) => fetchJSON('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  me: () => fetchJSON('/api/auth/me'),
  logout: () => fetchJSON('/api/auth/logout', { method: 'POST' }),

  syncPull: (since) => fetchJSON(`/api/sync/pull?since=${encodeURIComponent(since || '1970-01-01T00:00:00.000Z')}`),
  syncPush: (changes) => fetchJSON('/api/sync/push', { method: 'POST', body: JSON.stringify({ changes }) }),

  // Admin
  adminUsers: () => fetchJSON('/api/admin/users'),
  adminUserGet: (username) => fetchJSON(`/api/admin/users/${encodeURIComponent(username)}`),
  adminUserUpdate: (username, payload) => fetchJSON(`/api/admin/users/${encodeURIComponent(username)}`, { method: 'PUT', body: JSON.stringify(payload) }),
  adminActivity: (limit = 200) => fetchJSON(`/api/admin/activity?limit=${limit}`),

  // Data (not required for sync, but useful)
  listProperties: (q = '') => fetchJSON(`/api/properties?q=${encodeURIComponent(q)}`),
  createProperty: (payload) => fetchJSON('/api/properties', { method: 'POST', body: JSON.stringify(payload) }),
  updateProperty: (id, payload) => fetchJSON(`/api/properties/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(payload) }),
  deleteProperty: (id) => fetchJSON(`/api/properties/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  listCustomers: (q = '') => fetchJSON(`/api/customers?q=${encodeURIComponent(q)}`),
  createCustomer: (payload) => fetchJSON('/api/customers', { method: 'POST', body: JSON.stringify(payload) }),
  updateCustomer: (id, payload) => fetchJSON(`/api/customers/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(payload) }),
  deleteCustomer: (id) => fetchJSON(`/api/customers/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  // Files
  filesList: (entity, entityId) => fetchJSON(`/api/files/list?entity=${encodeURIComponent(entity)}&entityId=${encodeURIComponent(entityId)}`),
  filesUpload: async (entity, entityId, file) => {
    const fd = new FormData();
    fd.append('entity', entity);
    fd.append('entityId', entityId);
    fd.append('file', file);
    return fetchJSON('/api/files/upload', { method: 'POST', body: fd, headers: {} });
  },
};

function toast(msg, type = 'ok', ms = 2800) {
  const el = $('#toast');
  el.textContent = msg;
  el.className = `toast ${type}`;
  el.classList.remove('hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add('hidden'), ms);
}

function setNetBadge() {
  const b = $('#netBadge');
  if (state.online) {
    b.textContent = 'آنلاین';
    b.className = 'badge ok';
  } else {
    b.textContent = 'آفلاین';
    b.className = 'badge offline';
  }
}

function isAdmin() { return state.user?.role === 'admin'; }
function isAccountant() { return state.user?.role === 'accountant'; }
function isStaff() { return state.user?.role === 'staff'; }
function canWriteProperties() { return isAdmin() || isAccountant(); }
function canDeleteProperties() { return isAdmin(); }
function canReadCustomers() { return isAdmin() || isAccountant(); }
function canWriteCustomers() { return isAdmin() || isAccountant(); }

// -----------------------
// IndexedDB (local cache)
// -----------------------
const DB_NAME = 'saran_local_v1';
const DB_VERSION = 1;

let _dbPromise = null;

function openDB() {
  if (_dbPromise) return _dbPromise;
  _dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta');
      if (!db.objectStoreNames.contains('properties')) db.createObjectStore('properties', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('customers')) db.createObjectStore('customers', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('pending')) db.createObjectStore('pending', { keyPath: 'key' });
      if (!db.objectStoreNames.contains('offlineAuth')) db.createObjectStore('offlineAuth', { keyPath: 'username' });
    };
    req.onsuccess = () => resolve(req.result);
  });
  return _dbPromise;
}

async function idbTx(storeNames, mode, fn) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeNames, mode);
    const stores = storeNames.map(n => tx.objectStore(n));
    Promise.resolve(fn(...stores, tx)).then(resolve).catch(reject);
    tx.onerror = () => reject(tx.error);
  });
}

async function idbGet(store, key) {
  return idbTx([store], 'readonly', (s) => new Promise((resolve, reject) => {
    const r = s.get(key);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  }));
}
async function idbPut(store, value, key = undefined) {
  return idbTx([store], 'readwrite', (s) => new Promise((resolve, reject) => {
    const r = (key === undefined) ? s.put(value) : s.put(value, key);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  }));
}
async function idbDelete(store, key) {
  return idbTx([store], 'readwrite', (s) => new Promise((resolve, reject) => {
    const r = s.delete(key);
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  }));
}
async function idbGetAll(store) {
  return idbTx([store], 'readonly', (s) => new Promise((resolve, reject) => {
    const r = s.getAll();
    r.onsuccess = () => resolve(r.result || []);
    r.onerror = () => reject(r.error);
  }));
}
async function idbClear(store) {
  return idbTx([store], 'readwrite', (s) => new Promise((resolve, reject) => {
    const r = s.clear();
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  }));
}

// -----------------------
// Offline auth (device)
// -----------------------
async function pbkdf2Hash(password, saltBytes, iterations = 120000) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' }, key, 256);
  return new Uint8Array(bits);
}
function randBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}
function b64(bytes) {
  let s = '';
  bytes.forEach(b => s += String.fromCharCode(b));
  return btoa(s);
}
function b64ToBytes(b64s) {
  const bin = atob(b64s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= a[i] ^ b[i];
  return v === 0;
}
async function storeOfflineAuth({ username, role, displayName }, password) {
  // Per-device offline verifier (doesn't require server)
  const salt = randBytes(16);
  const iters = 120000;
  const hash = await pbkdf2Hash(password, salt, iters);
  await idbPut('offlineAuth', {
    username,
    role,
    displayName,
    saltB64: b64(salt),
    hashB64: b64(hash),
    iters,
    updatedAt: new Date().toISOString(),
  });
}
async function verifyOfflineAuth(username, password) {
  const row = await idbGet('offlineAuth', username);
  if (!row) return null;
  const salt = b64ToBytes(row.saltB64);
  const hash = await pbkdf2Hash(password, salt, row.iters);
  const stored = b64ToBytes(row.hashB64);
  if (!timingSafeEqual(hash, stored)) return null;
  return { username: row.username, role: row.role, displayName: row.displayName };
}

// -----------------------
// API fetch with token
// -----------------------
async function fetchJSON(url, init = {}) {
  const headers = new Headers(init.headers || {});
  // If body is FormData, do not set content-type
  const isForm = init.body instanceof FormData;
  if (!isForm) headers.set('Content-Type', 'application/json');

  if (state.token) headers.set('Authorization', `Bearer ${state.token}`);

  const res = await fetch(url, { ...init, headers });
  let data = null;
  const ct = res.headers.get('Content-Type') || '';
  if (ct.includes('application/json')) {
    data = await res.json().catch(() => null);
  } else {
    data = await res.text().catch(() => null);
  }

  if (!res.ok) {
    const msg = data?.message || data?.error || `HTTP ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

// -----------------------
// Sync
// -----------------------
async function getLastSync() {
  return (await idbGet('meta', 'lastSync')) || '1970-01-01T00:00:00.000Z';
}
async function setLastSync(v) {
  await idbPut('meta', v, 'lastSync');
}

async function listPending() {
  const all = await idbGetAll('pending');
  // stable order: oldest first (clientUpdatedAt)
  return all.sort((a, b) => (a.clientUpdatedAt || '').localeCompare(b.clientUpdatedAt || ''));
}

async function upsertPending(entity, op, id, record) {
  const key = `${entity}:${id}`;
  const clientUpdatedAt = new Date().toISOString();
  await idbPut('pending', { key, entity, op, id, record, clientUpdatedAt });
}

async function removePending(entity, id) {
  const key = `${entity}:${id}`;
  await idbDelete('pending', key);
}

async function applyServerRecord(entity, rec) {
  if (entity === 'properties') {
    if (rec.deleted) {
      await idbDelete('properties', rec.id);
    } else {
      await idbPut('properties', rec);
    }
  }
  if (entity === 'customers') {
    if (rec.deleted) {
      await idbDelete('customers', rec.id);
    } else {
      await idbPut('customers', rec);
    }
  }
}

async function syncNow(showToast = true) {
  if (!state.user) return;
  if (!state.online) {
    if (showToast) toast('آفلاین هستید. همگام‌سازی انجام نشد.', 'warn');
    return;
  }
  if (!state.token) {
    if (showToast) toast('برای همگام‌سازی باید دوباره وارد شوید.', 'warn');
    return;
  }
  if (state.syncing) return;

  state.syncing = true;
  $('#btnSync').textContent = 'Sync...';

  try {
    const pending = await listPending();
    if (pending.length) {
      const changes = pending.map(p => ({
        entity: p.entity,
        op: p.op,
        record: p.record,
        clientUpdatedAt: p.clientUpdatedAt,
      }));
      const pushRes = await API.syncPush(changes);

      // Conflicts: overwrite local with server, drop pending for that id
      for (const c of (pushRes.conflicts || [])) {
        if (c.server) await applyServerRecord(c.entity, c.server);
        await removePending(c.entity, c.id);
      }
      // Rejected: drop (keep local but stop retry loop)
      for (const r of (pushRes.rejected || [])) {
        const ent = r?.ch?.entity;
        const id = r?.ch?.record?.id || r?.ch?.id;
        if (ent && id) await removePending(ent, id);
      }
    }

    const since = await getLastSync();
    const pullRes = await API.syncPull(since);

    for (const rec of (pullRes.properties || [])) await applyServerRecord('properties', rec);
    for (const rec of (pullRes.customers || [])) await applyServerRecord('customers', rec);

    await setLastSync(pullRes.serverNow || new Date().toISOString());

    if (showToast) {
      const c = (pending?.length || 0);
      toast(c ? 'همگام‌سازی انجام شد.' : 'به‌روز شد.', 'ok');
    }
    // Re-render current route if it is data dependent
    renderRoute();
  } catch (e) {
    console.error(e);
    if (showToast) toast(`خطا در Sync: ${e.message}`, 'danger', 3800);
  } finally {
    state.syncing = false;
    $('#btnSync').textContent = 'Sync';
  }
}

// -----------------------
// State & Routing
// -----------------------
const state = {
  initialized: null,
  orgName: 'Saran',
  user: null,
  token: localStorage.getItem('saran_token') || null,
  online: navigator.onLine,
  syncing: false,
};

window.addEventListener('online', () => { state.online = true; setNetBadge(); syncNow(false); });
window.addEventListener('offline', () => { state.online = false; setNetBadge(); });

$('#btnSync').addEventListener('click', () => syncNow(true));
$('#btnLogout').addEventListener('click', async () => {
  try { if (state.token) await API.logout(); } catch {}
  state.token = null;
  localStorage.removeItem('saran_token');
  state.user = null;
  $('#btnLogout').classList.add('hidden');
  toast('خارج شدید.', 'ok');
  location.hash = '#/login';
});

window.addEventListener('hashchange', () => renderRoute());

async function boot() {
  setNetBadge();

  // 1) Check bootstrap status
  try {
    const st = await API.bootstrapStatus();
    state.initialized = !!st.initialized;
    state.orgName = st.orgName || 'Saran';
    document.title = `${state.orgName} | مدیریت املاک`;
    $('.brand-title').textContent = state.orgName;
  } catch (e) {
    // If API not reachable, we can still show offline login (if cached users exist)
    state.initialized = true; // assume already
  }

  // 2) If we have token, validate it
  if (state.token && state.online) {
    try {
      const me = await API.me();
      state.user = me.user;
      $('#btnLogout').classList.remove('hidden');
      // If first time on this device, warm cache
      syncNow(false);
    } catch (e) {
      state.token = null;
      localStorage.removeItem('saran_token');
    }
  }

  // 3) Route
  if (!location.hash) {
    if (!state.initialized) location.hash = '#/setup';
    else if (!state.user) location.hash = '#/login';
    else location.hash = '#/properties';
  } else {
    renderRoute();
  }
}

function layoutNav() {
  if (!state.user) return '';
  const tabs = [];
  tabs.push({ href: '#/properties', label: 'املاک' });
  if (canReadCustomers()) tabs.push({ href: '#/customers', label: 'مشتریان' });
  if (isAdmin()) tabs.push({ href: '#/activity', label: 'گزارش فعالیت' });
  if (isAdmin()) tabs.push({ href: '#/settings', label: 'تنظیمات' });

  const active = location.hash.split('?')[0];

  return `
    <div class="tabs" style="margin-bottom:14px">
      ${tabs.map(t => `<a class="tab ${active === t.href ? 'active' : ''}" href="${t.href}">${t.label}</a>`).join('')}
    </div>
  `;
}

function renderRoute() {
  const app = $('#app');
  const hash = location.hash || '#/';
  const [path] = hash.replace(/^#/, '').split('?');

  // if not initialized => setup only
  if (state.initialized === false && path !== '/setup') {
    location.hash = '#/setup';
    return;
  }

  // if initialized and no user => login only
  const publicRoutes = ['/login', '/setup'];
  if (state.initialized !== false && !state.user && !publicRoutes.includes(path)) {
    location.hash = '#/login';
    return;
  }

  if (path === '/setup') { app.innerHTML = renderSetup(); bindSetup(); return; }
  if (path === '/login') { app.innerHTML = renderLogin(); bindLogin(); return; }

  // logged in routes
  $('#btnLogout').classList.toggle('hidden', !state.user);

  if (path === '/properties') { renderPropertiesPage(); return; }
  if (path === '/customers') { renderCustomersPage(); return; }
  if (path === '/settings') { renderSettingsPage(); return; }
  if (path === '/activity') { renderActivityPage(); return; }

  // default
  location.hash = '#/properties';
}

// -----------------------
// UI: Setup
// -----------------------
function renderSetup() {
  return `
    <div class="card">
      <div class="h1">راه‌اندازی اولیه</div>
      <p class="p">
        این سیستم فقط <b>یک‌بار</b> راه‌اندازی می‌شود.
        بعد از انجام، دیگر هیچ‌کس نمی‌تواند دوباره اکانت‌ها را از اول بسازد.
      </p>

      <div class="hr"></div>

      <div class="form">
        <div>
          <div class="label">نام مجموعه (نمایشی)</div>
          <input id="orgName" class="input" placeholder="Saran" value="${escapeHtml(state.orgName || 'Saran')}" />
        </div>

        <div class="grid two">
          <div class="card" style="box-shadow:none">
            <div class="h2">مدیر (admin)</div>
            <div class="label">رمز عبور مدیر (حداقل ۶ کاراکتر)</div>
            <input id="adminPassword" type="password" class="input" placeholder="اجباری" />
          </div>

          <div class="card" style="box-shadow:none">
            <div class="h2">حسابدار (accountant)</div>
            <div class="label">رمز عبور حسابدار</div>
            <input id="accountantPassword" type="password" class="input" placeholder="اختیاری (خالی = غیرفعال)" />
          </div>
        </div>

        <div class="grid two">
          <div class="card" style="box-shadow:none">
            <div class="h2">کارمندان (staff)</div>
            ${['1','2','3','4'].map(n => `
              <div style="margin-top:10px">
                <div class="label">رمز عبور staff${n}</div>
                <input id="staff${n}Password" type="password" class="input" placeholder="اختیاری (خالی = غیرفعال)" />
              </div>
            `).join('')}
          </div>

          <div class="card" style="box-shadow:none">
            <div class="h2">نکات امنیتی</div>
            <p class="p">
              رمزهای عبور را برای هر نفر جدا انتخاب کنید.
              این سیستم روی Cloudflare و D1 اجرا می‌شود و اطلاعات در یک پایگاه‌داده مرکزی ذخیره می‌شود.
              برای کار آفلاین هم روی دستگاه کش می‌شود.
            </p>
            <p class="p"><span class="kbd">admin</span> دسترسی کامل دارد. <span class="kbd">accountant</span> ویرایش املاک و مشتریان. <span class="kbd">staff</span> فقط مشاهده املاک.</p>
          </div>
        </div>

        <div class="row">
          <button id="btnInit" class="btn btn-primary">ایجاد سیستم و شروع</button>
          <div class="label">پس از راه‌اندازی، وارد حساب مدیر شوید.</div>
        </div>
      </div>
    </div>
  `;
}

function bindSetup() {
  $('#btnInit').addEventListener('click', async () => {
    const payload = {
      orgName: $('#orgName').value.trim() || 'Saran',
      adminPassword: $('#adminPassword').value,
      accountantPassword: $('#accountantPassword').value,
      staff1Password: $('#staff1Password').value,
      staff2Password: $('#staff2Password').value,
      staff3Password: $('#staff3Password').value,
      staff4Password: $('#staff4Password').value,
    };
    try {
      $('#btnInit').textContent = 'درحال ایجاد...';
      $('#btnInit').disabled = true;
      await API.bootstrapInit(payload);
      toast('سیستم ایجاد شد. اکنون وارد شوید.', 'ok');
      state.initialized = true;
      state.orgName = payload.orgName;
      location.hash = '#/login';
    } catch (e) {
      toast(e.message, 'danger', 3800);
    } finally {
      $('#btnInit').textContent = 'ایجاد سیستم و شروع';
      $('#btnInit').disabled = false;
    }
  });
}

// -----------------------
// UI: Login
// -----------------------
function renderLogin() {
  const offlineHint = state.online ? '' : `
    <p class="p">
      شما <b>آفلاین</b> هستید. اگر قبلاً همین دستگاه با این کاربر وارد شده باشد، امکان ورود آفلاین دارید.
    </p>
  `;

  return `
    <div class="card">
      <div class="h1">ورود</div>
      ${offlineHint}

      <div class="form">
        <div>
          <div class="label">نام کاربری</div>
          <select id="username" class="select">
            <option value="admin">admin (مدیر)</option>
            <option value="accountant">accountant (حسابدار)</option>
            <option value="staff1">staff1 (کارمند ۱)</option>
            <option value="staff2">staff2 (کارمند ۲)</option>
            <option value="staff3">staff3 (کارمند ۳)</option>
            <option value="staff4">staff4 (کارمند ۴)</option>
          </select>
        </div>
        <div>
          <div class="label">رمز عبور</div>
          <input id="password" type="password" class="input" placeholder="رمز عبور" />
        </div>

        <div class="row">
          <button id="btnLogin" class="btn btn-primary">ورود</button>
          <button id="btnClearLocal" class="btn btn-secondary" title="حذف کش داده‌های آفلاین (فقط دستگاه)">
            پاک کردن داده آفلاین
          </button>
        </div>

        <p class="p" style="margin-top:4px">
          اگر مشکل ورود/آپدیت داشتید، یکبار <b>پاک کردن داده آفلاین</b> را بزنید و سپس آنلاین وارد شوید تا دوباره کش ساخته شود.
        </p>
      </div>
    </div>
  `;
}

function bindLogin() {
  $('#btnLogin').addEventListener('click', async () => {
    const username = $('#username').value;
    const password = $('#password').value;

    if (!username || !password) { toast('نام کاربری و رمز عبور را وارد کنید.', 'warn'); return; }

    if (state.online) {
      // Online login
      try {
        $('#btnLogin').textContent = 'درحال ورود...';
        $('#btnLogin').disabled = true;

        const res = await API.login(username, password);
        state.token = res.token;
        localStorage.setItem('saran_token', res.token);

        // Fetch profile (or use res.user)
        state.user = res.user;

        // Cache offline verifier for this device
        await storeOfflineAuth(state.user, password);

        toast(`خوش آمدید ${state.user.displayName || state.user.username}`, 'ok');
        $('#btnLogout').classList.remove('hidden');

        // Sync in background
        syncNow(false);

        location.hash = '#/properties';
      } catch (e) {
        toast(e.message, 'danger', 3800);
      } finally {
        $('#btnLogin').textContent = 'ورود';
        $('#btnLogin').disabled = false;
      }
    } else {
      // Offline login (device-cached)
      const offlineUser = await verifyOfflineAuth(username, password);
      if (!offlineUser) {
        toast('ورود آفلاین ناموفق است. یکبار آنلاین وارد شوید تا این دستگاه شناخته شود.', 'warn', 4200);
        return;
      }
      state.user = offlineUser;
      state.token = null;
      localStorage.removeItem('saran_token');
      toast(`ورود آفلاین: ${offlineUser.displayName || offlineUser.username}`, 'ok');
      $('#btnLogout').classList.remove('hidden');
      location.hash = '#/properties';
    }
  });

  $('#btnClearLocal').addEventListener('click', async () => {
    if (!confirm('داده‌های آفلاین (املاک/مشتریان/صف Sync) از همین دستگاه پاک شود؟')) return;
    await idbClear('properties');
    await idbClear('customers');
    await idbClear('pending');
    await setLastSync('1970-01-01T00:00:00.000Z');
    toast('داده آفلاین پاک شد.', 'ok');
  });
}

// -----------------------
// UI: Properties
// -----------------------
async function renderPropertiesPage() {
  const app = $('#app');
  const list = await idbGetAll('properties');
  const pending = await listPending();
  const dirtyIds = new Set(pending.filter(p => p.entity === 'properties').map(p => p.record?.id || p.id));

  // sort: updated desc
  list.sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || ''));

  app.innerHTML = `
    ${layoutNav()}
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <div class="h1">املاک</div>
          <div class="label">کاربر: ${escapeHtml(state.user.displayName || state.user.username)} (${escapeHtml(state.user.role)})</div>
        </div>
        <div class="row">
          <input id="propSearch" class="input" style="min-width:240px" placeholder="جستجو..." />
          ${canWriteProperties() ? `<button id="btnPropNew" class="btn btn-primary">ثبت ملک</button>` : ''}
        </div>
      </div>

      <div class="hr"></div>

      <div style="overflow:auto">
        <table class="table">
          <thead>
            <tr>
              <th>عنوان</th>
              <th>آدرس</th>
              <th>قیمت</th>
              <th>وضعیت</th>
              <th>بروزرسانی</th>
              <th class="actions">عملیات</th>
            </tr>
          </thead>
          <tbody id="propTbody">
            ${list.map(p => renderPropRow(p, dirtyIds.has(p.id))).join('')}
          </tbody>
        </table>
      </div>

      ${list.length === 0 ? `<p class="p" style="margin-top:12px">هنوز ملکی ثبت نشده. (اگر آنلاین هستید، Sync را بزنید.)</p>` : ''}

      <div class="hr"></div>
      <div class="row">
        <div class="label">آیتم‌های در صف Sync: ${pending.length}</div>
        <div class="label">آخرین Sync: <span class="kbd" id="lastSyncLbl">...</span></div>
      </div>
    </div>
  `;

  $('#lastSyncLbl').textContent = (await getLastSync()).replace('T', ' ').replace('Z','');

  $('#propSearch').addEventListener('input', async (e) => {
    const q = e.target.value.trim().toLowerCase();
    const all = await idbGetAll('properties');
    all.sort((a,b)=> (b.updated_at || '').localeCompare(a.updated_at || ''));
    const filtered = q ? all.filter(p => (p.title||'').toLowerCase().includes(q) || (p.address||'').toLowerCase().includes(q) || (p.owner_name||'').toLowerCase().includes(q) || (p.owner_phone||'').toLowerCase().includes(q)) : all;
    $('#propTbody').innerHTML = filtered.map(p => renderPropRow(p, dirtyIds.has(p.id))).join('');
    bindPropRowActions();
  });

  if (canWriteProperties()) {
    $('#btnPropNew').addEventListener('click', () => openPropEditor(null));
  }

  bindPropRowActions();

  // auto-sync on first open if online and we have no data
  if (state.online && state.token && list.length === 0) syncNow(false);
}

function renderPropRow(p, dirty) {
  const price = (p.price ?? '').toString();
  const dt = (p.updated_at || p.created_at || '').replace('T',' ').replace('Z','').slice(0, 19);
  const badge = dirty ? ` <span class="kbd" title="در صف Sync">SYNC</span>` : '';
  return `
    <tr data-id="${escapeHtml(p.id)}">
      <td><b>${escapeHtml(p.title || '')}</b>${badge}<br><small>${escapeHtml(p.owner_name || '') || ''}${p.owner_phone ? ` • ${escapeHtml(p.owner_phone)}` : ''}</small></td>
      <td>${escapeHtml(p.address || '')}</td>
      <td>${escapeHtml(price)}</td>
      <td>${escapeHtml(p.status || '')}</td>
      <td><small>${escapeHtml(dt)}</small></td>
      <td class="actions">
        <button class="btn btn-secondary btnView">مشاهده</button>
        ${canWriteProperties() ? `<button class="btn btn-primary btnEdit">ویرایش</button>` : ''}
        ${canDeleteProperties() ? `<button class="btn btn-danger btnDel">حذف</button>` : ''}
      </td>
    </tr>
  `;
}

function bindPropRowActions() {
  $$('.btnView').forEach(btn => btn.onclick = (e) => {
    const id = e.target.closest('tr').dataset.id;
    openPropViewer(id);
  });
  $$('.btnEdit').forEach(btn => btn.onclick = (e) => {
    const id = e.target.closest('tr').dataset.id;
    openPropEditor(id);
  });
  $$('.btnDel').forEach(btn => btn.onclick = async (e) => {
    const id = e.target.closest('tr').dataset.id;
    if (!confirm('حذف شود؟')) return;
    await deletePropertyFlow(id);
  });
}

async function openPropViewer(id) {
  const rec = await idbGet('properties', id);
  if (!rec) return toast('ملک پیدا نشد.', 'warn');
  const files = (state.online && state.token) ? (await API.filesList('properties', id).catch(()=>({results:[]}))).results : [];

  showModal(`
    <div class="h1">مشاهده ملک</div>
    <div class="p"><b>${escapeHtml(rec.title)}</b></div>
    <div class="grid two">
      <div>
        <div class="label">آدرس</div>
        <div>${escapeHtml(rec.address || '-')}</div>
      </div>
      <div>
        <div class="label">قیمت</div>
        <div>${escapeHtml((rec.price ?? '-')+'')}</div>
      </div>
      <div>
        <div class="label">وضعیت</div>
        <div>${escapeHtml(rec.status || '-')}</div>
      </div>
      <div>
        <div class="label">مالک</div>
        <div>${escapeHtml(rec.owner_name || '-')}${rec.owner_phone ? ` • ${escapeHtml(rec.owner_phone)}` : ''}</div>
      </div>
    </div>
    <div class="hr"></div>
    <div>
      <div class="label">توضیحات</div>
      <div style="white-space:pre-wrap">${escapeHtml(rec.description || '')}</div>
    </div>

    <div class="hr"></div>

    <div>
      <div class="h2">فایل‌ها</div>
      ${state.online && state.token ? `
        <div class="row" style="margin-bottom:10px">
          ${canWriteProperties() ? `<input id="fileInput" type="file" class="input" /> <button id="btnUpload" class="btn btn-primary">آپلود</button>` : `<div class="label">آپلود فقط برای مدیر/حسابدار فعال است.</div>`}
        </div>
      ` : `<p class="p">برای مشاهده/آپلود فایل‌ها باید آنلاین و وارد شده باشید.</p>`}

      <div class="grid">
        ${files.length ? files.map(f => `
          <div class="card" style="box-shadow:none">
            <div class="row" style="justify-content:space-between">
              <div>
                <div><b>${escapeHtml(f.contentType || 'file')}</b></div>
                <div class="label">${escapeHtml(f.createdAt || '')}</div>
              </div>
              <a class="btn btn-secondary" href="${f.url}" target="_blank" rel="noopener">باز کردن</a>
            </div>
          </div>
        `).join('') : `<div class="label">فایلی ثبت نشده.</div>`}
      </div>
    </div>

    <div class="hr"></div>
    <div class="row">
      <button id="btnClose" class="btn btn-secondary">بستن</button>
      ${canWriteProperties() ? `<button id="btnEditHere" class="btn btn-primary">ویرایش</button>` : ''}
    </div>
  `);

  $('#btnClose').onclick = closeModal;
  if (canWriteProperties()) {
    $('#btnEditHere').onclick = () => { closeModal(); openPropEditor(id); };

    const btnUpload = $('#btnUpload');
    if (btnUpload) {
      btnUpload.onclick = async () => {
        const fi = $('#fileInput');
        const file = fi.files?.[0];
        if (!file) return toast('فایل را انتخاب کنید.', 'warn');
        try {
          btnUpload.disabled = true;
          btnUpload.textContent = 'آپلود...';
          await API.filesUpload('properties', id, file);
          toast('آپلود شد.', 'ok');
          closeModal();
          openPropViewer(id);
        } catch (e) {
          toast(e.message, 'danger', 3800);
        } finally {
          btnUpload.disabled = false;
          btnUpload.textContent = 'آپلود';
        }
      };
    }
  }
}

async function openPropEditor(id) {
  const rec = id ? await idbGet('properties', id) : {
    id: crypto.randomUUID(),
    title: '',
    address: '',
    price: '',
    status: '',
    owner_name: '',
    owner_phone: '',
    description: '',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    deleted: 0,
    version: 0,
  };

  showModal(`
    <div class="h1">${id ? 'ویرایش ملک' : 'ثبت ملک'}</div>
    <div class="form">
      <div>
        <div class="label">عنوان</div>
        <input id="pTitle" class="input" value="${escapeAttr(rec.title || '')}" />
      </div>
      <div>
        <div class="label">آدرس</div>
        <input id="pAddress" class="input" value="${escapeAttr(rec.address || '')}" />
      </div>
      <div class="grid two">
        <div>
          <div class="label">قیمت</div>
          <input id="pPrice" class="input" inputmode="numeric" value="${escapeAttr((rec.price ?? '')+'')}" />
        </div>
        <div>
          <div class="label">وضعیت</div>
          <input id="pStatus" class="input" placeholder="مثلا: فعال / فروخته شد" value="${escapeAttr(rec.status || '')}" />
        </div>
      </div>
      <div class="grid two">
        <div>
          <div class="label">نام مالک</div>
          <input id="pOwner" class="input" value="${escapeAttr(rec.owner_name || '')}" />
        </div>
        <div>
          <div class="label">تلفن مالک</div>
          <input id="pPhone" class="input" inputmode="tel" value="${escapeAttr(rec.owner_phone || '')}" />
        </div>
      </div>
      <div>
        <div class="label">توضیحات</div>
        <textarea id="pDesc" class="textarea">${escapeHtml(rec.description || '')}</textarea>
      </div>

      <div class="row">
        <button id="btnSaveProp" class="btn btn-primary">ذخیره</button>
        <button id="btnCancel" class="btn btn-secondary">انصراف</button>
      </div>

      <p class="p" style="margin-top:6px">
        اگر آفلاین باشید، تغییرات در صف Sync می‌ماند و بعداً ارسال می‌شود.
      </p>
    </div>
  `);

  $('#btnCancel').onclick = closeModal;

  $('#btnSaveProp').onclick = async () => {
    const updated = {
      ...rec,
      title: $('#pTitle').value.trim(),
      address: $('#pAddress').value.trim() || null,
      price: $('#pPrice').value.trim() ? Number($('#pPrice').value.trim()) : null,
      status: $('#pStatus').value.trim() || null,
      owner_name: $('#pOwner').value.trim() || null,
      owner_phone: $('#pPhone').value.trim() || null,
      description: $('#pDesc').value.trim() || null,
      updated_at: new Date().toISOString(),
    };

    if (!updated.title) { toast('عنوان الزامی است.', 'warn'); return; }

    // save local immediately
    await idbPut('properties', updated);

    // queue for sync
    if (state.token) {
      await upsertPending('properties', 'upsert', updated.id, updated);
    }

    toast('ذخیره شد.', 'ok');
    closeModal();
    renderPropertiesPage();
    syncNow(false);
  };
}

async function deletePropertyFlow(id) {
  // local delete (staff can't reach here)
  await idbDelete('properties', id);
  if (state.token) {
    await upsertPending('properties', 'delete', id, { id, updated_at: new Date().toISOString() });
  }
  toast('حذف شد.', 'ok');
  renderPropertiesPage();
  syncNow(false);
}

// -----------------------
// UI: Customers
// -----------------------
async function renderCustomersPage() {
  if (!canReadCustomers()) {
    $('#app').innerHTML = `${layoutNav()}<div class="card"><div class="h1">مشتریان</div><p class="p">شما دسترسی ندارید.</p></div>`;
    return;
  }
  const app = $('#app');
  const list = await idbGetAll('customers');
  const pending = await listPending();
  const dirtyIds = new Set(pending.filter(p => p.entity === 'customers').map(p => p.record?.id || p.id));
  list.sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || ''));

  app.innerHTML = `
    ${layoutNav()}
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <div class="h1">مشتریان</div>
          <div class="label">کاربر: ${escapeHtml(state.user.displayName || state.user.username)}</div>
        </div>
        <div class="row">
          <input id="custSearch" class="input" style="min-width:240px" placeholder="جستجو..." />
          ${canWriteCustomers() ? `<button id="btnCustNew" class="btn btn-primary">ثبت مشتری</button>` : ''}
        </div>
      </div>

      <div class="hr"></div>

      <div style="overflow:auto">
        <table class="table">
          <thead>
            <tr>
              <th>نام</th>
              <th>تلفن</th>
              <th>یادداشت</th>
              <th>بروزرسانی</th>
              <th class="actions">عملیات</th>
            </tr>
          </thead>
          <tbody id="custTbody">
            ${list.map(c => renderCustRow(c, dirtyIds.has(c.id))).join('')}
          </tbody>
        </table>
      </div>

      ${list.length === 0 ? `<p class="p" style="margin-top:12px">هنوز مشتری ثبت نشده. (اگر آنلاین هستید، Sync را بزنید.)</p>` : ''}

      <div class="hr"></div>
      <div class="row">
        <div class="label">آیتم‌های در صف Sync: ${pending.length}</div>
      </div>
    </div>
  `;

  $('#custSearch').addEventListener('input', async (e) => {
    const q = e.target.value.trim().toLowerCase();
    const all = await idbGetAll('customers');
    all.sort((a,b)=> (b.updated_at || '').localeCompare(a.updated_at || ''));
    const filtered = q ? all.filter(c => (c.name||'').toLowerCase().includes(q) || (c.phone||'').toLowerCase().includes(q) || (c.notes||'').toLowerCase().includes(q)) : all;
    $('#custTbody').innerHTML = filtered.map(c => renderCustRow(c, dirtyIds.has(c.id))).join('');
    bindCustRowActions();
  });

  if (canWriteCustomers()) {
    $('#btnCustNew').addEventListener('click', () => openCustEditor(null));
  }
  bindCustRowActions();

  if (state.online && state.token && list.length === 0) syncNow(false);
}

function renderCustRow(c, dirty) {
  const dt = (c.updated_at || c.created_at || '').replace('T',' ').replace('Z','').slice(0, 19);
  const badge = dirty ? ` <span class="kbd" title="در صف Sync">SYNC</span>` : '';
  return `
    <tr data-id="${escapeHtml(c.id)}">
      <td><b>${escapeHtml(c.name || '')}</b>${badge}</td>
      <td>${escapeHtml(c.phone || '')}</td>
      <td><small>${escapeHtml(c.notes || '')}</small></td>
      <td><small>${escapeHtml(dt)}</small></td>
      <td class="actions">
        <button class="btn btn-secondary btnViewC">مشاهده</button>
        ${canWriteCustomers() ? `<button class="btn btn-primary btnEditC">ویرایش</button>` : ''}
        ${isAdmin() ? `<button class="btn btn-danger btnDelC">حذف</button>` : ''}
      </td>
    </tr>
  `;
}

function bindCustRowActions() {
  $$('.btnViewC').forEach(btn => btn.onclick = (e) => {
    const id = e.target.closest('tr').dataset.id;
    openCustViewer(id);
  });
  $$('.btnEditC').forEach(btn => btn.onclick = (e) => {
    const id = e.target.closest('tr').dataset.id;
    openCustEditor(id);
  });
  $$('.btnDelC').forEach(btn => btn.onclick = async (e) => {
    const id = e.target.closest('tr').dataset.id;
    if (!confirm('حذف شود؟')) return;
    await deleteCustomerFlow(id);
  });
}

async function openCustViewer(id) {
  const rec = await idbGet('customers', id);
  if (!rec) return toast('مشتری پیدا نشد.', 'warn');

  const files = (state.online && state.token) ? (await API.filesList('customers', id).catch(()=>({results:[]}))).results : [];

  showModal(`
    <div class="h1">مشاهده مشتری</div>
    <div class="p"><b>${escapeHtml(rec.name)}</b></div>
    <div class="grid two">
      <div>
        <div class="label">تلفن</div>
        <div>${escapeHtml(rec.phone || '-')}</div>
      </div>
      <div>
        <div class="label">بروزرسانی</div>
        <div>${escapeHtml((rec.updated_at || rec.created_at || '').replace('T',' ').slice(0,19))}</div>
      </div>
    </div>
    <div class="hr"></div>
    <div>
      <div class="label">یادداشت</div>
      <div style="white-space:pre-wrap">${escapeHtml(rec.notes || '')}</div>
    </div>

    <div class="hr"></div>

    <div>
      <div class="h2">فایل‌ها</div>
      ${state.online && state.token ? `
        <div class="row" style="margin-bottom:10px">
          ${canWriteCustomers() ? `<input id="fileInput" type="file" class="input" /> <button id="btnUpload" class="btn btn-primary">آپلود</button>` : `<div class="label">آپلود فقط برای مدیر/حسابدار فعال است.</div>`}
        </div>
      ` : `<p class="p">برای مشاهده/آپلود فایل‌ها باید آنلاین و وارد شده باشید.</p>`}

      <div class="grid">
        ${files.length ? files.map(f => `
          <div class="card" style="box-shadow:none">
            <div class="row" style="justify-content:space-between">
              <div>
                <div><b>${escapeHtml(f.contentType || 'file')}</b></div>
                <div class="label">${escapeHtml(f.createdAt || '')}</div>
              </div>
              <a class="btn btn-secondary" href="${f.url}" target="_blank" rel="noopener">باز کردن</a>
            </div>
          </div>
        `).join('') : `<div class="label">فایلی ثبت نشده.</div>`}
      </div>
    </div>

    <div class="hr"></div>
    <div class="row">
      <button id="btnClose" class="btn btn-secondary">بستن</button>
      ${canWriteCustomers() ? `<button id="btnEditHere" class="btn btn-primary">ویرایش</button>` : ''}
    </div>
  `);

  $('#btnClose').onclick = closeModal;
  if (canWriteCustomers()) {
    $('#btnEditHere').onclick = () => { closeModal(); openCustEditor(id); };

    const btnUpload = $('#btnUpload');
    if (btnUpload) {
      btnUpload.onclick = async () => {
        const fi = $('#fileInput');
        const file = fi.files?.[0];
        if (!file) return toast('فایل را انتخاب کنید.', 'warn');
        try {
          btnUpload.disabled = true;
          btnUpload.textContent = 'آپلود...';
          await API.filesUpload('customers', id, file);
          toast('آپلود شد.', 'ok');
          closeModal();
          openCustViewer(id);
        } catch (e) {
          toast(e.message, 'danger', 3800);
        } finally {
          btnUpload.disabled = false;
          btnUpload.textContent = 'آپلود';
        }
      };
    }
  }
}

async function openCustEditor(id) {
  const rec = id ? await idbGet('customers', id) : {
    id: crypto.randomUUID(),
    name: '',
    phone: '',
    notes: '',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    deleted: 0,
    version: 0,
  };

  showModal(`
    <div class="h1">${id ? 'ویرایش مشتری' : 'ثبت مشتری'}</div>
    <div class="form">
      <div>
        <div class="label">نام</div>
        <input id="cName" class="input" value="${escapeAttr(rec.name || '')}" />
      </div>
      <div>
        <div class="label">تلفن</div>
        <input id="cPhone" class="input" inputmode="tel" value="${escapeAttr(rec.phone || '')}" />
      </div>
      <div>
        <div class="label">یادداشت</div>
        <textarea id="cNotes" class="textarea">${escapeHtml(rec.notes || '')}</textarea>
      </div>

      <div class="row">
        <button id="btnSaveCust" class="btn btn-primary">ذخیره</button>
        <button id="btnCancel" class="btn btn-secondary">انصراف</button>
      </div>
    </div>
  `);

  $('#btnCancel').onclick = closeModal;

  $('#btnSaveCust').onclick = async () => {
    const updated = {
      ...rec,
      name: $('#cName').value.trim(),
      phone: $('#cPhone').value.trim() || null,
      notes: $('#cNotes').value.trim() || null,
      updated_at: new Date().toISOString(),
    };
    if (!updated.name) { toast('نام الزامی است.', 'warn'); return; }

    await idbPut('customers', updated);
    if (state.token) await upsertPending('customers', 'upsert', updated.id, updated);

    toast('ذخیره شد.', 'ok');
    closeModal();
    renderCustomersPage();
    syncNow(false);
  };
}

async function deleteCustomerFlow(id) {
  await idbDelete('customers', id);
  if (state.token) await upsertPending('customers', 'delete', id, { id, updated_at: new Date().toISOString() });
  toast('حذف شد.', 'ok');
  renderCustomersPage();
  syncNow(false);
}

// -----------------------
// UI: Settings (Admin)
// -----------------------
async function renderSettingsPage() {
  const app = $('#app');
  if (!isAdmin()) {
    app.innerHTML = `${layoutNav()}<div class="card"><div class="h1">تنظیمات</div><p class="p">فقط مدیر دسترسی دارد.</p></div>`;
    return;
  }

  app.innerHTML = `
    ${layoutNav()}
    <div class="card">
      <div class="h1">تنظیمات مدیر</div>
      <p class="p">مدیریت کاربران، فعال/غیرفعال کردن و تغییر رمز عبور.</p>

      <div class="hr"></div>

      <div class="row">
        <button id="btnReloadUsers" class="btn btn-secondary">بارگذاری کاربران</button>
      </div>

      <div style="margin-top:12px; overflow:auto">
        <table class="table">
          <thead>
            <tr>
              <th>نام کاربری</th>
              <th>نقش</th>
              <th>نام نمایشی</th>
              <th>فعال</th>
              <th class="actions">عملیات</th>
            </tr>
          </thead>
          <tbody id="usersTbody">
            <tr><td colspan="5"><small>برای مشاهده، «بارگذاری کاربران» را بزنید.</small></td></tr>
          </tbody>
        </table>
      </div>

      <div class="hr"></div>

      <p class="p">
        نکته: اگر کسی رمز عبور را خالی بگذارد، آن حساب غیرفعال می‌شود.
      </p>
    </div>
  `;

  $('#btnReloadUsers').onclick = async () => {
    if (!state.online || !state.token) return toast('برای این بخش باید آنلاین و وارد باشید.', 'warn');
    try {
      const res = await API.adminUsers();
      $('#usersTbody').innerHTML = (res.results || []).map(u => `
        <tr data-username="${escapeHtml(u.username)}">
          <td><b>${escapeHtml(u.username)}</b></td>
          <td>${escapeHtml(u.role)}</td>
          <td>${escapeHtml(u.display_name)}</td>
          <td>${u.active ? '✅' : '⛔️'}</td>
          <td class="actions">
            <button class="btn btn-primary btnEditUser">ویرایش</button>
          </td>
        </tr>
      `).join('');

      $$('.btnEditUser').forEach(btn => btn.onclick = async (e) => {
        const username = e.target.closest('tr').dataset.username;
        openUserEditor(username);
      });
    } catch (e) {
      toast(e.message, 'danger', 3800);
    }
  };
}

async function openUserEditor(username) {
  if (!state.online || !state.token) return toast('آنلاین نیستید.', 'warn');

  const u = (await API.adminUserGet(username)).user;

  showModal(`
    <div class="h1">ویرایش کاربر: ${escapeHtml(u.username)}</div>
    <div class="form">
      <div>
        <div class="label">نام نمایشی</div>
        <input id="uDisplayName" class="input" value="${escapeAttr(u.displayName)}" />
      </div>
      <div class="grid two">
        <div>
          <div class="label">فعال / غیرفعال</div>
          <select id="uActive" class="select">
            <option value="1" ${u.active ? 'selected' : ''}>فعال</option>
            <option value="0" ${!u.active ? 'selected' : ''}>غیرفعال</option>
          </select>
        </div>
        <div>
          <div class="label">رمز عبور جدید</div>
          <input id="uPassword" type="password" class="input" placeholder="خالی = غیرفعال کردن حساب" />
        </div>
      </div>

      <div class="row">
        <button id="btnSaveUser" class="btn btn-primary">ذخیره</button>
        <button id="btnCancel" class="btn btn-secondary">انصراف</button>
      </div>
      <p class="p">اگر رمز عبور را خالی بگذارید، سیستم آن حساب را غیرفعال می‌کند.</p>
    </div>
  `);

  $('#btnCancel').onclick = closeModal;

  $('#btnSaveUser').onclick = async () => {
    const payload = {
      displayName: $('#uDisplayName').value.trim(),
      active: $('#uActive').value === '1',
    };
    const pass = $('#uPassword').value;
    if (pass !== '') payload.password = pass; // empty means disable
    try {
      $('#btnSaveUser').disabled = true;
      $('#btnSaveUser').textContent = 'ذخیره...';
      await API.adminUserUpdate(username, payload);
      toast('ذخیره شد.', 'ok');
      closeModal();
      renderSettingsPage();
    } catch (e) {
      toast(e.message, 'danger', 3800);
    } finally {
      $('#btnSaveUser').disabled = false;
      $('#btnSaveUser').textContent = 'ذخیره';
    }
  };
}

// -----------------------
// UI: Activity (Admin)
// -----------------------
async function renderActivityPage() {
  const app = $('#app');
  if (!isAdmin()) {
    app.innerHTML = `${layoutNav()}<div class="card"><div class="h1">گزارش فعالیت</div><p class="p">فقط مدیر دسترسی دارد.</p></div>`;
    return;
  }
  if (!state.online || !state.token) {
    app.innerHTML = `${layoutNav()}<div class="card"><div class="h1">گزارش فعالیت</div><p class="p">برای دیدن گزارش باید آنلاین باشید.</p></div>`;
    return;
  }

  app.innerHTML = `
    ${layoutNav()}
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <div class="h1">گزارش فعالیت</div>
          <div class="label">آخرین ۲۰۰ رویداد</div>
        </div>
        <button id="btnReloadLog" class="btn btn-secondary">بارگذاری</button>
      </div>

      <div class="hr"></div>

      <div style="overflow:auto">
        <table class="table">
          <thead>
            <tr>
              <th>زمان</th>
              <th>کاربر</th>
              <th>عملیات</th>
              <th>جزئیات</th>
            </tr>
          </thead>
          <tbody id="logTbody">
            <tr><td colspan="4"><small>برای مشاهده، «بارگذاری» را بزنید.</small></td></tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  $('#btnReloadLog').onclick = async () => {
    try {
      const res = await API.adminActivity(200);
      $('#logTbody').innerHTML = (res.results || []).map(r => `
        <tr>
          <td><small>${escapeHtml((r.ts || '').replace('T',' ').slice(0,19))}</small></td>
          <td>${escapeHtml(r.display_name || r.username || '-')}</td>
          <td><b>${escapeHtml(r.action || '')}</b><br><small>${escapeHtml(r.entity || '')}${r.entity_id ? ` • ${escapeHtml(r.entity_id)}` : ''}</small></td>
          <td><small>${escapeHtml(r.detail || '')}</small></td>
        </tr>
      `).join('');
    } catch (e) {
      toast(e.message, 'danger', 3800);
    }
  };
}

// -----------------------
// Simple modal
// -----------------------
let modalEl = null;
function showModal(innerHtml) {
  closeModal();
  modalEl = document.createElement('div');
  modalEl.style.position = 'fixed';
  modalEl.style.inset = '0';
  modalEl.style.zIndex = '80';
  modalEl.style.background = 'rgba(0,0,0,0.55)';
  modalEl.style.backdropFilter = 'blur(10px)';
  modalEl.style.webkitBackdropFilter = 'blur(10px)';
  modalEl.innerHTML = `
    <div style="max-width:860px;margin:30px auto; padding:0 14px;">
      <div class="card" style="box-shadow: var(--shadow)">${innerHtml}</div>
    </div>
  `;
  modalEl.addEventListener('click', (e) => {
    if (e.target === modalEl) closeModal();
  });
  document.body.appendChild(modalEl);
}
function closeModal() {
  if (modalEl) modalEl.remove();
  modalEl = null;
}

// -----------------------
// Utils
// -----------------------
function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
function escapeAttr(s) {
  return escapeHtml(s).replace(/`/g, '&#096;');
}

// Start
boot();
