const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const multer = require('multer');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });
const port = Number(process.env.PORT || 10000);
const sessionTtl = Number(process.env.SESSION_TTL_SECONDS || 172800);
const sessions = new Map();
const adminSessions = new Map();
const state = new Map();
const claimedWorkers = new Map();
const startedAt = new Date().toISOString();

app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false, limit: '2mb' }));
app.use(express.json({ limit: '2mb' }));
app.use((req, _res, next) => {
  if (req.url.startsWith('//')) req.url = req.url.replace(/^\/+/, '/');
  next();
});

function clean(value) { return String(value ?? '').trim(); }
function nowSeconds() { return Math.floor(Date.now() / 1000); }
function json(res, body, status = 200) { return res.status(status).type('application/json').send(JSON.stringify(body)); }
function error(res, message, status = 400) { return json(res, { status: false, success: false, message }, status); }
function cookieValue(req, name) {
  const header = req.get('Cookie') || '';
  const match = header.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : '';
}
function adminOk(req) { return adminSessions.has(cookieValue(req, 'bs_admin')); }
function supabaseConfigured() { return Boolean(clean(process.env.SUPABASE_URL) && clean(process.env.SUPABASE_SERVICE_ROLE_KEY)); }
async function supabaseRequest(pathname, options = {}) {
  if (!supabaseConfigured()) throw new Error('Supabase is not configured');
  const response = await fetch(`${clean(process.env.SUPABASE_URL).replace(/\/$/, '')}/rest/v1/${pathname}`, {
    ...options,
    headers: {
      apikey: clean(process.env.SUPABASE_SERVICE_ROLE_KEY),
      Authorization: `Bearer ${clean(process.env.SUPABASE_SERVICE_ROLE_KEY)}`,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch (_) { body = { raw: text.slice(0, 200) }; }
  if (!response.ok) throw new Error(`Supabase HTTP ${response.status}`);
  return body;
}
function safeLicense(row) {
  return { id: row.id, license_key: row.license_key, device_id: row.device_id || '', expires_at: row.expires_at, active: Boolean(row.active), notes: row.notes || '', last_used_at: row.last_used_at || null, created_at: row.created_at || null };
}

function configuredLicenses() {
  return clean(process.env.LICENSE_KEYS).split(',').map((entry) => entry.trim()).filter(Boolean).map((entry) => {
    const separator = entry.indexOf(':');
    const key = separator >= 0 ? entry.slice(0, separator) : entry;
    const expiry = separator >= 0 ? entry.slice(separator + 1) : '';
    return { key: clean(key).toLowerCase(), expiry: clean(expiry) || '2099-12-31T23:59:59.000Z' };
  });
}

async function findLicense(key) {
  const normalized = clean(key).toLowerCase();
  if (supabaseConfigured()) {
    const rows = await supabaseRequest(`bs_licenses?select=*&license_key=eq.${encodeURIComponent(normalized.toUpperCase())}&limit=1`);
    const item = Array.isArray(rows) ? rows[0] : null;
    if (!item) return null;
    const expires = Date.parse(item.expires_at);
    return { key: item.license_key.toLowerCase(), expiry: item.expires_at, expired: !item.active || !Number.isFinite(expires) || expires <= Date.now(), deviceId: item.device_id || '', row: item };
  }
  const item = configuredLicenses().find((candidate) => candidate.key === normalized);
  if (!item) return null;
  const expires = Date.parse(item.expiry);
  if (!Number.isFinite(expires) || expires <= Date.now()) return { ...item, expired: true };
  return { ...item, expired: false };
}

function tokenFor(key, deviceId) {
  return crypto.createHmac('sha256', process.env.SESSION_SECRET || 'change-me-before-production')
    .update(`${key}\n${deviceId}\n${crypto.randomUUID()}`)
    .digest('hex');
}

function sessionFor(token) {
  const value = sessions.get(clean(token));
  if (!value || value.expiresAt <= Date.now()) {
    if (value) sessions.delete(clean(token));
    return null;
  }
  return value;
}

function endpointName(url) {
  const noQuery = clean(url).replaceAll('\\', '/').split('?')[0];
  return noQuery.slice(noQuery.lastIndexOf('/') + 1).trim();
}

function signatureMessage(method, endpoint, ts, nonce, license, deviceId) {
  return `${clean(method).toUpperCase()}\n${endpointName(endpoint)}\n${clean(ts)}\n${clean(nonce)}\n${clean(license).toLowerCase()}\n${clean(deviceId)}\n`;
}

function verifyAuth(req, endpoint) {
  const token = clean(req.get('X-NR-Token') || req.get('Authorization')?.replace(/^Bearer\s+/i, '') || req.body?.token);
  const license = clean(req.get('X-NR-License-Key') || req.body?.license_key);
  const deviceId = clean(req.get('X-NR-Device-Id') || req.body?.device_id);
  const ts = clean(req.get('X-NR-Timestamp') || req.body?.ts);
  const nonce = clean(req.get('X-NR-Nonce') || req.body?.nonce);
  const signature = clean(req.get('X-NR-Signature') || req.body?.signature);
  const session = sessionFor(token);
  if (!session || session.licenseKey !== license.toLowerCase() || session.deviceId !== deviceId) return { ok: false, message: 'Invalid or expired session' };
  if (!/^\d+$/.test(ts) || Math.abs(nowSeconds() - Number(ts)) > 300) return { ok: false, message: 'Request timestamp expired' };
  if (!nonce || !/^[a-f0-9]{16,128}$/i.test(nonce)) return { ok: false, message: 'Invalid request nonce' };
  const expected = crypto.createHmac('sha256', token).update(signatureMessage(req.method, endpoint, ts, nonce, license, deviceId)).digest('hex');
  const provided = Buffer.from(signature.toLowerCase());
  const expectedBuffer = Buffer.from(expected);
  if (!signature || provided.length !== expectedBuffer.length || !crypto.timingSafeEqual(expectedBuffer, provided)) return { ok: false, message: 'Invalid request signature' };
  return { ok: true, session };
}

function authOrError(req, res, endpoint) {
  const result = verifyAuth(req, endpoint);
  if (!result.ok) { error(res, result.message, 401); return null; }
  return result.session;
}

function deviceState(deviceId) {
  if (!state.has(deviceId)) state.set(deviceId, { logs: [], job: { status: 'idle', worker_limit: 0, join_delay_ms: 0, tick_delay_ms: 0, cursor: 0, cycle: 0, processed_count: 0, success_count: 0, error_count: 0, last_account: '', last_message: '', last_tick_at: '' }, workers: [], master_ready: false, account_count: 0 });
  return state.get(deviceId);
}
function result(s, message = 'OK') {
  return { status: true, success: true, message, account_count: s.account_count, prepared_count: s.workers.length, master_ready: s.master_ready, master_clan_id: '', master_uploaded_at: '', job: s.job, logs: s.logs.slice(-180), workers: s.workers };
}
function addLog(s, message) { s.logs.push(`${new Date().toISOString()} ${message}`); s.logs = s.logs.slice(-500); s.job.last_message = message; }

function workerPool() {
  const raw = clean(process.env.WORKER_POOL_JSON);
  if (!raw) {
    console.warn('WORKER_POOL_JSON is empty');
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (_) {
    console.warn('WORKER_POOL_JSON is not valid JSON');
    return [];
  }

  const workers = Array.isArray(parsed)
    ? parsed
    : parsed && Array.isArray(parsed.workers)
      ? parsed.workers
      : null;

  if (!workers) {
    console.warn('WORKER_POOL_JSON must be an array or an object containing workers[]');
    return [];
  }

  const seenIds = new Set();
  const seenCities = new Set();
  const validWorkers = [];

  for (const worker of workers) {
    if (!worker || typeof worker !== 'object' || Array.isArray(worker)) continue;

    const workerId = clean(worker.worker_id);
    const cityId = clean(worker.city_id);
    if (!workerId || !cityId) {
      console.warn('Ignoring worker with missing worker_id or city_id');
      continue;
    }

    if (seenIds.has(workerId)) {
      console.warn('Ignoring duplicate worker_id');
      continue;
    }

    if (seenCities.has(cityId)) {
      console.warn('Ignoring duplicate city_id');
      continue;
    }

    seenIds.add(workerId);
    seenCities.add(cityId);
    validWorkers.push(worker);
  }

  console.log(`Loaded ${validWorkers.length} worker(s) from WORKER_POOL_JSON`);
  return validWorkers;
}

app.get('/healthz', (_req, res) => json(res, { ok: true, service: 'bs-server', started_at: startedAt, uptime_seconds: Math.floor(process.uptime()) }));
app.get('/', (_req, res) => json(res, { service: 'bs-server', api: 'Dyluc Auto Regata compatible', health: '/healthz' }));

const adminPage = `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BS License Admin</title><style>body{font-family:Arial,sans-serif;background:#101827;color:#eef2ff;margin:0;padding:24px}main{max-width:1000px;margin:auto}section{background:#182338;border:1px solid #2d3b57;border-radius:14px;padding:18px;margin:14px 0}input,button{font:inherit;border-radius:9px;padding:10px;margin:4px;border:1px solid #425273}input{background:#0f1727;color:#fff}button{background:#2563eb;color:white;cursor:pointer}button.danger{background:#b91c1c}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #33415d;text-align:right;font-size:14px}.muted{color:#9fb0ca}.hidden{display:none}.msg{padding:10px;color:#fbbf24}</style></head><body><main><h1>إدارة تراخيص BS</h1><section id="login"><p class="muted">أدخل كلمة مرور الإدارة.</p><input id="password" type="password" placeholder="كلمة المرور"><button onclick="login()">دخول</button><div id="loginMsg" class="msg"></div></section><section id="panel" class="hidden"><div><button onclick="loadLicenses()">تحديث</button><button class="danger" onclick="logout()">خروج</button></div><h2>إضافة ترخيص</h2><input id="key" placeholder="BS-XXXXXX"><input id="expires" type="datetime-local"><input id="device" placeholder="Device ID اختياري"><input id="notes" placeholder="ملاحظات"><button onclick="createLicense()">إضافة</button><div id="msg" class="msg"></div><h2>التراخيص</h2><table><thead><tr><th>الترخيص</th><th>الجهاز</th><th>الانتهاء</th><th>الحالة</th><th>إجراء</th></tr></thead><tbody id="rows"></tbody></table></section></main><script>const $=id=>document.getElementById(id);async function api(url,opt={}){const r=await fetch(url,{credentials:'same-origin',...opt,headers:{'Content-Type':'application/json',...(opt.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.message||'فشل الطلب');return d}function show(m){$('msg').textContent=m}async function login(){try{await api('/admin/api/login',{method:'POST',body:JSON.stringify({password:$('password').value})});$('login').classList.add('hidden');$('panel').classList.remove('hidden');loadLicenses()}catch(e){$('loginMsg').textContent=e.message}}async function logout(){await api('/admin/api/logout',{method:'POST'});location.reload()}async function loadLicenses(){try{const d=await api('/admin/api/licenses');$('rows').innerHTML='';for(const x of d.licenses){const tr=document.createElement('tr');const vals=[x.license_key,x.device_id||'-',new Date(x.expires_at).toLocaleString(),x.active?'فعال':'متوقف'];for(const v of vals){const td=document.createElement('td');td.textContent=v;tr.appendChild(td)}const td=document.createElement('td');const b=document.createElement('button');b.textContent=x.active?'تعطيل':'تفعيل';b.onclick=()=>toggle(x.id,!x.active);td.appendChild(b);const del=document.createElement('button');del.textContent='حذف';del.className='danger';del.onclick=()=>removeLicense(x.id);td.appendChild(del);tr.appendChild(td);$('rows').appendChild(tr)}}catch(e){show(e.message)}}async function createLicense(){try{let key=$('key').value.trim().toUpperCase();if(!key)key='BS-'+crypto.randomUUID().replaceAll('-','').slice(0,12).toUpperCase();if(!/^BS-[A-Z0-9]+$/.test(key))throw Error('الترخيص يجب أن يبدأ بـ BS-');const exp=$('expires').value?new Date($('expires').value).toISOString():'2099-12-31T23:59:59.000Z';await api('/admin/api/licenses',{method:'POST',body:JSON.stringify({license_key:key,expires_at:exp,device_id:$('device').value.trim(),notes:$('notes').value.trim()})});show('تمت الإضافة');loadLicenses()}catch(e){show(e.message)}}async function toggle(id,active){try{await api('/admin/api/licenses/'+id,{method:'PATCH',body:JSON.stringify({active})});loadLicenses()}catch(e){show(e.message)}}async function removeLicense(id){if(!confirm('حذف الترخيص؟'))return;try{await api('/admin/api/licenses/'+id,{method:'DELETE'});loadLicenses()}catch(e){show(e.message)}}loadLicenses().catch(()=>{})</script></body></html>`;
app.get('/admin', (_req, res) => res.type('html').send(adminPage));
app.post('/admin/api/login', (req, res) => {
  if (clean(req.body.password) !== clean(process.env.ADMIN_PASSWORD || 'BS2973')) return error(res, 'كلمة المرور غير صحيحة', 401);
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, Date.now() + 8 * 60 * 60 * 1000);
  res.set('Set-Cookie', `bs_admin=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=28800`);
  return json(res, { ok: true });
});
app.post('/admin/api/logout', (req, res) => { adminSessions.delete(cookieValue(req, 'bs_admin')); res.set('Set-Cookie', 'bs_admin=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'); return json(res, { ok: true }); });
app.use('/admin/api', (req, res, next) => { if (!adminOk(req)) return error(res, 'Admin login required', 401); next(); });
app.get('/admin/api/licenses', async (_req, res) => { try { const rows = await supabaseRequest('bs_licenses?select=*&order=id.desc'); return json(res, { licenses: rows.map(safeLicense) }); } catch (_) { return error(res, 'Supabase is not configured or unavailable', 503); } });
app.post('/admin/api/licenses', async (req, res) => {
  const key = clean(req.body.license_key).toUpperCase();
  const expires = clean(req.body.expires_at);
  if (!/^BS-[A-Z0-9]+$/.test(key)) return error(res, 'license_key must start with BS-');
  if (!expires || !Number.isFinite(Date.parse(expires))) return error(res, 'expires_at is required');
  try { const rows = await supabaseRequest('bs_licenses', { method: 'POST', headers: { Prefer: 'return=representation' }, body: JSON.stringify({ license_key: key, expires_at: new Date(expires).toISOString(), device_id: clean(req.body.device_id) || null, notes: clean(req.body.notes) || null, active: true }) }); return json(res, { license: safeLicense(rows[0]) }, 201); } catch (_) { return error(res, 'تعذر إنشاء الترخيص', 400); }
});
app.patch('/admin/api/licenses/:id', async (req, res) => { try { const rows = await supabaseRequest(`bs_licenses?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'PATCH', headers: { Prefer: 'return=representation' }, body: JSON.stringify({ active: Boolean(req.body.active) }) }); return json(res, { license: safeLicense(rows[0]) }); } catch (_) { return error(res, 'تعذر تحديث الترخيص', 400); } });
app.delete('/admin/api/licenses/:id', async (req, res) => { try { await supabaseRequest(`bs_licenses?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'DELETE' }); return json(res, { ok: true }); } catch (_) { return error(res, 'تعذر حذف الترخيص', 400); } });

async function checkLicense(req, res) {
  const key = clean(req.body.license_key).toLowerCase();
  const deviceId = clean(req.body.device_id);
  if (!key || !deviceId) return error(res, 'license_key and device_id are required');
  let license;
  try { license = await findLicense(key); } catch (_) { return error(res, 'License database unavailable', 503); }
  if (!license || license.expired) return json(res, { status: false, success: false, message: license?.expired ? 'License expired' : 'Invalid license' }, 403);
  if (license.deviceId && license.deviceId !== deviceId) return json(res, { status: false, success: false, message: 'License is assigned to another device' }, 403);
  if (supabaseConfigured()) {
    try { await supabaseRequest(`bs_licenses?license_key=eq.${encodeURIComponent(license.key.toUpperCase())}`, { method: 'PATCH', body: JSON.stringify({ device_id: deviceId, last_used_at: new Date().toISOString() }) }); } catch (_) { /* validation already succeeded */ }
  }
  const sessionToken = tokenFor(key, deviceId);
  sessions.set(sessionToken, { licenseKey: key, deviceId, expiresAt: Date.now() + sessionTtl * 1000 });
  return json(res, {
    status: true,
    success: true,
    message: 'Valid License',
    session_token: sessionToken,
    expired_at: license.expiry,
    license_key: key,
    features: { auto_regata: true },
    license_features: { auto_regata: true },
    server_proof_v: 0
  });
}

app.post('/srv/check_license.php', checkLicense);
app.post('/c/12345', checkLicense);
app.post('/c/*', checkLicense);

function autoRegata(req, res) {
  const endpoint = 'auto_regata.php';
  const session = authOrError(req, res, endpoint);
  if (!session) return;
  const s = deviceState(session.deviceId);
  const action = clean(req.body.action || 'status');
  if (action === 'clear_log') { s.logs = []; return json(res, result(s, 'Logs cleared successfully.')); }
  if (action === 'status') return json(res, result(s));
  if (action === 'prepare_workers') {
    s.job.worker_limit = Math.max(0, Math.min(Number(req.body.count || 0), 7));
    s.job.join_delay_ms = Number(req.body.join_delay_ms || 0);
    addLog(s, `Prepared ${s.job.worker_limit} worker slot(s).`);
    return json(res, result(s, 'Workers prepared.'));
  }
  if (action === 'register_worker') { addLog(s, `Worker registered: ${clean(req.body.account_id)}`); return json(res, result(s, 'Worker registered.')); }
  if (action === 'upload_master' || action === 'import_workers_json') { s.master_ready = true; addLog(s, 'Master/workers data accepted.'); return json(res, result(s, 'Data uploaded successfully.')); }
  if (action === 'start') { s.job.status = 'running'; s.job.worker_limit = Number(req.body.worker_limit || s.job.worker_limit || 0); s.job.join_delay_ms = Number(req.body.join_delay_ms || 0); s.job.tick_delay_ms = Number(req.body.tick_delay_ms || 0); s.job.started_at = new Date().toISOString(); addLog(s, 'Auto Regata started.'); return json(res, result(s, 'Auto Regata started.')); }
  if (action === 'stop') { s.job.status = 'idle'; s.job.stopped_at = new Date().toISOString(); addLog(s, 'Auto Regata stopped.'); return json(res, result(s, 'Auto Regata stopped.')); }
  if (action === 'tick') { s.job.cycle += 1; s.job.last_tick_at = new Date().toISOString(); addLog(s, `Cycle #${s.job.cycle} checked.`); return json(res, result(s, 'Tick complete.')); }
  return error(res, `Unsupported action: ${action}`);
}

app.post('/srv/backup_api/auto_regata.php', upload.any(), autoRegata);
app.get('/srv/backup_api/auto_regata.php', autoRegata);
app.post('/auto_regata.php', upload.any(), autoRegata);
app.get('/auto_regata.php', autoRegata);
app.post('/srv/worker_api/release.php', (req, res) => {
  const session = authOrError(req, res, 'release.php');
  if (!session) return;
  const s = deviceState(session.deviceId);
  claimedWorkers.delete(clean(req.body.worker_id));
  s.workers = s.workers.filter((worker) => String(worker.worker_id) !== clean(req.body.worker_id));
  return json(res, { status: true, success: true, message: 'Worker released', workers: s.workers });
});
app.post('/release.php', (req, res) => {
  const session = authOrError(req, res, 'release.php');
  if (!session) return;
  const s = deviceState(session.deviceId);
  claimedWorkers.delete(clean(req.body.worker_id));
  s.workers = s.workers.filter((worker) => String(worker.worker_id) !== clean(req.body.worker_id));
  return json(res, { status: true, success: true, message: 'Worker released', workers: s.workers });
});
function claimWorker(req, res) {
  const session = authOrError(req, res, 'claim.php');
  if (!session) return;
  const pool = workerPool();
  if (!pool.length) return json(res, { status: true, available: false, message: 'No workers available in pool' });
  const worker = pool.find((candidate) => !claimedWorkers.has(String(candidate.worker_id)));
  if (!worker) return json(res, { status: true, available: false, message: 'No workers available in pool' });
  const claimToken = crypto.randomBytes(24).toString('hex');
  claimedWorkers.set(String(worker.worker_id), { deviceId: session.deviceId, claimToken });
  return json(res, { status: true, available: true, claim_token: claimToken, worker });
}
app.post('/srv/worker_api/claim.php', claimWorker);
app.post('/claim.php', claimWorker);

app.use((err, _req, res, _next) => { console.error(err); error(res, 'Internal server error', 500); });
app.listen(port, '0.0.0.0', () => console.log(`bs-server listening on ${port}`));
