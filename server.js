const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const multer = require('multer');

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });
const port = Number(process.env.PORT || 10000);
const sessionTtl = Number(process.env.SESSION_TTL_SECONDS || 172800);
const debugLogging = clean(process.env.DEBUG_LOGGING).toLowerCase() === 'true';
const sessions = new Map();
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
app.use((req, res, next) => {
  const started = Date.now();
  res.on('finish', () => logEvent('http_request', {
    method: req.method,
    path: req.path,
    status_code: res.statusCode,
    duration_ms: Date.now() - started,
    action: clean(req.body?.action) || undefined,
    body: safeBody(req.body),
  }));
  next();
});

function clean(value) { return String(value ?? '').trim(); }
function nowSeconds() { return Math.floor(Date.now() / 1000); }
function json(res, body, status = 200) { return res.status(status).type('application/json').send(JSON.stringify(body)); }
function error(res, message, status = 400) { return json(res, { status: false, success: false, message }, status); }
function logEvent(event, fields = {}) {
  if (!debugLogging) return;
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
}

function safeBody(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return {};
  const hidden = new Set(['token', 'authorization', 'license_key', 'device_id', 'ts', 'nonce', 'signature', 'claim_token', 'ts_token', 'savecity_data', 'master_file']);
  const output = {};
  for (const [key, value] of Object.entries(body)) {
    const normalized = key.toLowerCase();
    if (hidden.has(normalized) || normalized.includes('password') || normalized.includes('secret')) {
      output[key] = '[redacted]';
    } else if (typeof value === 'string' && value.length > 256) {
      output[key] = `[string:${value.length} chars]`;
    } else {
      output[key] = value;
    }
  }
  return output;
}

function configuredLicenses() {
  return clean(process.env.LICENSE_KEYS).split(',').map((entry) => entry.trim()).filter(Boolean).map((entry) => {
    const separator = entry.indexOf(':');
    const key = separator >= 0 ? entry.slice(0, separator) : entry;
    const expiry = separator >= 0 ? entry.slice(separator + 1) : '';
    return { key: clean(key).toLowerCase(), expiry: clean(expiry) || '2099-12-31T23:59:59.000Z' };
  });
}

function findLicense(key) {
  const normalized = clean(key).toLowerCase();
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
  try {
    const parsed = JSON.parse(process.env.WORKER_POOL_JSON || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
}

app.get('/healthz', (_req, res) => json(res, { ok: true, service: 'bs-server', started_at: startedAt, uptime_seconds: Math.floor(process.uptime()) }));
app.get('/', (_req, res) => json(res, { service: 'bs-server', api: 'Dyluc Auto Regata compatible', health: '/healthz' }));

function checkLicense(req, res) {
  const key = clean(req.body.license_key).toLowerCase();
  const deviceId = clean(req.body.device_id);
  logEvent('license_check', { has_license_key: Boolean(key), has_device_id: Boolean(deviceId) });
  if (!key || !deviceId) return error(res, 'license_key and device_id are required');
  const license = findLicense(key);
  if (!license || license.expired) return json(res, { status: false, success: false, message: license?.expired ? 'License expired' : 'Invalid license' }, 403);
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
  logEvent('auto_regata_action', { action });
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
  // The APK reads claim_token from WorkerItem.fromJson(worker). Keep it
  // inside worker as well as at the top level for compatibility.
  const responseWorker = {
    ...worker,
    worker_id: Number(worker.worker_id || worker.id || 0),
    claim_token: claimToken,
    city_id: clean(worker.city_id || worker.cityId),
    ts_bver: clean(worker.ts_bver || worker.bver || '39.0.5'),
    ts_fver: clean(worker.ts_fver || worker.fver || '3900'),
    ts_token: clean(worker.ts_token || worker.tsToken),
  };
  return json(res, { status: true, available: true, claim_token: claimToken, worker: responseWorker });
}
app.post('/srv/worker_api/claim.php', claimWorker);
app.post('/claim.php', claimWorker);

app.use((err, _req, res, _next) => { console.error(err); error(res, 'Internal server error', 500); });
app.listen(port, '0.0.0.0', () => console.log(`bs-server listening on ${port}`));
