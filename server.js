import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const API = 'https://api.cloudflare.com/client/v4';
const MIME = { js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml', html: 'text/html; charset=utf-8', json: 'application/json' };
const jobs = new Map();

// ---------- Cloudflare helpers ----------
async function cf(token, method, p, body, extra = {}) {
  const r = await fetch(API + p, {
    method,
    headers: { Authorization: 'Bearer ' + token, ...(body && !(body instanceof FormData) ? { 'content-type': 'application/json' } : {}), ...extra },
    body: body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
  });
  let j; try { j = await r.json(); } catch { j = { success: false, errors: [{ message: 'HTTP ' + r.status }] }; }
  if (!j.success) throw new Error((j.errors || []).map(e => e.message).join('; ') || 'HTTP ' + r.status);
  return j.result;
}

function walk(dir, base = dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
    const f = path.join(dir, e.name);
    return e.isDirectory() ? walk(f, base) : [{ file: f, rel: '/' + path.relative(base, f).split(path.sep).join('/') }];
  });
}

const loadFiles = () => walk(path.join(ROOT, 'worker/public')).map(f => {
  const buf = fs.readFileSync(f.file), ext = path.extname(f.file).slice(1), b64 = buf.toString('base64');
  return { ...f, b64, ext, size: buf.length, ct: MIME[ext] || 'application/octet-stream' };
});
const limitOf = plan => (plan === 'paid' ? '0' : '100000');

async function deployPages(job, { token, accountId, name, plan }) {
  const log = m => job.logs.push(m);
  const a = `/accounts/${accountId}`;
  try {
    log('db');
    const dbName = name + '-db';
    const found = (await cf(token, 'GET', `${a}/d1/database?name=${encodeURIComponent(dbName)}`)).find(d => d.name === dbName);
    const dbId = found ? found.uuid : (await cf(token, 'POST', `${a}/d1/database`, { name: dbName })).uuid;

    log('project');
    let proj;
    try { proj = await cf(token, 'GET', `${a}/pages/projects/${name}`); }
    catch { proj = await cf(token, 'POST', `${a}/pages/projects`, { name, production_branch: 'main' }); }
    const cfg = { compatibility_date: '2025-06-01', d1_databases: { DB: { id: dbId } }, env_vars: {
      CF_ACCOUNT_ID: { type: 'plain_text', value: accountId }, CF_REQ_LIMIT: { type: 'plain_text', value: limitOf(plan) }, CF_API_TOKEN: { type: 'secret_text', value: token } } };
    await cf(token, 'PATCH', `${a}/pages/projects/${name}`, { deployment_configs: { production: cfg, preview: cfg } });

    log('assets');
    const { blake3 } = await import('hash-wasm');
    const files = [];
    for (const f of loadFiles()) files.push({ ...f, hash: (await blake3(f.b64 + f.ext)).slice(0, 32) });
    const jwt = (await cf(token, 'GET', `${a}/pages/projects/${name}/upload-token`)).jwt;
    const hashes = files.map(f => f.hash);
    const missing = new Set(await cf(jwt, 'POST', '/pages/assets/check-missing', { hashes }));
    const todo = files.filter(f => missing.has(f.hash));
    if (todo.length) await cf(jwt, 'POST', '/pages/assets/upload', todo.map(f => ({ key: f.hash, value: f.b64, metadata: { contentType: f.ct }, base64: true })));
    await cf(jwt, 'POST', '/pages/assets/upsert-hashes', { hashes });

    log('script');
    // _worker.bundle = a multipart document with metadata + the bundled module (built by esbuild in the Dockerfile)
    const inner = new FormData();
    inner.append('metadata', new Blob([JSON.stringify({ main_module: '_worker.js' })], { type: 'application/json' }));
    inner.append('_worker.js', new Blob([fs.readFileSync(path.join(ROOT, 'worker/dist/_worker.js'))], { type: 'application/javascript+module' }), '_worker.js');
    const bundle = await new Response(inner).blob();
    const fd = new FormData();
    fd.append('manifest', JSON.stringify(Object.fromEntries(files.map(f => [f.rel, f.hash]))));
    fd.append('branch', 'main');
    fd.append('_worker.bundle', bundle, '_worker.bundle');
    fd.append('_routes.json', new Blob([JSON.stringify({ version: 1, include: ['/*'], exclude: ['/static/*'] })], { type: 'application/json' }), '_routes.json');
    await cf(token, 'POST', `${a}/pages/projects/${name}/deployments`, fd);

    const domain = proj.subdomain || `${name}.pages.dev`;
    log('check');
    for (let i = 0; i < 12; i++) {
      try { const r = await fetch(`https://${domain}/login`, { redirect: 'manual' }); if (r.status < 500) break; } catch {}
      await new Promise(r => setTimeout(r, 4000));
    }
    job.domain = domain; job.status = 'done';
  } catch (e) { job.status = 'error'; job.error = String(e.message || e); }
  setTimeout(() => jobs.delete(job.id), 30 * 60e3);
}

async function deploy(job, { token, accountId, name, plan }) {
  const log = m => job.logs.push(m);
  const a = `/accounts/${accountId}`;
  try {
    // 1. database
    log('db');
    const dbName = name + '-db';
    const found = (await cf(token, 'GET', `${a}/d1/database?name=${encodeURIComponent(dbName)}`)).find(d => d.name === dbName);
    const dbId = found ? found.uuid : (await cf(token, 'POST', `${a}/d1/database`, { name: dbName })).uuid;

    // 2. static assets
    log('assets');
    const files = walk(path.join(ROOT, 'worker/public')).map(f => {
      const buf = fs.readFileSync(f.file), ext = path.extname(f.file).slice(1), b64 = buf.toString('base64');
      return { ...f, b64, ext, size: buf.length, hash: crypto.createHash('sha256').update(b64 + ext).digest('hex').slice(0, 32) };
    });
    const manifest = Object.fromEntries(files.map(f => [f.rel, { hash: f.hash, size: f.size }]));
    const sess = await cf(token, 'POST', `${a}/workers/scripts/${name}/assets-upload-session`, { manifest });
    let jwt = sess.jwt;
    for (const bucket of sess.buckets || []) {
      const fd = new FormData();
      for (const h of bucket) { const f = files.find(x => x.hash === h); fd.append(h, new Blob([f.b64], { type: MIME[f.ext] || 'application/octet-stream' }), h); }
      const up = await cf(sess.jwt, 'POST', `${a}/workers/assets/upload?base64=true`, fd);
      if (up && up.jwt) jwt = up.jwt;
    }

    // 3. worker script + bindings
    log('script');
    const meta = {
      main_module: 'index.js',
      compatibility_date: '2025-06-01',
      assets: { jwt, config: {} },
      bindings: [
        { type: 'd1', name: 'DB', id: dbId },
        { type: 'plain_text', name: 'CF_ACCOUNT_ID', text: accountId },
        { type: 'plain_text', name: 'CF_REQ_LIMIT', text: limitOf(plan) },
        { type: 'secret_text', name: 'CF_API_TOKEN', text: token },
      ],
    };
    const fd = new FormData();
    fd.append('metadata', new Blob([JSON.stringify(meta)], { type: 'application/json' }));
    for (const f of fs.readdirSync(path.join(ROOT, 'worker/src')).filter(x => x.endsWith('.js')))
      fd.append(f, new Blob([fs.readFileSync(path.join(ROOT, 'worker/src', f))], { type: 'application/javascript+module' }), f);
    await cf(token, 'PUT', `${a}/workers/scripts/${name}`, fd);

    // 4. workers.dev address
    log('domain');
    let sub;
    try { sub = (await cf(token, 'GET', `${a}/workers/subdomain`)).subdomain; } catch {}
    for (let i = 0; !sub && i < 4; i++) {
      const s = 'xr-' + crypto.randomBytes(3).toString('hex');
      try { sub = (await cf(token, 'PUT', `${a}/workers/subdomain`, { subdomain: s })).subdomain; } catch {}
    }
    if (!sub) throw new Error('workers.dev subdomain could not be created');
    await cf(token, 'POST', `${a}/workers/scripts/${name}/subdomain`, { enabled: true, previews_enabled: false });
    const domain = `${name}.${sub}.workers.dev`;

    // 5. wait until it answers
    log('check');
    for (let i = 0; i < 10; i++) {
      try { const r = await fetch(`https://${domain}/login`, { redirect: 'manual' }); if (r.status < 500) break; } catch {}
      await new Promise(r => setTimeout(r, 3000));
    }
    job.domain = domain; job.status = 'done';
  } catch (e) { job.status = 'error'; job.error = String(e.message || e); }
  setTimeout(() => jobs.delete(job.id), 30 * 60e3);
}

// ---------- HTTP ----------
const body = req => new Promise(res => { let d = ''; req.on('data', c => (d += c) && d.length > 2e4 && req.destroy()); req.on('end', () => { try { res(JSON.parse(d || '{}')); } catch { res({}); } }); });
const send = (res, o, c = 200) => { res.writeHead(c, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(o)); };

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (req.method === 'POST' && url.pathname === '/api/verify') {
      const { token } = await body(req);
      if (!token || token.length < 20) return send(res, { error: 'bad token' }, 400);
      const accounts = await cf(token, 'GET', '/accounts?per_page=20');
      if (!accounts.length) return send(res, { error: 'no account for this token' }, 400);
      return send(res, { accounts: accounts.map(x => ({ id: x.id, name: x.name })) });
    }
    if (req.method === 'POST' && url.pathname === '/api/deploy') {
      const { token, accountId, name, plan, target } = await body(req);
      if (!/^[a-z0-9][a-z0-9-]{1,40}$/.test(name || '') || !/^[a-f0-9]{32}$/.test(accountId || '') || !token) return send(res, { error: 'bad input' }, 400);
      if (jobs.size > 20) return send(res, { error: 'busy' }, 429);
      const job = { id: crypto.randomUUID(), status: 'run', logs: [] };
      jobs.set(job.id, job);
      (target === 'pages' ? deployPages : deploy)(job, { token, accountId, name, plan });   // token lives only in this closure
      return send(res, { id: job.id });
    }
    if (url.pathname.startsWith('/api/job/')) {
      const j = jobs.get(url.pathname.slice(9));
      return j ? send(res, { status: j.status, logs: j.logs, domain: j.domain, error: j.error }) : send(res, { error: 'not found' }, 404);
    }
    if (url.pathname === '/health') return send(res, { ok: true });
    const f = path.join(ROOT, 'public', url.pathname === '/' ? 'index.html' : url.pathname.replace(/\.\./g, ''));
    if (fs.existsSync(f) && fs.statSync(f).isFile()) {
      res.writeHead(200, { 'content-type': MIME[path.extname(f).slice(1)] || 'application/octet-stream' });
      return fs.createReadStream(f).pipe(res);
    }
    res.writeHead(404).end('not found');
  } catch (e) { send(res, { error: String(e.message || e) }, 400); }
}).listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('xr deployer up'));
