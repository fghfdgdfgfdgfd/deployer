// Remote relays (Vercel / Netlify / Railway): a tiny proxy on another platform that forwards visitors to this Worker.
// A Worker request is short, so a deploy is a small state machine: /deploy runs the first calls, then every poll of
// /api/relays/<p> advances it one step (build -> reach panel -> ping) until it finishes.
import { now } from './db.js';

export const MARK = 'xr-panel-ok';
export class RelayError extends Error { }
export const STEPS = [['auth', 'Token'], ['create', 'Deploy'], ['build', 'Build'], ['verify', 'Reach panel'], ['ping', 'Ping']];
const fresh = () => STEPS.map(([k, l]) => ({ k, l, st: 'wait', m: '' }));
const rand = () => [...crypto.getRandomValues(new Uint8Array(3))].map(b => b.toString(16).padStart(2, '0')).join('');
const b64 = s => btoa(unescape(encodeURIComponent(s)));

async function req(method, url, token, body, o0 = {}) {
  const o = typeof o0 === 'function' ? { fetch: o0 } : (o0 || {});
  const h = { Accept: 'application/json', 'User-Agent': 'xr-panel' }; if (token) h.Authorization = 'Bearer ' + token;
  let b = o.raw; if (body !== undefined) { h['Content-Type'] = 'application/json'; b = JSON.stringify(body); } if (o.ctype) h['Content-Type'] = o.ctype;
  const r = await (o.fetch || fetch)(url, { method, headers: h, body: b }); const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = { raw: t.slice(0, 300) }; } return [r.status, j];
}

// ---------- Vercel ----------
const VERCEL_RELAY = `// xr relay (Vercel). Forwards HTTP and WebSocket traffic to the panel.
const http = require('http'), https = require('https');
const { WebSocketServer, WebSocket } = require('ws');
const TARGET = new URL(__TARGET__), HOST = TARGET.hostname, PORT = TARGET.port || 443;
const SKIP = new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade','host']);
function fwd(h) { const o = {}; for (const k in h) if (!SKIP.has(k)) o[k] = h[k]; o.host = HOST; return o; }
const server = http.createServer((req, res) => {
  const up = https.request({ hostname: HOST, port: PORT, method: req.method, path: req.url, headers: fwd(req.headers), servername: HOST }, (r) => {
    const h = { ...r.headers }; delete h['transfer-encoding']; delete h['connection']; delete h['keep-alive']; res.writeHead(r.statusCode, h); r.pipe(res); });
  up.on('error', () => { if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' }); res.end('relay: panel unreachable'); });
  res.on('close', () => up.destroy()); req.pipe(up);
});
const wss = new WebSocketServer({ server, perMessageDeflate: false });
wss.on('connection', (client, req) => {
  const protos = (req.headers['sec-websocket-protocol'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  const up = new WebSocket('wss://' + HOST + ':' + PORT + req.url, protos, { headers: { 'User-Agent': req.headers['user-agent'] || 'relay' }, servername: HOST, perMessageDeflate: false });
  const queue = []; const kill = () => { try { client.terminate(); } catch (e) {} try { up.terminate(); } catch (e) {} };
  up.on('open', () => { for (const [d, b] of queue) up.send(d, { binary: b }); queue.length = 0; });
  client.on('message', (d, bin) => { if (up.readyState === WebSocket.OPEN) up.send(d, { binary: bin }); else if (up.readyState === WebSocket.CONNECTING) queue.push([d, bin]); });
  up.on('message', (d, bin) => { if (client.readyState === WebSocket.OPEN) client.send(d, { binary: bin }); });
  client.on('close', kill); up.on('close', kill); client.on('error', kill); up.on('error', kill);
});
module.exports = server; module.exports.default = server;
`;
const vercel = {
  name: 'Vercel', ws: 'beta', token_url: 'https://vercel.com/account/settings/tokens',
  hint: 'Deploys a Node function that forwards HTTP and WebSocket traffic to the panel. WebSocket on Vercel Functions is in beta: each connection is cut after about 5 minutes and the client reconnects by itself.',
  files: url => [['api/relay.js', VERCEL_RELAY.replace('__TARGET__', JSON.stringify(url))], ['package.json', '{"name":"xr-relay","version":"1.0.0","private":true,"dependencies":{"ws":"8.18.0"}}'], ['vercel.json', '{"rewrites":[{"source":"/(.*)","destination":"/api/relay"}]}']]
    .map(([file, d]) => ({ file, encoding: 'base64', data: b64(d) })),
  err: (j, c) => ((j && j.error) || {}).message || 'HTTP ' + c,
  async start(t, run, f) {
    const API = 'https://api.vercel.com'; run.step('auth', 'run');
    let [c, j] = await req('GET', API + '/v2/user', t, undefined, f); if (c === 401 || c === 403) throw new RelayError('Vercel rejected this token (create one at vercel.com/account/settings/tokens).'); if (c !== 200) throw new RelayError('Vercel: ' + this.err(j, c));
    run.step('auth', 'ok', (j.user || {}).username || '');
    const name = run.ref.name || 'xr-relay-' + rand(); run.step('create', 'run', name);
    [c, j] = await req('POST', API + '/v13/deployments?skipAutoDetectionConfirmation=1&forceNew=1', t, { name, target: 'production', files: this.files(run.upUrl), projectSettings: { framework: null, buildCommand: null, outputDirectory: null } }, f);
    if (c >= 300) throw new RelayError('Vercel: ' + this.err(j, c));
    Object.assign(run.ref, { name, project: j.projectId || name, dep: j.id, phase: 'build' }); run.step('create', 'ok', name); run.step('build', 'run', 'queued');
  },
  async tick(t, run, f) {
    const API = 'https://api.vercel.com', [c, j] = await req('GET', `${API}/v13/deployments/${run.ref.dep}`, t, undefined, f); const rs = (j.readyState || j.status || '').toUpperCase();
    if (['ERROR', 'CANCELED', 'BLOCKED'].includes(rs)) throw new RelayError(`Vercel build ${rs.toLowerCase()}: ${j.errorMessage || 'see the Vercel dashboard'}`);
    if (rs !== 'READY') { run.step('build', 'run', rs.toLowerCase() || 'waiting'); return false; }
    await req('PATCH', `${API}/v9/projects/${run.ref.project}`, t, { ssoProtection: null }, f);       // production domain must be public
    const al = (j.alias || []).filter(a => a.endsWith('.vercel.app')); const dom = al.find(a => a === run.ref.name + '.vercel.app') || [...al].sort((a, b) => a.length - b.length)[0] || j.url || '';
    if (!dom) throw new RelayError('Vercel did not return a domain'); run.step('build', 'ok', 'ready'); run.domain = dom; return true;
  },
  async remove(t, ref, f) { const pid = ref.project || ref.name; if (!pid) return; const [c, j] = await req('DELETE', `https://api.vercel.com/v9/projects/${pid}`, t, undefined, f); if (![200, 204, 404].includes(c)) throw new RelayError('Vercel: ' + this.err(j, c)); },
};

// ---------- Netlify (static site with one proxy rule; zip written by hand) ----------
const crcT = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc32 = u8 => { let c = 0xFFFFFFFF; for (const b of u8) c = crcT[(c ^ b) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
export function zip(files) {                              // stored (no compression), enough for two tiny files
  const te = new TextEncoder(), parts = [], cd = []; let off = 0;
  for (const [name, text] of files) {
    const n = te.encode(name), d = te.encode(text), c = crc32(d), h = new DataView(new ArrayBuffer(30)); h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint32(14, c, true); h.setUint32(18, d.length, true); h.setUint32(22, d.length, true); h.setUint16(26, n.length, true);
    parts.push(new Uint8Array(h.buffer), n, d);
    const e = new DataView(new ArrayBuffer(46)); e.setUint32(0, 0x02014b50, true); e.setUint16(4, 20, true); e.setUint16(6, 20, true); e.setUint32(16, c, true); e.setUint32(20, d.length, true); e.setUint32(24, d.length, true); e.setUint16(28, n.length, true); e.setUint32(42, off, true); cd.push(new Uint8Array(e.buffer), n);
    off += 30 + n.length + d.length;
  }
  const size = cd.reduce((a, x) => a + x.length, 0), end = new DataView(new ArrayBuffer(22)); end.setUint32(0, 0x06054b50, true); end.setUint16(8, files.length, true); end.setUint16(10, files.length, true); end.setUint32(12, size, true); end.setUint32(16, off, true);
  const all = [...parts, ...cd, new Uint8Array(end.buffer)], out = new Uint8Array(all.reduce((a, x) => a + x.length, 0)); let i = 0; for (const x of all) { out.set(x, i); i += x.length; } return out;
}
const netlify = {
  name: 'Netlify', ws: 'http', token_url: 'https://app.netlify.com/user/applications#personal-access-tokens',
  hint: 'Deploys a static site with one proxy rule that forwards every request to the panel. Netlify proxies are HTTP only: the panel and subscription pages work through it, but WebSocket configs do not (Netlify has no WebSocket upgrade, 26 s proxy timeout).',
  err: (j, c) => (j && (j.message || j.raw)) || 'HTTP ' + c,
  async start(t, run, f) {
    const API = 'https://api.netlify.com/api/v1'; run.step('auth', 'run');
    let [c, j] = await req('GET', API + '/user', t, undefined, f); if (c === 401 || c === 403) throw new RelayError('Netlify rejected this token (create a personal access token in User settings > Applications).'); if (c !== 200) throw new RelayError('Netlify: ' + this.err(j, c));
    run.step('auth', 'ok', j.email || j.full_name || ''); run.step('create', 'run'); let sid = run.ref.site, dom = run.ref.domain;
    if (!sid) {
      let made = false; for (let i = 0; i < 4 && !made; i++) { [c, j] = await req('POST', API + '/sites', t, { name: 'xr-relay-' + rand() }, f); if (c === 200 || c === 201) made = true; else if (c !== 422) throw new RelayError('Netlify: ' + this.err(j, c)); }
      if (!made) throw new RelayError('Netlify could not create a site: ' + this.err(j, c)); sid = j.id; dom = `${j.name}.netlify.app`; Object.assign(run.ref, { site: sid, domain: dom });
    }
    [c, j] = await req('POST', `${API}/sites/${sid}/deploys`, t, undefined, { raw: zip([['_redirects', `/*  ${run.upUrl}/:splat  200!\n`], ['index.html', '<!doctype html><meta charset="utf-8"><title>relay</title>\n']]), ctype: 'application/zip', fetch: f });
    if (c >= 300) throw new RelayError('Netlify: ' + this.err(j, c)); run.ref.dep = j.id; run.ref.phase = 'build'; run.step('create', 'ok', dom); run.step('build', 'run', 'uploading');
  },
  async tick(t, run, f) {
    const [c, j] = await req('GET', `https://api.netlify.com/api/v1/deploys/${run.ref.dep}`, t, undefined, f), st = (j.state || '').toLowerCase();
    if (['error', 'rejected'].includes(st)) throw new RelayError('Netlify deploy failed: ' + (j.error_message || st));
    if (st !== 'ready') { run.step('build', 'run', st || 'waiting'); return false; } run.step('build', 'ok', 'ready'); run.domain = run.ref.domain; return true;
  },
  async remove(t, ref, f) { if (!ref.site) return; const [c, j] = await req('DELETE', `https://api.netlify.com/api/v1/sites/${ref.site}`, t, undefined, f); if (![200, 204, 404].includes(c)) throw new RelayError('Netlify: ' + this.err(j, c)); },
};

// ---------- Railway (stock nginx image configured through variables) ----------
const NGINX = `map $http_upgrade $connection_upgrade { default upgrade; '' close; }
server {
  listen 8080 default_server;
  server_name _;
  resolver 1.1.1.1 8.8.8.8 valid=60s ipv6=off;
  client_max_body_size 0;
  location / {
    set $up "https://__HOST__:__PORT__";
    proxy_pass $up;
    proxy_http_version 1.1;
    proxy_ssl_server_name on;
    proxy_ssl_name __HOST__;
    proxy_set_header Host __HOST__;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering off;
    proxy_read_timeout 1d;
    proxy_send_timeout 1d;
  }
}
`;
const RW_START = `sh -c 'printf "%s" "$RELAY_CONF" > /etc/nginx/conf.d/default.conf && exec nginx -g "daemon off;"'`;
const railway = {
  name: 'Railway', ws: 'ws', token_url: 'https://railway.com/account/tokens',
  hint: 'Deploys the nginx image as a Railway service that forwards HTTP and WebSocket traffic to the panel. Use an Account token (create it with “No workspace”).',
  async gql(t, query, variables, f) {
    const [c, j] = await req('POST', 'https://backboard.railway.com/graphql/v2', t, { query, variables: variables || {} }, f);
    if (c === 401 || c === 403) throw new RelayError('Railway rejected this token (use an Account token from railway.com/account/tokens).');
    if (j.errors) throw new RelayError('Railway: ' + String(j.errors[0].message || 'error').slice(0, 200)); if (c >= 300 || !j.data) throw new RelayError('Railway: HTTP ' + c); return j.data;
  },
  async start(t, run, f) {
    run.step('auth', 'run'); let who = {}; try { who = (await this.gql(t, 'query{me{name email}}', null, f)).me || {}; } catch (e) { if (/rejected/.test(e.message)) throw e; }
    run.step('auth', 'ok', who.email || who.name || ''); run.step('create', 'run');
    const conf = NGINX.replaceAll('__HOST__', run.upHost).replaceAll('__PORT__', String(run.upPort)), ref = run.ref;
    if (ref.service && ref.env) { try { await this.gql(t, 'mutation($i:VariableCollectionUpsertInput!){variableCollectionUpsert(input:$i)}', { i: { projectId: ref.project, environmentId: ref.env, serviceId: ref.service, variables: { RELAY_CONF: conf, PORT: '8080' }, skipDeploys: true } }, f); } catch { for (const k of Object.keys(ref)) delete ref[k]; } }
    if (!ref.service) {
      const d = (await this.gql(t, 'mutation($i:ProjectCreateInput!){projectCreate(input:$i){id environments{edges{node{id name}}}}}', { i: { name: 'xr-relay-' + rand(), defaultEnvironmentName: 'production' } }, f)).projectCreate;
      Object.assign(ref, { project: d.id, env: d.environments.edges[0].node.id });
      ref.service = (await this.gql(t, 'mutation($i:ServiceCreateInput!){serviceCreate(input:$i){id}}', { i: { projectId: d.id, name: 'relay', source: { image: 'nginx:alpine' }, variables: { RELAY_CONF: conf, PORT: '8080' } } }, f)).serviceCreate.id;
    }
    for (let i = 0; i < 6; i++) { try { await this.gql(t, 'mutation($s:String!,$e:String!,$i:ServiceInstanceUpdateInput!){serviceInstanceUpdate(serviceId:$s,environmentId:$e,input:$i)}', { s: ref.service, e: ref.env, i: { startCommand: RW_START } }, f); break; } catch (e) { if (i === 5) throw e; await new Promise(r => setTimeout(r, 1500)); } }
    await this.gql(t, 'mutation($s:String!,$e:String!){serviceInstanceDeploy(serviceId:$s,environmentId:$e)}', { s: ref.service, e: ref.env }, f);
    if (!ref.domain) ref.domain = (await this.gql(t, 'mutation($i:ServiceDomainCreateInput!){serviceDomainCreate(input:$i){domain}}', { i: { serviceId: ref.service, environmentId: ref.env, targetPort: 8080 } }, f)).serviceDomainCreate.domain;
    run.step('create', 'ok', ref.domain); ref.phase = 'build'; run.step('build', 'run', 'queued');
  },
  async tick(t, run, f) {
    const r = run.ref, e = (await this.gql(t, 'query($i:DeploymentListInput!){deployments(input:$i,first:1){edges{node{id status}}}}', { i: { projectId: r.project, serviceId: r.service, environmentId: r.env } }, f)).deployments.edges, st = e.length ? e[0].node.status : 'WAITING';
    if (['FAILED', 'CRASHED'].includes(st)) throw new RelayError(`Railway deployment ${st.toLowerCase()}. Open the project on railway.com to read its logs.`);
    if (st !== 'SUCCESS') { run.step('build', 'run', st.toLowerCase()); return false; } run.step('build', 'ok', 'success'); run.domain = r.domain; return true;
  },
  async remove(t, ref, f) { if (!ref.project) return; try { await this.gql(t, 'mutation($id:String!){projectDelete(id:$id)}', { id: ref.project }, f); } catch (e) { if (!/not found/i.test(e.message)) throw e; } },
};
export const PROVIDERS = { vercel, netlify, railway };
export const WS_TAG = { ws: 'WebSocket', beta: 'WS beta', http: 'HTTP only' };

// ---------- persistence + state machine ----------
const j = (s, d) => { try { return JSON.parse(s) ?? d; } catch { return d; } };
export async function row(db, p) { return (await db.one('SELECT * FROM relays WHERE p=?', p)) || {}; }
export async function save(db, p, kw) {
  if (!(await db.one('SELECT 1 x FROM relays WHERE p=?', p))) await db.run("INSERT INTO relays(p,status) VALUES(?,'idle')", p);
  kw.upd = now(); const ks = Object.keys(kw); await db.run(`UPDATE relays SET ${ks.map(k => k + '=?').join(',')} WHERE p=?`, ...ks.map(k => kw[k]), p);
}
export async function view(db, p) {
  const r = await row(db, p), m = PROVIDERS[p];
  return { id: p, name: m.name, ws: m.ws, tag: WS_TAG[m.ws], hint: m.hint, token_url: m.token_url, status: r.status || 'idle', steps: j(r.steps, null) || fresh(), domain: r.domain || '', err: r.err || '', ping: j(r.ping, null), has_token: !!r.token, has_ref: Object.keys(j(r.ref, {})).length > 0 };
}
export const allViews = async db => Promise.all(Object.keys(PROVIDERS).map(p => view(db, p)));
export const active = async db => (await allViews(db)).filter(v => v.domain);

class Run {
  constructor(db, p, steps, ref, up) { Object.assign(this, { db, p, steps, ref, domain: '', upHost: up[0], upPort: up[1], upUrl: 'https://' + up[0] + (up[1] === 443 ? '' : ':' + up[1]) }); }
  step(k, st, msg = '') { for (const s of this.steps) if (s.k === k) { s.st = st; s.m = String(msg).slice(0, 40); } }
  async flush(extra = {}) { await save(this.db, this.p, { steps: JSON.stringify(this.steps), ref: JSON.stringify(this.ref), ...extra }); }
  async fail(msg) { for (const s of this.steps) if (s.st === 'run') s.st = 'fail'; await this.flush({ status: 'failed', err: msg }); }
}

export async function ping(domain, f = fetch, n = 2) {
  const web = []; for (let i = 0; i < n; i++) { const t = Date.now(); try { const r = await f(`https://${domain}/relay-check?t=${t}`, { headers: { 'Cache-Control': 'no-cache' } }); if (r.status === 200 && (await r.text()).includes(MARK)) web.push(Math.max(1, Date.now() - t)); } catch { } }
  return { tcp: null, web: web.length ? Math.min(...web) : null, ok: web.length > 0, at: now() };
}

/** First phase: auth + create. Returns an error string or null. */
export async function startDeploy(db, p, token, up, f = fetch) {
  const m = PROVIDERS[p]; if (!m) return 'Unknown relay'; const r = await row(db, p);
  if (r.status === 'deploying' && now() - (r.upd || 0) < 900) return 'A deploy is already running';
  token = token || r.token || ''; if (!token) return 'Paste an API token first';
  const run = new Run(db, p, fresh(), j(r.ref, {}), up); await save(db, p, { token, status: 'deploying', steps: JSON.stringify(run.steps), err: '' });
  try { await m.start(token, run, f); await run.flush({ status: 'deploying' }); } catch (e) { await run.fail(e instanceof RelayError ? e.message : 'Unexpected error: ' + e.message); }
  return null;
}
/** Advance a running deploy by one step; called by every status poll. */
export async function advance(db, p, up, f = fetch) {
  const m = PROVIDERS[p], r = await row(db, p); if (r.status !== 'deploying') return;
  const ref = j(r.ref, {}); if (!ref.phase) return; const run = new Run(db, p, j(r.steps, null) || fresh(), ref, up); run.domain = r.domain || '';
  try {
    if (ref.phase === 'build') {
      if (now() - (r.upd || 0) > 900) throw new RelayError('Deploy timed out'); if (!(await m.tick(r.token, run, f))) { await run.flush(); return; }
      ref.phase = 'verify'; ref.vstart = now(); ref.vtries = 0; run.step('verify', 'run', 'waiting'); await run.flush({ domain: run.domain }); return;
    }
    if (ref.phase === 'verify') {
      const dom = r.domain || run.domain; const t = Date.now(); let code = 0, body = '';
      try { const x = await f(`https://${dom}/relay-check?t=${t}`, { headers: { 'Cache-Control': 'no-cache' } }); code = x.status; body = await x.text(); } catch { }
      if (code === 200 && body.includes(MARK)) { run.step('verify', 'ok', `${Date.now() - t} ms`); ref.phase = 'ping'; run.step('ping', 'run'); await run.flush(); return; }
      const why = ({ 0: 'not reachable yet', 401: 'blocked by the platform (401)', 404: 'up, not forwarding yet (404)' })[code] || (code === 200 ? 'answers, but not from the panel (200)' : 'HTTP ' + code);
      ref.vtries = (ref.vtries || 0) + 1; run.step('verify', 'run', why);
      if (now() - ref.vstart > 150) throw new RelayError(`Relay never reached the panel: ${why}. Check the panel domain/port in Settings.`);
      await run.flush(); return;
    }
    if (ref.phase === 'ping') {
      const dom = r.domain, pg = await ping(dom, f); run.step('ping', pg.ok ? 'ok' : 'fail', pg.ok ? `${pg.web} ms` : 'no answer'); delete ref.phase;
      await run.flush({ status: 'ok', ping: JSON.stringify(pg), err: '' });
    }
  } catch (e) { delete ref.phase; await run.fail(e instanceof RelayError ? e.message : 'Unexpected error: ' + e.message); }
}
export async function doPing(db, p, f = fetch) { const d = (await row(db, p)).domain; if (!d) return null; const pg = await ping(d, f, 3); await save(db, p, { ping: JSON.stringify(pg) }); return pg; }
export async function remove(db, p, f = fetch) {
  const r = await row(db, p); if (!r.p) return null;
  try { await PROVIDERS[p].remove(r.token || '', j(r.ref, {}), f); } catch (e) { return e.message; } await db.run('DELETE FROM relays WHERE p=?', p); return null;
}
