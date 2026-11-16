// Locations: country groups of exit proxies, geo lookup, Auto location and Recovery.
// A Worker request is short, so the job is driven in small steps: the browser calls /api/loc/step until it is done (or stopped).
import { probe, PROBES } from './proxy.js';
import { now } from './db.js';

export const valid = (host, port) => /^[A-Za-z0-9.\-:]{1,253}$/.test(host || '') && /^\d+$/.test(String(port)) && +port > 0 && +port < 65536;
export function isGlobal(ip) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return !(a === 10 || a === 127 || a === 0 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127));
  }
  const x = ip.toLowerCase(); return !(x === '::1' || x === '::' || x.startsWith('fe80') || x.startsWith('fc') || x.startsWith('fd'));
}
export async function resolve(host, fetchFn = fetch) {
  if (/^[\d.]+$/.test(host) || host.includes(':')) return host;
  try { const r = await (await fetchFn(`https://1.1.1.1/dns-query?name=${encodeURIComponent(host)}&type=A`, { headers: { accept: 'application/dns-json' } })).json(); const a = (r.Answer || []).find(x => x.type === 1); return a ? a.data : null; } catch { return null; }
}

const GEO = new Map();
export async function geo(host, fetchFn = fetch) {
  const ip = await resolve(host, fetchFn); if (!ip || !isGlobal(ip)) return null; if (GEO.has(ip)) return GEO.get(ip);
  const tries = [[`https://ipwho.is/${ip}`, d => d.success && [d.country_code, d.country]], [`http://ip-api.com/json/${ip}?fields=status,country,countryCode`, d => d.status === 'success' && [d.countryCode, d.country]]];
  for (const [url, get] of tries) {
    try { const d = await (await fetchFn(url, { headers: { 'User-Agent': 'xr-panel' } })).json(); const r = get(d); if (r && /^[A-Za-z]{2}$/.test(r[0] || '')) { const g = { cc: r[0].toLowerCase(), name: String(r[1] || r[0]).trim().slice(0, 60) }; GEO.set(ip, g); return g; } } catch { }
  }
  return null;
}
export async function geoBatch(ips, fetchFn = fetch) {
  const out = {}, todo = []; for (const ip of ips) { if (GEO.has(ip)) out[ip] = GEO.get(ip); else todo.push(ip); }
  for (let i = 0; i < todo.length; i += 100) {
    try {
      const r = await fetchFn('http://ip-api.com/batch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(todo.slice(i, i + 100).map(q => ({ query: q, fields: 'status,country,countryCode,query' }))) });
      for (const d of await r.json()) if (d.status === 'success' && /^[A-Za-z]{2}$/.test(d.countryCode || '')) { const g = { cc: d.countryCode.toLowerCase(), name: String(d.country || d.countryCode).trim().slice(0, 60) }; GEO.set(d.query, g); out[d.query] = g; }
    } catch { }
  }
  for (const ip of todo.filter(x => !out[x]).slice(0, 6)) { const g = await geo(ip, fetchFn); if (g) out[ip] = g; }
  return out;
}

// ---------- groups ----------
export async function groups(db) {
  const px = await db.all('SELECT * FROM proxies ORDER BY ms'), cnt = {};
  for (const r of await db.all('SELECT grp_id,COUNT(*) c FROM users GROUP BY grp_id')) cnt[r.grp_id] = r.c;
  return (await db.all('SELECT * FROM grps ORDER BY name')).map(g => { const p = px.filter(x => x.grp_id === g.id); return { id: g.id, name: g.name, cc: g.cc, px: p, n: p.length, users: cnt[g.id] || 0 }; });
}
export async function dropIfEmpty(db, gid) {
  if (!(await db.one('SELECT 1 x FROM proxies WHERE grp_id=?', gid))) await db.batch([['DELETE FROM grps WHERE id=?', gid], ['UPDATE users SET grp_id=0 WHERE grp_id=?', gid]]);
}
export async function putProxy(db, h, p, proto, ms, g) {
  let row = g.cc ? await db.one('SELECT id FROM grps WHERE cc=?', g.cc) : await db.one("SELECT id FROM grps WHERE name='Other' AND cc=''");
  if (!row) { await db.run('INSERT INTO grps(name,cc) VALUES(?,?)', g.name, g.cc); row = await db.one('SELECT id FROM grps WHERE cc=? AND name=? ORDER BY id DESC', g.cc, g.name); }
  await db.run('INSERT INTO proxies(grp_id,host,port,proto,ms) VALUES(?,?,?,?,?)', row.id, h, p, proto, ms);
}

// ---------- free proxy lists ----------
export const PX_SOURCES = [['https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt', 'socks5'], ['https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt', 'socks4'],
  ['https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt', 'http'], ['https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt', 'socks5'],
  ['https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt', 'http'], ['https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt', 'socks5'],
  ['https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt', ''], ['https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=6000&country=all&simplified=true', 'socks5'],
  ['https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=6000&country=all&simplified=true', 'http'], ['https://www.proxy-list.download/api/v1/get?type=socks5', 'socks5']];
const PX_RE = /(?:([a-z0-9]+):\/\/)?((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})/gi;
export async function fetchList(url, hint, fetchFn = fetch) {
  let txt; try { const r = await fetchFn(url, { headers: { 'User-Agent': 'xr-panel' } }); if (!r.ok) return null; txt = (await r.text()).slice(0, 2_000_000); } catch { return null; }
  const out = new Map();
  for (const m of txt.matchAll(PX_RE)) {
    let pr = (m[1] || hint || '').toLowerCase(); if (pr === 'socks5h') pr = 'socks5'; const h = m[2], pt = +m[3];
    if (!['socks5', 'socks4', 'http', 'https', ''].includes(pr) || !isGlobal(h) || !(pt > 0 && pt < 65536)) continue; out.set(`${h}:${pt}`, pr);
  }
  return out;
}
export async function candidates(skip, fetchFn = fetch, max = 600) {
  const res = await Promise.all(PX_SOURCES.map(([u, h]) => fetchList(u, h, fetchFn))), all = new Map();
  for (const r of res) for (const [k, v] of r || []) if (!skip.has(k) && !all.has(k)) all.set(k, v);
  const list = [...all].map(([k, v]) => { const i = k.lastIndexOf(':'); return [k.slice(0, i), +k.slice(i + 1), v]; });
  for (let i = list.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [list[i], list[j]] = [list[j], list[i]]; }
  return { list: list.slice(0, max), good: res.filter(Boolean).length, total: PX_SOURCES.length, found: list.length };
}

// ---------- the job (state lives in settings.job) ----------
export const LOC_MAX = 10, BATCH = 12, CONC = 6;       // 12 candidates x up to 3 protocol tries stays under the 50-subrequest limit of the free plan
const blank = () => ({ run: false, stop: false, kind: '', total: 0, done: 0, added: 0, tried: 0, alive: 0, msg: '', seq: 0, log: [], used: [], have: [], last: [], need: {}, pool: [] });
export async function getJob(db) { try { return { ...blank(), ...JSON.parse((await db.one("SELECT v FROM settings WHERE k='job'"))?.v || '{}') }; } catch { return blank(); } }
const saveJob = (db, j) => db.set('job', JSON.stringify(j));
const lg = (j, cls, txt) => { j.seq++; j.log.push([j.seq, cls, txt]); if (j.log.length > 120) j.log.splice(0, j.log.length - 120); };
export function view(j, since = 0) { return { run: j.run, kind: j.kind, total: j.total, done: j.done, added: j.added, tried: j.tried, alive: j.alive, msg: j.msg, stopping: false, seq: j.seq, log: j.log.filter(x => x[0] > since) }; }

export async function startJob(db, kind, fetchFn = fetch) {
  const cur = await getJob(db); if (cur.run && now() - (cur.ts || 0) < 120) return { error: 'Another job is running', kind: cur.kind };
  const j = { ...blank(), run: true, kind, ts: now() };
  const existing = new Set((await db.all('SELECT host,port FROM proxies')).map(r => `${r.host}:${r.port}`));
  if (kind === 'auto') {
    j.have = (await db.all("SELECT cc FROM grps WHERE cc!=''")).map(r => r.cc); try { j.last = JSON.parse((await db.one("SELECT v FROM settings WHERE k='loc_last'"))?.v || '[]'); } catch { } j.total = LOC_MAX; lg(j, 'i', 'looking for proxies…');
  } else {
    const rows = await db.all("SELECT p.id,p.host,p.port,g.cc,g.name FROM proxies p JOIN grps g ON g.id=p.grp_id WHERE g.cc!='' ORDER BY g.name,p.ms");
    if (!rows.length) { j.run = false; lg(j, 'bad', 'No country groups to recover yet.'); await saveJob(db, j); return { ok: true }; }
    for (const r of rows) (j.need[r.cc] = j.need[r.cc] || []).push({ id: r.id, name: r.name, host: r.host, port: r.port });
    j.total = rows.length; lg(j, 'i', `${rows.length} proxies in ${Object.keys(j.need).length} countries to replace`);
  }
  const c = await candidates(existing, fetchFn); lg(j, 'i', `${c.good}/${c.total} proxy sites answered · ${c.found} candidates`);
  if (!c.list.length) { j.run = false; j.msg = 'finished · 0'; lg(j, 'bad', 'No proxy list could be downloaded. Check that this Worker can reach the internet.'); await saveJob(db, j); return { ok: true }; }
  await db.run('DELETE FROM cand');
  for (let i = 0; i < c.list.length; i += 30) { const ch = c.list.slice(i, i + 30); await db.run(`INSERT INTO cand(host,port,proto) VALUES ${ch.map(() => '(?,?,?)').join(',')}`, ...ch.flat()); }
  await saveJob(db, j); return { ok: true };
}
export async function stopJob(db) { const j = await getJob(db); if (j.run) { j.run = false; j.stop = true; j.msg = `stopped · ${j.added} ${j.kind === 'recover' ? 'replaced' : 'added'}`; lg(j, 'w', j.msg); await saveJob(db, j); } return view(j); }

async function probeOne(connect, [h, p, pr]) {
  for (const x of (PROBES.includes(pr) && pr !== 'https' ? [pr] : ['socks5', 'http', 'socks4'])) { const ms = await probe(connect, x, h, p, 3000); if (ms) return { host: h, port: p, proto: x, ms }; }
  return null;
}
async function pool(items, n, fn) { const out = []; let i = 0; await Promise.all(Array.from({ length: n }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } })); return out; }

export async function stepJob(db, connect, fetchFn = fetch) {
  const j = await getJob(db); if (!j.run) return view(j);
  const rows = await db.all('SELECT id,host,port,proto FROM cand ORDER BY id LIMIT ?', BATCH);
  const finish = async () => {
    if (j.kind === 'auto') {
      if (j.added < LOC_MAX) for (const r of j.pool.sort((a, b) => a.ms - b.ms)) { if (j.added >= LOC_MAX) break; if (!j.used.includes(r.g.cc)) await take(r, ' · known country'); }
      if (j.used.length) await db.set('loc_last', JSON.stringify(j.used));
      if (!j.added) lg(j, 'bad', 'No working proxy found this time. Try again in a minute.');
    } else { const left = Object.values(j.need).reduce((n, v) => n + v.length, 0); if (left) lg(j, 'w', `${left} proxy(ies) kept their old address: no replacement from the same country was found.`); }
    j.run = false; j.pool = []; j.msg = `finished · ${j.added} ${j.kind === 'recover' ? 'replaced' : 'added'}`; lg(j, 'ok', j.msg); await db.run('DELETE FROM cand');
  };
  const take = async (r, why) => { await putProxy(db, r.host, r.port, r.proto, r.ms, r.g); j.used.push(r.g.cc); j.added++; j.done = j.added; lg(j, 'ok', `+ ${r.g.name} · ${r.host}:${r.port} · ${r.proto} ${r.ms}ms${why}`); };
  if (!rows.length) { await finish(); await saveJob(db, j); return view(j); }
  await db.run(`DELETE FROM cand WHERE id IN (${rows.map(() => '?').join(',')})`, ...rows.map(r => r.id));
  const ok = (await pool(rows, CONC, r => probeOne(connect, [r.host, r.port, r.proto]))).filter(Boolean);
  j.tried += rows.length; j.alive += ok.length;
  if (ok.length) {
    const g = await geoBatch(ok.map(r => r.host), fetchFn);
    for (const r of ok.sort((a, b) => a.ms - b.ms)) {
      r.g = g[r.host]; if (!r.g) continue; const cc = r.g.cc;
      if (j.kind === 'auto') {
        if (j.added >= LOC_MAX || j.used.includes(cc)) continue;
        if (j.have.includes(cc) || j.last.includes(cc)) { j.pool.push(r); continue; }
        await take(r, '');
      } else if ((j.need[cc] || []).length) {
        const old = j.need[cc].shift();
        await db.run('UPDATE proxies SET host=?,port=?,proto=?,ms=? WHERE id=?', r.host, r.port, r.proto, r.ms, old.id); j.added++; j.done = j.added;
        lg(j, 'ok', `↻ ${old.name} · ${old.host}:${old.port} → ${r.host}:${r.port} · ${r.proto} ${r.ms}ms`);
      }
    }
  }
  lg(j, 'd', `· ${j.tried} checked · ${j.alive} alive`);
  if ((j.kind === 'auto' && j.added >= LOC_MAX) || (j.kind === 'recover' && !Object.values(j.need).some(v => v.length))) await finish();
  j.ts = now(); await saveJob(db, j); return view(j);
}
