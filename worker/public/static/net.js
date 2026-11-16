/* xr PANEL network tools. Everything here runs in YOUR browser, on YOUR network, so a "clean" result is clean for you.
   - IP scanner:   Cloudflare IPv4/IPv6 on TLS + non-TLS ports, custom ports
   - SNI scanner:  which domains really sit behind Cloudflare (verified through /cdn-cgi/trace)
   - Endpoint scanner (WARP / MASQUE): TCP-level reachability of the endpoint IPs (browsers cannot send UDP). */
(() => {
'use strict';
const B = BigInt, now = () => performance.now(), sleep = ms => new Promise(r => setTimeout(r, ms));
const E = t => String(t).replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';');

/* ---------- IP maths (BigInt, v4 + v6) ---------- */
const p4 = s => { const p = s.split('.'); if (p.length !== 4) return null; let n = 0n; for (const x of p) { if (!/^\d{1,3}$/.test(x) || +x > 255) return null; n = (n << 8n) | B(+x); } return n; };
const f4 = n => [24n, 16n, 8n, 0n].map(k => Number((n >> k) & 255n)).join('.');
const p6 = s => {
  s = s.toLowerCase(); const two = s.split('::'); if (two.length > 2 || s.includes('%')) return null;
  const a = two[0] ? two[0].split(':') : [], b = two.length === 2 && two[1] ? two[1].split(':') : [];
  if (two.length === 1 ? a.length !== 8 : a.length + b.length > 7) return null;
  const g = two.length === 1 ? a : [...a, ...Array(8 - a.length - b.length).fill('0'), ...b]; let n = 0n;
  for (const x of g) { if (!/^[0-9a-f]{1,4}$/.test(x)) return null; n = (n << 16n) | B(parseInt(x, 16)); } return n;
};
const f6 = n => {
  const g = []; for (let i = 7; i >= 0; i--) g.push(Number((n >> B(i * 16)) & 0xffffn));
  let bs = -1, bl = 0; for (let i = 0; i < 8;) { if (g[i]) { i++; continue; } let j = i; while (j < 8 && !g[j]) j++; if (j - i > bl) { bs = i; bl = j - i; } i = j; }
  const h = g.map(x => x.toString(16)); if (bl < 2) return h.join(':');
  return h.slice(0, bs).join(':') + '::' + h.slice(bs + bl).join(':');
};
const rnd = max => { // uniform-enough BigInt in [0, max)
  if (max <= 1n) return 0n; const bits = max.toString(2).length + 16; let h = ''; for (let i = 0; i < Math.ceil(bits / 4); i++) h += Math.floor(Math.random() * 16).toString(16);
  return B('0x' + h) % max;
};
const pick = a => a[Math.floor(Math.random() * a.length)];
function parseRange(line) {
  line = line.replace(/#.*/, '').trim(); if (!line) return null;
  const [a, b] = line.split('/'), v6 = a.includes(':'), base = v6 ? p6(a) : p4(a); if (base === null) return null;
  const bits = v6 ? 128 : 32, pl = b === undefined ? bits : +b; if (!/^\d+$/.test(String(pl)) || pl > bits) return null;
  const size = B(bits - pl), mask = (1n << size) - 1n; return { v: v6 ? 6 : 4, base: base & ~mask, size, pl, text: line };
}
const parseRanges = txt => { const ok = [], bad = []; for (const l of txt.split(/[\n,;]+/)) { if (!l.replace(/#.*/, '').trim()) continue; const r = parseRange(l); r ? ok.push(r) : bad.push(l.trim()); } return { ok, bad }; };

/* Cloudflare edge ranges (cloudflare.com/ips) */
const CF4 = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'];
const CF6 = ['2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'];
const WARP4 = ['8.6.112.0/24', '8.34.70.0/24', '8.34.146.0/24', '8.35.211.0/24', '8.39.125.0/24', '8.39.204.0/24', '8.39.214.0/24', '8.47.69.0/24', '162.159.192.0/24', '162.159.195.0/24', '188.114.96.0/24', '188.114.97.0/24', '188.114.98.0/24', '188.114.99.0/24'];
const WARP6 = ['2606:4700:d0::/48', '2606:4700:d1::/48'];
const MASQUE4 = ['162.159.197.0/24', '162.159.198.0/24'], MASQUE6 = ['2606:4700:103::/48'];
const WARP_PORTS = [500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886];
const MASQUE_PORTS = [443, 500, 1701, 4443, 4500, 8443, 8095];
const DEFAULT_PORT = 2053;                                    // default port of the scanners (was 8080)
const TLS_PORTS = [2053, 443, 2083, 2087, 2096, 8443], HTTP_PORTS = [80, 8880, 8080, 2052, 2082, 2086, 2095];
/* ports browsers refuse to connect to (Chromium/Firefox "restricted ports") */
const BAD_PORTS = new Set([1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080]);
const SNI_DEFAULT = ['www.cloudflare.com', 'cloudflare.com', 'blog.cloudflare.com', 'developers.cloudflare.com', 'workers.cloudflare.com', 'speed.cloudflare.com', 'dash.cloudflare.com', 'cdnjs.cloudflare.com', 'discord.com', 'gateway.discord.gg', 'medium.com', 'www.digitalocean.com', 'www.udemy.com', 'openai.com', 'chatgpt.com', 'www.gitlab.com', 'www.canva.com', 'www.shopify.com', 'www.zendesk.com', 'www.nordvpn.com', 'www.ikea.com', 'www.crunchyroll.com', 'www.coindesk.com', 'www.statista.com', 'www.wattpad.com', 'www.npmjs.com', 'www.kaggle.com', 'www.notion.so', 'www.figma.com', 'www.pixiv.net'];

/* Draw n IPs from a list of ranges. mode.pool = IPv4 ranges whose addresses are embedded in the IPv6 low 32 bits (how Cloudflare lays out its v6 edge). */
function sample(ranges, n, mode = {}) {
  const out = new Set(), per = Math.max(1, Math.ceil(n / Math.max(1, ranges.length))), pool = (mode.pool || []).map(parseRange).filter(Boolean);
  for (const r of ranges) {
    const total = r.size > 40n ? Infinity : Number(1n << r.size); let got = 0, tries = 0;
    if (total <= per) { for (let i = 0n; i < BigInt(total); i++) out.add(r.v === 4 ? f4(r.base + i) : f6(r.base + i)); continue; }
    while (got < per && tries++ < per * 8) {
      let ip;
      if (r.v === 4) { const o = r.base + rnd(1n << r.size); if (r.size >= 8n && (o & 255n) % 255n === 0n) continue; ip = f4(o); }
      else if (mode.smart6 && r.pl <= 96 && pool.length) {
        const m = pick(pool), v4 = m.base + rnd(1n << m.size); let o = r.base | v4;
        if (r.pl <= 32) o |= B(pick(mode.mids || [0])) << 80n;                  // 2606:4700:3030:: style prefixes
        ip = f6(o);
      } else ip = f6(r.base + rnd(1n << r.size));
      if (!out.has(ip)) { out.add(ip); got++; }
    }
  }
  const a = [...out]; for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a.slice(0, n);
}

/* ---------- probes ---------- */
const hostUrl = h => h.includes(':') ? '[' + h + ']' : h;
const FETCH = { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' };
async function timedFetch(url, mode, timeout) {
  const ac = new AbortController(), t0 = now(), tm = setTimeout(() => ac.abort(), timeout);
  try { const r = await fetch(url, { ...FETCH, mode, signal: ac.signal }); return { ok: true, ms: now() - t0, r, ac, tm }; }
  catch (e) { clearTimeout(tm); return { ok: false, ms: now() - t0, timeout: ac.signal.aborted }; }
}
const traceInfo = txt => (/(^|\n)(fl|colo)=/.test(txt)) ? { cf: true, colo: (txt.match(/colo=(\w+)/) || [])[1] || '', loc: (txt.match(/loc=(\w+)/) || [])[1] || '' } : { cf: false };

/* plain HTTP: needs an http:// page (or "insecure content: allow") because of mixed-content rules */
async function probeHttp(host, port, timeout, verify = true) {
  const url = `http://${hostUrl(host)}:${port}/cdn-cgi/trace`, a = await timedFetch(url, 'no-cors', timeout);
  if (!a.ok) return { ok: false, ms: a.ms, timeout: a.timeout };
  clearTimeout(a.tm); const res = { ok: true, ms: a.ms, via: 'http' };
  if (verify) { const v = await timedFetch(url + '?v=' + Date.now(), 'cors', 2000); if (v.ok) { try { const i = traceInfo(await v.r.text()); if (i.cf) Object.assign(res, { via: 'cf', colo: i.colo }); } catch (e) {} clearTimeout(v.tm); } }
  return res;
}
/* TLS ports: the certificate cannot match a bare IP, so the page can only see "an error" -> we time it.
   A completed handshake fails after ~2 round trips; a closed or filtered port fails instantly (reset) or never (timeout). */
async function probeTls(host, port, timeout, cal) {
  const a = await timedFetch(`https://${hostUrl(host)}:${port}/cdn-cgi/trace`, 'no-cors', timeout);
  if (a.ok) { clearTimeout(a.tm); return { ok: true, ms: a.ms, via: 'tls' }; }
  if (a.timeout) return { ok: false, ms: a.ms, timeout: true };
  return a.ms >= (cal ? cal.minHs : 0) ? { ok: true, ms: a.ms, via: 'tls' } : { ok: false, ms: a.ms, reset: true };
}
async function probe(host, port, tls, timeout, cal, verify) { return tls ? probeTls(host, port, timeout, cal) : probeHttp(host, port, timeout, verify); }

/* domain behind Cloudflare? trace is read through CORS when allowed, so the answer is verified instead of guessed */
async function probeSni(domain, timeout) {
  const url = `https://${domain}/cdn-cgi/trace?v=${Date.now()}`, a = await timedFetch(url, 'cors', timeout);
  if (a.ok) {
    let txt = ''; try { txt = await a.r.text(); } catch (e) {} clearTimeout(a.tm);
    const i = traceInfo(txt); let ms = a.ms;
    if (i.cf) { const b = await timedFetch(url + '&w=1', 'cors', timeout); if (b.ok) { clearTimeout(b.tm); ms = Math.min(ms, b.ms); } }   // warm connection ~ 1 round trip
    return i.cf ? { ok: true, ms, via: 'cf', colo: i.colo } : { ok: false, ms, why: 'not Cloudflare' };
  }
  if (a.timeout) return { ok: false, ms: a.ms, why: 'timeout' };
  const b = await timedFetch(url, 'no-cors', timeout);           // reachable but CORS hides the body
  if (b.ok) { clearTimeout(b.tm); return { ok: true, ms: b.ms, via: 'open' }; }
  return { ok: false, ms: b.ms, why: b.timeout ? 'timeout' : 'blocked' };
}

/* self-test: tells the user what this browser/network can and cannot measure */
async function calibrate(timeout = 3000) {
  const cal = { tls: false, tlsMs: 0, http: null, v6: false, minHs: 0, fastReject: 0, secure: location.protocol === 'https:' };
  const good = await timedFetch('https://1.1.1.1/cdn-cgi/trace', 'cors', timeout); if (good.ok) { clearTimeout(good.tm); cal.tls = true; cal.tlsMs = Math.round(good.ms); }
  const bad = await timedFetch('https://192.0.2.1/', 'no-cors', timeout);       // TEST-NET-1: must never answer
  if (!bad.ok && !bad.timeout) { cal.fastReject = bad.ms; cal.minHs = Math.max(bad.ms * 1.6, 4); } else clearTimeout(bad.tm);
  const h = await probeHttp('1.1.1.1', 80, timeout, false);
  cal.http = !h.ok && cal.secure && h.ms < 25 ? 'blocked' : true;      // only mixed-content blocking disables plain HTTP; a filtered 1.1.1.1 says nothing about other IPs
  const v6 = await timedFetch('https://[2606:4700:4700::1111]/cdn-cgi/trace', 'cors', timeout); if (v6.ok) { clearTimeout(v6.tm); cal.v6 = true; }
  return cal;
}

/* ---------- engine ---------- */
async function pool(n, conc, fn, ctl) { let i = 0; await Promise.all(Array.from({ length: Math.min(conc, n) }, async () => { while (i < n && !ctl.stop) await fn(i++); })); }

/* ---------- UI bits ---------- */
const BOLT = '<svg class="bolt" viewBox="0 0 24 24" aria-hidden="true"><path d="M13.2 2.5 5 13.6h5.6l-1 7.9 9.4-12.1h-5.8z"/></svg>';
const COPY = async (t, btn) => { try { await navigator.clipboard.writeText(t); } catch (e) { const x = document.createElement('textarea'); x.value = t; document.body.append(x); x.select(); document.execCommand('copy'); x.remove(); } if (btn) { const l = btn.dataset.l = btn.dataset.l || btn.textContent; btn.textContent = 'Copied'; setTimeout(() => btn.textContent = l, 1300); } };
const fmtT = s => String(Math.floor(s / 60)).padStart(2, '0') + ':' + (s % 60).toFixed(1).padStart(4, '0');

class Log {
  constructor(el) { this.el = el; this.q = []; this.t0 = now(); this.raf = 0; }
  reset() { this.el.textContent = ''; this.t0 = now(); }
  add(cls, txt) { this.q.push([cls, txt, (now() - this.t0) / 1000]); if (!this.raf) this.raf = requestAnimationFrame(() => this.flush()); }
  flush() {
    this.raf = 0; const f = document.createDocumentFragment();
    for (const [c, t, s] of this.q.splice(0)) { const d = document.createElement('div'); d.className = 'l ' + c; d.innerHTML = `<i>${fmtT(s)}</i>${t}`; f.append(d); }
    this.el.append(f); while (this.el.childElementCount > 260) this.el.firstChild.remove(); this.el.scrollTop = this.el.scrollHeight;
  }
}
const chipSet = (items, on, cls = '') => { on = on.map(String); return items.map(p => `<button type="button" class="cb ${cls} ${on.includes(String(p)) ? 'sel' : ''}" data-v="${p}">${p}</button>`).join(''); };   // ports are numbers, defaults were strings -> nothing was pre-selected
const selOf = el => [...el.querySelectorAll('.cb.sel')].map(b => b.dataset.v);
function bindChips(root) { root.addEventListener('click', e => { const b = e.target.closest('.cb'); if (b && root.contains(b)) b.classList.toggle('sel'); }); }

/* write the fastest endpoint into the WireGuard / Masque panels (they listen for this event) */
const fmtEp = r => (r.host.includes(':') ? '[' + r.host + ']' : r.host) + ':' + r.port;
async function useFastest(kind, hint) {
  let r = hint; if (!r) { try { r = (await (await fetch('/api/net/list?kind=' + kind)).json())[0]; } catch (e) {} }
  if (!r) return null; window.dispatchEvent(new CustomEvent('xr:endpoint', { detail: { kind, host: r.host, port: r.port, ms: r.ms } })); return r;
}

/* saved list (server side) */
class Saved {
  constructor(el, kind, limit = 0) { this.el = el; this.kind = kind; this.limit = limit; this.load(); }
  async load() {
    let rows = []; try { rows = await (await fetch('/api/net/list?kind=' + this.kind)).json(); } catch (e) {}
    this.rows = rows; const k = this.kind;
    this.el.innerHTML = `<div class="sv-h"><b>Saved · ${rows.length}</b><span><button type="button" class="btn o tl" data-a="copy">Copy</button><button type="button" class="btn o pk" data-a="clear">Clear</button></span></div>` +
      (rows.length ? `<div class="xr">${rows.slice(0, 60).map((r, i) => `<div class="${this.limit && i < this.limit && k === 'ip' ? 'use' : ''}"><span>${E(this.fmt(r))}</span><em>${r.ms} ms</em><button type="button" class="x" data-id="${r.id}" aria-label="Delete">×</button></div>`).join('')}</div>` : '<p class="hint">Nothing saved yet.</p>');
    this.el.onclick = async e => {
      const b = e.target.closest('button'); if (!b) return;
      if (b.dataset.a === 'copy') return COPY(rows.map(r => this.fmt(r)).join('\n'), b);
      if (b.dataset.a === 'clear') { if (!confirm('Delete every saved ' + k + ' entry?')) return; await post('/api/net/delete', { kind: k, all: 1 }); }
      else if (b.dataset.id) await post('/api/net/delete', { kind: k, id: +b.dataset.id }); else return;
      this.load();
    };
  }
  fmt(r) { const h = r.host.includes(':') ? `[${r.host}]` : r.host; return this.kind === 'sni' ? r.host : `${h}:${r.port}`; }
}
const post = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }).then(r => r.json());

/* result board shared by every scanner */
class Board {
  constructor(el, kind, fmt) { this.el = el; this.kind = kind; this.rows = []; this.fmt = fmt; this.dirty = 0; }
  reset() { this.rows = []; this.draw(); }
  add(r) { this.rows.push(r); if (!this.dirty) this.dirty = setTimeout(() => { this.dirty = 0; this.draw(); }, 200); }
  top(n) { return [...this.rows].sort((a, b) => (a.rank || 0) - (b.rank || 0) || a.ms - b.ms).slice(0, n); }
  draw() {
    const t = this.top(40); this.el.innerHTML = t.length ? `<div class="xr">${t.map((r, i) => `<div><u>${i + 1}</u><span>${E(this.fmt(r))}</span><small class="v-${r.via}">${E(r.via === 'cf' ? 'cf' + (r.colo ? '·' + r.colo : '') : r.via)}</small><em>${Math.round(r.ms)} ms</em></div>`).join('')}</div>` : '';
  }
}

/* ---------- scanner panel (IP / SNI / WARP / MASQUE share this shell) ---------- */
function shell(root, { title, note, fast }) {
  root.innerHTML = `<p class="hint">${note}</p><div class="st" data-st></div>
  <div data-body></div>
  <div class="row"><button type="button" class="btn" data-go>Start</button><button type="button" class="btn o pk" data-stop disabled>Stop</button><button type="button" class="btn o yl" data-test>Self-test</button>${fast ? `<button type="button" class="btn o tl" data-fast>${BOLT}Use fastest</button>` : ''}</div>
  <div class="seg" style="--v:0"><i></i><span data-prog>idle</span></div>
  <div class="xlog" data-log aria-live="polite"></div>
  <h3 class="sub">Results</h3><div data-board></div>
  <div class="row"><button type="button" class="btn o tl" data-save disabled>Save top</button><label class="ck"><input type="checkbox" data-auto checked> auto-save when finished</label></div>
  <div class="saved" data-saved></div>`;
  return { body: root.querySelector('[data-body]'), go: root.querySelector('[data-go]'), stop: root.querySelector('[data-stop]'), test: root.querySelector('[data-test]'),
    seg: root.querySelector('.seg'), prog: root.querySelector('[data-prog]'), log: new Log(root.querySelector('[data-log]')), board: root.querySelector('[data-board]'),
    save: root.querySelector('[data-save]'), fast: root.querySelector('[data-fast]'), auto: root.querySelector('[data-auto]'), saved: root.querySelector('[data-saved]'), st: root.querySelector('[data-st]') };
}
function showCal(ui, cal) {
  const c = (ok, t) => `<span class="chip ${ok === true ? 'ok' : ok === 'warn' ? 'run' : ''}">${ok === true ? '✓' : ok === 'warn' ? '!' : '✕'} ${t}</span>`;
  ui.st.innerHTML = c(cal.tls, 'TLS' + (cal.tls ? ' ' + cal.tlsMs + ' ms' : '')) + c(cal.fastReject ? 'warn' : true, cal.fastReject ? 'timing coarse' : 'timing') +
    c(cal.http === true ? true : 'warn', cal.http === 'blocked' ? 'HTTP blocked (https page)' : 'HTTP') + c(cal.v6, 'IPv6');
}
const tick = (ui, done, total, alive, best, t0) => { const p = total ? done / total : 0, s = (now() - t0) / 1000; ui.seg.style.setProperty('--v', Math.round(p * 100)); ui.prog.textContent = `${done}/${total} · ${alive} alive · best ${best ? Math.round(best) + ' ms' : '–'} · ${(done / Math.max(s, .1)).toFixed(1)}/s`; };

function mountScanner(root, cfg) {
  const ui = shell(root, cfg), ctl = { stop: false }; let cal = null, running = false;
  ui.body.innerHTML = cfg.form(); bindChips(ui.body);
  const get = n => ui.body.querySelector(`[data-f="${n}"]`);
  const board = new Board(ui.board, cfg.kind, cfg.fmt), saved = new Saved(ui.saved, cfg.kind, +root.dataset.limit || 0);
  const ensureCal = async () => { if (cal) return cal; ui.log.add('i', 'self-test…'); cal = await calibrate(); showCal(ui, cal); return cal; };
  ui.test.onclick = async () => { ui.test.disabled = true; cal = null; await ensureCal(); ui.log.add(cal.tls ? 'ok' : 'bad', cal.tls ? `Cloudflare reachable · ${cal.tlsMs} ms` : 'Cloudflare 1.1.1.1 not reachable from this network'); ui.test.disabled = false; };
  ui.save.onclick = async () => { const items = board.top(+(get('keep') || { value: 50 }).value || 50).map(cfg.item); if (!items.length) return; const r = await post('/api/net/save', { kind: cfg.kind, items }); ui.log.add('ok', `saved ${r.saved}`); saved.load(); };
  ui.stop.onclick = () => { ctl.stop = true; ui.log.add('w', 'stopping…'); };
  if (ui.fast) ui.fast.onclick = async () => {
    const r = await useFastest(cfg.kind, board.top(1)[0]); ui.log.add(r ? 'ok' : 'bad', r ? `fastest ${E(fmtEp(r))} · ${Math.round(r.ms)} ms → ${cfg.kind === 'warp' ? 'WireGuard' : 'Masque'} endpoint` : 'no endpoint yet — run a scan first');
  };
  ui.go.onclick = async () => {
    if (running) return; running = true; ctl.stop = false; ui.go.disabled = true; ui.stop.disabled = false; ui.save.disabled = true; ui.log.reset(); board.reset();
    const t0 = now(); let done = 0, alive = 0, best = 0, skipped = 0;
    try {
      if (cfg.gate) { const why = await cfg.gate(); if (why) { ui.log.add('bad', why); ui.st.innerHTML = `<span class="chip">✕ ${E(why)}</span>`; return; } }
      await ensureCal();
      const plan = await cfg.plan({ get, cal, log: ui.log }); if (!plan) return;
      const total = plan.total; ui.log.add('i', plan.info);
      const upd = () => tick(ui, done, total, alive, best, t0), iv = setInterval(upd, 250);
      await pool(plan.units.length, plan.conc, async i => {
        const res = await plan.run(plan.units[i], ctl);
        alive += res.alive !== undefined ? res.alive : res.hits.length; for (const r of res.hits) { if (!best || r.ms < best) best = r.ms; board.add(r); ui.log.add('ok', cfg.line(r)); }
        if (res.note) ui.log.add(res.cls || 'd', res.note);
        done += res.count; skipped += res.miss || 0;
        if (res.miss && skipped % 50 < res.miss) ui.log.add('d', `· ${skipped} without answer so far`);
      }, ctl);
      clearInterval(iv); upd();
      ui.log.add(alive ? 'ok' : 'bad', `${ctl.stop ? 'stopped' : 'done'} · ${alive} alive of ${done} · ${((now() - t0) / 1000).toFixed(1)}s`);
      ui.save.disabled = !alive; if (alive && ui.auto.checked && !ctl.stop) ui.save.onclick();
    } catch (e) { ui.log.add('bad', 'error: ' + E(e.message || e)); }
    finally { running = false; ui.go.disabled = false; ui.stop.disabled = true; }
  };
  return { ui, board, saved, setBusy: v => { if (!running) ui.go.disabled = v; } };
}

/* ---------- IP scanner ---------- */
const rangeTxt = a => a.join('\n');
function mountIP(root) {
  const wrap = document.createElement('div'); root.append(wrap);
  const tabs = document.createElement('div'); tabs.className = 'tabs'; tabs.innerHTML = '<button type="button" class="on" data-t="ip">IP</button><button type="button" data-t="sni">SNI</button>';
  wrap.append(tabs); const a = document.createElement('div'), b = document.createElement('div'); b.hidden = true; wrap.append(a, b);
  tabs.onclick = e => { const t = e.target.closest('button'); if (!t) return; tabs.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === t)); a.hidden = t.dataset.t !== 'ip'; b.hidden = t.dataset.t !== 'sni'; };
  a.dataset.limit = root.dataset.limit || 0;

  mountScanner(a, {
    kind: 'ip', note: 'Scans Cloudflare IPs from this browser, so the result is clean for <b>your</b> network. TLS ports are timed (a bare IP cannot match a certificate, so this is meant for Cloudflare ranges); plain-HTTP ports are verified through <code>/cdn-cgi/trace</code>.',
    fmt: r => `${r.host.includes(':') ? '[' + r.host + ']' : r.host}:${r.port}`, item: r => ({ host: r.host, port: r.port, tls: r.tls, ms: r.ms, via: r.via }),
    line: r => `<b>${E(r.host)}</b>:${r.port} <u>${r.tls ? 'tls' : 'http'}</u> ${Math.round(r.ms)}ms ${r.via === 'cf' ? '<s>cf·' + E(r.colo || '?') + '</s>' : ''}`,
    form: () => `
      <div class="grp"><h3>Version</h3>${chipSet(['IPv4', 'IPv6'], ['IPv4', 'IPv6'], 'ver')}</div>
      <div class="grp" data-f="tls"><h3>TLS ports</h3>${chipSet(TLS_PORTS, [DEFAULT_PORT, 443, 2083, 2087, 2096, 8443].map(String))}</div>
      <div class="grp" data-f="http"><h3>Non-TLS ports</h3>${chipSet(HTTP_PORTS, ['80', '8880'])}</div>
      <div class="grp"><h3>Custom port</h3><div class="row" style="margin:0"><input data-f="cport" inputmode="numeric" placeholder="e.g. 2408" style="max-width:130px"><select data-f="ctype"><option value="1">TLS</option><option value="0">non-TLS</option></select><button type="button" class="btn o tl" data-f="cadd">Add</button></div></div>
      <label class="wide">Ranges · IPs or CIDR, one per line<textarea data-f="ranges" rows="5" spellcheck="false">${rangeTxt([...CF4, ...CF6])}</textarea></label>
      <div class="f"><label>IPs to test<input data-f="count" inputmode="numeric" value="150"></label><label>Parallel<input data-f="conc" inputmode="numeric" value="30"></label><label>Timeout (ms)<input data-f="timeout" inputmode="numeric" value="3000"></label><label>Keep best<input data-f="keep" inputmode="numeric" value="50"></label></div>
      <label class="ck"><input type="checkbox" data-f="smart6" checked> smart IPv6 (Cloudflare-style addresses)</label>`,
    async plan({ get, cal, log }) {
      const q = n => get(n), num = (n, d, lo, hi) => Math.min(hi, Math.max(lo, parseInt(q(n).value) || d));
      const vers = selOf(root.querySelector('.grp')); const want4 = vers.includes('IPv4'), want6 = vers.includes('IPv6');
      const ports = [...selOf(q('tls')).map(p => [+p, true]), ...selOf(q('http')).map(p => [+p, false])];
      const bad = ports.filter(([p]) => BAD_PORTS.has(p)); if (bad.length) log.add('w', `browser refuses port ${bad.map(x => x[0]).join(', ')} — skipped`);
      let P = ports.filter(([p]) => !BAD_PORTS.has(p));
      if (cal.http !== true && P.some(x => !x[1])) { log.add('w', cal.http === 'blocked' ? 'non-TLS ports need an http:// panel page (or “insecure content: allow” for this site) — skipped' : 'plain HTTP unavailable — non-TLS ports skipped'); P = P.filter(x => x[1]); }
      if (!P.length) { log.add('bad', 'no usable port selected'); return null; }
      const { ok, bad: badR } = parseRanges(q('ranges').value); if (badR.length) log.add('w', 'ignored: ' + E(badR.slice(0, 3).join(' · ')));
      let R = ok.filter(r => (r.v === 4 ? want4 : want6)); if (!cal.v6) { const n = R.length; R = R.filter(r => r.v === 4); if (n !== R.length) log.add('w', 'no IPv6 on this network — IPv6 ranges skipped'); }
      if (!R.length) { log.add('bad', 'no valid range for the selected versions'); return null; }
      const count = num('count', 150, 1, 5000), timeout = num('timeout', 3000, 500, 15000), conc = num('conc', 30, 1, 120), verify = true;
      const ips = sample(R, count, { smart6: q('smart6').checked, pool: ['104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13'], mids: [0, 0x3030, 0x3031, 0x3032, 0x3033, 0x3034, 0x3035, 0x3036, 0x3037] });
      return {
        units: ips, conc, total: ips.length * P.length, info: `${ips.length} IPs × ${P.length} ports · ${conc} parallel · ${timeout} ms`,
        async run(ip, ctl) {
          const hits = []; let miss = 0, fails = 0, cnt = 0;
          for (const [port, tls] of [...P].sort(() => Math.random() - .5)) {          // an IP that times out twice in a row is skipped
            if (ctl.stop) break; cnt++;
            const r = await probe(ip, port, tls, timeout, cal, verify);
            if (r.ok && (r.via === 'cf' || r.ms >= 2)) { fails = 0; hits.push({ host: ip, port, tls, ms: r.ms, via: r.via, colo: r.colo }); } else { miss++; fails = r.timeout ? fails + 1 : 0; if (fails >= 2) break; }
          }
          return { hits, miss, count: P.length, note: null, cnt };
        }
      };
    }
  }).ui.body.addEventListener('click', e => {
    const b = e.target.closest('[data-f="cadd"]'); if (!b) return; const f = n => a.querySelector(`[data-f="${n}"]`), p = parseInt(f('cport').value);
    if (!(p > 0 && p < 65536)) return; const tls = f('ctype').value === '1', grp = f(tls ? 'tls' : 'http');
    if (!grp.querySelector(`[data-v="${p}"]`)) grp.insertAdjacentHTML('beforeend', `<button type="button" class="cb sel cust" data-v="${p}">${p}</button>`); f('cport').value = '';
  });

  mountScanner(b, {
    kind: 'sni', note: 'Finds domains that really are behind Cloudflare: each one is asked for <code>/cdn-cgi/trace</code> and must answer like a Cloudflare edge. The scan runs from this browser, so latency is yours.',
    fmt: r => r.host, item: r => ({ host: r.host, port: 0, tls: true, ms: r.ms, via: r.via }),
    line: r => `<b>${E(r.host)}</b> ${Math.round(r.ms)}ms <s>${r.via === 'cf' ? 'cf·' + E(r.colo || '?') : 'reachable'}</s>`,
    form: () => `<label class="wide">Domains · one per line (paste your own list or import a file)<textarea data-f="list" rows="6" spellcheck="false">${SNI_DEFAULT.join('\n')}</textarea></label>
      <div class="row" style="margin-top:0"><label class="btn o tl" style="margin:0">Import .txt<input type="file" data-f="file" accept=".txt,text/plain" hidden></label></div>
      <div class="f"><label>Parallel<input data-f="conc" inputmode="numeric" value="12"></label><label>Timeout (ms)<input data-f="timeout" inputmode="numeric" value="4000"></label><label>Keep best<input data-f="keep" inputmode="numeric" value="30"></label></div>
      <label class="ck"><input type="checkbox" data-f="loose"> include reachable domains that hide the trace (CORS) — unverified</label>`,
    async plan({ get, log }) {
      const list = [...new Set(get('list').value.split(/[\s,;]+/).map(s => s.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[\/?#].*$/, '')).filter(s => /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z0-9-]{2,}$/.test(s)))];
      if (!list.length) { log.add('bad', 'no valid domain'); return null; }
      const timeout = Math.min(15000, Math.max(800, parseInt(get('timeout').value) || 4000)), conc = Math.min(40, Math.max(1, parseInt(get('conc').value) || 12)), loose = get('loose').checked;
      return {
        units: list, conc, total: list.length, info: `${list.length} domains · ${conc} parallel`,
        async run(d) { const r = await probeSni(d, timeout); const hit = r.ok && (r.via === 'cf' || loose);
          return { hits: hit ? [{ host: d, port: 0, tls: true, ms: r.ms, via: r.via, colo: r.colo }] : [], count: 1, miss: hit ? 0 : 1, note: !hit && r.why === 'not Cloudflare' ? `<b>${E(d)}</b> answers, but not from Cloudflare` : null, cls: 'w' }; }
      };
    }
  }).ui.body.querySelector('[data-f="file"]').onchange = async e => { const f = e.target.files[0]; if (f) b.querySelector('[data-f="list"]').value = (await f.text()).slice(0, 400000); };
}

/* ---------- WARP / MASQUE endpoint scanner ---------- */
function mountEndpoints(root) {
  const modeBox = document.createElement('div'); modeBox.className = 'tabs'; modeBox.innerHTML = '<button type="button" class="on" data-t="warp">WARP</button><button type="button" data-t="masque">MASQUE</button>';
  const a = document.createElement('div'), b = document.createElement('div'); b.hidden = true; root.append(modeBox, a, b);
  modeBox.onclick = e => { const t = e.target.closest('button'); if (!t) return; modeBox.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === t)); a.hidden = t.dataset.t !== 'warp'; b.hidden = t.dataset.t !== 'masque'; };
  /* MASQUE only scans once a MASQUE device is registered (the endpoint list is useless without one) */
  const masqueReady = async () => { try { const d = await (await fetch('/api/masque', { cache: 'no-store' })).json(); return !!(d && d.private_key); } catch (e) { return false; } };
  const make = (el, kind, label, r4, r6, ports, pool) => {
    const isM = kind === 'masque';
    const sc = mountScanner(el, {
    kind, fast: true, note: `${label} endpoints speak UDP, which a browser cannot send. For every endpoint IP this scan checks the <b>reachability and round-trip time</b> (TCP) and then tests <b>each ${label} port</b> on it. A port that answers over TCP is marked <code>tcp</code> (verified open); a port that cannot be proven from a browser is kept as <code>udp</code> (IP is alive, the UDP port itself can only be confirmed by the client app). Verified ports are ranked first.${isM ? ' <b>Needs a registered Masque device.</b>' : ''}`,
    gate: isM ? async () => (await masqueReady()) ? null : 'Register Masque first — scanning is disabled until a Masque device exists' : null,
    fmt: r => `${r.host.includes(':') ? '[' + r.host + ']' : r.host}:${r.port}`, item: r => ({ host: r.host, port: r.port, tls: false, ms: r.ms, via: r.via || 'tcp' }),
    line: r => `<b>${E(r.host)}</b>:${r.port} ${Math.round(r.ms)}ms <s>${r.via === 'tcp' ? 'tcp ✓' : 'udp ?'}</s>`,
    form: () => `<div class="grp"><h3>Version</h3>${chipSet(['IPv4', 'IPv6'], ['IPv4', 'IPv6'], 'ver')}</div>
      <label class="wide">Ranges<textarea data-f="ranges" rows="4" spellcheck="false">${rangeTxt([...r4, ...r6])}</textarea></label>
      <label class="wide">Ports to scan (comma separated)<textarea data-f="ports" rows="2" spellcheck="false">${ports.join(', ')}</textarea></label>
      <div class="f"><label>IPs to test<input data-f="count" inputmode="numeric" value="120"></label><label>Ports kept per IP<input data-f="pp" inputmode="numeric" value="${ports.length}"></label><label>Parallel<input data-f="conc" inputmode="numeric" value="12"></label><label>Timeout (ms)<input data-f="timeout" inputmode="numeric" value="2500"></label><label>Keep best<input data-f="keep" inputmode="numeric" value="30"></label></div>`,
    async plan({ get, cal, log }) {
      const vers = selOf(el.querySelector('.grp')), { ok } = parseRanges(get('ranges').value);
      let R = ok.filter(r => vers.includes(r.v === 4 ? 'IPv4' : 'IPv6')); if (!cal.v6) R = R.filter(r => r.v === 4);
      const P = [...new Set(get('ports').value.split(/[\s,;]+/).map(Number).filter(p => p > 0 && p < 65536))]; if (!R.length || !P.length) { log.add('bad', 'need a range and a port'); return null; }
      const timeout = Math.min(15000, Math.max(500, parseInt(get('timeout').value) || 2500)), conc = Math.min(60, Math.max(1, parseInt(get('conc').value) || 12)), pp = Math.min(P.length, Math.max(1, parseInt(get('pp').value) || P.length));
      const ips = sample(R, Math.min(5000, Math.max(1, parseInt(get('count').value) || 120)), { smart6: true, pool, mids: [0] });
      const probes = [[443, true]]; if (cal.http === true) probes.push([80, false]);
      const refused = P.filter(p => BAD_PORTS.has(p)); if (refused.length) log.add('w', `browser refuses port ${refused.join(', ')} — kept as unverified udp`);
      return {
        units: ips, conc, total: ips.length, info: `${ips.length} endpoint IPs × ${P.length} ports (${P.join(', ')}) · reachability on ${probes.map(p => p[0]).join('/')} then every port`,
        async run(ip, ctl) {
          let best = null; for (const [p, tls] of probes) { if (ctl.stop) break; const r = await probe(ip, p, tls, timeout, cal, false); if (r.ok && (!best || r.ms < best)) best = r.ms; }
          if (best === null || ctl.stop) return { hits: [], count: 1, miss: 1 };
          const res = await Promise.all(P.map(async port => {
            if (port === 443) return { port, ok: true, ms: best };                      // already measured above
            if (BAD_PORTS.has(port)) return { port, ok: false };
            const r = await probeTls(ip, port, timeout, cal); return { port, ok: r.ok, ms: r.ms };
          }));
          const open = res.filter(x => x.ok).map(x => ({ host: ip, port: x.port, tls: false, ms: x.ms, via: 'tcp', rank: 0 }));
          const rest = res.filter(x => !x.ok).sort(() => Math.random() - .5).map(x => ({ host: ip, port: x.port, tls: false, ms: best, via: 'udp', rank: 1 }));
          return { hits: [...open, ...rest].slice(0, pp), count: 1, alive: 1 };
        }
      };
    }
    });
    if (isM) {   // Start stays disabled until Masque is registered
      const sync = async () => { const ok = await masqueReady(); sc.setBusy(!ok); sc.ui.st.innerHTML = ok ? '' : '<span class="chip">✕ Masque not registered — register it above to enable scanning</span>'; };
      sync(); window.addEventListener('xr:reg', e => { if (e.detail && e.detail.kind === 'masque') sync(); });
    }
    return sc;
  };
  make(a, 'warp', 'WARP', WARP4, WARP6, WARP_PORTS, WARP4); make(b, 'masque', 'MASQUE', MASQUE4, MASQUE6, MASQUE_PORTS, MASQUE4);
}

/* ---------- boot ---------- */
window.XRNET = { BOLT, useFastest, fmtEp, p4, f4, p6, f6, parseRange, parseRanges, sample, probe, probeSni, calibrate, COPY, post, Saved, CF4, CF6, WARP_PORTS, MASQUE_PORTS };
document.addEventListener('DOMContentLoaded', () => {
  const ip = document.querySelector('[data-scan="ip"]'), ep = document.querySelector('[data-scan="ep"]');
  if (ip) mountIP(ip); if (ep) mountEndpoints(ep);
});
if (document.readyState !== 'loading') { const ip = document.querySelector('[data-scan="ip"]'), ep = document.querySelector('[data-scan="ep"]'); if (ip && !ip.firstChild) mountIP(ip); if (ep && !ep.firstChild) mountEndpoints(ep); }
})();
