/* xr PANEL converter (window.CONV): v2ray links <-> Clash <-> sing-box, bulk edit, QR, WireGuard -> Clash / AmneziaWG / Wiresock. All in the browser. */
(() => {
'use strict';
const E = t => String(t).replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';');
const b64d = s => { s = s.trim().replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, ''); while (s.length % 4) s += '='; try { const bin = atob(s); return new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0))); } catch (e) { return null; } };
const b64e = s => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
const dec = s => { try { return decodeURIComponent(s); } catch (e) { return s; } };
const num = (v, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; };
const csv = v => (v ? String(v).split(',').map(s => s.trim()).filter(Boolean) : []);
const hostFmt = h => h.includes(':') && !h.startsWith('[') ? '[' + h + ']' : h;

/* ---------- YAML (the subset Clash files use) ---------- */
function yamlParse(src) {
  const L = []; for (const raw of src.split(/\r?\n/)) { if (/^\s*(#|---|\.\.\.)/.test(raw) || !raw.trim()) continue; const t = stripComment(raw); if (t.trim()) L.push({ ind: t.match(/^ */)[0].length, t: t.trim() }); }
  let i = 0;
  function stripComment(s) { let q = null; for (let k = 0; k < s.length; k++) { const c = s[k]; if (q) { if (c === q && s[k - 1] !== '\\') q = null; } else if (c === '"' || c === "'") q = c; else if (c === '#' && (k === 0 || /\s/.test(s[k - 1]))) return s.slice(0, k).replace(/\s+$/, ''); } return s; }
  function splitKV(t) { let q = null, d = 0; for (let k = 0; k < t.length; k++) { const c = t[k]; if (q) { if (c === q) q = null; } else if (c === '"' || c === "'") q = c; else if ('{['.includes(c)) d++; else if ('}]'.includes(c)) d--; else if (c === ':' && !d && (k === t.length - 1 || t[k + 1] === ' ')) return [unq(t.slice(0, k).trim()), t.slice(k + 1).trim()]; } return null; }
  function unq(s) { if (/^".*"$/.test(s)) { try { return JSON.parse(s); } catch (e) { return s.slice(1, -1); } } if (/^'.*'$/.test(s)) return s.slice(1, -1).replace(/''/g, "'"); return s; }
  function scalar(s) { s = s.trim(); if (s === '') return null; if (s[0] === '{' || s[0] === '[') return flow(s); if (/^["']/.test(s)) return unq(s); if (/^(true|yes)$/i.test(s)) return true; if (/^(false|no)$/i.test(s)) return false; if (/^(null|~)$/i.test(s)) return null; if (/^-?\d+$/.test(s) && s.length < 16) return +s; if (/^-?\d*\.\d+$/.test(s)) return +s; return s; }
  function flow(s) {
    let p = 0; const ws = () => { while (/\s/.test(s[p] || '')) p++; };
    const val = () => { ws(); if (s[p] === '{') { p++; const o = {}; for (; ;) { ws(); if (s[p] === '}') { p++; return o; } let k = tok(':'); ws(); if (s[p] === ':') p++; o[unq(k)] = val(); ws(); if (s[p] === ',') p++; } } if (s[p] === '[') { p++; const a = []; for (; ;) { ws(); if (s[p] === ']') { p++; return a; } a.push(val()); ws(); if (s[p] === ',') p++; } } return scalar(tok(',}]')); };
    const tok = stops => { ws(); let q = s[p] === '"' || s[p] === "'" ? s[p] : null, st = p; if (q) { p++; while (p < s.length && s[p] !== q) p++; p++; return s.slice(st, p); } while (p < s.length && !stops.includes(s[p])) p++; return s.slice(st, p).trim(); };
    return val();
  }
  function block(ind) { return L[i].t.startsWith('- ') || L[i].t === '-' ? list(L[i].ind) : map(L[i].ind); }
  function list(ind) {
    const a = [];
    while (i < L.length && L[i].ind === ind && (L[i].t.startsWith('- ') || L[i].t === '-')) {
      const rest = L[i].t.slice(1).trim();
      if (!rest) { i++; a.push(i < L.length && L[i].ind > ind ? block(L[i].ind) : null); continue; }
      if (splitKV(rest) && !/^[\[{"']/.test(rest)) { L[i] = { ind: ind + 2, t: rest }; a.push(map(ind + 2)); } else { i++; a.push(scalar(rest)); }
    } return a;
  }
  function map(ind) {
    const o = {};
    while (i < L.length && L[i].ind === ind && !L[i].t.startsWith('- ')) {
      const kv = splitKV(L[i].t); if (!kv) { i++; continue; } const [k, v] = kv; i++;
      if (v === '') o[k] = i < L.length && (L[i].ind > ind || (L[i].ind === ind && L[i].t.startsWith('- '))) ? block(L[i].ind) : null; else o[k] = scalar(v);
    } return o;
  }
  return L.length ? block(L[0].ind) : null;
}
const yq = s => (typeof s === 'string' && (s === '' || /^[\w.\-\/+@]+$/.test(s) && !/^(true|false|null|yes|no|~|[\d.]+)$/i.test(s)) ? (s === '' ? '""' : s) : JSON.stringify(s));
function yamlDump(v, ind = 0, inList = false) {
  const pad = ' '.repeat(ind);
  if (Array.isArray(v)) return v.length && v.every(x => typeof x !== 'object' || x === null) ? '[' + v.map(x => typeof x === 'string' ? yq(x) : x).join(', ') + ']' : v.map(x => pad + '- ' + yamlDump(x, ind + 2, true).replace(/^\s+/, '')).join('\n');
  if (v && typeof v === 'object') { const e = Object.entries(v).filter(([, x]) => x !== undefined && x !== null && x !== '' && !(Array.isArray(x) && !x.length)); return e.map(([k, x], n) => { const lead = inList && n === 0 ? '' : pad; const sub = x && typeof x === 'object' && !(Array.isArray(x) && x.every(y => typeof y !== 'object' || y === null)); return lead + k + ':' + (sub ? '\n' + yamlDump(x, ind + 2) : ' ' + yamlDump(x, ind + 2)); }).join('\n'); }
  return typeof v === 'string' ? yq(v) : String(v);
}

/* ---------- links -> model ---------- */
/* model: { type, name, server, port, id (uuid | password), method, net, tls ('' | tls | reality), sni, host, path, alpn:[], fp, pbk, sid, spx, flow, svc, insecure, obfs, obfsPw, user, aid } */
function parseLink(raw) {
  raw = raw.trim(); const m = raw.match(/^([a-z0-9]+):\/\//i); if (!m) return null; const sch = m[1].toLowerCase(), rest = raw.slice(m[0].length);
  try {
    if (sch === 'vmess') {
      const j = JSON.parse(b64d(rest.split('#')[0]) || 'null'); if (!j) return null;
      return { type: 'vmess', name: j.ps || '', server: j.add, port: num(j.port, 443), id: j.id, aid: num(j.aid, 0), method: j.scy || 'auto', net: j.net || 'tcp', tls: j.tls === 'tls' ? 'tls' : '', sni: j.sni || '', host: j.host || '', path: j.path || '', alpn: csv(j.alpn), fp: j.fp || '', svc: j.net === 'grpc' ? j.path || '' : '', htype: j.type || '' };
    }
    if (sch === 'ss') {
      const [body, name = ''] = rest.split('#'); let main = body.split('?')[0], q = new URLSearchParams(body.split('?')[1] || '');
      let userinfo, hp; if (main.includes('@')) { const at = main.lastIndexOf('@'); userinfo = main.slice(0, at); hp = main.slice(at + 1); const d = b64d(dec(userinfo)); userinfo = d && d.includes(':') ? d : dec(userinfo); } else { const d = b64d(main); if (!d) return null; const at = d.lastIndexOf('@'); userinfo = d.slice(0, at); hp = d.slice(at + 1); }
      const i = userinfo.indexOf(':'), hm = hp.replace(/\/$/, '').match(/^(\[[^\]]+\]|[^:]+):(\d+)$/); if (!hm || i < 0) return null;
      const p = { type: 'ss', name: dec(name), server: hm[1].replace(/^\[|\]$/g, ''), port: +hm[2], method: userinfo.slice(0, i), id: userinfo.slice(i + 1), net: q.get('type') || 'tcp', tls: q.get('security') === 'tls' ? 'tls' : '', sni: q.get('sni') || '', host: q.get('host') || '', path: q.get('path') || '', alpn: csv(q.get('alpn')), fp: q.get('fp') || '', plugin: q.get('plugin') || '' };
      return p;
    }
    const u = new URL(raw); const q = u.searchParams, server = u.hostname.replace(/^\[|\]$/g, ''), port = num(u.port, 443), name = dec((u.hash || '').slice(1)), id = dec(u.username);
    const tr = { name, server, port, net: q.get('type') || 'tcp', tls: q.get('security') === 'reality' ? 'reality' : q.get('security') === 'tls' ? 'tls' : '', sni: q.get('sni') || q.get('peer') || '', host: q.get('host') || '', path: q.get('path') || '', alpn: csv(q.get('alpn')), fp: q.get('fp') || '', pbk: q.get('pbk') || '', sid: q.get('sid') || '', spx: q.get('spx') || '', flow: q.get('flow') || '', svc: q.get('serviceName') || '', insecure: q.get('allowInsecure') === '1' || q.get('insecure') === '1', htype: q.get('headerType') || '', mode: q.get('mode') || '' };
    if (sch === 'vless') return { type: 'vless', id, ...tr, enc: q.get('encryption') || 'none' };
    if (sch === 'trojan') return { type: 'trojan', id: dec(u.username), ...tr, tls: tr.tls || 'tls' };
    if (sch === 'hysteria2' || sch === 'hy2') return { type: 'hysteria2', id: dec(u.username + (u.password ? ':' + u.password : '')), name, server, port, tls: 'tls', sni: q.get('sni') || '', insecure: q.get('insecure') === '1', obfs: q.get('obfs') || '', obfsPw: q.get('obfs-password') || '', alpn: csv(q.get('alpn')) };
    if (sch === 'socks' || sch === 'socks5' || sch === 'http' || sch === 'https') { let user = dec(u.username), pw = dec(u.password); if (user && !pw) { const d = b64d(user); if (d && d.includes(':')) [user, pw] = d.split(/:(.*)/s); } return { type: sch.startsWith('socks') ? 'socks' : 'http', name, server, port: num(u.port, sch === 'https' ? 443 : 1080), user, id: pw, tls: sch === 'https' ? 'tls' : '' }; }
  } catch (e) { return null; } return null;
}

function toLink(p) {
  const H = hostFmt(p.server), tag = '#' + encodeURIComponent(p.name || ''), Q = (o) => { const s = new URLSearchParams(); for (const [k, v] of Object.entries(o)) if (v !== '' && v !== undefined && v !== null && v !== false) s.set(k, v === true ? '1' : v); return s.toString().replace(/\+/g, '%20'); };
  const tq = () => Q({ type: p.net && p.net !== 'tcp' ? p.net : (p.type === 'vless' ? 'tcp' : ''), security: p.tls || (p.type === 'vless' ? 'none' : ''), sni: p.sni, host: p.host, path: p.net === 'grpc' ? '' : p.path, serviceName: p.svc, alpn: (p.alpn || []).join(','), fp: p.fp, pbk: p.pbk, sid: p.sid, spx: p.spx, flow: p.flow, allowInsecure: p.insecure, headerType: p.htype && p.htype !== 'none' ? p.htype : '', mode: p.mode });
  switch (p.type) {
    case 'vmess': return 'vmess://' + b64e(JSON.stringify({ v: '2', ps: p.name || '', add: p.server, port: String(p.port), id: p.id, aid: String(p.aid || 0), scy: p.method || 'auto', net: p.net || 'tcp', type: p.htype || 'none', host: p.host || '', path: p.net === 'grpc' ? p.svc : p.path || '', tls: p.tls === 'tls' ? 'tls' : '', sni: p.sni || '', alpn: (p.alpn || []).join(','), fp: p.fp || '' }));
    case 'vless': return `vless://${encodeURIComponent(p.id)}@${H}:${p.port}?${Q({ encryption: p.enc || 'none' })}&${tq()}${tag}`;
    case 'trojan': return `trojan://${encodeURIComponent(p.id)}@${H}:${p.port}?${tq()}${tag}`;
    case 'ss': return `ss://${b64e(p.method + ':' + p.id).replace(/=+$/, '')}@${H}:${p.port}${p.net && p.net !== 'tcp' || p.tls || p.plugin ? '?' + Q({ type: p.net !== 'tcp' ? p.net : '', security: p.tls, sni: p.sni, host: p.host, path: p.path, plugin: p.plugin }) : ''}${tag}`;
    case 'hysteria2': return `hysteria2://${encodeURIComponent(p.id)}@${H}:${p.port}?${Q({ sni: p.sni, insecure: p.insecure, obfs: p.obfs, 'obfs-password': p.obfsPw, alpn: (p.alpn || []).join(',') })}${tag}`;
    case 'socks': return `socks://${b64e((p.user || '') + ':' + (p.id || '')).replace(/=+$/, '')}@${H}:${p.port}${tag}`;
    case 'http': return `${p.tls ? 'https' : 'http'}://${p.user ? encodeURIComponent(p.user) + ':' + encodeURIComponent(p.id || '') + '@' : ''}${H}:${p.port}${tag}`;
  } return '';
}

/* ---------- model <-> Clash / sing-box ---------- */
const NET_CL = { tcp: 'tcp', ws: 'ws', grpc: 'grpc', h2: 'h2', http: 'h2', httpupgrade: 'ws' };
function toClash(p) {
  const c = { name: p.name || p.server, type: { ss: 'ss', socks: 'socks5' }[p.type] || p.type, server: p.server, port: p.port, udp: true };
  if (p.type === 'vless' || p.type === 'vmess') { c.uuid = p.id; if (p.type === 'vmess') { c.alterId = p.aid || 0; c.cipher = p.method || 'auto'; } if (p.flow) c.flow = p.flow; }
  else if (p.type === 'trojan' || p.type === 'hysteria2') c.password = p.id; else if (p.type === 'ss') { c.cipher = p.method; c.password = p.id; if (p.plugin) c.plugin = p.plugin; }
  else if (p.type === 'socks' || p.type === 'http') { if (p.user) c.username = p.user; if (p.id) c.password = p.id; if (p.tls) c.tls = true; return c; }
  if (p.type === 'hysteria2') { c.sni = p.sni; if (p.insecure) c['skip-cert-verify'] = true; if (p.obfs) { c.obfs = p.obfs; c['obfs-password'] = p.obfsPw; } if (p.alpn && p.alpn.length) c.alpn = p.alpn; return c; }
  if (p.type !== 'ss') { c.network = NET_CL[p.net] || p.net || 'tcp'; if (p.tls) c.tls = true; if (p.sni) c[p.type === 'trojan' ? 'sni' : 'servername'] = p.sni; if (p.insecure) c['skip-cert-verify'] = true; if (p.fp) c['client-fingerprint'] = p.fp; if (p.alpn && p.alpn.length) c.alpn = p.alpn; }
  if (p.tls === 'reality') c['reality-opts'] = { 'public-key': p.pbk, 'short-id': p.sid };
  if (p.net === 'ws' || p.net === 'httpupgrade') c['ws-opts'] = { path: p.path || '/', headers: p.host ? { Host: p.host } : undefined, 'v2ray-http-upgrade': p.net === 'httpupgrade' || undefined };
  if (p.net === 'grpc') c['grpc-opts'] = { 'grpc-service-name': p.svc || p.path };
  if (p.net === 'h2' || p.net === 'http') c['h2-opts'] = { path: p.path || '/', host: p.host ? [p.host] : undefined };
  return c;
}
function fromClash(c) {
  const t = { socks5: 'socks', ssr: 'ssr' }[c.type] || c.type; if (!['vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'socks', 'http'].includes(t)) return null;
  const p = { type: t, name: c.name || '', server: c.server, port: num(c.port, 443), id: c.uuid || c.password || c.auth || '', method: t === 'ss' ? c.cipher : c.cipher, aid: c.alterId, net: c.network || 'tcp', tls: c['reality-opts'] ? 'reality' : (c.tls || t === 'trojan' || t === 'hysteria2') ? 'tls' : '', sni: c.servername || c.sni || '', insecure: !!c['skip-cert-verify'], fp: c['client-fingerprint'] || '', alpn: c.alpn || [], flow: c.flow || '', user: c.username || '', plugin: c.plugin || '' };
  if (c['reality-opts']) { p.pbk = c['reality-opts']['public-key']; p.sid = c['reality-opts']['short-id']; }
  const ws = c['ws-opts']; if (ws) { p.path = ws.path || ''; p.host = (ws.headers && (ws.headers.Host || ws.headers.host)) || ''; if (ws['v2ray-http-upgrade']) p.net = 'httpupgrade'; }
  if (c['grpc-opts']) p.svc = c['grpc-opts']['grpc-service-name'] || ''; const h2 = c['h2-opts']; if (h2) { p.path = h2.path || ''; p.host = [].concat(h2.host || [])[0] || ''; }
  if (t === 'hysteria2') { p.obfs = c.obfs || ''; p.obfsPw = c['obfs-password'] || ''; }
  return p;
}
function toSing(p) {
  const o = { type: { ss: 'shadowsocks', socks: 'socks' }[p.type] || p.type, tag: p.name || p.server, server: p.server, server_port: p.port };
  if (p.type === 'vless') { o.uuid = p.id; if (p.flow) o.flow = p.flow; } else if (p.type === 'vmess') { o.uuid = p.id; o.security = p.method || 'auto'; o.alter_id = p.aid || 0; }
  else if (p.type === 'trojan' || p.type === 'hysteria2') o.password = p.id; else if (p.type === 'ss') { o.method = p.method; o.password = p.id; if (p.plugin) { const [pl, ...r] = p.plugin.split(';'); o.plugin = pl; o.plugin_opts = r.join(';'); } }
  else { if (p.user) o.username = p.user; if (p.id) o.password = p.id; if (p.tls) o.tls = { enabled: true }; return o; }
  if (p.tls || p.type === 'hysteria2') { o.tls = { enabled: true, server_name: p.sni || undefined, insecure: p.insecure || undefined, alpn: p.alpn && p.alpn.length ? p.alpn : undefined }; if (p.fp) o.tls.utls = { enabled: true, fingerprint: p.fp }; if (p.tls === 'reality') o.tls.reality = { enabled: true, public_key: p.pbk, short_id: p.sid }; }
  if (p.type === 'hysteria2' && p.obfs) o.obfs = { type: p.obfs, password: p.obfsPw };
  if (p.type !== 'ss' && p.type !== 'hysteria2') {
    if (p.net === 'ws') o.transport = { type: 'ws', path: p.path || '/', headers: p.host ? { Host: p.host } : undefined };
    else if (p.net === 'grpc') o.transport = { type: 'grpc', service_name: p.svc || p.path };
    else if (p.net === 'httpupgrade') o.transport = { type: 'httpupgrade', path: p.path || '/', host: p.host || undefined };
    else if (p.net === 'h2' || p.net === 'http') o.transport = { type: 'http', path: p.path || '/', host: p.host ? [p.host] : undefined };
  } return o;
}
function fromSing(o) {
  const t = { shadowsocks: 'ss', socks: 'socks' }[o.type] || o.type; if (!['vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'socks', 'http'].includes(t)) return null;
  const tl = o.tls || {}, tr = o.transport || {}, p = { type: t, name: o.tag || '', server: o.server, port: num(o.server_port, 443), id: o.uuid || o.password || '', method: o.method || o.security || '', aid: o.alter_id, net: ({ http: 'h2' }[tr.type]) || tr.type || 'tcp', tls: tl.reality && tl.reality.enabled ? 'reality' : tl.enabled ? 'tls' : '', sni: tl.server_name || '', insecure: !!tl.insecure, fp: tl.utls ? tl.utls.fingerprint : '', alpn: tl.alpn || [], flow: o.flow || '', user: o.username || '', host: (tr.headers && tr.headers.Host) || [].concat(tr.host || [])[0] || '', path: tr.path || '', svc: tr.service_name || '', pbk: tl.reality ? tl.reality.public_key : '', sid: tl.reality ? tl.reality.short_id : '' };
  if (o.plugin) p.plugin = o.plugin + (o.plugin_opts ? ';' + o.plugin_opts : ''); if (o.obfs) { p.obfs = o.obfs.type; p.obfsPw = o.obfs.password; } return p;
}

/* any text -> list of models (+ notes) */
function extract(text) {
  const t = text.trim(), notes = []; if (!t) return { list: [], notes };
  const out = [];
  try { if (/^[\[{]/.test(t)) { const j = JSON.parse(t); const arr = Array.isArray(j) ? j : j.outbounds || j.proxies || []; for (const o of arr) { const p = fromSing(o); if (p) out.push(p); } if (out.length) return { list: out, notes }; } } catch (e) {}
  if (/^\s*(proxies|proxy-groups|port|mixed-port|mode)\s*:/m.test(t) || /^\s*-\s+(name|\{)/m.test(t)) { try { const y = yamlParse(t); const arr = (y && y.proxies) || (Array.isArray(y) ? y : []); let skipped = 0; for (const c of arr) { const p = fromClash(c); p ? out.push(p) : skipped++; } if (skipped) notes.push(skipped + ' unsupported entr' + (skipped === 1 ? 'y' : 'ies') + ' skipped'); if (out.length) return { list: out, notes }; } catch (e) { notes.push('YAML could not be read'); } }
  let body = t; if (!/:\/\//.test(t)) { const d = b64d(t); if (d && /:\/\//.test(d)) body = d; }
  let bad = 0; for (const m of body.matchAll(/\b(?:vless|vmess|trojan|ss|hysteria2|hy2|socks5?|https?):\/\/[^\s"'<>]+/gi)) { const p = parseLink(m[0]); p ? out.push(p) : bad++; }
  if (bad) notes.push(bad + ' link' + (bad === 1 ? '' : 's') + ' could not be read'); return { list: out, notes };
}
window.CONV = { yamlParse, yamlDump, parseLink, toLink, toClash, fromClash, toSing, fromSing, extract, b64d, b64e };

/* ---------- UI ---------- */
const copy = (t, b) => XRNET_COPY(t, b);
const XRNET_COPY = async (t, btn) => { try { await navigator.clipboard.writeText(t); } catch (e) { const x = document.createElement('textarea'); x.value = t; document.body.append(x); x.select(); document.execCommand('copy'); x.remove(); } if (btn) { const l = btn.dataset.l = btn.dataset.l || btn.textContent; btn.textContent = 'Copied'; setTimeout(() => btn.textContent = l, 1300); } };
const dl = (name, text) => WG.download(name, text);
const fetchSub = async url => { const r = await (await fetch('/api/fetch', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) })).json(); if (!r.ok) throw new Error(r.error || 'failed'); return r.text; };
const TYPES = ['vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'socks', 'http'];

function mountConfigs(root, mode) {
  const bulk = mode === 'links';
  root.innerHTML = `<p class="hint">${bulk ? 'Paste links, a base64 subscription, Clash YAML or sing-box JSON (or fetch a subscription URL). Filter, edit in bulk, then copy or scan.' : 'Paste any of: links, base64 subscription, Clash YAML, sing-box JSON. Pick the output format.'}</p>
  <textarea data-in rows="6" spellcheck="false" placeholder="vless://… vmess://… trojan://… ss://…  or  proxies: …  or  { &quot;outbounds&quot;: … }"></textarea>
  <div class="row"><input data-url placeholder="Subscription URL (fetched by the panel)" spellcheck="false" autocapitalize="off" style="flex:1;min-width:200px"><button type="button" class="btn o tl" data-fetch>Fetch</button><label class="btn o yl" style="margin:0">File<input type="file" data-file hidden></label></div>
  <p class="hint err" data-msg hidden></p><div class="st" data-chips></div>
  ${bulk ? `<div class="f"><label>Address (one per line, makes a copy of each config)<textarea data-o="addr" rows="2" spellcheck="false" placeholder="keep original"></textarea></label><label>Port<input data-o="port" inputmode="numeric" placeholder="keep"></label><label>SNI<input data-o="sni" placeholder="keep" spellcheck="false"></label><label>Host header<input data-o="host" placeholder="keep" spellcheck="false"></label><label>Name template<input data-o="name" value="{name}" spellcheck="false"></label></div><p class="hint">Template tokens: {n} number · {name} original · {proto} · {addr}</p>` : `<div class="tabs" data-fmt><button type="button" class="on" data-o2="clash">Clash</button><button type="button" data-o2="sing">Sing-box</button><button type="button" data-o2="links">Links</button><button type="button" data-o2="sub">Base64 sub</button></div>`}
  <div data-out></div>`;
  const q = s => root.querySelector(s), st = { list: [], types: new Set(TYPES), fmt: 'clash' };
  const msg = (t, bad = true) => { const m = q('[data-msg]'); m.hidden = !t; m.textContent = t || ''; m.className = 'hint ' + (bad ? 'err' : ''); };
  const apply = () => {
    let L = st.list.filter(p => st.types.has(p.type)); if (!bulk) return L;
    const O = n => (q(`[data-o="${n}"]`).value || '').trim(), addrs = O('addr').split(/[\s,]+/).filter(Boolean), port = num(O('port'), 0), tpl = q('[data-o="name"]').value || '{name}', res = []; let n = 0;
    for (const p of L) for (const a of (addrs.length ? addrs : [null])) { const c = { ...p }; if (a) c.server = a.replace(/^\[|\]$/g, ''); if (port) c.port = port; if (O('sni')) c.sni = O('sni'); if (O('host')) c.host = O('host'); n++; c.name = tpl.replace(/\{n\}/g, n).replace(/\{name\}/g, p.name || '').replace(/\{proto\}/g, p.type).replace(/\{addr\}/g, c.server); res.push(c); }
    return res;
  };
  const chips = () => { const cnt = {}; st.list.forEach(p => cnt[p.type] = (cnt[p.type] || 0) + 1); q('[data-chips]').innerHTML = Object.keys(cnt).map(t => `<button type="button" class="cb ${st.types.has(t) ? 'sel' : ''}" data-t="${t}">${t} · ${cnt[t]}</button>`).join(''); };
  const render = () => {
    const L = apply(), out = q('[data-out]');
    if (!L.length) { out.innerHTML = ''; return; }
    if (bulk) {
      const links = L.map(toLink);
      out.innerHTML = `<div class="sv-h"><b>${L.length} config${L.length === 1 ? '' : 's'}</b><span><button type="button" class="btn o tl" data-all>Copy all</button><button type="button" class="btn o yl" data-b64>Copy base64</button><button type="button" class="btn o tl" data-save>.txt</button></span></div><div class="cfgs">${L.map((p, i) => `<div class="cfg"><div><b>${E(p.name || p.server)}</b><small>${p.type}${p.net && p.net !== 'tcp' ? ' · ' + E(p.net) : ''}${p.tls ? ' · ' + p.tls : ''} · ${E(p.server)}:${p.port}</small></div><span><button type="button" class="btn o tl" data-c="${i}">Copy</button><button type="button" class="btn o pu" data-q="${i}">QR</button></span><div class="qr" data-qr="${i}" hidden></div></div>`).join('')}</div>`;
      out.querySelector('[data-all]').onclick = e => copy(links.join('\n'), e.target); out.querySelector('[data-b64]').onclick = e => copy(b64e(links.join('\n')), e.target); out.querySelector('[data-save]').onclick = () => dl('configs.txt', links.join('\n'));
      out.querySelectorAll('[data-c]').forEach(b => b.onclick = e => copy(links[b.dataset.c], e.target));
      out.querySelectorAll('[data-q]').forEach(b => b.onclick = () => { const box = out.querySelector(`[data-qr="${b.dataset.q}"]`); if (box.hidden) { try { box.innerHTML = QR.svg(links[b.dataset.q], 4); } catch (e) { box.textContent = 'Too long for a QR code'; } } box.hidden = !box.hidden; });
    } else {
      const f = st.fmt; let txt = '', ext = 'txt', skipped = 0;
      if (f === 'clash') { txt = 'proxies:\n' + yamlDump(L.map(toClash), 2).replace(/^/gm, '').split('\n').map(l => l).join('\n'); txt = 'proxies:\n' + yamlDump(L.map(toClash), 2); ext = 'yaml'; }
      else if (f === 'sing') { txt = JSON.stringify({ outbounds: L.map(toSing) }, null, 2); ext = 'json'; }
      else { const ls = L.map(toLink); txt = f === 'sub' ? b64e(ls.join('\n')) : ls.join('\n'); }
      out.innerHTML = `<textarea class="code" rows="12" readonly spellcheck="false"></textarea><div class="row"><button type="button" class="btn o tl" data-cp>Copy</button><button type="button" class="btn o yl" data-dl>Download</button></div>`; out.querySelector('textarea').value = txt;
      out.querySelector('[data-cp]').onclick = e => copy(txt, e.target); out.querySelector('[data-dl]').onclick = () => dl('converted.' + ext, txt);
    }
  };
  const load = text => { const { list, notes } = extract(text); st.list = list; st.types = new Set(TYPES); chips(); msg(!list.length ? 'Nothing recognised in this text.' : notes.join(' · '), !list.length); render(); };
  q('[data-in]').addEventListener('input', () => load(q('[data-in]').value));
  q('[data-chips]').onclick = e => { const b = e.target.closest('[data-t]'); if (!b) return; st.types.has(b.dataset.t) ? st.types.delete(b.dataset.t) : st.types.add(b.dataset.t); chips(); render(); };
  root.querySelectorAll('[data-o]').forEach(i => i.addEventListener('input', render));
  const fm = q('[data-fmt]'); if (fm) fm.onclick = e => { const b = e.target.closest('button'); if (!b) return; fm.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); st.fmt = b.dataset.o2; render(); };
  q('[data-fetch]').onclick = async e => { const u = q('[data-url]').value.trim(); if (!u) return; const b = e.target; b.disabled = true; msg(''); try { const t = await fetchSub(u); q('[data-in]').value = t.slice(0, 600000); load(t); } catch (x) { msg(x.message); } b.disabled = false; };
  q('[data-file]').onchange = async e => { const f = e.target.files[0]; if (f) { const t = await f.text(); q('[data-in]').value = t.slice(0, 600000); load(t); } };
}

/* ---------- WireGuard converter ---------- */
function mountWG(root) {
  const { I_PRESETS, IK, JUNK } = WG;
  root.innerHTML = `<p class="hint">Paste or upload WireGuard <code>.conf</code> files (a WARP config works too) and convert them to Clash, AmneziaWG or Wiresock.</p>
  <textarea data-in rows="8" spellcheck="false" placeholder="[Interface]&#10;PrivateKey = …&#10;Address = …&#10;&#10;[Peer]&#10;PublicKey = …&#10;Endpoint = host:port"></textarea>
  <div class="row"><label class="btn o yl" style="margin:0">Upload .conf<input type="file" data-file accept=".conf,.txt" multiple hidden></label></div>
  <p class="hint err" data-msg hidden></p>
  <div class="grp"><h3>Output</h3><div class="tabs" data-kind><button type="button" class="on" data-k="clash">Clash</button><button type="button" data-k="awg">AmneziaWG</button><button type="button" data-k="wiresock">Wiresock</button></div></div>
  <div data-opts>
    <div class="grp"><h3>Junk packets</h3><div class="tabs" data-junk><button type="button" class="on" data-j="light">Light</button><button type="button" data-j="heavy">Heavy</button><button type="button" data-j="custom">Custom</button><button type="button" data-j="random">Random</button></div></div>
    <div class="f" data-cj hidden><label>Jc<input data-f="jc" value="3" inputmode="numeric"></label><label>Jmin<input data-f="jmin" value="1" inputmode="numeric"></label><label>Jmax<input data-f="jmax" value="3" inputmode="numeric"></label></div>
    <div data-i hidden><label class="ck"><input type="checkbox" data-f="a15"> Amnezia 1.5 packets (I1–I5)</label><div data-a15 hidden><div class="row" style="margin-top:0">${[1, 2, 3, 4].map(n => `<button type="button" class="btn o tl" data-set="${n}">Set ${n}</button>`).join('')}</div>${IK.map(k => `<label class="wide">${k.toUpperCase()}<input data-f="${k}" spellcheck="false"></label>`).join('')}</div></div>
    <div class="f"><label>MTU<input data-f="mtu" placeholder="keep" inputmode="numeric"></label><label>Endpoint<input data-f="ep" placeholder="keep" spellcheck="false"></label><label data-rs>Reserved (a,b,c)<input data-f="rs" placeholder="optional" spellcheck="false"></label><label data-wsk hidden>Id / Ip / Ib<input data-f="ws" placeholder="Id, QUIC, Chrome" spellcheck="false"></label></div>
  </div>
  <div data-out></div>`;
  const q = s => root.querySelector(s), f = n => q(`[data-f="${n}"]`); let kind = 'clash', junk = 'light', files = [];
  const msg = t => { const m = q('[data-msg]'); m.hidden = !t; m.textContent = t || ''; };
  const model = (c, i) => {
    const I = c.iface, P = c.peers[0]; if (!I || !I.privatekey || !P || !P.publickey || !P.endpoint) return null;
    const m = { name: (files[i] ? files[i].replace(/\.\w+$/, '') : 'wg-' + (i + 1)), private: I.privatekey, public: P.publickey, psk: P.presharedkey || '', address: I.address || '', dns: I.dns || '1.1.1.1', mtu: +f('mtu').value || +I.mtu || 1280, allowed: P.allowedips || '0.0.0.0/0, ::/0', endpoint: f('ep').value.trim() || P.endpoint, keepalive: +P.persistentkeepalive || '', reserved: f('rs').value.split(',').map(x => parseInt(x)).filter(n => n >= 0 && n < 256).slice(0, 3) };
    if (kind !== 'clash') { const have = I.jc !== undefined; let j; if (junk === 'custom') j = { jc: f('jc').value, jmin: f('jmin').value, jmax: f('jmax').value }; else if (junk === 'random') j = WG.randJunk(); else j = JUNK[junk]; m.awg = WG.awgBase(j); if (have && junk === 'light' && false) m.awg = { ...m.awg }; if (kind === 'awg' && f('a15').checked) IK.forEach(k => m.awg[k] = f(k).value.trim()); if (kind === 'wiresock') { const [id, ip, ib] = f('ws').value.split(',').map(s => s.trim()); m.ws = { id, ip: ip || 'QUIC', ib: ib || 'Chrome' }; } }
    return m;
  };
  const render = () => {
    const text = q('[data-in]').value.trim(); const out = q('[data-out]'); out.innerHTML = '';
    const blocks = text ? text.split(/(?=^\s*\[Interface\])/mi).filter(b => /\[Interface\]/i.test(b)) : []; if (!blocks.length) { msg(text ? 'No [Interface] section found.' : ''); return; }
    const ms = blocks.map((b, i) => model(WG.parseConf(b), i)); const ok = ms.filter(Boolean); msg(ok.length < ms.length ? (ms.length - ok.length) + ' config(s) skipped: PrivateKey, PublicKey and Endpoint are required.' : '');
    if (!ok.length) return; const txt = kind === 'clash' ? 'proxies:\n' + ok.map(m => WG.toClash(m).replace(/^/gm, '  ')).join('\n') : ok.map(m => WG.toConf(m, kind)).join('\n\n');
    out.innerHTML = `<textarea class="code" rows="14" readonly spellcheck="false"></textarea><div class="row"><button type="button" class="btn o tl" data-cp>Copy</button><button type="button" class="btn o yl" data-dl>Download</button></div>`; out.querySelector('textarea').value = txt;
    out.querySelector('[data-cp]').onclick = e => copy(txt, e.target);
    out.querySelector('[data-dl]').onclick = () => { if (kind === 'clash' || ok.length === 1) dl(kind === 'clash' ? 'wireguard-clash.yaml' : (ok[0].name || 'wg') + '.conf', txt); else ok.forEach((m, i) => setTimeout(() => dl((m.name || 'wg' + i) + '.conf', WG.toConf(m, kind)), i * 350)); };
  };
  const tabs = (el, attr, fn) => el.onclick = e => { const b = e.target.closest('button'); if (!b) return; el.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); fn(b.dataset[attr]); render(); };
  tabs(q('[data-kind]'), 'k', k => { kind = k; q('[data-opts] .grp').hidden = q('[data-cj]').hidden = k === 'clash'; q('[data-junk]').parentElement.hidden = k === 'clash'; q('[data-cj]').hidden = k === 'clash' || junk !== 'custom'; q('[data-i]').hidden = k !== 'awg'; q('[data-rs]').hidden = k !== 'clash'; q('[data-wsk]').hidden = k !== 'wiresock'; });
  tabs(q('[data-junk]'), 'j', j => { junk = j; q('[data-cj]').hidden = j !== 'custom'; });
  q('[data-junk]').parentElement.hidden = true; q('[data-cj]').hidden = true;
  f('a15').onchange = () => { q('[data-a15]').hidden = !f('a15').checked; render(); };
  root.querySelectorAll('[data-set]').forEach(b => b.onclick = () => { IK.forEach(k => f(k).value = I_PRESETS[b.dataset.set][k] || ''); render(); });
  root.querySelectorAll('[data-f]').forEach(i => i.addEventListener('input', render)); q('[data-in]').addEventListener('input', () => { files = []; render(); });
  q('[data-file]').onchange = async e => { files = [...e.target.files].map(x => x.name); const t = (await Promise.all([...e.target.files].map(x => x.text()))).join('\n\n'); q('[data-in]').value = t.slice(0, 400000); render(); };
}

document.addEventListener('DOMContentLoaded', () => { const a = document.querySelector('[data-conv="links"]'), b = document.querySelector('[data-conv="wg"]'), c = document.querySelector('[data-conv="formats"]'); if (a) mountConfigs(a, 'links'); if (b) mountWG(b); if (c) mountConfigs(c, 'formats'); });
})();
