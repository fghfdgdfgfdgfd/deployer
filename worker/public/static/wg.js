/* WireGuard / AmneziaWG / Wiresock helpers (window.WG) + the WireGuard and MASQUE panels of the Network page. */
(() => {
'use strict';
const E = t => String(t).replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';');
const ri = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
const hex = s => [...new TextEncoder().encode(s)].map(b => b.toString(16).padStart(2, '0')).join('');
const AWG = ['jc', 'jmin', 'jmax', 's1', 's2', 'h1', 'h2', 'h3', 'h4'], IK = ['i1', 'i2', 'i3', 'i4', 'i5'];

/* AmneziaWG 1.5 "signature" packets. They imitate a protocol's first datagram so DPI sees something familiar.
   Syntax: <b 0x..> fixed bytes, <r N> N random bytes. Built here from parts (no captured blobs). */
const dns = d => '<r 2><b 0x' + '01000001000000000000' + d.split('.').map(l => l.length.toString(16).padStart(2, '0') + hex(l)).join('') + '0000010001>';
const sip = '<b 0x' + hex('INVITE sip:bob@biloxi.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\nMax-Forwards: 70\r\nTo: Bob <sip:bob@biloxi.com>\r\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\r\nCall-ID: a84b4c76e66710@pc33.atlanta.com\r\nCSeq: 314159 INVITE\r\nContent-Length: 0\r\n\r\n') + '>';
const quic = n => `<b 0xc00000000108><r 8><b 0x0000${(0x4000 | n).toString(16).padStart(4, '0')}><r ${n}>`;
const I_PRESETS = {
  1: { i1: dns('www.apple.com'), i2: dns('www.apple.com').replace('0000010001>', '00001c0001>'), i3: '', i4: '', i5: '' },
  2: { i1: sip, i2: '', i3: '', i4: '', i5: '' },
  3: { i1: quic(1180), i2: '', i3: '', i4: '', i5: '' },
  4: { i1: quic(1180), i2: '<r 64>', i3: '', i4: '', i5: '' },
};
const JUNK = { light: { jc: 3, jmin: 1, jmax: 3 }, heavy: { jc: 5, jmin: 10, jmax: 40 } };
const randJunk = () => { const jmin = ri(1, 1279); return { jc: ri(1, 128), jmin, jmax: ri(jmin + 1, 1280) }; };
const fixJunk = j => { j = { ...j }; j.jc = Math.max(1, +j.jc || 3); j.jmin = Math.max(1, +j.jmin || 1); j.jmax = +j.jmax || j.jmin + 1; if (j.jmax <= j.jmin) j.jmax = j.jmin + 1; return j; };
const awgBase = j => ({ ...fixJunk(j), s1: 0, s2: 0, h1: 1, h2: 2, h3: 3, h4: 4 });

/* .conf parser: keeps unknown keys, supports several [Peer] blocks */
function parseConf(text) {
  const c = { iface: {}, peers: [] }; let cur = null;
  for (let line of text.split(/\r?\n/)) {
    line = line.replace(/^\s*[#;].*$/, '').trim(); if (!line) continue;
    const m = line.match(/^\[(\w+)\]$/); if (m) { cur = m[1].toLowerCase() === 'peer' ? (c.peers.push({}), c.peers[c.peers.length - 1]) : c.iface; continue; }
    const i = line.indexOf('='); if (i < 0 || !cur) continue; cur[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return c;
}
const splitEp = ep => { const i = ep.lastIndexOf(':'); return { host: ep.slice(0, i).replace(/^\[|\]$/g, ''), port: +ep.slice(i + 1) || 0 }; };
const listOf = s => (s || '').split(',').map(x => x.trim()).filter(Boolean);
const addrs = a => { const l = listOf(a); return { v4: l.find(x => !x.includes(':')) || '', v6: l.find(x => x.includes(':')) || '' }; };

/* model: { name, private, public, psk, address, dns, mtu, allowed, endpoint, keepalive, reserved:[..], awg:{..}, ws:{id,ip,ib} } */
function toConf(m, kind) {
  const L = ['# ' + (m.name || 'xr PANEL'), '[Interface]', 'PrivateKey = ' + m.private, 'Address = ' + m.address];
  if (m.dns) L.push('DNS = ' + m.dns); L.push('MTU = ' + (m.mtu || 1280));
  if (kind === 'awg' || kind === 'wiresock') {
    const a = m.awg || awgBase(JUNK.light); for (const k of AWG) L.push(k[0].toUpperCase() + k.slice(1) + ' = ' + a[k]);
    if (kind === 'awg') { for (const k of IK) if (a[k]) L.push(k.toUpperCase() + ' = ' + a[k]); for (const [k, v] of Object.entries(a.x || {})) L.push(k + ' = ' + v); }
    else { const w = m.ws || {}; if (w.id) L.push('Id = ' + w.id); if (w.ip) L.push('Ip = ' + w.ip); if (w.ib) L.push('Ib = ' + w.ib); }
  }
  L.push('', '[Peer]', 'PublicKey = ' + m.public); if (m.psk) L.push('PresharedKey = ' + m.psk);
  L.push('AllowedIPs = ' + (m.allowed || '0.0.0.0/0, ::/0')); if (m.keepalive) L.push('PersistentKeepalive = ' + m.keepalive);
  L.push('Endpoint = ' + m.endpoint); return L.join('\n');
}
const yq = s => /^[\w.\-\/:+]+$/.test(s) ? s : JSON.stringify(s);
function toClash(m) {
  const e = splitEp(m.endpoint), a = addrs(m.address), L = ['- name: ' + yq(m.name || 'WARP'), '  type: wireguard', '  server: ' + yq(e.host), '  port: ' + e.port];
  if (a.v4) L.push('  ip: ' + a.v4.replace(/\/\d+$/, '')); if (a.v6) L.push('  ipv6: ' + a.v6.replace(/\/\d+$/, ''));
  L.push('  private-key: ' + yq(m.private), '  public-key: ' + yq(m.public)); if (m.psk) L.push('  pre-shared-key: ' + yq(m.psk));
  L.push('  allowed-ips: [' + listOf(m.allowed || '0.0.0.0/0, ::/0').map(yq).join(', ') + ']'); if (m.reserved && m.reserved.length) L.push('  reserved: [' + m.reserved.join(', ') + ']');
  L.push('  udp: true', '  mtu: ' + (m.mtu || 1280), '  remote-dns-resolve: true', '  dns: [' + listOf(m.dns || '1.1.1.1').map(yq).join(', ') + ']'); if (m.keepalive) L.push('  persistent-keepalive: ' + m.keepalive);
  if (m.awg) { L.push('  amnezia-wg-option:'); for (const k of [...AWG, ...IK]) if (m.awg[k] !== undefined && m.awg[k] !== '') L.push(`    ${k}: ${typeof m.awg[k] === 'number' ? m.awg[k] : JSON.stringify(m.awg[k])}`); }
  return L.join('\n');
}
function toXray(m) {
  const a = addrs(m.address), ad = [a.v4 && (a.v4.includes('/') ? a.v4 : a.v4 + '/32'), a.v6 && (a.v6.includes('/') ? a.v6 : a.v6 + '/128')].filter(Boolean);
  const s = { secretKey: m.private, address: ad, peers: [{ publicKey: m.public, ...(m.psk ? { preSharedKey: m.psk } : {}), allowedIPs: listOf(m.allowed || '0.0.0.0/0, ::/0'), endpoint: m.endpoint, keepAlive: +m.keepalive || 25 }], mtu: +m.mtu || 1280 };
  if (m.reserved && m.reserved.length) s.reserved = m.reserved; return JSON.stringify({ protocol: 'wireguard', tag: 'warp', settings: s }, null, 2);
}
const download = (name, text) => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); a.download = name; document.body.append(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500); };
window.WG = { AWG, IK, I_PRESETS, JUNK, randJunk, fixJunk, awgBase, parseConf, splitEp, listOf, addrs, toConf, toClash, toXray, download, hex };

/* ---------- Network page: WireGuard (WARP) ---------- */
const jget = async u => { try { return await (await fetch(u)).json(); } catch (e) { return {}; } };
const jpost = async u => { try { const r = await fetch(u, { method: 'POST' }); return await r.json(); } catch (e) { return { ok: false, error: 'Network error' }; } };

function regButton(btn, info, url, getUrl, onOk, label) {
  let data = null;
  const paint = () => { btn.classList.toggle('ok', !!data); info.textContent = data ? 'registered · ' + (data.v4 || data.ipv4 || '') : 'not registered'; info.className = 'reg-i ' + (data ? 'ok' : 'no'); window.dispatchEvent(new CustomEvent('xr:reg', { detail: { kind: label === 'MASQUE' ? 'masque' : 'warp', ok: !!data } })); };
  (async () => { const d = await jget(getUrl); data = d && d.private_key ? d : null; paint(); onOk(data); })();
  btn.onclick = async () => {
    if (data && !confirm('Register a new ' + label + ' device? The current keys will be replaced.')) return;
    btn.disabled = true; const l = btn.textContent; btn.textContent = 'Registering…'; const r = await jpost(url); btn.disabled = false; btn.textContent = l;
    if (r.ok) { data = r; paint(); onOk(data); } else { info.textContent = r.error || 'failed'; info.className = 'reg-i no'; }
  };
}

function mountWG(root) {
  root.innerHTML = `<p class="hint">The panel registers a Cloudflare WARP device for you (this cannot be done from a browser). Then build WireGuard / AmneziaWG / Wiresock configs, or Xray and Clash outbounds, with the endpoint you want.</p>
  <div class="row regrow"><button type="button" class="btn reg" data-reg>Warp register</button><span class="reg-i no" data-info>checking…</span></div>
  <div class="f"><label>Endpoint<input data-f="ep" value="engage.cloudflareclient.com:2408" spellcheck="false" autocapitalize="off"></label>
  <label>Saved endpoints<select data-f="pick"><option value="">pick…</option></select></label>
  <label>MTU<input data-f="mtu" value="1280" inputmode="numeric"></label><label>DNS<input data-f="dns" value="1.1.1.1" spellcheck="false"></label>
  <label>Allowed IPs<input data-f="allowed" value="0.0.0.0/0, ::/0" spellcheck="false"></label><label>Keepalive<input data-f="ka" placeholder="off" inputmode="numeric"></label></div>
  <div class="row" style="margin-top:0"><button type="button" class="btn o tl" data-fast>${XRNET.BOLT}Use fastest endpoint</button><span class="hint" data-fastmsg></span></div>
  <div class="grp"><h3>Type</h3><div class="tabs" data-kind><button type="button" class="on" data-k="wg">WireGuard</button><button type="button" data-k="awg">AmneziaWG</button><button type="button" data-k="wiresock">Wiresock</button></div></div>
  <div data-awg hidden>
    <div class="grp"><h3>Junk packets</h3><div class="tabs" data-junk><button type="button" class="on" data-j="light">Light</button><button type="button" data-j="heavy">Heavy</button><button type="button" data-j="custom">Custom</button></div></div>
    <div class="f" data-cj hidden><label>Jc<input data-f="jc" value="3" inputmode="numeric"></label><label>Jmin<input data-f="jmin" value="1" inputmode="numeric"></label><label>Jmax<input data-f="jmax" value="3" inputmode="numeric"></label></div>
    <div class="row" style="margin-top:0"><button type="button" class="btn o yl" data-rnd>Random junk</button></div>
    <div data-pa><label class="ck"><input type="checkbox" data-f="a15"> Amnezia 1.5 packets (I1–I5)</label>
      <div data-a15 hidden><div class="row" style="margin-top:0">${[1, 2, 3, 4].map(n => `<button type="button" class="btn o tl" data-set="${n}">Set ${n}</button>`).join('')}</div>
      <div class="grp">${[1, 2, 3, 4, 5].map(n => `<label class="wide">I${n}<input data-f="i${n}" spellcheck="false" autocapitalize="off"></label>`).join('')}</div></div>
      <label class="ck"><input type="checkbox" data-f="a3"> Amnezia 3.0 timing (experimental)</label>
      <div class="f" data-a3 hidden>${[['ContentPaddingAddition', '27-97'], ['MaxHandshakeAttempts', '18-26'], ['KeepaliveTimeout', '9-16'], ['RejectAfterTime', '171-196'], ['RekeyAfterTime', '116-131'], ['RekeyTimeout', '6-9']].map(([k, v]) => `<label>${k}<input data-x="${k}" value="${v}"></label>`).join('')}</div>
      <label class="ck"><input type="checkbox" data-f="a31"> Amnezia 3.1 (random trailers, no cookies)</label></div>
    <div data-pw hidden><div class="f"><label>Id<input data-f="wid" placeholder="optional"></label><label>Ip (mimic)<input data-f="wip" value="QUIC"></label><label>Ib (browser)<input data-f="wib" value="Chrome"></label></div></div>
  </div>
  <div class="row"><button type="button" class="btn" data-gen disabled>Generate</button></div>
  <div data-out hidden><div class="tabs" data-fmt><button type="button" class="on" data-o="conf">Config</button><button type="button" data-o="xray">Xray</button><button type="button" data-o="clash">Clash</button></div>
  <textarea class="code" data-text readonly rows="12" spellcheck="false"></textarea>
  <p class="hint" data-res></p><div class="row"><button type="button" class="btn o tl" data-copy2>Copy</button><button type="button" class="btn o yl" data-dl>Download</button></div></div>`;
  const q = s => root.querySelector(s), f = n => q(`[data-f="${n}"]`); let warp = null, kind = 'wg', fmt = 'conf', junk = 'light', cur = null;
  const gen = q('[data-gen]');
  regButton(q('[data-reg]'), q('[data-info]'), '/api/warp/register', '/api/warp', d => { warp = d; gen.disabled = !d; if (d && !f('ep').dataset.t) f('ep').value = (d.endpoint_host || 'engage.cloudflareclient.com') + ':2408'; }, 'WARP');
  (async () => { const rows = await jget('/api/net/list?kind=warp'); f('pick').insertAdjacentHTML('beforeend', rows.slice(0, 40).map(r => `<option value="${E((r.host.includes(':') ? '[' + r.host + ']' : r.host) + ':' + r.port)}">${E((r.host.includes(':') ? '[' + r.host + ']' : r.host) + ':' + r.port)} · ${r.ms} ms</option>`).join('')); })();
  f('pick').onchange = e => { if (e.target.value) { f('ep').value = e.target.value; f('ep').dataset.t = 1; } }; f('ep').oninput = () => f('ep').dataset.t = 1;
  const setEp = d => { f('ep').value = XRNET.fmtEp(d); f('ep').dataset.t = 1; q('[data-fastmsg]').textContent = `${XRNET.fmtEp(d)} · ${Math.round(d.ms)} ms`; if (cur && warp) gen.onclick(); };
  window.addEventListener('xr:endpoint', e => { if (e.detail.kind === 'warp') setEp(e.detail); });
  q('[data-fast]').onclick = async () => { const r = await XRNET.useFastest('warp'); if (!r) q('[data-fastmsg]').textContent = 'No saved WARP endpoint — scan first'; };
  const tabs = (el, attr, fn) => el.onclick = e => { const b = e.target.closest('button'); if (!b) return; el.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); fn(b.dataset[attr]); };
  const view = () => { q('[data-awg]').hidden = kind === 'wg'; q('[data-pa]').hidden = kind !== 'awg'; q('[data-pw]').hidden = kind !== 'wiresock'; if (cur) render(); };
  tabs(q('[data-kind]'), 'k', k => { kind = k; view(); });
  tabs(q('[data-junk]'), 'j', j => { junk = j; q('[data-cj]').hidden = j !== 'custom'; });
  tabs(q('[data-fmt]'), 'o', o => { fmt = o; render(); });
  f('a15').onchange = () => q('[data-a15]').hidden = !f('a15').checked; f('a3').onchange = () => q('[data-a3]').hidden = !f('a3').checked;
  root.querySelectorAll('[data-set]').forEach(b => b.onclick = () => { const s = I_PRESETS[b.dataset.set]; IK.forEach(k => f(k).value = s[k] || ''); });
  q('[data-rnd]').onclick = () => { const j = randJunk(); f('jc').value = j.jc; f('jmin').value = j.jmin; f('jmax').value = j.jmax; q('[data-junk] [data-j="custom"]').click(); };
  const awgModel = () => {
    const j = junk === 'custom' ? { jc: f('jc').value, jmin: f('jmin').value, jmax: f('jmax').value } : JUNK[junk], a = awgBase(j);
    if (kind === 'awg') { if (f('a15').checked) IK.forEach(k => a[k] = f(k).value.trim()); a.x = {}; if (f('a3').checked) root.querySelectorAll('[data-x]').forEach(i => { if (i.value.trim()) a.x[i.dataset.x] = i.value.trim(); }); if (f('a31').checked) { a.x.RandomTrailers = 'on'; a.x.DisableCookies = 'on'; } }
    return a;
  };
  const model = () => ({ name: 'WARP', private: warp.private_key, public: warp.peer_public_key, address: [warp.v4, warp.v6].filter(Boolean).map((a, i) => a.includes('/') ? a : a + (i ? '/128' : '/32')).join(', '),
    dns: f('dns').value.trim(), mtu: +f('mtu').value || 1280, allowed: f('allowed').value.trim(), endpoint: f('ep').value.trim(), keepalive: +f('ka').value || '', reserved: warp.reserved,
    awg: kind === 'wg' ? null : awgModel(), ws: { id: f('wid').value.trim(), ip: f('wip').value.trim(), ib: f('wib').value.trim() } });
  const render = () => {
    if (!cur) return; const m = cur, t = q('[data-text]'); q('[data-fmt]').hidden = false;
    t.value = fmt === 'conf' ? toConf(m, kind) : fmt === 'xray' ? toXray(m) : toClash(m);
    q('[data-res]').textContent = 'Reserved bytes: [' + (m.reserved || []).join(', ') + '] — needed by Xray, Clash and sing-box; the plain .conf does not use them.';
  };
  gen.onclick = () => { if (!warp) return; if (!/^(\[[0-9a-f:]+\]|[\w.\-]+):\d{1,5}$/i.test(f('ep').value.trim())) { alert('Endpoint must look like host:port or [ipv6]:port'); return; } cur = model(); q('[data-out]').hidden = false; render(); };
  q('[data-copy2]').onclick = e => XRNET.COPY(q('[data-text]').value, e.target);
  q('[data-dl]').onclick = () => download(fmt === 'conf' ? (kind === 'wg' ? 'warp.conf' : kind + '.conf') : fmt === 'xray' ? 'warp-outbound.json' : 'warp-clash.yaml', q('[data-text]').value);
}

/* ---------- Network page: MASQUE ---------- */
function mountMasque(root) {
  root.innerHTML = `<p class="hint">MASQUE is WARP's newer tunnel (HTTP/3 CONNECT-IP). The panel registers a separate device and enrolls a P-256 key. The output is a <b>usque</b> client config. Xray and Clash have no MASQUE support yet.</p>
  <div class="row regrow"><button type="button" class="btn reg" data-reg>Masque register</button><span class="reg-i no" data-info>checking…</span></div>
  <div class="f"><label>Endpoint IP<input data-f="ep4" spellcheck="false"></label><label>Endpoint IPv6<input data-f="ep6" spellcheck="false"></label><label>Saved endpoints<select data-f="pick"><option value="">pick…</option></select></label></div>
  <div class="row" style="margin-top:0"><button type="button" class="btn o tl" data-fast>${XRNET.BOLT}Use fastest endpoint</button><span class="hint" data-fastmsg></span></div>
  <p class="hint">Ports used by MASQUE: <b>443, 500, 1701, 4443, 4500, 8443, 8095</b> (UDP).</p>
  <div class="row"><button type="button" class="btn" data-gen disabled>Generate</button></div>
  <div data-out hidden><textarea class="code" data-text readonly rows="12" spellcheck="false"></textarea><p class="hint" data-res></p><div class="row"><button type="button" class="btn o tl" data-copy2>Copy</button><button type="button" class="btn o yl" data-dl>Download config.json</button></div></div>`;
  const q = s => root.querySelector(s), f = n => q(`[data-f="${n}"]`); let d = null, made = false;
  const gen = q('[data-gen]');
  const pem = k => k.startsWith('-----') ? k : '-----BEGIN PUBLIC KEY-----\n' + (k.match(/.{1,64}/g) || []).join('\n') + '\n-----END PUBLIC KEY-----\n';
  const show = () => { if (!d || !made) { q('[data-out]').hidden = true; return; } q('[data-out]').hidden = false; q('[data-res]').textContent = 'Save as config.json and run it with usque (MASQUE client). Endpoint ports: 443, 500, 1701, 4443, 4500, 8443, 8095.';
    q('[data-text]').value = JSON.stringify({ private_key: d.private_key, endpoint_v4: f('ep4').value.trim() || d.endpoint_v4, endpoint_v6: f('ep6').value.trim() || d.endpoint_v6, endpoint_pub_key: pem(d.endpoint_pub_key), license: d.license, id: d.id, access_token: d.access_token, ipv4: d.ipv4, ipv6: d.ipv6, sni: 'consumer-masque.cloudflareclient.com' }, null, 2); };
  regButton(q('[data-reg]'), q('[data-info]'), '/api/masque/register', '/api/masque', x => { d = x; gen.disabled = !x; if (x) { f('ep4').value = f('ep4').value || x.endpoint_v4; f('ep6').value = f('ep6').value || x.endpoint_v6; } else made = false; show(); }, 'MASQUE');
  gen.onclick = () => { if (!d) return; made = true; show(); };
  (async () => { const rows = await jget('/api/net/list?kind=masque'); f('pick').insertAdjacentHTML('beforeend', rows.slice(0, 40).map(r => `<option value="${E(r.host)}">${E(r.host)}:${r.port} · ${r.ms} ms</option>`).join('')); })();
  f('pick').onchange = e => { if (e.target.value) { f(e.target.value.includes(':') ? 'ep6' : 'ep4').value = e.target.value; show(); } }; f('ep4').oninput = f('ep6').oninput = show;
  const setEp = x => { f(x.host.includes(':') ? 'ep6' : 'ep4').value = x.host; q('[data-fastmsg]').textContent = `${XRNET.fmtEp(x)} · ${Math.round(x.ms)} ms — use port ${x.port}`; show(); };
  window.addEventListener('xr:endpoint', e => { if (e.detail.kind === 'masque') setEp(e.detail); });
  q('[data-fast]').onclick = async () => { const r = await XRNET.useFastest('masque'); if (!r) q('[data-fastmsg]').textContent = 'No saved MASQUE endpoint — scan first'; };
  q('[data-copy2]').onclick = e => XRNET.COPY(q('[data-text]').value, e.target); q('[data-dl]').onclick = () => download('config.json', q('[data-text]').value);
}

document.addEventListener('DOMContentLoaded', () => { const a = document.querySelector('[data-wg]'), b = document.querySelector('[data-masque]'); if (a) mountWG(a); if (b) mountMasque(b); });
})();
