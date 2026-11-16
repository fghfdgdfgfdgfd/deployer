// The "Xray replacement": VLESS and Trojan over WebSocket are terminated here, bytes leave through the user's exit group
// (SOCKS5 / SOCKS4 / HTTP proxies) or directly. With an upstream set, any protocol is relayed unchanged to that server.
import { direct, viaProxy, timeout } from './proxy.js';
import { state, now } from './db.js';

const te = new TextEncoder();
export const toU8 = d => d instanceof Uint8Array ? d : d instanceof ArrayBuffer ? new Uint8Array(d) : ArrayBuffer.isView(d) ? new Uint8Array(d.buffer, d.byteOffset, d.byteLength) : te.encode(String(d));
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
const uuidBytes = id => Uint8Array.from(id.replace(/-/g, '').match(/../g).map(h => parseInt(h, 16)));

// ---------- SHA-224 (WebCrypto has none): SHA-256 with another IV, cut to 28 bytes ----------
const K = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
export function sha224(msg) {
  const H = new Uint32Array([0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]);
  const len = msg.length, padLen = ((len + 9 + 63) >> 6) << 6, m = new Uint8Array(padLen); m.set(msg); m[len] = 0x80;
  const dv = new DataView(m.buffer); dv.setUint32(padLen - 8, Math.floor(len * 8 / 2 ** 32)); dv.setUint32(padLen - 4, (len * 8) >>> 0);
  const w = new Uint32Array(64), r = (x, n) => (x >>> n) | (x << (32 - n));
  for (let o = 0; o < padLen; o += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
    for (let i = 16; i < 64; i++) { const s0 = r(w[i - 15], 7) ^ r(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = r(w[i - 2], 17) ^ r(w[i - 2], 19) ^ (w[i - 2] >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0; }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h + S1 + ch + K[i] + w[i]) >>> 0, S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), mj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + mj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  const out = new Uint8Array(28), ov = new DataView(out.buffer); for (let i = 0; i < 7; i++) ov.setUint32(i * 4, H[i]); return out;
}
export const trojanHash = uuid => hex(sha224(te.encode(uuid)));

// ---------- protocol headers ----------
function readAddr(b, i, atyp, v6atyp) {
  if (atyp === 1) return [`${b[i]}.${b[i + 1]}.${b[i + 2]}.${b[i + 3]}`, i + 4];
  if (atyp === 2 && v6atyp === 3) return [new TextDecoder().decode(b.slice(i + 1, i + 1 + b[i])), i + 1 + b[i]];
  if (atyp === v6atyp) { const dv = new DataView(b.buffer, b.byteOffset + i, 16); return [Array.from({ length: 8 }, (_, k) => dv.getUint16(k * 2).toString(16)).join(':'), i + 16]; }
  return null;
}
/** -> {cmd, host, port, rest, reply} or null when the header is wrong / belongs to another user */
export function parseVless(b, uuid) {
  if (b.length < 24) return null; const id = uuidBytes(uuid);
  for (let i = 0; i < 16; i++) if (b[1 + i] !== id[i]) return null;
  const o = 18 + b[17]; const cmd = b[o], port = (b[o + 1] << 8) | b[o + 2], atyp = b[o + 3]; if (cmd !== 1 && cmd !== 2) return null;
  let host, i = o + 4;
  if (atyp === 2) { host = new TextDecoder().decode(b.slice(i + 1, i + 1 + b[i])); i += 1 + b[i]; }
  else { const a = readAddr(b, i, atyp, 3); if (!a) return null; [host, i] = a; }
  return { cmd, host, port, rest: b.slice(i), reply: Uint8Array.of(b[0], 0) };
}
export function parseTrojan(b, uuid) {
  if (b.length < 62) return null; if (new TextDecoder().decode(b.slice(0, 56)) !== trojanHash(uuid) || b[56] !== 13 || b[57] !== 10) return null;
  const cmd = b[58], atyp = b[59]; if (cmd !== 1) return null; let host, i = 60;
  if (atyp === 3) { host = new TextDecoder().decode(b.slice(i + 1, i + 1 + b[i])); i += 1 + b[i]; }
  else { const a = readAddr(b, i, atyp, 4); if (!a) return null; [host, i] = a; }
  const port = (b[i] << 8) | b[i + 1]; return { cmd: 1, host, port, rest: b.slice(i + 4), reply: null };
}

// ---------- usage accounting + enforcement ----------
export class Meter {
  constructor(db, user) { this.db = db; this.id = user.id; this.up = 0; this.down = 0; this.last = Date.now(); this.dead = false; }
  async flush(ws) {
    const n = this.up + this.down; this.up = this.down = 0; this.last = Date.now(); if (!n) return;
    try {
      await this.db.run('UPDATE users SET used=used+? WHERE id=?', n, this.id);
      const u = await this.db.one('SELECT * FROM users WHERE id=?', this.id);
      if (!u || state(u) !== 'active') { this.dead = true; try { ws.close(1008, 'account ' + (u ? state(u) : 'removed')); } catch { } }
    } catch { }
  }
  tick(ws, ctx) { if (this.up + this.down >= 512 * 1024 || Date.now() - this.last > 30000) { const p = this.flush(ws); ctx && ctx.waitUntil && ctx.waitUntil(p); } }
}

// ---------- exits ----------
export async function dialer(db, connect, user) {
  const px = user.grp_id ? await db.all('SELECT host,port,proto FROM proxies WHERE grp_id=? ORDER BY ms LIMIT 4', user.grp_id) : [];
  return async (host, port) => {
    for (const p of px) { try { return await viaProxy(connect, p, host, port); } catch { } }
    if (px.length) throw new Error('every exit proxy of this group failed');
    return direct(connect, host, port);
  };
}

async function dnsOverHttps(q) {
  const r = await fetch('https://1.1.1.1/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' }, body: q });
  return new Uint8Array(await r.arrayBuffer());
}

/** Serve one accepted WebSocket (`ws`) for a native VLESS / Trojan user. */
export function serveNative(ws, { proto, user, dial, meter, ctx, early }) {
  let phase = 0, remote = null, started = Promise.resolve(), udp = false, replyPending = null, closed = false;
  const close = () => { if (closed) return; closed = true; try { remote && remote.sock.close(); } catch { } try { ws.close(); } catch { } meter.flush(ws); };
  const onData = async raw => {
    const data = toU8(raw); meter.up += data.length; meter.tick(ws, ctx);
    if (meter.dead) return;
    if (phase === 0) {
      phase = 1;
      const h = proto === 'vless' ? parseVless(data, user.uuid) : parseTrojan(data, user.uuid);
      if (!h) { close(); return; }
      replyPending = h.reply;
      if (h.cmd === 2) {                                   // UDP: DNS only
        if (h.port !== 53) { close(); return; } udp = true; remote = { dns: true }; phase = 2; if (h.rest.length) await onUdp(h.rest); return;
      }
      try { remote = await dial(h.host, h.port); } catch { close(); return; }
      phase = 2; const w = remote.w; if (h.rest.length) await w.write(h.rest);
      (async () => {
        try {
          for (; ;) {
            const { value, done } = await remote.rd.next(); if (done) break;
            meter.down += value.length; let out = value; if (replyPending) { out = cat(replyPending, value); replyPending = null; } ws.send(out); meter.tick(ws, ctx);
          }
        } catch { }
        close();
      })();
      return;
    }
    if (udp) return onUdp(data);
    if (remote && remote.w) await remote.w.write(data);
  };
  async function onUdp(buf) {                              // VLESS UDP framing: [len(2) | dns query]*
    let i = 0; while (i + 2 <= buf.length) {
      const n = (buf[i] << 8) | buf[i + 1]; const q = buf.slice(i + 2, i + 2 + n); i += 2 + n; if (q.length < n) break;
      const a = await dnsOverHttps(q).catch(() => null); if (!a) continue;
      const out = cat(Uint8Array.of(a.length >> 8, a.length & 255), a); meter.down += out.length;
      ws.send(replyPending ? (() => { const r = cat(replyPending, out); replyPending = null; return r; })() : out);
    }
  }
  const run = d => { started = started.then(() => onData(d)).catch(close); };
  ws.addEventListener('message', e => run(e.data)); ws.addEventListener('close', close); ws.addEventListener('error', close);
  if (early && early.length) run(early);
  return { close };
}

/** Relay one accepted WebSocket to an upstream server unchanged (any protocol), metering both directions. */
export async function serveUpstream(ws, { upstream, path, protocolHeader, meter, ctx, fetchFn = fetch }) {
  const url = 'https://' + upstream.replace(/^https?:\/\//, '').replace(/\/.*$/, '') + path;
  const headers = { Upgrade: 'websocket' }; if (protocolHeader) headers['Sec-WebSocket-Protocol'] = protocolHeader;
  let up = null, over = false; const queue = [];
  const end = () => { if (over) return; over = true; try { up && up.close(); } catch { } try { ws.close(); } catch { } meter.flush(ws); };
  ws.addEventListener('message', e => { const d = toU8(e.data); meter.up += d.length; meter.tick(ws, ctx); if (meter.dead) return; if (up) up.send(e.data); else queue.push(e.data); });   // buffer until the upstream is open
  ws.addEventListener('close', end); ws.addEventListener('error', end);
  try { const r = await timeout(fetchFn(url, { headers }), 10000, 'upstream timeout'); up = r.webSocket; } catch { }
  if (!up) { try { ws.close(1011, 'upstream unreachable'); } catch { } over = true; return false; }
  up.accept();
  up.addEventListener('message', e => { meter.down += toU8(e.data).length; meter.tick(ws, ctx); if (!meter.dead) ws.send(e.data); });
  up.addEventListener('close', end); up.addEventListener('error', end);
  for (const d of queue.splice(0)) up.send(d);
  return true;
}

export const WS_PATH = /^\/ws\/(?:[A-Za-z0-9_-]+\/)?(vless|vmess|shadowsocks|trojan)\/([0-9a-fA-F-]{36})$/;
export function earlyData(h) { if (!h) return null; try { const b = atob(h.replace(/-/g, '+').replace(/_/g, '/')); return Uint8Array.from(b, c => c.charCodeAt(0)); } catch { return null; } }
