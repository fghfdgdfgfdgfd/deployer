// Outbound TCP through SOCKS5 / SOCKS4 / HTTP(S) proxies using the Workers socket API (`connect` is injected).
const te = new TextEncoder(), td = new TextDecoder();
export const TARGET = ['1.1.1.1', 80];
export const timeout = (p, ms, what = 'timeout') => { let t; return Promise.race([p, new Promise((_, r) => { t = setTimeout(() => r(new Error(what)), ms); })]).finally(() => clearTimeout(t)); };

// Buffered reader over a socket: handshakes read exact amounts, the relay then continues with whatever is left.
export class Rd {
  constructor(sock) { this.r = sock.readable.getReader(); this.buf = new Uint8Array(0); this.done = false; }
  async pull() { const { value, done } = await this.r.read(); if (done) { this.done = true; return false; } const n = new Uint8Array(this.buf.length + value.length); n.set(this.buf); n.set(value, this.buf.length); this.buf = n; return true; }
  async need(n) { while (this.buf.length < n) if (!(await this.pull())) throw new Error('closed'); const o = this.buf.slice(0, n); this.buf = this.buf.slice(n); return o; }
  async until(marker, max = 8192) { const m = te.encode(marker); for (; ;) { const i = indexOf(this.buf, m); if (i >= 0) { const o = this.buf.slice(0, i + m.length); this.buf = this.buf.slice(i + m.length); return o; } if (this.buf.length > max || !(await this.pull())) throw new Error('bad answer'); } }
  async next() { if (this.buf.length) { const o = this.buf; this.buf = new Uint8Array(0); return { value: o, done: false }; } return this.r.read(); }
  release() { try { this.r.releaseLock(); } catch { } }
}
export function indexOf(a, m) { outer: for (let i = 0; i + m.length <= a.length; i++) { for (let j = 0; j < m.length; j++) if (a[i + j] !== m[j]) continue outer; return i; } return -1; }

const isV4 = h => /^\d{1,3}(\.\d{1,3}){3}$/.test(h);
const isV6 = h => h.includes(':');
function v4(h) { return Uint8Array.from(h.split('.').map(Number)); }

export async function handshake(w, rd, proto, host, port) {
  const p2 = Uint8Array.of(port >> 8, port & 255);
  if (proto === 'socks5') {
    await w.write(Uint8Array.of(5, 1, 0)); const r = await rd.need(2); if (r[0] !== 5 || r[1] !== 0) throw new Error('socks5 auth');
    const addr = isV4(host) ? [1, ...v4(host)] : isV6(host) ? [4, ...ipv6Bytes(host)] : [3, host.length, ...te.encode(host)];
    await w.write(Uint8Array.from([5, 1, 0, ...addr, ...p2]));
    const h = await rd.need(4); if (h[1] !== 0) throw new Error('socks5 refused');
    const rest = h[3] === 1 ? 6 : h[3] === 4 ? 18 : (await rd.need(1))[0] + 2; await rd.need(rest);
  } else if (proto === 'socks4') {
    const ip = isV4(host) ? v4(host) : Uint8Array.of(0, 0, 0, 1);
    await w.write(Uint8Array.from([4, 1, ...p2, ...ip, 0, ...(isV4(host) ? [] : [...te.encode(host), 0])]));
    const r = await rd.need(8); if (r[1] !== 0x5a) throw new Error('socks4 refused');
  } else {
    await w.write(te.encode(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
    const head = td.decode(await rd.until('\r\n\r\n')); if (!/^HTTP\/1\.[01] 200/.test(head)) throw new Error('connect refused');
  }
}
export function ipv6Bytes(h) {
  const [a, b] = h.split('::'); const A = a ? a.split(':') : [], B = b !== undefined && b ? b.split(':') : [];
  const g = [...A, ...Array(Math.max(0, 8 - A.length - B.length)).fill('0'), ...B]; const o = [];
  for (const x of g) { const n = parseInt(x || '0', 16); o.push(n >> 8, n & 255); } return o;
}

/** Open host:port through one proxy ({host,port,proto}). Resolves {sock, rd, w}. */
export async function viaProxy(connect, px, host, port, ms = 6000) {
  const sock = connect({ hostname: px.host, port: px.port }, px.proto === 'https' ? { secureTransport: 'on', allowHalfOpen: false } : undefined);
  const w = sock.writable.getWriter(), rd = new Rd(sock);
  try { await timeout((async () => { await sock.opened; await handshake(w, rd, px.proto === 'https' ? 'http' : px.proto, host, port); })(), ms); }
  catch (e) { try { sock.close(); } catch { } throw e; }
  return { sock, rd, w };
}
export async function direct(connect, host, port, ms = 6000) {
  const sock = connect({ hostname: host, port }); await timeout(sock.opened, ms, 'connect timeout');
  return { sock, rd: new Rd(sock), w: sock.writable.getWriter() };
}

/** Round trip through a proxy to TARGET, in ms, or null. */
export async function probe(connect, proto, host, port, ms = 4000) {
  const t = Date.now(); let c;
  try { c = await viaProxy(connect, { host, port, proto }, TARGET[0], TARGET[1], ms); return Math.max(1, Date.now() - t); }
  catch { return null; }
  finally { if (c) { try { c.sock.close(); } catch { } } }
}
export const PROBES = ['socks5', 'socks4', 'http', 'https'];
export async function probeAll(connect, host, port) {
  const res = await Promise.all(PROBES.map(async p => ({ proto: p, ms: await probe(connect, p, host, port) })));
  const ok = res.filter(x => x.ms !== null); return [res, ok.length ? ok.reduce((a, b) => (b.ms < a.ms ? b : a)) : null];
}
