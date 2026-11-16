/* Small QR code encoder (byte mode, error correction M, versions 1-40) -> window.QR.svg(text) */
(() => {
'use strict';
const ECC = [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];
const BLK = [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];

const rawModules = v => { let r = (16 * v + 128) * v + 64; if (v >= 2) { const a = Math.floor(v / 7) + 2; r -= (25 * a - 10) * a - 55; if (v >= 7) r -= 36; } return r; };
const dataCodewords = v => Math.floor(rawModules(v) / 8) - ECC[v] * BLK[v];
const alignPos = v => { if (v === 1) return []; const n = Math.floor(v / 7) + 2, step = v === 32 ? 26 : Math.ceil((v * 4 + 4) / (n * 2 - 2)) * 2, r = [6]; for (let p = v * 4 + 10; r.length < n; p -= step) r.splice(1, 0, p); return r; };

/* Reed-Solomon over GF(256) */
const mul = (x, y) => { let z = 0; for (let i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >>> 7) * 0x11d); z ^= ((y >>> i) & 1) * x; } return z & 255; };
const rsDiv = n => { const r = new Array(n).fill(0); r[n - 1] = 1; let root = 1; for (let i = 0; i < n; i++) { for (let j = 0; j < n; j++) { r[j] = mul(r[j], root); if (j + 1 < n) r[j] ^= r[j + 1]; } root = mul(root, 2); } return r; };
const rsRem = (data, div) => { const r = div.map(() => 0); for (const b of data) { const f = b ^ r.shift(); r.push(0); div.forEach((c, i) => r[i] ^= mul(c, f)); } return r; };

function addEcc(data, v) {
  const nb = BLK[v], el = ECC[v], raw = Math.floor(rawModules(v) / 8), short = nb - raw % nb, sl = Math.floor(raw / nb), div = rsDiv(el), blocks = []; let k = 0;
  for (let i = 0; i < nb; i++) { const d = data.slice(k, k + sl - el + (i < short ? 0 : 1)); k += d.length; const e = rsRem(d, div); if (i < short) d.push(0); blocks.push(d.concat(e)); }
  const out = []; for (let i = 0; i < blocks[0].length; i++) blocks.forEach((b, j) => { if (i !== sl - el || j >= short) out.push(b[i]); }); return out;
}

function encode(text) {
  const bytes = [...new TextEncoder().encode(text)]; let v = 1;
  for (; ; v++) { if (v > 40) throw new Error('Too long for a QR code'); if (4 + (v < 10 ? 8 : 16) + bytes.length * 8 <= dataCodewords(v) * 8) break; }
  const bits = []; const put = (x, n) => { for (let i = n - 1; i >= 0; i--) bits.push((x >>> i) & 1); };
  put(4, 4); put(bytes.length, v < 10 ? 8 : 16); bytes.forEach(b => put(b, 8));
  const cap = dataCodewords(v) * 8; put(0, Math.min(4, cap - bits.length)); put(0, (8 - bits.length % 8) % 8);
  for (let p = 0xec; bits.length < cap; p ^= 0xec ^ 0x11) put(p, 8);
  const cw = []; for (let i = 0; i < bits.length; i += 8) cw.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  return { v, words: addEcc(cw, v) };
}

function build(v, words, mask) {
  const n = v * 4 + 17, m = Array.from({ length: n }, () => new Array(n).fill(false)), fn = Array.from({ length: n }, () => new Array(n).fill(false));
  const set = (x, y, d) => { m[y][x] = d; fn[y][x] = true; };
  for (let i = 0; i < n; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  const finder = (cx, cy) => { for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) { const d = Math.max(Math.abs(dx), Math.abs(dy)), x = cx + dx, y = cy + dy; if (x >= 0 && x < n && y >= 0 && y < n) set(x, y, d !== 2 && d !== 4); } };
  finder(3, 3); finder(n - 4, 3); finder(3, n - 4);
  const ap = alignPos(v); for (let i = 0; i < ap.length; i++) for (let j = 0; j < ap.length; j++) { if ((i === 0 && j === 0) || (i === 0 && j === ap.length - 1) || (i === ap.length - 1 && j === 0)) continue; for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ap[i] + dx, ap[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1); }
  const fmt = (() => { const d = (0 << 3) | mask; let r = d; for (let i = 0; i < 10; i++) r = (r << 1) ^ ((r >>> 9) * 0x537); return ((d << 10) | r) ^ 0x5412; })();   // M = 00
  const b = i => ((fmt >>> i) & 1) !== 0;
  for (let i = 0; i <= 5; i++) set(8, i, b(i)); set(8, 7, b(6)); set(8, 8, b(7)); set(7, 8, b(8)); for (let i = 9; i < 15; i++) set(14 - i, 8, b(i));
  for (let i = 0; i < 8; i++) set(n - 1 - i, 8, b(i)); for (let i = 8; i < 15; i++) set(8, n - 15 + i, b(i)); set(8, n - 8, true);
  if (v >= 7) { let r = v; for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25); const bitsV = (v << 12) | r; for (let i = 0; i < 18; i++) { const bit = ((bitsV >>> i) & 1) !== 0, a = n - 11 + i % 3, c = Math.floor(i / 3); set(a, c, bit); set(c, a, bit); } }
  let i = 0; for (let right = n - 1; right >= 1; right -= 2) { if (right === 6) right = 5; for (let vert = 0; vert < n; vert++) for (let j = 0; j < 2; j++) { const x = right - j, up = ((right + 1) & 2) === 0, y = up ? n - 1 - vert : vert; if (!fn[y][x] && i < words.length * 8) { m[y][x] = ((words[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0; i++; } } }
  const inv = [(x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, (x, y) => x % 3 === 0, (x, y) => (x + y) % 3 === 0, (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => x * y % 2 + x * y % 3 === 0, (x, y) => (x * y % 2 + x * y % 3) % 2 === 0, (x, y) => ((x + y) % 2 + x * y % 3) % 2 === 0][mask];
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (!fn[y][x] && inv(x, y)) m[y][x] = !m[y][x];
  return m;
}

function penalty(m) {
  const n = m.length; let p = 0;
  const run = line => { let s = 0, c = 1; for (let i = 1; i <= n; i++) { if (i < n && line[i] === line[i - 1]) c++; else { if (c >= 5) s += 3 + c - 5; c = 1; } } return s; };
  const fin = line => { let s = 0; const pat = [1, 0, 1, 1, 1, 0, 1]; for (let i = 0; i + 6 < n; i++) { if (pat.every((b, k) => (line[i + k] ? 1 : 0) === b)) { const l = i >= 4 && [1, 2, 3, 4].every(k => !line[i - k]), r = i + 10 < n + 0 && [7, 8, 9, 10].every(k => !line[i + k]); if (l || i < 4 && [1, 2, 3, 4].every(k => i - k < 0 || !line[i - k])) s += 40; if (r || i + 10 >= n) s += 40; } } return s; };
  for (let y = 0; y < n; y++) { p += run(m[y]); p += fin(m[y]); } for (let x = 0; x < n; x++) { const col = m.map(r => r[x]); p += run(col); p += fin(col); }
  for (let y = 0; y < n - 1; y++) for (let x = 0; x < n - 1; x++) if (m[y][x] === m[y][x + 1] && m[y][x] === m[y + 1][x] && m[y][x] === m[y + 1][x + 1]) p += 3;
  let dark = 0; for (const r of m) for (const c of r) if (c) dark++; p += (Math.ceil(Math.abs(dark * 20 - n * n * 10) / (n * n)) - 1) * 10; return p;
}

function matrix(text) { const { v, words } = encode(text); let best = null, bp = Infinity; for (let k = 0; k < 8; k++) { const m = build(v, words, k), s = penalty(m); if (s < bp) { bp = s; best = m; } } return best; }
function svg(text, px = 4) {
  const m = matrix(text), n = m.length, q = 4; let d = '';
  for (let y = 0; y < n; y++) { let x = 0; while (x < n) { if (!m[y][x]) { x++; continue; } let e = x; while (e < n && m[y][e]) e++; d += `M${x + q} ${y + q}h${e - x}v1h-${e - x}z`; x = e; } }
  const s = (n + 2 * q); return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${s} ${s}" width="${s * px}" height="${s * px}" shape-rendering="crispEdges"><rect width="${s}" height="${s}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}
window.QR = { svg, matrix, _encode: encode, _build: build };
})();
