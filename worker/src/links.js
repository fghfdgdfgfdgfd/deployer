// Subscription links: advanced options (spoof / F+F / fragment / ECH / IPv6), config domain, White IPs.
import { DEFAULT_SITES } from './db.js';

export const SS = 'chacha20-ietf-poly1305';
export const NATIVE = ['vless', 'trojan'];                 // terminated inside the Worker
export const ALL = ['vless', 'vmess', 'shadowsocks', 'trojan'];
export const protos = s => (s.upstream && s.upstream.trim() ? ALL : NATIVE);

export const Q = x => encodeURIComponent(x).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());

export const ECH = [
  ['Static config', 'base64', 'AEX+DQBBXgAgACBsvLac2HVdvp+J2QTKPNjn24b5D6yHyxAcG0m+cmDcXAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA='],
  ['crypto.cloudflare.com', 'udp 8.8.8.8', 'crypto.cloudflare.com+udp://8.8.8.8'],
  ['ridanbe.net', 'udp 8.8.8.8', 'ridanbe.net+udp://8.8.8.8'],
  ['iranva.ir', 'udp 1.1.1.1', 'iranva.ir+udp://1.1.1.1'],
  ['cloudflare-ech.com', 'udp 1.1.1.1', 'cloudflare-ech.com+udp://1.1.1.1'],
];

// ---- Fragment profiles: "fast" is exactly the F+F mask; slower networks get longer pauses and fewer splits ----
export const FRAG_TIERS = { fast: ['0', '1', '11'], mid: ['1', '3', '8'], slow: ['2', '6', '5'] };
export function fragMask(tier) {
  const [d1, d2, ms] = FRAG_TIERS[tier];
  return JSON.stringify({ tcp: [{ type: 'fragment', settings: { packets: 'tlshello', lengths: ['0', '104', '1'], delays: [d1], maxSplit: '0' } },
    { type: 'fragment', settings: { packets: '1-1', lengths: ['114', '1'], delays: [d2], maxSplit: ms } }] });
}
export const FM = fragMask('fast');
export function fragProf(s) {
  let p = null; try { p = JSON.parse(s.frag_prof || 'null'); } catch { }
  return p && typeof p === 'object' && p.tier in FRAG_TIERS ? p : (p && p.tier === 'none' ? p : null);
}
export function fragFm(s) { const p = s.frag_on === '1' ? fragProf(s) : null; return p && p.tier in FRAG_TIERS ? fragMask(p.tier) : ''; }
export function tierOf(rtt, ok) {
  if (ok <= 0) return 'none';
  if (rtt < 150 && ok >= 0.9) return 'fast';
  if (rtt < 400 && ok >= 0.6) return 'mid';
  return 'slow';
}

// ---- test sites (round robin) ----
export function cleanSite(u) {
  u = (u || '').trim(); if (!u) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) u = 'https://' + u;
  let x; try { x = new URL(u); } catch { return null; }
  if (!['http:', 'https:'].includes(x.protocol) || !/^[A-Za-z0-9.\-]{1,253}$/.test(x.hostname) || !x.hostname.includes('.') || u.length > 300) return null;
  return u;
}
export function sitesList(s) {
  let L = []; try { L = JSON.parse(s.test_sites || '[]'); } catch { }
  const out = []; for (const u of Array.isArray(L) ? L : []) { const c = cleanSite(String(u)); if (c && !out.includes(c)) out.push(c); }
  return out.length ? out : [...DEFAULT_SITES];
}

// ---- advanced options -> (snispoofing JSON | null, F+F on, ECH value) ----
export function adv(s) {
  const [sni, sip, sp] = ['spoof_sni', 'spoof_ip', 'spoof_port'].map(k => (s[k] || '').trim());
  let spoof = null;
  if (sni && sip) spoof = `{\n  "active" : true,\n  "fakeSni" : ${JSON.stringify(sni)},\n  "spoofIp" : ${JSON.stringify(sip)},\n  "targetPort" : ${/^\d+$/.test(sp) ? parseInt(sp, 10) : 0}\n}`;
  const i = parseInt(s.ech_i || '-1', 10);
  return [spoof, s.ff_on === '1', (s.ech_on === '1' && i >= 0 && i < ECH.length) ? ECH[i][2] : ''];
}

// ---- which domain the configs point to ----
export async function relayDomain(db, p) { const r = await db.one('SELECT domain FROM relays WHERE p=?', p); return (r && r.domain) || ''; }
export const RELAY_NAMES = { vercel: 'Vercel', netlify: 'Netlify', railway: 'Railway' };
export function panelDomain(s, host) { const d = (s.domain || '').trim(); return d && d !== 'example.com' ? d : host; }
export async function cfgDom(db, s, host) {
  const src = s.cfg_src || 'panel';
  if (src.startsWith('relay:')) { const d = await relayDomain(db, src.slice(6)); if (d) return [d, '443', RELAY_NAMES[src.slice(6)] || 'Relay']; }
  if (src === 'custom' && s.cfg_custom) { const [h, p] = s.cfg_custom.split(':'); return [h, p || s.tls_port, 'Custom']; }
  return [panelDomain(s, host), s.tls_port, 'Direct'];
}

export async function whiteList(db, s) {
  const lim = Math.max(0, parseInt(s.white_limit || '0', 10) || 0);
  const ips = lim ? await db.all("SELECT * FROM scan_ips WHERE kind='ip' ORDER BY ms ASC, id ASC LIMIT ?", lim) : [];
  const snis = s.white_sni === '1' ? (await db.all("SELECT host FROM scan_ips WHERE kind='sni' ORDER BY ms ASC LIMIT 50")).map(r => r.host) : [];
  return [ips, snis];
}

export async function links(db, u, s, host) {
  const [d, port, label] = await cfgDom(db, s, host); const uid = u.uuid; const isip = /^[\d.]+$/.test(d); const ins = isip ? '&allowInsecure=1' : '';
  const [spoof, ffOn, ech] = adv(s);
  const fm = fragFm(s) || (ffOn ? FM : ''); const ff = !!fm;
  const prof = s.frag_on === '1' ? fragProf(s) : null; const bad = new Set((prof && prof.bad) || []);
  const echq = ech ? `&ech=${Q(ech)}` : '';
  const a6 = (s.ipv6 || '').trim().replace(/^\[|\]$/g, ''); const ua = a6.includes(':') ? `[${a6}]` : a6;
  const hosts = [[label, d, port, null, true, d, ua]];                    // (name, address, port, tag, tls, sni, address override)
  if (u.white) {
    const [ips, snis] = await whiteList(db, s); let k = 0;
    for (const x of ips) {
      const h = x.host; const tls = !!x.tls; let sn = d;
      if (tls && snis.length) { sn = snis[k % snis.length]; k++; }
      hosts.push([h.includes(':') ? h.slice(0, 16) : h, h.includes(':') ? `[${h}]` : h, x.port, null, tls, sn, '']);
    }
  }
  const out = [];
  for (const [nm, addr0, p, tag, tls, sni, ov] of hosts) {
    const raw = ov ? (a6 || addr0) : addr0; const addr = ov || addr0;
    for (const pr of protos(s)) {
      const fu = ff && !(bad.has(pr) && fragFm(s));
      const extra = echq + (fu ? `&fm=${Q(fm)}` : '');
      const path = tag ? `/ws/${tag}/${pr}/${uid}` : `/ws/${pr}/${uid}`;
      const ps = `${u.name}-${nm}-${pr}`;
      const t = tls ? `security=tls&type=ws&host=${d}&sni=${sni}&path=${Q(path)}${ins}${extra}` + (fu ? '&fp=unsafe' : '') : `security=none&type=ws&host=${d}&path=${Q(path)}`;
      const add = l => out.push([nm, pr, l]);
      if (pr === 'vless') {
        const z = isip ? '1' : '0';
        if (tls) add(`vless://${uid}@${addr}:${p}?sni=${sni}&security=tls&encryption=none&type=ws&alpn=http%2F1.1&insecure=${z}&host=${d}&path=${Q(path)}&allowInsecure=${z}` + (spoof ? `&snispoofing=${Q(spoof)}` : '') + extra + `&fp=${fu ? 'unsafe' : 'chrome'}#${Q(ps)}`);
        else add(`vless://${uid}@${addr}:${p}?security=none&encryption=none&type=ws&host=${d}&path=${Q(path)}#${Q(ps)}`);
      } else if (pr === 'trojan') add(`trojan://${uid}@${addr}:${p}?${t}#${Q(ps)}`);
      else if (pr === 'shadowsocks') add(`ss://${btoa(`${SS}:${uid}`)}@${addr}:${p}?${t}#${Q(ps)}`);
      else {
        const j = { v: '2', ps, add: raw.replace(/^\[|\]$/g, ''), port: String(p), id: uid, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: d, path, tls: tls ? 'tls' : '' };
        if (tls) j.sni = sni;
        add('vmess://' + btoa(JSON.stringify(j)));
      }
    }
  }
  return out;
}
