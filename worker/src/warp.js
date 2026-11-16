// Cloudflare WARP registration done by the Worker (browsers cannot call this API: no CORS).
//  - WireGuard device: X25519 key pair (WebCrypto) -> POST /reg
//  - MASQUE device:    ECDSA P-256 key pair (WebCrypto) -> POST /reg, then PATCH /reg/{id} to enroll the key
const API = 'https://api.cloudflareclient.com/v0a4005/reg', UA = 'insomnia/8.6.1';
export const MASQUE_PORTS = [443, 500, 1701, 4443, 4500, 8443, 8095];
export class WarpError extends Error { }

const b64 = u8 => btoa(String.fromCharCode(...u8));
const b64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

export async function wgKeypair() {
  const k = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', k.privateKey)), pub = new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey));
  return [b64(pkcs8.slice(-32)), b64(pub)];                // the private scalar is the last 32 bytes of the PKCS#8 wrapper
}
const der = (tag, body) => { const n = body.length; return Uint8Array.from([tag, ...(n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255]), ...body]); };
const cat = (...a) => Uint8Array.from(a.flatMap(x => [...x]));
const hex = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
export async function ecKeypair() {
  const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', k.privateKey), spki = new Uint8Array(await crypto.subtle.exportKey('spki', k.publicKey));
  const pt = cat([4], b64u(jwk.x), b64u(jwk.y)), oidP256 = hex('2a8648ce3d030107');
  const priv = der(0x30, cat(der(2, [1]), der(4, b64u(jwk.d)), der(0xA0, der(6, oidP256)), der(0xA1, der(3, cat([0], pt)))));   // SEC1 ECPrivateKey
  return [b64(priv), b64(spki)];
}

async function call(method, url, body, token, fetchFn = fetch) {
  const h = { 'User-Agent': UA, 'Content-Type': 'application/json' }; if (token) h.Authorization = 'Bearer ' + token;
  let r; try { r = await fetchFn(url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }); } catch (e) { throw new WarpError('Could not reach Cloudflare: ' + (e.message || e)); }
  if (!r.ok) throw new WarpError('Cloudflare answered HTTP ' + r.status);
  try { return await r.json(); } catch { return {}; }
}
const register = (pub, f) => call('POST', API, { install_id: '', fcm_token: '', tos: new Date().toISOString(), type: 'Android', model: 'PC', locale: 'en_US', warp_enabled: true, key: pub }, undefined, f);
const hostOf = ep => { ep = (ep || '').trim(); if (ep.startsWith('[')) return ep.slice(1, ep.indexOf(']')); const m = ep.match(/^(.*):\d+$/); return m && ep.split(':').length === 2 ? m[1] : ep; };

export async function registerWireguard(f = fetch) {
  const [priv, pub] = await wgKeypair(), j = await register(pub, f);
  try {
    const c = j.config, peer = c.peers[0], a = c.interface.addresses;
    return { private_key: priv, peer_public_key: peer.public_key, v4: a.v4, v6: a.v6, reserved: [...Uint8Array.from(atob(c.client_id), x => x.charCodeAt(0))], endpoint_host: hostOf((peer.endpoint || {}).host) || 'engage.cloudflareclient.com', id: j.id || '', account: (j.account || {}).id || '', license: (j.account || {}).license || '', created: Math.floor(Date.now() / 1000) };
  } catch { throw new WarpError('Cloudflare returned an unexpected answer'); }
}
export async function registerMasque(f = fetch) {
  const [, wpub] = await wgKeypair(), j = await register(wpub, f);
  if (!j.id || !j.token) throw new WarpError('Cloudflare returned an unexpected answer');
  const [priv, pub] = await ecKeypair();
  const r = await call('PATCH', `${API}/${j.id}`, { key: pub, key_type: 'secp256r1', tunnel_type: 'masque', name: 'xr-panel' }, j.token, f);
  try {
    const c = r.config, peer = c.peers[0], a = c.interface.addresses, ep = peer.endpoint || {};
    return { private_key: priv, public_key: pub, endpoint_pub_key: peer.public_key, endpoint_v4: hostOf(ep.v4) || '162.159.198.2', endpoint_v6: hostOf(ep.v6) || '2606:4700:103::2', ipv4: a.v4, ipv6: a.v6, id: j.id, access_token: j.token, license: ((r.account || j.account) || {}).license || '', created: Math.floor(Date.now() / 1000) };
  } catch { throw new WarpError('Cloudflare returned an unexpected answer'); }
}
