// Password hashing (PBKDF2 via WebCrypto), signed session cookie, flash messages.
const enc = new TextEncoder();
const b64 = u8 => btoa(String.fromCharCode(...u8));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const ITER = 20000;                                     // Workers cap PBKDF2 at 100000; 20000 keeps login inside small CPU budgets

async function pbkdf2(pw, salt, iter) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, k, 256));
}
export async function hashPw(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${ITER}$${b64(salt)}$${b64(await pbkdf2(pw, salt, ITER))}`;
}
export async function checkPw(stored, pw) {
  const [t, it, s, h] = String(stored || '').split('$');
  if (t !== 'pbkdf2') return false;
  const a = await pbkdf2(pw, unb64(s), +it), b = unb64(h);
  let d = a.length ^ b.length; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

async function hmac(secret, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return [...new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(msg)))].map(x => x.toString(16).padStart(2, '0')).join('');
}
export const cookies = req => Object.fromEntries((req.headers.get('Cookie') || '').split(/;\s*/).filter(Boolean).map(c => { const i = c.indexOf('='); return [c.slice(0, i), decodeURIComponent(c.slice(i + 1))]; }));
export async function makeSession(secret, days = 7) { const exp = Math.floor(Date.now() / 1000) + days * 86400; return `${exp}.${await hmac(secret, 'ok.' + exp)}`; }
export async function validSession(secret, v) {
  const [exp, sig] = String(v || '').split('.');
  if (!exp || !sig || +exp < Date.now() / 1000) return false;
  const want = await hmac(secret, 'ok.' + exp); let d = want.length ^ sig.length; for (let i = 0; i < want.length; i++) d |= want.charCodeAt(i) ^ (sig.charCodeAt(i) || 0); return d === 0;
}
export const cookie = (name, val, o = {}) => `${name}=${encodeURIComponent(val)}; Path=/; HttpOnly; Secure; SameSite=Lax` + (o.max !== undefined ? `; Max-Age=${o.max}` : '');
