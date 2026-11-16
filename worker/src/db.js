// D1 helpers, defaults and one-time schema creation.
export const GB = 1024 ** 3;

export const DEFAULT_SITES = ['https://www.google.com/generate_204', 'https://www.gstatic.com/generate_204', 'https://cp.cloudflare.com/generate_204',
  'https://www.cloudflare.com/cdn-cgi/trace', 'https://www.apple.com/library/test/success.html', 'https://www.msftconnecttest.com/connecttest.txt',
  'https://detectportal.firefox.com/success.txt', 'https://www.youtube.com/generate_204', 'https://www.wikipedia.org/'];

export const DEFAULTS = {
  domain: '', tls_port: '443', max_users: '100', white_limit: '10', white_sni: '0', upstream: '',
  cfg_src: 'panel', cfg_custom: '', warp: '', masque: '', test_sites: JSON.stringify(DEFAULT_SITES), site_rr: '0', loc_last: '[]', job: '',
  spoof_sni: '', spoof_ip: '', spoof_port: '', ff_on: '0', ech_on: '0', ech_i: '-1', ipv6: '', frag_on: '0', frag_prof: '',
};

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, uuid TEXT UNIQUE, limit_gb REAL DEFAULT 0, used INTEGER DEFAULT 0, expire INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1, created INTEGER, grp_id INTEGER DEFAULT 0, white INTEGER DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT)`,
  `CREATE TABLE IF NOT EXISTS grps(id INTEGER PRIMARY KEY, name TEXT, cc TEXT DEFAULT '')`,
  `CREATE TABLE IF NOT EXISTS proxies(id INTEGER PRIMARY KEY, grp_id INTEGER, host TEXT, port INTEGER, proto TEXT, ms INTEGER)`,
  `CREATE TABLE IF NOT EXISTS relays(p TEXT PRIMARY KEY, token TEXT, status TEXT DEFAULT 'idle', steps TEXT, domain TEXT, ref TEXT, ping TEXT, err TEXT, upd INTEGER DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS scan_ips(id INTEGER PRIMARY KEY, kind TEXT, host TEXT, port INTEGER DEFAULT 0, tls INTEGER DEFAULT 1, ms INTEGER, via TEXT, ts INTEGER, UNIQUE(kind,host,port,tls))`,
  `CREATE TABLE IF NOT EXISTS cand(id INTEGER PRIMARY KEY, host TEXT, port INTEGER, proto TEXT)`,
];

export const now = () => Math.floor(Date.now() / 1000);

export class DB {
  constructor(env) { this.d = env.DB; }
  async all(sql, ...a) { return (await this.d.prepare(sql).bind(...a).all()).results || []; }
  async one(sql, ...a) { return (await this.d.prepare(sql).bind(...a).first()) || null; }
  async run(sql, ...a) { return this.d.prepare(sql).bind(...a).run(); }
  async batch(list) { return this.d.batch(list.map(([sql, ...a]) => this.d.prepare(sql).bind(...a))); }
  async S() { const o = {}; for (const r of await this.all('SELECT k,v FROM settings')) o[r.k] = r.v; return o; }
  async set(k, v) { await this.run('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', k, String(v)); }
}

let ready = null;
export function init(env, hashPw) {
  // runs once per isolate; every statement is idempotent
  return ready || (ready = (async () => {
    const db = new DB(env);
    await db.batch(SCHEMA.map(s => [s]));
    await db.batch(Object.entries(DEFAULTS).map(([k, v]) => ['INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)', k, v]));
    const have = await db.one("SELECT 1 x FROM settings WHERE k='pw'");
    if (!have) {
      const secret = [...crypto.getRandomValues(new Uint8Array(24))].map(b => b.toString(16).padStart(2, '0')).join('');
      await db.batch([['INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)', 'pw', await hashPw('admin')], ['INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)', 'secret', secret]]);
    }
  })().catch(e => { ready = null; throw e; }));
}
export const resetInit = () => { ready = null; };

export function state(u) {
  if (!u.enabled) return 'disabled';
  if (u.expire && u.expire < now()) return 'expired';
  if (u.limit_gb && u.used >= u.limit_gb * GB) return 'limited';
  return 'active';
}
export function left(u) {
  if (!u.expire) return 'no expiry';
  const d = Math.floor((u.expire - now()) / 86400); return d >= 0 ? `${d}d left` : 'expired';
}
export const pct = u => (u.limit_gb ? Math.min(100, Math.round(u.used / (u.limit_gb * GB) * 100)) : 0);
export function fmt(b) {
  for (const x of ['B', 'KB', 'MB', 'GB', 'TB']) {
    if (b < 1024 || x === 'TB') return x === 'B' ? `${Math.floor(b)} B` : `${b.toFixed(1)} ${x}`;
    b /= 1024;
  }
}
