// xr PANEL for Cloudflare Workers + D1. No Xray: VLESS / Trojan run inside the Worker, everything else is relayed.
import { connect } from 'cloudflare:sockets';
import { DB, init, state, fmt, GB, now, DEFAULTS, DEFAULT_SITES } from './db.js';
import { hashPw, checkPw, makeSession, validSession, cookies, cookie } from './auth.js';
import { links, cfgDom, whiteList, cleanSite, sitesList, fragProf, tierOf, FRAG_TIERS, ECH, adv, protos, NATIVE, ALL, panelDomain } from './links.js';
import * as UI from './ui.js';
import * as LOC from './loc.js';
import * as WP from './warp.js';
import * as RL from './relays.js';
import { probeAll } from './proxy.js';
import { Meter, dialer, serveNative, serveUpstream, WS_PATH, earlyData } from './relay.js';

const CLIENTS = [['iOS', [['Streisand', 'https://apps.apple.com/app/streisand/id6450534064', 'streisand://import/{u}'], ['V2Box', 'https://apps.apple.com/app/v2box-v2ray-client/id6446814690', 'v2box://install-sub?url={u}&name=VPN'], ['Shadowrocket', 'https://apps.apple.com/app/shadowrocket/id932747118', 'shadowrocket://add/sub://{b}']]],
  ['Android', [['v2rayNG', 'https://github.com/2dust/v2rayNG/releases', 'v2rayng://install-sub?url={u}&name=VPN'], ['Hiddify', 'https://github.com/hiddify/hiddify-app/releases', 'hiddify://import/{u}'], ['NekoBox', 'https://github.com/MatsuriDayo/NekoBoxForAndroid/releases', null]]]];
const clientGroups = su => CLIENTS.map(([g, a]) => [g, a.map(([n, d, i]) => [n, d, i ? i.replace('{u}', encodeURIComponent(su)).replace('{b}', btoa(su)) : null])]);
const KINDS = ['ip', 'sni', 'warp', 'masque'];
const NOFLAG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 4 3"><rect width="4" height="3" fill="#3a3a4a"/><path d="M1 .5v2M1 .5h1.7l-.4.5.4.5H1" fill="#8c8ca0"/></svg>';
const MARK = RL.MARK;

const J = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const HTML = (h, extra = {}) => new Response(String(h), { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...extra } });
const body = async req => { try { return await req.json(); } catch { return {}; } };

export function makeApp({ connectFn = connect, fetchFn = (...a) => fetch(...a), pair = () => new WebSocketPair(), wsResponse = (ws, headers) => new Response(null, { status: 101, webSocket: ws, headers }) } = {}) {
  const userCache = new Map();
  const hostOf = url => url.hostname;

  async function ctxFor(db, req, url, extra = {}) {
    const flashes = []; const ck = cookies(req); if (ck.flash) { try { flashes.push(...JSON.parse(ck.flash)); } catch { } }
    const s = extra.s || await db.S();
    const base = (s.domain || '').trim() && s.domain.trim() !== 'example.com' ? `https://${s.domain.trim()}` : `${url.protocol}//${url.host}`;
    return { s, flashes, chrome: extra.chrome !== false, endpoint: extra.endpoint, suburl: u => `${base}/sub/${u.uuid}`, host: hostOf(url), clearFlash: flashes.length > 0 };
  }
  const page = (c, h, extra) => HTML(h, c.clearFlash ? { 'set-cookie': cookie('flash', '', { max: 0 }), ...extra } : extra);
  const redirect = (to, ...msgs) => { const h = new Headers({ Location: to }); if (msgs.length) h.append('set-cookie', cookie('flash', JSON.stringify(msgs), { max: 30 })); return new Response(null, { status: 302, headers: h }); };

  async function status(db, s) {
    const us = await db.all('SELECT * FROM users'); const act = us.filter(u => state(u) === 'active').length, used = us.reduce((a, u) => a + (u.used || 0), 0), quota = us.reduce((a, u) => a + (u.limit_gb || 0) * GB, 0);
    const g = (await db.one('SELECT COUNT(*) c FROM grps')).c, p = (await db.one('SELECT COUNT(*) c FROM proxies')).c, ips = (await db.one("SELECT COUNT(*) c FROM scan_ips WHERE kind='ip'")).c;
    const rl = (await db.one("SELECT COUNT(*) c FROM relays WHERE domain!='' AND domain IS NOT NULL")).c, fp = s.frag_on === '1' ? fragProf(s) : null;
    return { users: us.length, active: act, ap: us.length ? Math.round(act / us.length * 100) : 0, traffic: fmt(used), tp: quota ? Math.min(100, Math.round(used / quota * 100)) : 0, mode: protos(s).length === 2 ? 'Built-in' : 'Upstream', groups: g, proxies: p, ips, relays: rl, frag: fp ? fp.tier : (s.frag_on === '1' ? 'measuring' : 'off') };
  }

  async function panelTarget(db, s, url) {
    const h = panelDomain(s, url.hostname), p = /^\d+$/.test(s.tls_port) ? +s.tls_port : 443;
    const ok = /^[\d.]+$/.test(h) ? LOC.isGlobal(h) : (h !== 'localhost' && h.includes('.')); return ok ? [h, p] : null;
  }

  // ---------------- WebSocket relay ----------------
  async function wsRoute(req, env, ctx, m) {
    if (req.headers.get('Upgrade') !== 'websocket') return new Response('Expected WebSocket', { status: 426 });
    const proto = m[1], uid = m[2].toLowerCase(), db = new DB(env); await init(env, hashPw);
    let hit = userCache.get(uid); if (!hit || Date.now() - hit.t > 15000) { hit = { t: Date.now(), u: await db.one('SELECT * FROM users WHERE uuid=?', uid), s: await db.S() }; userCache.set(uid, hit); }
    const { u, s } = hit; if (!u || state(u) !== 'active') return new Response('Forbidden', { status: 403 });
    const up = (s.upstream || '').trim();
    if (!up && !NATIVE.includes(proto)) return new Response('This protocol needs an upstream relay (Settings)', { status: 404 });
    const [client, server] = Object.values(pair()); server.accept(); const meter = new Meter(db, u), ph = req.headers.get('Sec-WebSocket-Protocol') || '';
    if (up) ctx.waitUntil(serveUpstream(server, { upstream: up, path: `/ws/${proto}/${uid}`, protocolHeader: ph, meter, ctx, fetchFn }));
    else serveNative(server, { proto, user: u, dial: await dialer(db, connectFn, u), meter, ctx, early: earlyData(ph) });
    return wsResponse(client, ph ? { 'Sec-WebSocket-Protocol': ph } : {});
  }

  // ---------------- main ----------------
  async function handle(req, env, ctx) {
    const url = new URL(req.url), path = url.pathname, method = req.method;
    const wm = path.match(WS_PATH); if (wm) return wsRoute(req, env, ctx, wm);
    if (path === '/relay-check') return new Response(MARK, { headers: { 'content-type': 'text/plain', 'cache-control': 'no-store' } });
    await init(env, hashPw); const db = new DB(env); let s = await db.S();

    if (path === '/login') {
      if (method === 'POST') {
        const f = await req.formData();
        if (f.get('user') === 'admin' && await checkPw(s.pw, String(f.get('pw') || ''))) return new Response(null, { status: 302, headers: { Location: '/', 'set-cookie': cookie('xr', await makeSession(s.secret), { max: 7 * 86400 }) } });
        await new Promise(r => setTimeout(r, 800)); return redirect('/login', 'Wrong username or password');
      }
      const c = await ctxFor(db, req, url, { s, chrome: false }); return page(c, UI.login(c));
    }
    if (path === '/logout') return new Response(null, { status: 302, headers: { Location: '/login', 'set-cookie': cookie('xr', '', { max: 0 }) } });

    // public subscription
    let m;
    if ((m = path.match(/^\/sub\/([0-9a-fA-F-]{36})$/))) {
      const u = await db.one('SELECT * FROM users WHERE uuid=?', m[1].toLowerCase()); if (!u) return new Response('Not found', { status: 404 });
      const st = state(u), L = st === 'active' ? await links(db, u, s, url.hostname) : [];
      if ((req.headers.get('Accept') || '').includes('text/html') && !url.searchParams.get('raw')) { const c = await ctxFor(db, req, url, { s, chrome: false }); return page(c, UI.sub(c, u, st, L, c.suburl(u), clientGroups(c.suburl(u)))); }
      return new Response(btoa(L.map(x => x[2]).join('\n')), { headers: { 'content-type': 'text/plain', 'subscription-userinfo': `upload=0; download=${u.used}; total=${Math.floor(u.limit_gb * GB)}; expire=${u.expire}`, 'profile-update-interval': '1', 'profile-title': 'VPN' } });
    }

    // everything below needs a session
    if (!(await validSession(s.secret, cookies(req).xr))) return method === 'GET' && !path.startsWith('/api/') ? redirect('/login') : (path.startsWith('/api/') ? J({ error: 'login required' }, 401) : redirect('/login'));
    const C = (endpoint, extra = {}) => ctxFor(db, req, url, { s, endpoint, ...extra });
    const form = async () => { let f; try { f = await req.formData(); } catch { f = new FormData(); } return { get: k => f.get(k), all: k => f.getAll(k), has: k => f.has(k) }; };

    if (path === '/' ) { const c = await C('home'); return page(c, UI.home(c, await status(db, s))); }
    if (path === '/api/status') return J(await status(db, s));
    if (path === '/api/cf') return J(await cfUsage(env));

    if ((m = path.match(/^\/flag\/([a-z]{2})\.svg$/))) {
      const cache = typeof caches !== 'undefined' ? caches.default : null, key = new Request(`https://flags.invalid/${m[1]}.svg`);
      const hit = cache && await cache.match(key); if (hit) return hit;
      for (const src of [`https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.2.3/flags/4x3/${m[1]}.svg`, `https://flagcdn.com/${m[1]}.svg`]) {
        try { const r = await fetchFn(src); const t = r.ok ? await r.text() : ''; if (/<svg/i.test(t) && !/<script|onload|foreignobject/i.test(t)) { const res = new Response(t, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'private, max-age=86400' } }); if (cache) ctx.waitUntil(cache.put(key, res.clone())); return res; } } catch { }
      }
      return new Response(NOFLAG, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'no-store' } });
    }

    if (path === '/api/probe' && method === 'POST') {
      const d = await body(req), h = String(d.host || '').trim(), p = String(d.port || '').trim(); if (!LOC.valid(h, p)) return J({ error: 'Enter a valid IP/host and port' }, 400);
      const [[res, best], g] = await Promise.all([probeAll(connectFn, h, +p), LOC.geo(h, fetchFn)]); return J({ results: res, best, geo: g });
    }

    // ---- users ----
    if (path === '/users') { const c = await C('users'); return page(c, UI.users(c, await db.all('SELECT * FROM users ORDER BY id DESC'), s, await LOC.groups(db), url.searchParams)); }
    if (path === '/users/add' && method === 'POST') {
      const f = await form(); if ((await db.one('SELECT COUNT(*) c FROM users')).c >= parseInt(s.max_users, 10)) return redirect('/users', 'User limit reached. Raise it in Settings.');
      const days = parseFloat(f.get('days') || 0) || 0; await db.run('INSERT INTO users(name,uuid,limit_gb,expire,created) VALUES(?,?,?,?,?)', (f.get('name') || '').trim() || 'user', crypto.randomUUID(), parseFloat(f.get('limit') || 0) || 0, days ? Math.floor(now() + days * 86400) : 0, now());
      return redirect('/users', 'User created');
    }
    if ((m = path.match(/^\/users\/(\d+)\/(edit|group|delete)$/)) && method === 'POST') {
      const id = +m[1], f = await form(); userCache.clear();
      if (m[2] === 'edit') {
        await db.run('UPDATE users SET name=?,limit_gb=?,enabled=? WHERE id=?', (f.get('name') || '').trim(), parseFloat(f.get('limit') || 0) || 0, f.has('enabled') ? 1 : 0, id);
        if (f.get('days') !== null && f.get('days') !== '') { const d = parseFloat(f.get('days')) || 0; await db.run('UPDATE users SET expire=? WHERE id=?', d ? Math.floor(now() + d * 86400) : 0, id); }
        if (f.has('reset')) await db.run('UPDATE users SET used=0 WHERE id=?', id); return redirect(`/users?o=${id}&p=edit`, 'User saved');
      }
      if (m[2] === 'group') { const g = await db.one('SELECT * FROM grps WHERE id=?', parseInt(f.get('g') || 0, 10) || 0); await db.run('UPDATE users SET grp_id=? WHERE id=?', g ? g.id : 0, id); return redirect(`/users?o=${id}&p=loc`, g ? `Traffic now exits through ${g.name}` : 'Traffic now exits directly from the Worker'); }
      await db.run('DELETE FROM users WHERE id=?', id); return redirect('/users', 'User deleted');
    }

    // ---- locations ----
    if (path === '/locations') { const c = await C('locations'); return page(c, UI.locations(c, await LOC.groups(db))); }
    if (path === '/locations/add' && method === 'POST') {
      const f = await form(), h = (f.get('host') || '').trim(), p = (f.get('port') || '').trim();
      if (!LOC.valid(h, p)) return redirect('/locations', 'Enter a valid IP/host and port');
      if (await db.one('SELECT 1 x FROM proxies WHERE host=? AND port=?', h, +p)) return redirect('/locations', 'This IP is already in a group');
      const [, best] = await probeAll(connectFn, h, +p); if (!best) return redirect('/locations', 'No protocol connected. IP not added.');
      const g = (await LOC.geo(h, fetchFn)) || { cc: '', name: 'Other' }; await LOC.putProxy(db, h, +p, best.proto, best.ms, g); userCache.clear();
      return redirect('/locations', `Added to ${g.name} · ${best.proto} ${best.ms}ms` + (g.cc ? '' : ' · country unknown (private IP or lookup failed)'));
    }
    if ((m = path.match(/^\/proxies\/(\d+)\/delete$/)) && method === 'POST') { const r = await db.one('SELECT grp_id FROM proxies WHERE id=?', +m[1]); if (r) { await db.run('DELETE FROM proxies WHERE id=?', +m[1]); await LOC.dropIfEmpty(db, r.grp_id); userCache.clear(); } return redirect('/locations'); }
    if ((m = path.match(/^\/groups\/(\d+)\/delete$/)) && method === 'POST') { await db.run('DELETE FROM proxies WHERE grp_id=?', +m[1]); await LOC.dropIfEmpty(db, +m[1]); await db.run('DELETE FROM grps WHERE id=?', +m[1]); userCache.clear(); return redirect('/locations'); }
    if (path === '/api/loc/start' && method === 'POST') { const r = await LOC.startJob(db, (await body(req)).kind === 'recover' ? 'recover' : 'auto', fetchFn); return r.error ? J({ ok: false, ...r }, 409) : J({ ok: true }); }
    if (path === '/api/loc/step' && method === 'POST') { userCache.clear(); return J(await LOC.stepJob(db, connectFn, fetchFn)); }
    if (path === '/api/loc/stop' && method === 'POST') return J({ ok: true, ...(await LOC.stopJob(db)) });
    if (path === '/api/loc/status') return J(LOC.view(await LOC.getJob(db), +(url.searchParams.get('since') || 0)));

    // ---- clients ----
    if (path === '/clients') {
      const c = await C('clients'), us = await db.all('SELECT * FROM users ORDER BY id DESC'), [ips] = await whiteList(db, s);
      return page(c, UI.clients(c, us.map(x => { const su = c.suburl(x); return { x, sub: su, groups: clientGroups(su) }; }), url.searchParams.get('u') || '', ips.length, s.white_limit || '0'));
    }
    if ((m = path.match(/^\/clients\/(\d+)\/white$/)) && method === 'POST') { const f = await form(); await db.run('UPDATE users SET white=? WHERE id=?', f.has('on') ? 1 : 0, +m[1]); const u = await db.one('SELECT uuid FROM users WHERE id=?', +m[1]); return redirect(`/clients?u=${u ? u.uuid : ''}`); }

    // ---- test sites / fragment ----
    if (path === '/api/sites/next' && method === 'POST') {
      const L = sitesList(s), n = L.length, cur = (parseInt(s.site_rr || 0, 10) || 0) % n, w = Math.min(n, 3); await db.set('site_rr', (cur + w) % n);
      return J({ sites: Array.from({ length: w }, (_, i) => L[(cur + i) % n]), total: n, start: cur });
    }
    if (path === '/advanced') { const c = await C('advanced'); return page(c, UI.advanced(c, s, adv(s)[0], url.searchParams.get('o') || '')); }
    if (path === '/advanced/spoof' && method === 'POST') {
      const f = await form(), [sni, ip, port] = ['sni', 'ip', 'port'].map(k => (f.get(k) || '').trim());
      if ((sni && !/^[A-Za-z0-9.\-]{1,253}$/.test(sni)) || (ip && !/^[A-Za-z0-9.\-:]{1,253}$/.test(ip)) || (port && !(/^\d+$/.test(port) && +port <= 65535))) return redirect('/advanced?o=spoof', 'Invalid SNI, IP or port');
      await db.batch([['UPDATE settings SET v=? WHERE k=?', sni, 'spoof_sni'], ['UPDATE settings SET v=? WHERE k=?', ip, 'spoof_ip'], ['UPDATE settings SET v=? WHERE k=?', port, 'spoof_port']]);
      return redirect('/advanced?o=spoof', sni && ip ? 'Spoof saved · applied to VLESS configs' : 'Spoof is off (fill both SNI and IP to turn it on)');
    }
    if (path === '/advanced/ipv6' && method === 'POST') {
      const v = ((await form()).get('ip') || '').trim().replace(/^\[|\]$/g, ''); if (v && !/^[A-Za-z0-9.:\-]{1,253}$/.test(v)) return redirect('/advanced?o=ipv6', 'Invalid address');
      await db.set('ipv6', v); return redirect('/advanced?o=ipv6', v ? 'Address saved · used in all configs' : 'Address cleared · configs use the domain again');
    }
    if ((m = path.match(/^\/advanced\/toggle\/(ff|ech|frag)$/)) && method === 'POST') {
      const on = (await form()).has('on') ? '1' : '0'; await db.set(m[1] + '_on', on); if (m[1] === 'frag' && on === '1') await db.set('frag_prof', ''); return redirect('/advanced?o=' + m[1]);
    }
    if (path === '/advanced/ech' && method === 'POST') { const i = parseInt((await form()).get('e'), 10); if (i >= 0 && i < ECH.length) { await db.set('ech_i', i); return redirect('/advanced?o=ech', `ECH: ${ECH[i][0]} · applied to all configs`); } return redirect('/advanced?o=ech'); }
    if (path === '/advanced/fragment/save' && method === 'POST') {
      const d = await body(req), rtt = Math.max(0, parseFloat(d.rtt)), ok = Math.min(1, Math.max(0, parseFloat(d.ok))), jit = Math.max(0, parseFloat(d.jitter || 0)), n = Math.max(0, parseInt(d.n || 0, 10) || 0);
      if (!isFinite(rtt) || !isFinite(ok)) return J({ ok: false, error: 'Bad measurement' }, 400);
      const tier = tierOf(rtt, ok), net = d.net && typeof d.net === 'object' ? d.net : {}, sites = (d.sites || []).slice(0, 12).map(u => cleanSite(String(u))).filter(Boolean);
      const prof = { tier: tier in FRAG_TIERS ? tier : 'none', rtt: Math.round(rtt), ok: Math.round(ok * 100) / 100, jitter: Math.round(jit || 0), n, sites, ts: now(), net: Object.fromEntries(['type', 'downlink', 'rtt'].filter(k => net[k] != null).map(k => [k, String(net[k]).slice(0, 12)])), verified: null };
      await db.set('frag_prof', JSON.stringify(prof)); return J({ ok: true, tier, profile: prof });
    }
    if (path === '/api/fragment/test' && method === 'POST') {
      const pr = fragProf(s); if (!pr) return J({ ok: false, error: 'Nothing measured yet' }, 400);
      const first = await db.one('SELECT uuid FROM users WHERE enabled=1 LIMIT 1'), uid = first ? first.uuid : crypto.randomUUID(), on = protos(s);
      return J({ ok: true, results: ALL.map(p => p === 'vmess' ? { proto: p, skip: true, text: 'no fragment field in vmess links' } : on.includes(p) ? { proto: p, path: `/ws/${p}/${uid}` } : { proto: p, skip: true, text: 'needs an upstream relay' }) });
    }
    if (path === '/api/fragment/verdict' && method === 'POST') {
      const d = await body(req), pr = fragProf(s); if (!pr) return J({ ok: false }, 400); const bad = (d.bad || []).filter(x => ALL.includes(x));
      pr.bad = bad; pr.verified = d.verified === null ? null : !bad.length; pr.verified_ts = now(); await db.set('frag_prof', JSON.stringify(pr)); return J({ ok: true });
    }

    // ---- settings ----
    if (path === '/settings') {
      const c = await C('settings'), rv = await RL.active(db), [d, , lbl] = await cfgDom(db, s, url.hostname), src = lbl === 'Direct' ? 'panel' : lbl === 'Custom' ? 'custom' : s.cfg_src;
      c.settings = { sites: sitesList(s), defaultPw: await checkPw(s.pw, 'admin'), detected: url.hostname, relays: rv, panelDom: panelDomain(s, url.hostname), cfgSrc: src, cfgLabel: src === 'panel' ? 'panel' : d };
      return page(c, UI.settings(c, s, url.searchParams.get('o') || ''));
    }
    if (path === '/settings/cfgdomain' && method === 'POST') {
      const fd = await req.formData(), pick = String(fd.get('pick') || '');
      if (pick === 'panel') { await db.set('cfg_src', 'panel'); return redirect('/settings', 'Configs use the panel domain: ' + panelDomain(s, url.hostname)); }
      if (pick.startsWith('relay:')) { const r = await RL.row(db, pick.slice(6)); if (r.domain) { await db.set('cfg_src', pick); return redirect('/settings', 'Configs use ' + r.domain); } return redirect('/settings'); }
      if (pick === 'custom') {
        const v = String(fd.get('custom') || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/\/+$/, '');
        if (!/^[a-z0-9.\-]{1,253}(:\d{1,5})?$/.test(v)) return redirect('/settings', 'Enter a domain like sub.example.com or sub.example.com:8443');
        await db.batch([['UPDATE settings SET v=? WHERE k=?', v, 'cfg_custom'], ['UPDATE settings SET v=? WHERE k=?', 'custom', 'cfg_src']]); return redirect('/settings', 'Configs use ' + v);
      }
      return redirect('/settings');
    }
    if (path === '/settings/password' && method === 'POST') {
      const f = await form(); if (!(await checkPw(s.pw, f.get('old') || ''))) return redirect('/settings', 'Current password is wrong');
      if ((f.get('new') || '').length < 4) return redirect('/settings', 'New password needs at least 4 characters'); await db.set('pw', await hashPw(f.get('new'))); return redirect('/settings', 'Password changed');
    }
    if (path === '/settings/save' && method === 'POST') {
      const f = await form(); userCache.clear();
      for (const k of ['domain', 'tls_port', 'max_users', 'upstream']) if (f.get(k) !== null) { let v = String(f.get(k)).trim(); if (k === 'upstream') v = v.replace(/^https?:\/\//, '').replace(/\/.*$/, ''); if (k === 'domain') v = v.replace(/^https?:\/\//, '').replace(/\/.*$/, ''); await db.set(k, v); }
      if (f.get('white_limit') !== null) { const v = String(f.get('white_limit')).trim(); await db.set('white_limit', /^\d+$/.test(v) ? Math.min(+v, 200) : 10); await db.set('white_sni', f.has('white_sni') ? '1' : '0'); }
      return redirect('/settings', 'Settings saved');
    }
    if (path === '/settings/sites' && method === 'POST') {
      const f = await form(); let L, msg;
      if (f.has('reset')) { L = [...DEFAULT_SITES]; msg = `Test sites reset to the ${L.length} defaults`; }
      else { L = []; for (const u of f.all('site').slice(0, 40)) { const c = cleanSite(u); if (c && !L.includes(c)) L.push(c); } if (!L.length) return redirect('/settings?o=sites', 'Keep at least one valid site (like https://www.google.com/generate_204)'); msg = `Saved ${L.length} test site${L.length === 1 ? '' : 's'}`; }
      await db.batch([['UPDATE settings SET v=? WHERE k=?', JSON.stringify(L), 'test_sites'], ['UPDATE settings SET v=? WHERE k=?', '0', 'site_rr']]); return redirect('/settings?o=sites', msg);
    }

    // ---- network / WARP / MASQUE ----
    if (path === '/network') { const cnt = {}; for (const k of KINDS) cnt[k] = (await db.one('SELECT COUNT(*) c FROM scan_ips WHERE kind=?', k)).c; const c = await C('network'); return page(c, UI.network(c, s, cnt)); }
    if (path === '/api/net/list') { const k = url.searchParams.get('kind'); if (!KINDS.includes(k)) return J({}, 400); return J(await db.all('SELECT id,host,port,tls,ms,via,ts FROM scan_ips WHERE kind=? ORDER BY ms ASC, id ASC LIMIT 500', k)); }
    if (path === '/api/net/save' && method === 'POST') {
      const d = await body(req), k = d.kind; if (!KINDS.includes(k)) return J({}, 400); let n = 0;
      if (k === 'masque') { let mj = {}; try { mj = JSON.parse(s.masque || '{}'); } catch { } if (!mj.private_key) return J({ saved: 0, error: 'Register Masque first' }, 403); }
      const stmts = [];
      for (const x of (d.items || []).slice(0, 2000)) {
        const h = String(x.host || '').trim().toLowerCase().replace(/^\[|\]$/g, ''), p = parseInt(x.port || 0, 10), ms = Math.max(1, Math.round(parseFloat(x.ms))), tls = x.tls === false || x.tls === 0 ? 0 : 1;
        const okHost = k === 'sni' ? /^[a-z0-9]([a-z0-9.\-]{0,251}[a-z0-9])?$/.test(h) && h.includes('.') : /^[\d.]+$/.test(h) || /^[0-9a-f:]+$/.test(h) && h.includes(':');
        if (!okHost || !(p >= 0 && p <= 65535) || !isFinite(ms)) continue;
        stmts.push(['INSERT INTO scan_ips(kind,host,port,tls,ms,via,ts) VALUES(?,?,?,?,?,?,?) ON CONFLICT(kind,host,port,tls) DO UPDATE SET ms=excluded.ms,via=excluded.via,ts=excluded.ts', k, h, p, tls, ms, String(x.via || '').slice(0, 12), now()]); n++;
      }
      for (let i = 0; i < stmts.length; i += 50) await db.batch(stmts.slice(i, i + 50)); return J({ saved: n });
    }
    if (path === '/api/net/delete' && method === 'POST') { const d = await body(req); if (!KINDS.includes(d.kind)) return J({}, 400); if (d.all) await db.run('DELETE FROM scan_ips WHERE kind=?', d.kind); else await db.run('DELETE FROM scan_ips WHERE kind=? AND id=?', d.kind, parseInt(d.id || 0, 10)); return J({ ok: true }); }
    const sj = k => { try { return JSON.parse(s[k] || 'null') || {}; } catch { return {}; } };
    if (path === '/api/warp') return J(sj('warp')); if (path === '/api/masque') return J(sj('masque'));
    if ((m = path.match(/^\/api\/(warp|masque)\/register$/)) && method === 'POST') {
      try { const v = m[1] === 'warp' ? await WP.registerWireguard(fetchFn) : await WP.registerMasque(fetchFn); await db.set(m[1], JSON.stringify(v)); return J({ ok: true, ...v }); }
      catch (e) { return J({ ok: false, error: e.message }, 502); }
    }
    if (path === '/api/fetch' && method === 'POST') return fetchSub(await body(req));
    if (path === '/convert') { const c = await C('convert'); return page(c, UI.convert(c)); }

    // ---- relays ----
    if (path === '/relays') { const t = await panelTarget(db, s, url), c = await C('relays'); return page(c, UI.relays(c, await RL.allViews(db), url.searchParams.get('o') || '', t ? `${t[0]}:${t[1]}` : '', !!t)); }
    if ((m = path.match(/^\/relays\/(vercel|netlify|railway)\/(deploy|remove)$/)) && method === 'POST') {
      const p = m[1];
      if (m[2] === 'deploy') { const t = await panelTarget(db, s, url); if (!t) return redirect(`/relays?o=${p}`, `Set your public panel domain in Settings first (now: ${panelDomain(s, url.hostname)}).`); const e = await RL.startDeploy(db, p, ((await form()).get('token') || '').trim(), t, fetchFn); return e ? redirect(`/relays?o=${p}`, e) : redirect(`/relays?o=${p}`); }
      const e = await RL.remove(db, p, fetchFn); if (e) return redirect(`/relays?o=${p}`, 'Could not remove: ' + e);
      if (s.cfg_src === 'relay:' + p) await db.set('cfg_src', 'panel'); return redirect(`/relays?o=${p}`, 'Relay removed');
    }
    if ((m = path.match(/^\/api\/relays\/(vercel|netlify|railway)(\/ping)?$/))) {
      const p = m[1]; if (m[2]) return method === 'POST' ? J({ ping: await RL.doPing(db, p, fetchFn) }) : J({}, 405);
      const t = await panelTarget(db, s, url); if (t) await RL.advance(db, p, t, fetchFn); return J(await RL.view(db, p));
    }
    return new Response('Not found', { status: 404 });
  }

  async function fetchSub(d) {
    let u = String(d.url || '').trim();
    for (let i = 0; i < 4; i++) {
      let x; try { x = new URL(u); } catch { return J({ ok: false, error: 'Enter a full http(s) link' }, 400); }
      if (!['http:', 'https:'].includes(x.protocol) || !x.hostname) return J({ ok: false, error: 'Enter a full http(s) link' }, 400);
      const ip = await LOC.resolve(x.hostname, fetchFn); if (!ip || !LOC.isGlobal(ip)) return J({ ok: false, error: 'Only public hosts are allowed' }, 400);
      let r; try { r = await fetchFn(u, { headers: { 'User-Agent': 'v2rayN/7.0' }, redirect: 'manual' }); } catch (e) { return J({ ok: false, error: 'Could not fetch: ' + (e.message || e) }, 502); }
      if ([301, 302, 303, 307, 308].includes(r.status) && r.headers.get('location')) { u = new URL(r.headers.get('location'), u).href; continue; }
      if (!r.ok) return J({ ok: false, error: 'The server answered HTTP ' + r.status }, 502);
      return J({ ok: true, text: (await r.text()).slice(0, 2_000_000) });
    }
    return J({ ok: false, error: 'Too many redirects' }, 502);
  }

  return { fetch: async (req, env, ctx) => { try { return await handle(req, env, ctx); } catch (e) { console.error(e); return new Response('Internal error: ' + (e.message || e), { status: 500 }); } } };
}


// ---- Cloudflare account usage (requests today) ----
let _cf = { t: 0, v: null };
async function cfUsage(env) {
  if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { ok: false, error: 'not_configured' };
  if (_cf.v && Date.now() - _cf.t < 60000) return _cf.v;
  const d = new Date(), from = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const gq = async (field, must) => {
    try {
      const q = 'query($a:String!,$f:Time!,$t:Time!){viewer{accounts(filter:{accountTag:$a}){x:' + field + '(limit:10000,filter:{datetime_geq:$f,datetime_leq:$t}){sum{requests}}}}}';
      const r = await fetch('https://api.cloudflare.com/client/v4/graphql', { method: 'POST', headers: { Authorization: 'Bearer ' + env.CF_API_TOKEN, 'content-type': 'application/json' }, body: JSON.stringify({ query: q, variables: { a: env.CF_ACCOUNT_ID, f: from.toISOString(), t: d.toISOString() } }) });
      const j = await r.json();
      if (j.errors && j.errors.length) throw new Error(j.errors[0].message);
      return (((j.data || {}).viewer || {}).accounts || [{}])[0].x.reduce((n, x) => n + ((x.sum || {}).requests || 0), 0);
    } catch (e) { if (must) throw e; return 0; }
  };
  let v;
  try {
    const used = (await gq('workersInvocationsAdaptive', true)) + (await gq('pagesFunctionsInvocationsAdaptiveGroups', false)), limit = Number(env.CF_REQ_LIMIT) || 0;
    v = { ok: true, used, limit, left: limit ? Math.max(0, limit - used) : null, reset: from.getTime() + 86400000 };
  } catch (e) { return { ok: false, error: String(e.message || e) }; }
  _cf = { t: Date.now(), v };
  return v;
}

export default makeApp();
