// Pages. Same markup and classes as the original Flask templates, so s.css / a.js work unchanged.
import { html, raw, join, esc } from './html.js';
import { state, left, pct, fmt } from './db.js';
import { ECH, FM, fragProf, fragMask, sitesList, protos, NATIVE } from './links.js';

const BOLT = raw('<svg class="bolt" viewBox="0 0 24 24" aria-hidden="true"><path d="M13.2 2.5 5 13.6h5.6l-1 7.9 9.4-12.1h-5.8z"/></svg>');
const NAV = [['home', '/', 'Home'], ['users', '/users', 'Users'], ['locations', '/locations', 'Locations'], ['clients', '/clients', 'Clients'], ['relays', '/relays', 'Relays'], ['network', '/network', 'Network'], ['convert', '/convert', 'Convert'], ['advanced', '/advanced', 'Advanced'], ['settings', '/settings', 'Settings']];
const flash = ms => join(ms, m => html`<div class="toast">${m}</div>`);

export function layout(c, title, body, js = []) {
  const chrome = c.chrome;
  return html`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover"><title>${title || 'xr PANEL'}</title><link rel="icon" type="image/svg+xml" href="/static/bolt.svg"><meta name="robots" content="noindex"><script>try{document.documentElement.dataset.theme=localStorage.getItem("th")||"dark"}catch(e){document.documentElement.dataset.theme="dark"}</script>
<link rel="stylesheet" href="/static/s.css?v=5"></head><body class="${chrome ? 'app' : ''}">
<button id="theme" class="glass" aria-label="Toggle theme"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><g class="sun"><circle cx="12" cy="12" r="4.5"/><path d="M12 2v2.2M12 19.8V22M4.9 4.9l1.6 1.6M17.5 17.5l1.6 1.6M2 12h2.2M19.8 12H22M4.9 19.1l1.6-1.6M17.5 6.5l1.6-1.6"/></g><path class="moon" d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z"/></svg></button>
${chrome ? html`<header class="top"><button id="menu" aria-label="Menu"><i></i><i></i><i></i></button><b class="brand">${BOLT}xr PANEL</b></header><div id="scrim"></div>
<nav class="side"><b class="brand">${BOLT}<span>xr<br>PANEL</span></b>${join(NAV, ([e, h, l]) => html`<a href="${h}" class="${c.endpoint === e ? 'on' : ''}">${l}</a>`)}<a class="out" href="/logout">Logout</a></nav>` : ''}
<main>${chrome ? flash(c.flashes) : ''}${body}</main>
<script src="/static/a.js?v=5"></script>${join(js, f => html`<script src="/static/${f}?v=5"></script>`)}</body></html>`;
}

const flag = (cc, name = '') => cc ? html`<img class="flag" src="/flag/${cc}.svg" alt="${cc.toUpperCase()}" title="${name}" loading="lazy" onerror="this.replaceWith(Object.assign(document.createElement('span'),{className:'flag none',textContent:'?'}))">` : html`<span class="flag none" title="${name}">?</span>`;
const hint = (...a) => html`<p class="hint">${html(...a)}</p>`;

export const login = c => layout(c, 'xr PANEL', html`<div class="login"><form method="post" action="/login"><b class="brand">${BOLT}xr PANEL</b>${flash(c.flashes)}
<label>Username<input name="user" value="admin" autocomplete="username" required></label>
<label>Password<input name="pw" type="password" autocomplete="current-password" autofocus required></label>
<button class="btn">Sign in</button></form></div>`);

// ---------------- home ----------------
export function homeStats(st) { return st; }
export const home = (c, st) => layout(c, 'Home', html`<h1>Home</h1><section class="grid">
<div class="box tl"><h3>Users</h3><p class="big"><span data-k="active">${st.active}</span>/<span data-k="users">${st.users}</span></p><small>active / total</small><div class="bar" data-bar="ap" style="--v:${st.ap}"></div></div>
<div class="box pk"><h3>Traffic</h3><p class="big" data-k="traffic">${st.traffic}</p><div class="bar" data-bar="tp" style="--v:${st.tp}"></div></div>
<div class="box yl"><h3>Mode</h3><p class="big" data-k="mode">${st.mode}</p><small>${st.mode === 'Built-in' ? 'VLESS + Trojan run inside the Worker' : 'every protocol is relayed to your upstream'}</small></div>
<div class="box pu"><h3>Exits</h3><p class="big"><span data-k="groups">${st.groups}</span><small> groups</small></p><small><span data-k="proxies">${st.proxies}</span> proxies</small></div>
<div class="box tl"><h3>Clean IPs</h3><p class="big" data-k="ips">${st.ips}</p><small>saved by the scanner</small></div>
<div class="box pk"><h3>Relays</h3><p class="big" data-k="relays">${st.relays}</p><small>deployed on other platforms</small></div>
<div class="box tl" id="cfbox"><h3>Requests today</h3><p class="big"><span id="cf-used">…</span></p><small id="cf-left">Cloudflare account · resets 00:00 UTC</small><div class="bar" id="cf-bar" style="--v:0"></div></div>
<div class="box yl"><h3>Fragment</h3><p class="big" data-k="frag">${st.frag}</p></div>
<div class="box pu"><h3>Runtime</h3><p class="big">Workers</p><small>D1 database</small></div></section><script>(function(){var n=function(x){return Number(x).toLocaleString()};fetch('/api/cf').then(function(r){return r.json()}).then(function(d){var u=document.getElementById('cf-used'),l=document.getElementById('cf-left'),b=document.getElementById('cf-bar');if(!d.ok){u.textContent='—';l.textContent='Cloudflare token not configured';return}u.textContent=n(d.used);if(d.limit){l.textContent=n(d.left)+' left of '+n(d.limit)+' · resets 00:00 UTC';b.style.setProperty('--v',Math.min(100,d.used*100/d.limit))}else l.textContent='used today · resets 00:00 UTC'}).catch(function(){})})()</script>`);

// ---------------- users ----------------
export function users(c, list, s, grps, q) {
  const gm = Object.fromEntries(grps.map(g => [g.id, g]));
  return layout(c, 'Users', html`<h1>Users <small>${list.length}/${s.max_users}</small></h1>
<div class="acc"><div class="hd"><span>+ New user</span></div><div class="bd"><div>
<form class="f" method="post" action="/users/add">
<label>Name<input name="name" required></label><label>Limit GB (0 = none)<input name="limit" type="number" step="any" min="0" value="0"></label>
<label>Days (0 = none)<input name="days" type="number" min="0" value="30"></label>
<button class="btn">Create</button></form></div></div></div>
${list.length ? join(list, u => {
    const st = state(u), g = gm[u.grp_id], o = q.get('o') === String(u.id), pp = o ? q.get('p') : '', su = c.suburl(u);
    return html`<div class="acc ${o ? 'open' : ''}"><div class="hd"><span class="gn">${u.name}${g ? flag(g.cc, g.name) : ''}</span><em class="tag ${st}">${st}</em></div><div class="bd"><div>
<p class="meta">${fmt(u.used)} / ${u.limit_gb ? u.limit_gb + ' GB' : 'unlimited'} · ${left(u)} · exit: ${g ? g.name : 'direct'}</p>
<div class="bar" style="--v:${pct(u)}"></div><code>${su}</code>
<div class="row">
<button type="button" class="btn o tl ${pp === 'edit' ? 'on' : ''}" data-pn="edit">Edit</button>
<button type="button" class="btn o pu ${pp === 'loc' ? 'on' : ''}" data-pn="loc">Location</button>
<button type="button" class="btn o pu" data-copy="${su}">Copy sub</button>
<a class="btn o yl" href="/clients?u=${u.uuid}">Apps</a>
<form method="post" action="/users/${u.id}/delete" data-m="Delete ${u.name}?" onsubmit="return confirm(this.dataset.m)"><button class="btn o pk">Delete</button></form>
</div>
<div class="pn ${pp === 'edit' ? 'open' : ''}" data-p="edit"><div><div class="in">
<form class="f" method="post" action="/users/${u.id}/edit" style="margin-top:0">
<label>Name<input name="name" value="${u.name}" required></label><label>Limit GB<input name="limit" type="number" step="any" min="0" value="${u.limit_gb}"></label>
<label>Days from now (empty = keep)<input name="days" type="number" min="0"></label>
<label class="ck"><input type="checkbox" name="enabled" ${u.enabled ? raw('checked') : ''}>Enabled</label><label class="ck"><input type="checkbox" name="reset">Reset usage</label>
<button class="btn">Save</button></form>
</div></div></div>
<div class="pn ${pp === 'loc' ? 'open' : ''}" data-p="loc"><div><div class="in">
<h3>Exit location</h3>
<p class="hint">Pick the group this user's traffic leaves through. With several IPs in the group the Worker tries the fastest first.</p>
<form class="opts" method="post" action="/users/${u.id}/group">
<button class="opt ${!g ? 'on' : ''}" name="g" value="0"><span class="flag none">·</span>Direct</button>
${join(grps, x => html`<button class="opt ${g && g.id === x.id ? 'on' : ''}" name="g" value="${x.id}">${flag(x.cc, x.name)}<span>${x.name}</span><small>${x.n} IP</small></button>`)}
</form>
${!grps.length ? html`<p class="hint">No groups yet. Add an IP in Locations first.</p>` : ''}
</div></div></div>
</div></div></div>`;
  }) : html`<p class="hint">No users yet. Open “New user” to create the first one.</p>`}`);
}

// ---------------- clients ----------------
export function clients(c, items, sel, wn, wl) {
  return layout(c, 'Clients', html`<h1>Clients</h1>
${items.length ? join(items, ({ x, sub, groups }) => html`<div class="acc ${x.uuid === sel ? 'open' : ''}"><div class="hd"><span class="gn">${x.name}</span><em class="tag ${state(x)}">${state(x)}</em></div><div class="bd"><div>
<code>${sub}</code><div class="row" style="margin-top:0"><button class="btn" data-copy="${sub}">Copy sub link</button></div>
<form method="post" action="/clients/${x.id}/white" class="wl"><label class="sw"><input type="checkbox" name="on" value="1" ${x.white ? raw('checked') : ''} onchange="this.form.submit()"><i></i><span>White IP</span></label><small class="hint">${wn} clean IP${wn === 1 ? '' : 's'} ready · limit ${wl}. When on, this client's sub gets one set of configs per clean IP, fastest first.</small></form>
${join(groups, ([g, apps]) => html`<h3 style="margin:20px 0 12px">${g}</h3>
${join(apps, ([n, d, i]) => html`<div class="acc"><div class="hd"><span>${n}</span><em class="tag ${i ? 'active' : ''}">${i ? 'one-tap import' : 'manual'}</em></div><div class="bd"><div>
<div class="row" style="margin-top:0"><a class="btn o yl" href="${d}" target="_blank" rel="noopener">Download</a>
${i ? html`<a class="btn" href="${i}">Import</a>` : html`<button class="btn o tl" data-copy="${sub}">Copy sub link</button>`}</div>
${!i ? html`<p class="hint">No import link for this app. Copy the sub link and paste it in the app manually.</p>` : ''}
</div></div></div>`)}`)}
</div></div></div>`) : html`<p class="hint">Create a user first.</p>`}`);
}

// ---------------- sub (public) ----------------
export const sub = (c, u, st, L, su, groups) => layout(c, 'VPN', html`<h1>${u.name}</h1>
<section class="grid"><div class="box tl"><h3>Status</h3><p class="big">${st}</p></div>
<div class="box pk"><h3>Traffic</h3><p class="big">${fmt(u.used)}</p><small>of ${u.limit_gb ? u.limit_gb + ' GB' : 'unlimited'}</small><div class="bar" style="--v:${pct(u)}"></div></div>
<div class="box yl"><h3>Expires</h3><p class="big">${left(u)}</p></div></section><br>
<div class="box pu"><h3>Subscription link</h3><code>${su}</code><button class="btn" data-copy="${su}">Copy link</button>
<p class="hint">Add this same link in your app. Apps read the configs from it directly; browsers see this page.</p></div><br>
${join(groups, ([g, apps]) => html`<h1>${g}</h1><section class="grid">${join(apps, ([n, d, i]) => html`<div class="box pu"><h3>${n}</h3><div class="row"><a class="btn o yl" href="${d}" target="_blank" rel="noopener">Download</a>${i ? html`<a class="btn" href="${i}">Import</a>` : ''}</div></div>`)}</section><br>`)}
<h1>Configs</h1>${L.length ? join(L, ([nm, pr, l]) => html`<div class="acc"><div class="hd"><span>${nm}</span><em class="tag active">${pr}</em></div><div class="bd"><div><code>${l}</code><button class="btn o tl" data-copy="${l}">Copy</button></div></div></div>`) : html`<p class="hint">This account is ${st}, so no configs are available.</p>`}`);

// ---------------- locations ----------------
export const locations = (c, grps) => layout(c, 'Locations', html`<h1>Locations</h1>
<p class="hint">Add a proxy IP and port. The Worker verifies it (SOCKS5, SOCKS4, HTTP, HTTPS), finds the country of the IP and files it into that country's group. A user assigned to a group exits through its IPs, fastest first.</p>
<div class="box pu" data-loc><h3>Auto</h3><p class="hint"><b>Auto location</b> downloads free proxy lists, keeps only working proxies and adds up to 10 locations, one per country, preferring countries you do not have and did not get last time. <b>Recovery</b> takes the IP and port of every current country and swaps them for new working ones from the same country. Click a running button again to stop it.</p>
<div class="row"><button type="button" class="btn" data-lgo="auto">Auto location</button><button type="button" class="btn o yl" data-lgo="recover">Recovery</button></div>
<div class="seg" style="--v:0" data-lseg hidden><i></i><span data-lprog>idle</span></div><div class="xlog" data-llog hidden aria-live="polite"></div></div><br>
<div class="box tl"><h3>Add IP</h3><form class="f" method="post" action="/locations/add" data-slow>
<label>Proxy IP<input name="host" placeholder="1.2.3.4" required></label><label>Port<input name="port" type="number" min="1" max="65535" required></label>
<button type="button" class="btn o yl" data-check>Check</button><div class="res" style="grid-column:1/-1"></div><button class="btn">Add</button></form></div><br>
${grps.length ? join(grps, g => html`<div class="acc"><div class="hd"><span class="gn">${flag(g.cc, g.name)}${g.name}</span><em class="tag active">${g.n} IP</em></div><div class="bd"><div>
${join(g.px, x => html`<form class="row up" method="post" action="/proxies/${x.id}/delete"><span class="chip ok">✓ ${x.proto} ${x.ms}ms</span><span>${x.host}:${x.port}</span><button class="btn o pk">Remove</button></form>`)}
<p class="hint">${g.users} user${g.users === 1 ? '' : 's'} use this group.${g.n > 1 ? ' Traffic goes through the fastest IP; if it fails the next one is tried.' : ''}</p>
<form method="post" action="/groups/${g.id}/delete" data-m="Delete group ${g.name} and its IPs?" onsubmit="return confirm(this.dataset.m)"><div class="row"><button class="btn o pk">Delete group</button></div></form>
</div></div></div>`) : html`<p class="hint">No groups yet. Add the first IP above and its country group is created automatically.</p>`}`, ['loc.js']);

// ---------------- network / convert ----------------
export const network = (c, s, cnt) => layout(c, 'Network', html`<h1>Network</h1>
<p class="hint">Scanners run in <b>your browser</b>, on your own connection, so the IPs they find are clean for you. Results are saved in the panel and used by clients with the White IP switch.</p>
<div class="acc"><div class="hd"><span>IP Scanner</span><em class="tag ${cnt.ip ? 'active' : ''}">${cnt.ip} saved</em></div><div class="bd"><div data-scan="ip" data-limit="${s.white_limit}"></div></div></div>
<div class="acc"><div class="hd"><span>WireGuard</span><em class="tag ${s.warp ? 'active' : 'expired'}">${s.warp ? 'registered' : 'not registered'}</em></div><div class="bd"><div data-wg></div></div></div>
<div class="acc"><div class="hd"><span>Masque</span><em class="tag ${s.masque ? 'active' : 'expired'}">${s.masque ? 'registered' : 'not registered'}</em></div><div class="bd"><div data-masque></div></div></div>
<div class="acc"><div class="hd"><span>Endpoint Scanner</span><em class="tag ${cnt.warp + cnt.masque ? 'active' : ''}">${cnt.warp + cnt.masque} saved</em></div><div class="bd"><div data-scan="ep"></div></div></div>`, ['net.js', 'wg.js']);

export const convert = c => layout(c, 'Convert', html`<h1>Convert</h1>
<p class="hint">Everything here runs in your browser. Nothing you paste is sent anywhere, except a subscription URL, which the Worker fetches for you.</p>
<div class="acc open"><div class="hd"><span>V2Ray Links</span><em class="tag">edit · QR</em></div><div class="bd"><div data-conv="links"></div></div></div>
<div class="acc"><div class="hd"><span>WireGuard</span><em class="tag">clash · amnezia · wiresock</em></div><div class="bd"><div data-conv="wg"></div></div></div>
<div class="acc"><div class="hd"><span>Clash / Sing-box</span><em class="tag">↔ links</em></div><div class="bd"><div data-conv="formats"></div></div></div>`, ['qr.js', 'wg.js', 'convert.js']);

// ---------------- relays ----------------
const STAG = { idle: 'off', deploying: 'deploying', ok: 'on', failed: 'failed' }, SSYM = { ok: '✓', run: '…', fail: '✕', wait: '·' };
export const relays = (c, rv, o, panel, ok) => layout(c, 'Relays', html`<h1>Relays</h1>
<p class="hint">A relay is a small proxy deployed on a hosting platform. Anyone who opens the relay domain is forwarded to this Worker${panel ? html` (<b>${panel}</b>)` : ''}. Paste an API token, the Worker deploys it, tracks the result and measures the ping from here.</p>
${!ok ? html`<div class="toast">Set a public panel domain in Settings first (a custom domain or your workers.dev address). Relays need an address to forward to.</div>` : ''}
${join(rv, v => html`<div class="acc ${o === v.id || v.status === 'deploying' ? 'open' : ''}" data-relay="${v.id}" data-st="${v.status}">
<div class="hd"><span>${v.name}</span><em class="tag ${v.status === 'ok' ? 'active' : ''} ${v.status === 'failed' ? 'expired' : ''}" data-tag>${STAG[v.status]}</em></div>
<div class="bd"><div>
<p class="hint">${v.hint}</p>
<form class="f" method="post" action="/relays/${v.id}/deploy" style="margin-top:0">
<label>API token<input name="token" type="password" autocomplete="off" autocapitalize="off" placeholder="${v.has_token ? 'saved · leave empty to reuse' : 'paste token'}" ${v.has_token ? '' : raw('required')}></label>
<button class="btn" data-go ${v.status === 'deploying' ? raw('disabled') : ''}>${v.has_ref ? 'Redeploy' : 'Deploy'}</button></form>
<p class="hint"><a href="${v.token_url}" target="_blank" rel="noopener">Get a token</a> · the token is stored only in this Worker's D1 database and is never shown again.</p>
<div data-steps ${v.status === 'idle' ? raw('hidden') : ''}>${join(v.steps, s => html`<span class="chip ${s.st}">${SSYM[s.st]} ${s.l}${s.m && (s.st === 'ok' || s.st === 'run') ? ' · ' + s.m : ''}</span>`)}</div>
<p class="hint err" data-err ${!v.err ? raw('hidden') : ''}>${v.err}</p>
<div data-out ${!v.domain ? raw('hidden') : ''}>
<code data-dom>${v.domain}</code>
<div data-ping>${v.ping ? html`${v.ping.ok ? html`<span class="chip ok">panel ⇄ relay · ${v.ping.web} ms</span>` : html`<span class="chip">✕ no answer through the relay</span>`}` : ''}</div>
<div class="row"><button type="button" class="btn o tl" data-copy="${v.domain}">Copy domain</button><button type="button" class="btn o yl" data-rping>Ping</button></div>
</div>
${v.has_ref ? html`<div class="row"><form method="post" action="/relays/${v.id}/remove" data-m="Delete the ${v.name} relay?" onsubmit="return confirm(this.dataset.m)"><button class="btn o pk">Remove</button></form></div>` : ''}
</div></div></div>`)}`);

// ---------------- advanced ----------------
const sw = (k, on) => html`<form method="post" action="/advanced/toggle/${k}"><label class="sw"><input type="checkbox" name="on" ${on ? raw('checked') : ''} onchange="this.form.submit()"><i></i><span>${on ? 'On' : 'Off'}</span></label></form>`;
export function advanced(c, s, spoof, o) {
  const ei0 = parseInt(s.ech_i, 10), ei = ei0 >= 0 && ei0 < ECH.length ? ei0 : -1, fp = s.frag_on === '1' ? fragProf(s) : null, fpAny = fragProf(s), nsites = sitesList(s).length;
  const fmprev = fpAny && fpAny.tier !== 'none' ? fragMask(fpAny.tier) : '';
  return layout(c, 'Advanced', html`<h1>Advanced</h1>
<div class="acc ${o === 'spoof' ? 'open' : ''}"><div class="hd"><span>Spoof</span><em class="tag ${spoof ? 'active' : ''}">${spoof ? 'on' : 'off'}</em></div><div class="bd"><div>
<p class="hint">Fill SNI and IP and every VLESS config gets the <b>snispoofing</b> parameter. Port is optional (empty = 0). Leave SNI or IP empty to turn it off.</p>
<form class="f" method="post" action="/advanced/spoof" style="margin-top:0">
<label>SNI<input name="sni" value="${s.spoof_sni}" placeholder="sni here" autocapitalize="off" autocomplete="off"></label>
<label>IP<input name="ip" value="${s.spoof_ip}" placeholder="ip here" autocapitalize="off" autocomplete="off"></label>
<label>Port<input name="port" type="number" min="0" max="65535" value="${s.spoof_port}" placeholder="0"></label>
<button class="btn">Save</button></form></div></div></div>

<div class="acc ${o === 'ff' ? 'open' : ''}"><div class="hd"><span>F+F</span><em class="tag ${s.ff_on === '1' ? 'active' : ''}">${s.ff_on === '1' ? 'on' : 'off'}</em></div><div class="bd"><div>
${sw('ff', s.ff_on === '1')}
<p class="hint">When on, every supported config (VLESS, Trojan, Shadowsocks) gets this finalMask and the fingerprint is set to <b>unsafe</b>:</p>
<code>${FM}</code></div></div></div>

<div class="acc ${o === 'frag' ? 'open' : ''}" data-frag data-on="${s.frag_on}"><div class="hd"><span>Fragment</span><em class="tag ${s.frag_on === '1' && fp && fp.tier !== 'none' ? 'active' : ''}" data-ftag>${s.frag_on === '1' && fp ? fp.tier : (s.frag_on === '1' ? 'on' : 'off')}</em></div><div class="bd"><div>
${sw('frag', s.frag_on === '1')}
<p class="hint">When on, the panel measures <b>your browser's connection</b> automatically (round-trip time and success rate on the test sites from Settings, ${nsites} in rotation) and gives every config that can carry it a fragment tuned to that network: fast, mid or slow.</p>
${s.frag_on === '1' ? html`
<div class="st" data-fst>${fp ? html`<span class="chip ${fp.tier !== 'none' ? 'ok' : ''}">${fp.tier !== 'none' ? fp.tier : 'no fragment'}</span><span class="chip ok">${fp.rtt} ms</span><span class="chip ${fp.ok >= 0.6 ? 'ok' : 'run'}">${Math.round(fp.ok * 100)}% reachable</span>${fp.verified !== null && fp.verified !== undefined ? html`<span class="chip ${fp.verified ? 'ok' : ''}">${fp.verified ? '✓ verified' : '✕ failed check'}</span>` : ''}` : html`<span class="chip run">measuring…</span>`}</div>
<div class="row"><button type="button" class="btn o tl" data-fgo>Measure again</button></div>
<div class="cfgs" data-fres></div>
<p class="hint" data-fmsg>${fp && fp.tier !== 'none' ? 'Fragment applied to the VLESS and Trojan configs of this panel (and Shadowsocks when an upstream is set).' : (fp ? 'The network could not be measured, so no fragment is added.' : '')}</p>
${fmprev ? html`<code data-fcode>${fmprev}</code>` : ''}
<p class="hint">Not touched: VMess (its link has no field for a fragment) and plain non-TLS White IP configs (no handshake to fragment). A protocol whose WebSocket endpoint does not answer in the live check gets no fragment.</p>`
    : html`<p class="hint">Turn it on to start the first measurement. The result is saved and written into the subscription links of all supported configs. It replaces the fixed F+F mask while it is on.</p>`}
</div></div></div>

<div class="acc ${o === 'ech' ? 'open' : ''}"><div class="hd"><span>ECH</span><em class="tag ${s.ech_on === '1' && ei >= 0 ? 'active' : ''}">${s.ech_on === '1' && ei >= 0 ? 'on' : 'off'}</em></div><div class="bd"><div>
${sw('ech', s.ech_on === '1')}
${s.ech_on === '1' ? html`
<div class="row"><button type="button" class="btn o pu ${o === 'ech' && ei < 0 ? 'on' : ''}" data-pn="ech">${ei >= 0 ? 'ECH: ' + ECH[ei][0] : 'Choose ECH'}</button></div>
<div class="pn ${o === 'ech' && ei < 0 ? 'open' : ''}" data-p="ech"><div><div class="in">
<h3>ECH list</h3>
<form class="opts" method="post" action="/advanced/ech">
${join(ECH, ([n, d], i) => html`<button class="opt ${ei === i ? 'on' : ''}" name="e" value="${i}"><span>${n}</span><small>${d}</small></button>`)}
</form></div></div></div>
<p class="hint">${ei >= 0 ? 'The selected ECH is applied to all supported configs (VLESS, Trojan, Shadowsocks).' : 'No ECH selected yet. Pick one and it is applied to all supported configs.'}</p>`
    : html`<p class="hint">Turn it on, then pick an ECH from the list. The choice is applied to all supported configs (VLESS, Trojan, Shadowsocks).</p>`}
</div></div></div>

<div class="acc ${o === 'ipv6' ? 'open' : ''}"><div class="hd"><span>IPv6</span><em class="tag ${s.ipv6 ? 'active' : ''}">${s.ipv6 ? 'on' : 'off'}</em></div><div class="bd"><div>
<p class="hint">Whatever you enter here becomes the address of every config (IPv6 is wrapped in [ ] automatically). SNI and host stay the domain. Leave empty to use the domain.</p>
<form class="f" method="post" action="/advanced/ipv6" style="margin-top:0">
<label>Address<input name="ip" value="${s.ipv6}" placeholder="2606:4700::1111" autocapitalize="off" autocomplete="off"></label>
<button class="btn">Save</button></form></div></div></div>`, ['frag.js']);
}

// ---------------- settings ----------------
export function settings(c, s, o) {
  const { sites, defaultPw, detected, relays, panelDom, cfgSrc, cfgLabel } = c.settings;
  const fields = [['domain', 'Domain (empty = auto)'], ['tls_port', 'TLS port'], ['max_users', 'Max users'], ['white_limit', 'White IP limit'], ['upstream', 'Upstream (empty = built-in VLESS + Trojan)']];
  return layout(c, 'Settings', html`<h1>Settings</h1>
${defaultPw ? html`<div class="toast">Default password “admin” is still active. Change it below.</div>` : ''}
<div class="box pk"><h3>Password</h3><form class="f" method="post" action="/settings/password"><label>Current<input name="old" type="password" required></label>
<label>New<input name="new" type="password" required></label><button class="btn pk">Change</button></form></div><br>
<div class="box tl"><h3>Server</h3><p class="hint">Auto-detected from how you opened this panel: ${detected}</p><form class="f" method="post" action="/settings/save">
${join(fields, ([k, l]) => html`<label>${l}<input name="${k}" value="${s[k]}"${k === 'upstream' ? raw(' placeholder="relay.example.com or relay.example.com:8443"') : ''}></label>
${k === 'domain' && relays.length ? html`<div class="dp"><button type="button" class="btn o pu" data-pn="cfgdom">Configs use: ${cfgLabel} ▾</button>
<div class="pn" data-p="cfgdom"><div><div class="in"><h3>Domain used by configs</h3>
<div class="opts">
<button form="cfgform" name="pick" value="panel" class="opt ${cfgSrc === 'panel' ? 'on' : ''}"><span>${panelDom}</span><small>panel</small></button>
${join(relays, r => html`<button form="cfgform" name="pick" value="relay:${r.id}" class="opt ${cfgSrc === 'relay:' + r.id ? 'on' : ''}"><span>${r.domain}</span><small>${r.name} · ${r.tag}</small></button>`)}
<button type="button" class="opt ${cfgSrc === 'custom' ? 'on' : ''}" data-custom><span>Custom…</span></button></div>
<div class="row" data-cust ${cfgSrc !== 'custom' ? raw('hidden') : ''}><input form="cfgform" name="custom" value="${s.cfg_custom}" placeholder="sub.example.com" autocapitalize="off" autocomplete="off" style="flex:1;min-width:180px"><button form="cfgform" name="pick" value="custom" class="btn">Use</button></div>
<p class="hint">Every generated config (address, host, SNI) uses the domain you pick. Relay domains always use port 443.</p>
</div></div></div></div>` : ''}`)}
<label class="ck"><input type="checkbox" name="white_sni" value="1" ${s.white_sni === '1' ? raw('checked') : ''}> White IPs use scanned SNI</label><button class="btn">Save</button></form><form id="cfgform" method="post" action="/settings/cfgdomain"></form></div><br>
<div class="box pu ${o === 'sites' ? 'open' : ''}"><h3>Test sites</h3><p class="hint">Links the Fragment measurement uses to test your connection. Each measurement takes the next few sites of the list, so every site is used in turn. Add or remove as many as you like.</p>
<form method="post" action="/settings/sites" data-sites><div class="sites" data-list>
${join(sites, u => html`<div class="row site"><input name="site" value="${u}" placeholder="https://example.com/generate_204" autocapitalize="off" autocomplete="off" spellcheck="false"><button type="button" class="btn o pk" data-rm aria-label="Remove">−</button></div>`)}</div>
<div class="row"><button type="button" class="btn o tl" data-add>+ Add site</button><button class="btn">Save</button><button class="btn o yl" name="reset" value="1" formnovalidate>Reset to 9 defaults</button></div></form></div><br>
<div class="box yl"><h3>Relay mode</h3>${protos(s).length === 2
    ? html`<p class="hint"><b>Built-in.</b> The Worker itself terminates <b>VLESS</b> and <b>Trojan</b> over WebSocket and sends traffic out directly or through the user's exit group. VMess and Shadowsocks need a server that speaks them: set an <b>Upstream</b> above and every protocol is relayed to it unchanged.</p>`
    : html`<p class="hint"><b>Upstream relay.</b> Every protocol (${protos(s).join(', ')}) is relayed unchanged to <b>${s.upstream}</b> using the same <code>/ws/&lt;protocol&gt;/&lt;uuid&gt;</code> path. Quotas and expiry are enforced here; traffic is metered here.</p>`}
<p class="hint">Changes apply immediately: there is no config to write and nothing to restart.</p></div>`);
}
export { NATIVE };
