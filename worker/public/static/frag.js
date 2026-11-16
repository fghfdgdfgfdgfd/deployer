/* Advanced > Fragment: measures THIS browser's network on the Settings test sites (round robin, a few per run),
   saves the result, then checks from this browser that the WebSocket endpoint of each config type answers. */
(() => {
'use strict';
const acc = document.querySelector('[data-frag]'); if (!acc || acc.dataset.on !== '1') return;
const $ = s => acc.querySelector(s), E = t => String(t).replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';');
const post = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) }).then(r => r.json());
const med = a => { if (!a.length) return 0; const s = [...a].sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const wsOpen = path => new Promise(res => { let w, done = false; const end = ok => { if (done) return; done = true; try { w && w.close(); } catch (e) { } res(ok); }; try { w = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + path); w.onopen = () => end(true); w.onerror = () => end(false); w.onclose = () => end(false); setTimeout(() => end(false), 4000); } catch (e) { res(false); } });
const NAMES = { vless: 'VLESS', trojan: 'Trojan', shadowsocks: 'Shadowsocks', vmess: 'VMess' };
let busy = false;

async function hit(url, timeout = 4000) {
  const ac = new AbortController(), tm = setTimeout(() => ac.abort(), timeout), t0 = performance.now();
  try { await fetch(url + (url.includes('?') ? '&' : '?') + '_=' + Date.now() + Math.random().toString(36).slice(2, 6), { mode: 'no-cors', cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: ac.signal }); return performance.now() - t0; }
  catch (e) { return null; } finally { clearTimeout(tm); }
}
async function measure() {
  const r = await post('/api/sites/next'), all = [], warm = []; let tries = 0, okc = 0, skipped = 0;
  const sites = (r.sites || []).filter(u => { const bad = u.startsWith('http:') && location.protocol === 'https:'; if (bad) skipped++; return !bad; });   // https page cannot fetch plain http
  await Promise.all(sites.map(async u => { for (let k = 0; k < 3; k++) { tries++; const ms = await hit(u); if (ms !== null) { okc++; all.push(ms); if (k) warm.push(ms); } } }));
  const use = warm.length ? warm : all, c = navigator.connection || {}, m = med(use), dev = med(use.map(x => Math.abs(x - m)));
  return { rtt: m, ok: tries ? okc / tries : 0, jitter: dev, n: tries, sites: sites, skipped, net: { type: c.effectiveType, downlink: c.downlink, rtt: c.rtt } };
}
const chips = (p, ver) => `<span class="chip ${p.tier !== 'none' ? 'ok' : ''}">${p.tier === 'none' ? 'no fragment' : E(p.tier)}</span><span class="chip ok">${Math.round(p.rtt)} ms</span><span class="chip ${p.ok >= .6 ? 'ok' : 'run'}">${Math.round(p.ok * 100)}% reachable</span>` + (ver === true ? '<span class="chip ok">✓ verified</span>' : ver === false ? '<span class="chip">✕ failed check</span>' : '');
const tag = t => { const e = acc.querySelector('[data-ftag]'); e.textContent = t; e.className = 'tag' + (t !== 'none' && t !== 'on' && t !== 'measuring' ? ' active' : ''); };

async function run() {
  if (busy) return; busy = true; const go = $('[data-fgo]'), msg = $('[data-fmsg]'), res = $('[data-fres]'), st = $('[data-fst]');
  go.disabled = true; tag('measuring'); st.innerHTML = '<span class="chip run">measuring…</span>'; res.innerHTML = ''; msg.textContent = 'Testing your connection on the next sites in the list…';
  try {
    const m = await measure(), d = await post('/advanced/fragment/save', m);
    if (!d.ok) throw new Error(d.error || 'save failed');
    const p = d.profile; st.innerHTML = chips(p); tag(p.tier === 'none' ? 'none' : p.tier);
    const used = m.sites.map(u => { try { return new URL(u).hostname; } catch (e) { return u; } }).join(', ');
    if (p.tier === 'none') { msg.textContent = `No test site answered (${used || 'none usable'}). Nothing was applied: configs stay without a fragment.`; return; }
    msg.textContent = `Measured on ${used}. Checking that each config type answers…`;
    const v = await post('/api/fragment/test'); if (!v.ok) throw new Error(v.error || 'check failed');
    await Promise.all(v.results.filter(x => !x.skip).map(async x => { const t0 = performance.now(); x.ok = await wsOpen(x.path); x.ms = Math.round(performance.now() - t0); x.text = x.ok ? 'ws open' : 'no answer'; }));
    const live = v.results.filter(x => !x.skip); v.verified = live.length ? live.every(x => x.ok) : null;
    await post('/api/fragment/verdict', { bad: live.filter(x => !x.ok).map(x => x.proto), verified: v.verified });
    st.innerHTML = chips(p, v.verified === null ? undefined : v.verified);
    res.innerHTML = v.results.map(x => `<div class="cfg"><div><b>${E(NAMES[x.proto] || x.proto)}</b><small>${x.skip ? 'not applied · ' + E(x.text) : E(x.text) + (x.ms ? ' · ' + x.ms + ' ms' : '')}</small></div><span class="chip ${x.skip || v.verified === null ? 'wait' : x.ok ? 'ok' : ''}">${x.skip ? '—' : x.ok ? '✓ works' : '✕ failed'}</span></div>`).join('');
    const bad = v.results.filter(x => !x.skip && !x.ok).map(x => NAMES[x.proto] || x.proto), good = v.results.filter(x => !x.skip && x.ok).map(x => NAMES[x.proto] || x.proto);
    msg.textContent = v.verified === null ? 'Fragment saved and applied to VLESS, Trojan and Shadowsocks. No protocol of this panel could be checked.'
      : v.verified ? 'Fragment is applied to ' + good.join(', ') + ' and each WebSocket endpoint answered. (The fragment itself is performed by your client app.)'
      : (bad.join(', ') + ' failed the check with a fragment, so they get no fragment. Applied to: ' + (good.join(', ') || 'nothing') + '.');
  } catch (e) { msg.textContent = 'Error: ' + (e.message || e); tag('on'); }
  finally { busy = false; go.disabled = false; }
}
$('[data-fgo]').onclick = run;
run();      // switched on (or page opened with Fragment on): measure right away, next sites in the rotation
})();
