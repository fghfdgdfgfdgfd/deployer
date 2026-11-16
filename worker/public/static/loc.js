/* Locations: Auto location + Recovery. Both run in small steps on the Worker (free proxy lists -> verified -> geo-located); this page drives the steps and shows progress. */
(() => {
'use strict';
const box = document.querySelector('[data-loc]'); if (!box) return;
const E = t => String(t).replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';');
const seg = box.querySelector('[data-lseg]'), prog = box.querySelector('[data-lprog]'), log = box.querySelector('[data-llog]');
const btn = {}; box.querySelectorAll('[data-lgo]').forEach(b => { btn[b.dataset.lgo] = b; b.dataset.l = b.textContent; });
const post = (u, b) => fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) }).then(r => r.json().catch(() => ({})));
let since = 0, timer = 0, wasRun = false, t0 = Date.now();

const msg = sessionStorage.getItem('locmsg');
if (msg) { sessionStorage.removeItem('locmsg'); const d = document.createElement('div'); d.className = 'toast'; d.textContent = msg; document.querySelector('main').prepend(d); }

function paint(st) {
  for (const k in btn) {
    const b = btn[k], mine = st.run && st.kind === k;
    b.classList.toggle('live', mine); b.disabled = st.run && !mine;
    b.textContent = mine ? (st.stopping ? 'Stopping…' : 'Stop · ' + b.dataset.l) : b.dataset.l;
  }
  if (st.run || st.seq) { seg.hidden = log.hidden = false; }
  const word = st.kind === 'recover' ? 'replaced' : 'added', p = st.total ? Math.round(st.done / st.total * 100) : 0;
  seg.style.setProperty('--v', st.run && !st.total ? 6 : p);
  prog.textContent = st.run || st.msg ? `${st.msg || 'running'} · ${st.added} ${word}${st.total ? '/' + st.total : ''} · ${st.tried} checked · ${st.alive} alive` : 'idle';
  for (const [, cls, txt] of st.log) { const d = document.createElement('div'); d.className = 'l ' + cls; d.innerHTML = `<i>${((Date.now() - t0) / 1000).toFixed(0).padStart(3, '0')}s</i>${E(txt)}`; log.append(d); }
  if (st.log.length) { while (log.childElementCount > 300) log.firstChild.remove(); log.scrollTop = log.scrollHeight; }
}
async function tick() {
  let st; try { st = await (await fetch('/api/loc/status?since=' + since, { cache: 'no-store' })).json(); } catch (e) { timer = setTimeout(tick, 2000); return; }
  if (st.run) { try { const s2 = await post('/api/loc/step'); if (s2 && 'run' in s2) { st = s2; st.log = (st.log || []).filter(x => x[0] > since); } } catch (e) { timer = setTimeout(tick, 2500); return; } }
  if (st.log.length) since = Math.max(since, ...st.log.map(x => x[0]));
  paint(st);
  if (st.run) { wasRun = true; timer = setTimeout(tick, 200); return; }
  if (wasRun && st.added) { sessionStorage.setItem('locmsg', st.msg); setTimeout(() => location.reload(), 1400); }
  wasRun = false;
}
for (const k in btn) btn[k].onclick = async () => {
  const st = await (await fetch('/api/loc/status?since=' + since, { cache: 'no-store' })).json();
  if (st.run && st.kind === k) { await post('/api/loc/stop'); clearTimeout(timer); tick(); return; }
  if (st.run) return;
  log.textContent = ''; since = 0; t0 = Date.now(); wasRun = true;
  const r = await post('/api/loc/start', { kind: k }); if (r.ok === false) { wasRun = false; }
  clearTimeout(timer); tick();
};
tick();   // resume the view when the page is opened while a job is running
})();
