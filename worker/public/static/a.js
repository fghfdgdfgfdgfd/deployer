const $=s=>document.querySelector(s),$$=s=>document.querySelectorAll(s);
$('#menu')&&($('#menu').onclick=()=>document.body.classList.toggle('nav'));
$('#scrim')&&($('#scrim').onclick=()=>document.body.classList.remove('nav'));
$$('.acc>.hd').forEach(h=>h.onclick=()=>h.parentElement.classList.toggle('open'));
$$('.pn').forEach(p=>p.inert=!p.classList.contains('open'));
$$('[data-pn]').forEach(b=>b.onclick=()=>{const a=b.closest('.acc,.box'),p=a.querySelector('.pn[data-p="'+b.dataset.pn+'"]'),o=!p.classList.contains('open');
 a.querySelectorAll('.pn').forEach(x=>{x.classList.remove('open');x.inert=true});a.querySelectorAll('[data-pn]').forEach(x=>x.classList.remove('on'));
 if(o){p.classList.add('open');p.inert=false;b.classList.add('on')}});
$$('[data-copy]').forEach(b=>b.onclick=e=>{e.stopPropagation();const t=b.dataset.copy,l=b.dataset.l=b.dataset.l||b.textContent,ok=()=>{b.textContent='Copied';setTimeout(()=>b.textContent=l,1400)};
 if(navigator.clipboard&&isSecureContext)navigator.clipboard.writeText(t).then(ok);else{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();ok()}});
if($('[data-bar]'))setInterval(async()=>{try{const r=await(await fetch('/api/status')).json();for(const k in r){const e=$('[data-k='+k+']');if(e)e.textContent=r[k]}$$('[data-bar]').forEach(b=>b.style.setProperty('--v',r[b.dataset.bar]))}catch(e){}},4000);

$$('form[data-slow]').forEach(f=>f.addEventListener('submit',()=>{const b=f.querySelector('button:not([type=button])');b.disabled=true;b.textContent='Checking…'}));
$$('[data-check]').forEach(b=>b.onclick=async()=>{const f=b.closest('form'),r=f.querySelector('.res'),h=f.querySelector('[name=host]').value,p=f.querySelector('[name=port]').value;
 r.innerHTML='<span class="chip" style="border-color:var(--yl);color:var(--yl)">Checking…</span>';
 try{const d=await(await fetch('/api/probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host:h,port:p})})).json();
  if(d.error){r.innerHTML='<span class="chip">'+d.error+'</span>';return}
  const esc=t=>String(t).replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';'),G=d.geo&&/^[a-z]{2}$/.test(d.geo.cc)?'<span class="chip ok"><img class="flag" src="/flag/'+d.geo.cc+'.svg" alt=""> → '+esc(d.geo.name)+'</span>':'<span class="chip">Country unknown → Other</span>';
  r.innerHTML=G+(d.best?'<span class="chip ok best">✓ Fastest: '+d.best.proto+' '+d.best.ms+'ms</span>':'<span class="chip">✕ No protocol connected</span>')+d.results.map(x=>'<span class="chip'+(x.ms!==null?' ok':'')+'">'+(x.ms!==null?'✓ ':'✕ ')+x.proto+(x.ms!==null?' '+x.ms+'ms':'')+'</span>').join('')
 }catch(e){r.innerHTML='<span class="chip">Check failed</span>'}});

/* locks: zoom + text selection/copy outside inputs */
const okEl=t=>((t&&t.nodeType===3?t.parentElement:t)||document.body).closest('input,textarea,select');
['gesturestart','gesturechange','gestureend'].forEach(t=>document.addEventListener(t,e=>e.preventDefault()));
document.addEventListener('touchmove',e=>{if(e.touches.length>1)e.preventDefault()},{passive:false});
addEventListener('wheel',e=>{if(e.ctrlKey)e.preventDefault()},{passive:false});
addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&['+','-','=','0'].includes(e.key))e.preventDefault()});
['selectstart','contextmenu','copy','cut','dragstart'].forEach(t=>document.addEventListener(t,e=>{if(!okEl(e.target))e.preventDefault()}));
/* theme toggle: glass button, Telegram-stars style burst + page shockwave */
const STAR='<svg viewBox="0 0 24 24"><path d="M12 2l2.9 6.6 7.1.6-5.4 4.7 1.7 7-6.3-3.8-6.3 3.8 1.7-7L2 9.2l7.1-.6z"/></svg>';
function burst(x,y){const rg=document.createElement('div');rg.className='ring';rg.style.left=x+'px';rg.style.top=y+'px';document.body.appendChild(rg);
 rg.animate([{transform:'translate(-50%,-50%) scale(.5)',opacity:.95},{transform:'translate(-50%,-50%) scale(3.4)',opacity:0}],{duration:900,easing:'cubic-bezier(.2,.8,.2,1)'}).onfinish=()=>rg.remove();
 for(let i=0;i<18;i++){const s=document.createElement('i');s.className='star';s.innerHTML=STAR;const z=10+Math.random()*16;
  s.style.cssText=`left:${x}px;top:${y}px;width:${z}px;height:${z}px;color:${['#ffb02e','#ffd35c','#ff8a3d'][i%3]}`;document.body.appendChild(s);
  const a=Math.random()*6.283,d=50+Math.random()*110,dx=Math.cos(a)*d,dy=Math.sin(a)*d-30,r1=(Math.random()-.5)*240,r2=(Math.random()-.5)*400;
  s.animate([{transform:'translate(-50%,-50%) scale(.2) rotate(0)',opacity:1},{transform:`translate(calc(-50% + ${dx}px),calc(-50% + ${dy}px)) scale(1) rotate(${r1}deg)`,opacity:1,offset:.55},
   {transform:`translate(calc(-50% + ${dx*1.15}px),calc(-50% + ${dy+55}px)) scale(.3) rotate(${r2}deg)`,opacity:0}],{duration:900+Math.random()*500,easing:'cubic-bezier(.2,.8,.2,1)'}).onfinish=()=>s.remove()}}
function wobble(x,y){if(matchMedia('(prefers-reduced-motion: reduce)').matches)return;
 /* Web Animations API: never touches classes, so the elements' own CSS animations (rise) are not re-triggered */
 const E='cubic-bezier(.32,.72,0,1)',P='perspective(700px)';
 $$('main .box,main .acc,main h1,main .toast,main .login form,main .chip,.side a,.top').forEach(e=>{
  const r=e.getBoundingClientRect(),dx=r.x+r.width/2-x,dy=r.y+r.height/2-y,d=Math.hypot(dx,dy)||1,tx=dx/d*7,ty=dy/d*7;
  e._w&&e._w.cancel();
  e._w=e.animate([{transform:'none',easing:E},
   {transform:`${P} translate(${tx}px,${ty}px) rotateX(5deg) rotateY(-4deg) scale(1.025)`,offset:.22,easing:E},
   {transform:`${P} translate(${-tx*.6}px,${-ty*.6}px) rotateX(-3deg) rotateY(2.5deg) scale(.99)`,offset:.48,easing:E},
   {transform:`${P} rotateX(1.2deg) scale(1.005)`,offset:.72,easing:E},
   {transform:'none'}],{duration:1400,delay:Math.min(d/1800,.5)*1000,fill:'backwards'})})}
$('#theme').onclick=e=>{const b=e.currentTarget,r=b.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2,H=document.documentElement,n=H.dataset.theme==='light'?'dark':'light';
 b.animate([{transform:'scale(1)'},{transform:'scale(.8)'},{transform:'scale(1.14)'},{transform:'scale(1)'}],{duration:750,easing:'cubic-bezier(.32,.72,0,1)'});
 burst(x,y);wobble(x,y);H.classList.add('theming');setTimeout(()=>H.classList.remove('theming'),1000);
 setTimeout(()=>{H.dataset.theme=n;try{localStorage.setItem('th',n)}catch(_){}},120)};

/* config-domain picker: custom row */
$$('[data-custom]').forEach(b=>b.onclick=()=>{const r=b.closest('.in').querySelector('[data-cust]');r.hidden=!r.hidden;if(!r.hidden)r.querySelector('input').focus()});
/* relays: live tracking + ping */
const esc=t=>String(t).replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';'),SYM={ok:'✓',run:'…',fail:'✕',wait:'·'};
function relayPing(acc,pg){const e=acc.querySelector('[data-ping]');if(!pg)return;
 e.innerHTML=(pg.ok?'<span class="chip ok">panel ⇄ relay · '+pg.web+' ms</span>':'<span class="chip">✕ no answer through the relay</span>')+(pg.tcp?'<span class="chip ok">TCP '+pg.tcp+' ms</span>':'')}
function relayView(acc,v){acc.dataset.st=v.status;
 const t=acc.querySelector('[data-tag]');t.textContent={idle:'off',deploying:'deploying',ok:'on',failed:'failed'}[v.status];t.className='tag'+(v.status==='ok'?' active':v.status==='failed'?' expired':'');
 const s=acc.querySelector('[data-steps]');s.hidden=v.status==='idle';
 s.innerHTML=v.steps.map(x=>'<span class="chip '+x.st+'">'+SYM[x.st]+' '+esc(x.l)+(x.m&&(x.st==='ok'||x.st==='run')?' · '+esc(x.m):'')+'</span>').join('');
 const er=acc.querySelector('[data-err]');er.hidden=!v.err;er.textContent=v.err;
 const o=acc.querySelector('[data-out]');o.hidden=!v.domain;acc.querySelector('[data-dom]').textContent=v.domain;
 const c=o.querySelector('[data-copy]');if(c)c.dataset.copy=v.domain;relayPing(acc,v.ping);
 acc.querySelector('[data-go]').disabled=v.status==='deploying'}
async function relayPoll(acc){const p=acc.dataset.relay;
 for(;;){try{const v=await(await fetch('/api/relays/'+p)).json();relayView(acc,v);
   if(v.status!=='deploying'){if(v.status==='ok'&&!acc.dataset.done){acc.dataset.done=1;setTimeout(()=>location.replace('/relays?o='+p),1200)}return}}catch(e){}
  await new Promise(r=>setTimeout(r,1500))}}
$$('[data-relay]').forEach(acc=>{if(acc.dataset.st==='deploying')relayPoll(acc);
 const b=acc.querySelector('[data-rping]');if(!b)return;
 const run=async()=>{b.disabled=true;b.textContent='Pinging…';try{const d=await(await fetch('/api/relays/'+acc.dataset.relay+'/ping',{method:'POST'})).json();relayPing(acc,d.ping)}catch(e){}b.disabled=false;b.textContent='Ping'};
 b.onclick=run;if(acc.dataset.st==='ok'){run();setInterval(run,30000)}});

/* settings: test-site list (add / remove rows) */
$$('[data-sites]').forEach(f=>{const L=f.querySelector('[data-list]');
 f.addEventListener('click',e=>{const r=e.target.closest('[data-rm]');if(r){r.closest('.site').remove();return}
  if(e.target.closest('[data-add]')){const d=document.createElement('div');d.className='row site';
   d.innerHTML='<input name="site" placeholder="https://example.com/generate_204" autocapitalize="off" autocomplete="off" spellcheck="false"><button type="button" class="btn o pk" data-rm aria-label="Remove">−</button>';L.append(d);d.querySelector('input').focus()}});
 f.addEventListener('submit',()=>L.querySelectorAll('input').forEach(i=>{if(!i.value.trim())i.closest('.site').remove()}))});
