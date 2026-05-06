// ──────────────────────────────────────────────────────────────────────
//  Hybrid IDS Security Dashboard – frontend logic
//  Loaded as an external file so browser security extensions (e.g.
//  SquareX) cannot strip it via injected CSP rules on inline scripts.
// ──────────────────────────────────────────────────────────────────────
console.log('[IDS] dashboard.js loaded at', new Date().toISOString());

// ── live dashboard ────────────────────────────────────────────────────────────
function topKey(obj){const e=Object.entries(obj||{});if(!e.length)return'-';e.sort((a,b)=>b[1]-a[1]);return e[0][0];}
function renderPills(el,map,cls){const e=Object.entries(map||{});if(!e.length){el.innerHTML='<span class="pill">No data</span>';return;}el.innerHTML=e.sort((a,b)=>b[1]-a[1]).map(([k,v])=>`<span class="pill ${cls(k)}">${k}: ${v}</span>`).join('');}
async function fetchJSON(url){const r=await fetch(url);if(!r.ok)throw new Error('HTTP '+r.status);return r.json();}

async function refreshLive(){
  const data=await fetchJSON('/api/live?limit=120');
  const s=data.summary||{};const alerts=data.recent_alerts||[];
  document.getElementById('totalAlerts').textContent=s.total_alerts??0;
  document.getElementById('topType').textContent=topKey(s.by_attack_type);
  const ts=s.top_source_ips&&s.top_source_ips.length?s.top_source_ips[0][0]:'-';
  document.getElementById('topSource').textContent=ts;
  const avg=s.confidence&&s.confidence.avg;
  document.getElementById('avgConf').textContent=typeof avg==='number'?avg.toFixed(4):'-';
  renderPills(document.getElementById('typePills'),s.by_attack_type,()=>'');
  renderPills(document.getElementById('severityPills'),s.by_severity,k=>k.toUpperCase()==='HIGH'?'high':'medium');
  document.getElementById('recentBody').innerHTML=alerts.slice(0,40).map(a=>`<tr><td>${a.timestamp||'-'}</td><td>${a.source_ip||'-'}</td><td>${a.attack_type||'-'}</td><td>${a.severity||'-'}</td><td>${a.confidence??'-'}</td></tr>`).join('');
}
async function refreshHistory(){
  const data=await fetchJSON('/api/history');
  const runs=data.runs||[];
  document.getElementById('historyBody').innerHTML=runs.map(r=>{
    const t=Object.entries(r.by_attack_type||{}).sort((a,b)=>b[1]-a[1]);
    const tt=t.length?t[0][0]:'-';
    return `<tr class="history-row" data-run="${r.run_id}"><td>${r.time}</td><td>${r.total_alerts}</td><td>${tt}</td></tr>`;
  }).join('');
  document.querySelectorAll('.history-row').forEach(row=>row.addEventListener('click',()=>loadRun(row.dataset.run)));
}
async function loadRun(id){
  const data=await fetchJSON('/api/run/'+id);
  const s=data.summary||{};const a=data.recent_alerts||[];
  document.getElementById('runDetail').style.display='block';
  document.getElementById('detailTitle').textContent='Run: '+id;
  document.getElementById('detailMeta').innerHTML=`<span class="pill">Alerts: ${s.total_alerts??0}</span><span class="pill">Types: ${JSON.stringify(s.by_attack_type||{})}</span>`;
  document.getElementById('detailAlertsBody').innerHTML=a.slice(0,80).map(x=>`<tr><td>${x.timestamp||'-'}</td><td>${x.source_ip||'-'}</td><td>${x.attack_type||'-'}</td><td>${x.severity||'-'}</td><td>${x.confidence??'-'}</td></tr>`).join('');
}
function _setStatus(msg, isError){
  const el = document.getElementById('refreshNote');
  if (!el) return;
  el.textContent = msg;
  el.style.color = isError ? '#ff5d73' : '';
}
async function boot(){
  try {
    await Promise.all([
      refreshLive().catch(e => { console.error('[refreshLive]', e); throw new Error('live: ' + e.message); }),
      refreshHistory().catch(e => { console.error('[refreshHistory]', e); throw new Error('history: ' + e.message); })
    ]);
    _setStatus('Last refresh: ' + new Date().toLocaleTimeString(), false);
  } catch (e) {
    _setStatus('Refresh failed: ' + e.message, true);
  }
}
function _bootOnce(){
  console.log('[IDS] dashboard JS booted at', new Date().toISOString());
  boot();
  setInterval(boot, 5000);
}
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _bootOnce);
} else {
  _bootOnce();
}
window.addEventListener('error', ev => {
  console.error('[IDS] uncaught', ev.error || ev.message);
  _setStatus('JS error: ' + (ev.message || 'unknown'), true);
});

// ── simulation ────────────────────────────────────────────────────────────────
let _simFrame=null,_simAnimDone=false,_simApiDone=false,_simApiData=null;

function launchSimulation(){
  const btn=document.getElementById('simBtn');
  btn.disabled=true;
  btn.innerHTML='<span class="btn-icon">&#x23F3;</span> Simulating...';

  const attackType=document.getElementById('attackType').value;
  const packetCount=parseInt(document.getElementById('packetCount').value);

  // reset state
  _simAnimDone=false; _simApiDone=false; _simApiData=null;

  // show canvas, hide results
  document.getElementById('simAnimArea').style.display='block';
  document.getElementById('simResults').style.display='none';
  document.getElementById('simBreakdown').innerHTML='';
  const _bn=document.getElementById('bypassNote'); if(_bn){_bn.style.display='none';_bn.innerHTML='';}
  document.getElementById('simProgressBar').style.width='0%';
  document.getElementById('simStatusText').textContent='Launching attack\u2026';
  ['liveFlooded','liveBlocked'].forEach(id=>document.getElementById(id).textContent='0');
  document.getElementById('liveRate').textContent='-';

  // start canvas animation
  _startSimAnimation(attackType, packetCount);

  // call backend
  fetch('/api/simulate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({attack_type:attackType,packet_count:packetCount})})
    .then(r=>r.json())
    .then(data=>{_simApiData=data;_simApiDone=true;_checkSimDone();})
    .catch(err=>{
      document.getElementById('simStatusText').textContent='API error: '+err.message;
      btn.disabled=false;btn.innerHTML='<span class="btn-icon">&#x26A1;</span> Launch Simulation';
    });
}

function _checkSimDone(){
  if(_simAnimDone&&_simApiDone&&_simApiData) _showResults(_simApiData);
}

function resetSimulation(){
  if(_simFrame){cancelAnimationFrame(_simFrame);_simFrame=null;}
  document.getElementById('simAnimArea').style.display='none';
  document.getElementById('simResults').style.display='none';
  const btn=document.getElementById('simBtn');
  btn.disabled=false;
  btn.innerHTML='<span class="btn-icon">&#x26A1;</span> Launch Simulation';
}

function _easeOut(t){return 1-Math.pow(1-t,3);}

function _animCount(id,to,dur,fmt){
  const el=document.getElementById(id);
  const t0=performance.now();
  function tick(now){
    const p=Math.min((now-t0)/dur,1),v=Math.round(to*_easeOut(p));
    el.textContent=fmt?fmt(v):v;
    if(p<1)requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function _setBar(id,valId,count,total){
  const pct=total>0?Math.min(count/total*100,100):0;
  setTimeout(()=>{
    document.getElementById(id).style.width=pct+'%';
    document.getElementById(valId).textContent=count;
  },120);
}

function _showResults(data){
  document.getElementById('simStatusText').textContent='&#x2714; Simulation complete';
  document.getElementById('simProgressBar').style.width='100%';
  document.getElementById('liveFlooded').textContent=data.total_flooded;
  document.getElementById('liveBlocked').textContent=data.total_blocked;
  document.getElementById('liveRate').textContent=(data.detection_rate*100).toFixed(1)+'%';

  const btn=document.getElementById('simBtn');
  btn.disabled=false;btn.innerHTML='<span class="btn-icon">&#x26A1;</span> Launch Simulation';

  setTimeout(()=>{
    document.getElementById('simResults').style.display='block';
    const T=data.total_flooded;
    _animCount('res-flooded',data.total_flooded,900);
    _animCount('res-blocked',data.total_blocked,900);
    _animCount('res-rate',Math.round(data.detection_rate*1000),900,v=>((v/10).toFixed(1)+'%'));
    _animCount('res-bypassed',data.bypassed,900);
    _setBar('bar-sig','val-sig',data.blocked_by_signature,T);
    _setBar('bar-ml','val-ml',data.blocked_by_ml,T);
    // For mixed: show normal-traffic-passed separately so "bypassed" only = true bypasses
    const trueBypassed = isMixed ? (data.bypassed - (data.normal_passed||0)) : data.bypassed;
    const normRow=document.getElementById('normRow');
    if(isMixed && data.normal_passed>0){
      _setBar('bar-byp','val-byp', trueBypassed, T);
      _setBar('bar-norm','val-norm', data.normal_passed, T);
      if(normRow) normRow.style.display='flex';
    } else {
      _setBar('bar-byp','val-byp', data.bypassed, T);
      if(normRow) normRow.style.display='none';
    }

    // bypass / detection explanation note
    const cfg=data.config||{};
    const isMixed=cfg.attack_type==='mixed';
    const isNormal=cfg.attack_type==='normal';
    let bypassNote='';
    if(isNormal){
      bypassNote='&#x2705; Normal traffic baseline &mdash; 0 false positives. All packets correctly allowed through.';
    } else if(isMixed && data.normal_passed>0){
      const atkRate=(data.detection_rate*100).toFixed(1);
      bypassNote=`&#x2139; Mixed mode sends <b>25% normal traffic</b> alongside attacks. `
        +`The <b>${data.normal_passed}</b> bypassed packets are benign flows the IDS correctly let through &mdash; `
        +`blocking them would be false positives. `
        +`<b>True attack detection rate: ${atkRate}%</b> (${data.attack_blocked} / ${data.attack_flooded} attack packets blocked).`;
    } else if(data.bypassed===0){
      bypassNote='&#x1F6E1; IDS blocked 100% of attack traffic.';
    } else {
      bypassNote=`&#x26A0; <b>${data.bypassed}</b> packet${data.bypassed===1?'':'s'} bypassed IDS. `
        +`These are the initial <em>warm-up packets</em> seen before the flow hit signature thresholds &mdash; normal IDS behavior on any new connection.`;
    }
    const noteEl=document.getElementById('bypassNote');
    if(noteEl){noteEl.innerHTML=bypassNote; noteEl.style.display='block';}

    // breakdown for mixed
    if(data.breakdown){
      const bd=document.getElementById('simBreakdown');
      let html='<div class="breakdown-wrap"><div class="breakdown-title">Per-Type Breakdown</div><table><thead><tr><th>Type</th><th>Sent</th><th>Blocked</th><th>Sig</th><th>ML</th><th>Rate</th></tr></thead><tbody>';
      for(const[t,s] of Object.entries(data.breakdown)){
        const pct=s.total_flooded>0?(s.total_blocked/s.total_flooded*100).toFixed(1):0;
        html+=`<tr><td>${t}</td><td>${s.total_flooded}</td><td>${s.total_blocked}</td><td>${s.blocked_by_signature}</td><td>${s.blocked_by_ml}</td><td>${pct}%</td></tr>`;
      }
      html+='</tbody></table></div>';
      bd.innerHTML=html;
    }
  },200);
}

// ── canvas animation ──────────────────────────────────────────────────────────
function _startSimAnimation(attackType, packetCount){
  if(_simFrame){cancelAnimationFrame(_simFrame);_simFrame=null;}

  const canvas=document.getElementById('simCanvas');
  const ctx=canvas.getContext('2d');
  const W=canvas.width, H=canvas.height;

  const ANIM_MS  = Math.min(6000, Math.max(3000, packetCount * 4));
  const VIS_PKTS = Math.min(packetCount, 180); // visual representation cap
  const SPAWN_INTERVAL = ANIM_MS / VIS_PKTS;   // ms between visual spawns

  const ATTACK_RATIO = attackType==='normal' ? 0 : attackType==='mixed' ? 0.75 : 1.0;

  // Node positions
  const ATK  = {x:85,  y:H/2, lbl:'ATTACKER', col:'#ff5d73'};
  const IDS  = {x:W/2, y:H/2, lbl:'IDS',      col:'#40c4ff'};
  const TGT  = {x:W-85,y:H/2, lbl:'SERVER',   col:'#3ddc97'};

  const PKT_SPEED = 7; // px/frame at 60fps → crosses ~960px in ~137 frames ≈ 2.3s
  const BLOCK_RATE = ATTACK_RATIO * 0.87; // approximate, overridden by real API result

  let packets=[], explosions=[], sparks=[], rings=[];
  let spawned=0, animBlocked=0, animPassed=0;
  let t0=null, gridOff=0;

  function spawnPkt(isAtk){
    packets.push({
      x: ATK.x+32, y: ATK.y+(Math.random()-.5)*44,
      vx: PKT_SPEED+(Math.random()-.5)*2,
      isAtk, opacity:1, sz: isAtk?5.5:4,
      blocked:false, passed:false,
      trail:[]
    });
  }

  function addExplosion(x,y){
    explosions.push({x,y,r:0,maxR:28+Math.random()*14,op:1,col:'#ff5d73'});
    for(let i=0;i<8;i++){
      const a=Math.PI*2*i/8+Math.random()*.6;
      sparks.push({x,y,vx:Math.cos(a)*(2+Math.random()*4),vy:Math.sin(a)*(2+Math.random()*4),op:1,col:Math.random()<.5?'#ff5d73':'#ffbf47'});
    }
    rings.push({x,y,r:0,op:.8});
  }

  function update(elapsed){
    // spawn
    const shouldSpawn=Math.floor(elapsed/SPAWN_INTERVAL);
    while(spawned<shouldSpawn&&spawned<VIS_PKTS){
      spawnPkt(Math.random()<ATTACK_RATIO);
      spawned++;
    }

    // progress bar
    const prog=Math.min(elapsed/ANIM_MS*100,99);
    document.getElementById('simProgressBar').style.width=prog+'%';

    // status text
    if(elapsed<ANIM_MS*.25) document.getElementById('simStatusText').textContent='&#x26A1; Flooding packets\u2026';
    else if(elapsed<ANIM_MS*.6) document.getElementById('simStatusText').textContent='&#x1F6E1; IDS analyzing traffic\u2026';
    else document.getElementById('simStatusText').textContent='&#x1F4CA; Finalizing detection\u2026';

    // live counter approx
    const scaleFactor=packetCount/VIS_PKTS;
    document.getElementById('liveFlooded').textContent=Math.round((animBlocked+animPassed)*scaleFactor);
    document.getElementById('liveBlocked').textContent=Math.round(animBlocked*scaleFactor);
    const total=animBlocked+animPassed;
    document.getElementById('liveRate').textContent=total>0?(animBlocked/total*100).toFixed(1)+'%':'-';

    gridOff=(gridOff+0.4)%40;

    // move packets
    for(let i=packets.length-1;i>=0;i--){
      const p=packets[i];
      p.trail.push({x:p.x,y:p.y,op:p.opacity*.65});
      if(p.trail.length>7)p.trail.shift();

      if(!p.blocked&&!p.passed){
        p.x+=p.vx;
        if(p.x>=IDS.x-32){
          if(p.isAtk&&Math.random()<BLOCK_RATE){
            p.blocked=true; p.vx=0; animBlocked++;
            addExplosion(p.x,p.y);
          } else {
            p.passed=true; animPassed++;
          }
        }
      } else if(p.passed){ p.x+=p.vx; }

      if(p.blocked) p.opacity-=.055;
      if(p.passed&&p.x>TGT.x) p.opacity-=.12;
      if(p.opacity<=0) packets.splice(i,1);
    }

    for(let i=explosions.length-1;i>=0;i--){
      const e=explosions[i]; e.r+=2.8; e.op-=.048;
      if(e.op<=0)explosions.splice(i,1);
    }
    for(let i=sparks.length-1;i>=0;i--){
      const s=sparks[i]; s.x+=s.vx; s.y+=s.vy; s.vy+=.12; s.op-=.038;
      if(s.op<=0)sparks.splice(i,1);
    }
    for(let i=rings.length-1;i>=0;i--){
      const r=rings[i]; r.r+=5; r.op-=.04;
      if(r.op<=0)rings.splice(i,1);
    }
  }

  function drawGrid(){
    ctx.save();
    ctx.strokeStyle='rgba(32,90,145,.1)'; ctx.lineWidth=.5;
    for(let x=-gridOff;x<W;x+=40){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
    for(let y=0;y<H;y+=40){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
    ctx.restore();
  }

  function drawConn(a,b,active){
    ctx.save();
    ctx.strokeStyle=active?'rgba(64,196,255,.22)':'rgba(64,196,255,.07)';
    ctx.lineWidth=1.5; ctx.setLineDash([8,14]);
    ctx.lineDashOffset=-((Date.now()/60)%22);
    ctx.beginPath(); ctx.moveTo(a.x+36,a.y); ctx.lineTo(b.x-36,b.y); ctx.stroke();
    ctx.setLineDash([]); ctx.restore();
  }

  function drawNode(n, pulse){
    ctx.save();
    const beat=pulse?(Math.sin(Date.now()/220)*.5+.5):0;
    const r=30+beat*4;
    // glow halo
    const g=ctx.createRadialGradient(n.x,n.y,r*.2,n.x,n.y,r*2.2);
    g.addColorStop(0,n.col+'50'); g.addColorStop(1,'transparent');
    ctx.fillStyle=g; ctx.beginPath(); ctx.arc(n.x,n.y,r*2.2,0,Math.PI*2); ctx.fill();
    // ring
    ctx.strokeStyle=n.col; ctx.lineWidth=2;
    ctx.shadowColor=n.col; ctx.shadowBlur=18;
    ctx.beginPath(); ctx.arc(n.x,n.y,r,0,Math.PI*2); ctx.stroke();
    ctx.fillStyle=n.col+'18'; ctx.fill();
    ctx.shadowBlur=0;
    // label
    ctx.fillStyle=n.col; ctx.font='bold 8.5px IBM Plex Mono,monospace';
    ctx.textAlign='center'; ctx.fillText(n.lbl,n.x,n.y+r+15);
    ctx.restore();
  }

  function draw(){
    ctx.clearRect(0,0,W,H);
    drawGrid();
    drawConn(ATK,IDS,spawned>0);
    drawConn(IDS,TGT,animPassed>0);

    // trails
    for(const p of packets){
      for(let t=0;t<p.trail.length;t++){
        const pt=p.trail[t];
        ctx.globalAlpha=pt.op*(t/p.trail.length)*.55;
        ctx.fillStyle=p.isAtk?'#ff5d73':'#3ddc97';
        ctx.beginPath(); ctx.arc(pt.x,pt.y,p.sz*.55,0,Math.PI*2); ctx.fill();
      }
      ctx.globalAlpha=1;
    }
    // rings
    for(const r of rings){
      ctx.globalAlpha=r.op;
      ctx.strokeStyle='#ff5d73'; ctx.lineWidth=1.5;
      ctx.shadowColor='#ff5d73'; ctx.shadowBlur=6;
      ctx.beginPath(); ctx.arc(r.x,r.y,r.r,0,Math.PI*2); ctx.stroke();
      ctx.shadowBlur=0; ctx.globalAlpha=1;
    }
    // explosions
    for(const e of explosions){
      ctx.globalAlpha=e.op;
      ctx.strokeStyle=e.col; ctx.lineWidth=1.8;
      ctx.shadowColor=e.col; ctx.shadowBlur=12;
      ctx.beginPath(); ctx.arc(e.x,e.y,e.r,0,Math.PI*2); ctx.stroke();
      if(e.r>10){ctx.globalAlpha=e.op*.4;ctx.beginPath();ctx.arc(e.x,e.y,e.r*.55,0,Math.PI*2);ctx.stroke();}
      ctx.shadowBlur=0; ctx.globalAlpha=1;
    }
    // sparks
    for(const s of sparks){
      ctx.globalAlpha=s.op;
      ctx.fillStyle=s.col; ctx.shadowColor=s.col; ctx.shadowBlur=6;
      ctx.beginPath(); ctx.arc(s.x,s.y,2.2,0,Math.PI*2); ctx.fill();
      ctx.shadowBlur=0; ctx.globalAlpha=1;
    }
    // packets
    for(const p of packets){
      ctx.globalAlpha=p.opacity;
      ctx.fillStyle=p.isAtk?'#ff5d73':'#3ddc97';
      ctx.shadowColor=p.isAtk?'#ff2244':'#00ff88'; ctx.shadowBlur=12;
      ctx.beginPath(); ctx.arc(p.x,p.y,p.sz,0,Math.PI*2); ctx.fill();
      ctx.shadowBlur=0; ctx.globalAlpha=1;
    }
    // nodes on top
    drawNode(ATK, spawned>0&&spawned<VIS_PKTS);
    drawNode(IDS, packets.length>0);
    drawNode(TGT, animPassed>0);

    // IDS label overlay when blocking
    if(animBlocked>0){
      ctx.save();
      ctx.fillStyle='rgba(255,93,115,.85)';
      ctx.font='bold 9px IBM Plex Mono,monospace';
      ctx.textAlign='center';
      ctx.fillText('BLOCKING',IDS.x,IDS.y-36);
      ctx.restore();
    }
  }

  function frame(ts){
    if(!t0) t0=ts;
    const elapsed=ts-t0;
    update(elapsed);
    draw();
    const done=elapsed>ANIM_MS+1200&&packets.length===0&&explosions.length===0;
    if(!done){ _simFrame=requestAnimationFrame(frame); }
    else { _simFrame=null; _simAnimDone=true; _checkSimDone(); }
  }

  _simFrame=requestAnimationFrame(frame);
}
