/* ══════════════════════════════════════════════════
   WSN-GUARD — App.js  |  QOR Lifecycle Edition
══════════════════════════════════════════════════ */
"use strict";

const C = {
  bg:'#07090d', bg2:'#0c1018', bg3:'#111820',
  a:'#00d2aa', a2:'#00ffcc',
  red:'#ff3a5c', yel:'#ffcc40', grn:'#36e87a',
  blu:'#3d8dff', pur:'#a855f7', ora:'#ff7a30',
  tx:'#bcd4e0', tx2:'#607888', tx3:'#3a5060',
  // QOR state colors
  sNormal:'#3d8dff', sSuspected:'#ffcc40', sQuarantine:'#ff3a5c',
  sObserving:'#a855f7', sRehab:'#36e87a', sExpelled:'#ff7a30',
  sMal:'#ff1a3c', sDead:'#2a3540',
};

const STATE_COLOR = {
  NORMAL:        C.sNormal,
  SUSPECTED:     C.sSuspected,
  QUARANTINED:   C.sQuarantine,
  OBSERVING:     C.sObserving,
  REHABILITATED: C.sRehab,
  EXPELLED:      C.sExpelled,
  DEAD:          C.sDead,
};

const EV_ICON = {
  QUARANTINED:       '🔒',
  OBSERVATION_START: '🔬',
  REHABILITATED:     '✅',
  EXPELLED:          '⛔',
};

// ── State ──
let animData = null, curRound = 0, animTimer = null;
let animSpeed = 250, isPlaying = false;
let demoData = null, charts = {};
let eventLog = [];

// ══════════════════════════════════════
// NAVIGATION
// ══════════════════════════════════════
function initNav() {
  document.querySelectorAll('.nb').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.nb').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const sec = btn.dataset.sec;
      document.querySelectorAll('.sec').forEach(s => s.classList.remove('active'));
      document.getElementById('sec-' + sec).classList.add('active');
      if (sec === 'charts' && demoData) renderCharts(demoData);
      if (sec === 'novelty') renderNoveltyCharts();
      if (sec === 'qor' && demoData) renderQORCharts(demoData);
    });
  });
}

// ══════════════════════════════════════
// CONTROLS
// ══════════════════════════════════════
function initControls() {
  document.querySelectorAll('.seg .sb').forEach(btn => {
    btn.addEventListener('click', () => {
      const seg = btn.closest('.seg');
      seg.querySelectorAll('.sb').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      if (seg.id === 'spdSeg') {
        animSpeed = parseInt(btn.dataset.v);
        if (isPlaying) { stopAnim(); startAnim(); }
      }
    });
  });

  const sl = document.getElementById('malSl');
  sl.addEventListener('input', () => {
    document.getElementById('malV').textContent = sl.value + '%';
  });

  document.getElementById('runBtn').addEventListener('click', runSim);
  document.getElementById('pauseBtn').addEventListener('click', () => {
    if (isPlaying) { stopAnim(); setLive('Paused'); }
    else { startAnim(); }
  });
  document.getElementById('resetBtn').addEventListener('click', resetSim);
}

// ══════════════════════════════════════
// SIMULATION
// ══════════════════════════════════════
async function runSim() {
  const method  = document.querySelector('#methSeg .sb.active')?.dataset.v || 'REM_MD';
  const malPct  = parseInt(document.getElementById('malSl').value);
  stopAnim(); showLoad('Running WSN simulation…');
  setLive('Starting GA-LEACH + QOR engine…');
  try {
    const r = await fetch('/api/live_sim', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ method, malicious_fraction:malPct/100,
                             max_rounds:80, seed:Math.floor(Math.random()*1000) })
    });
    if (!r.ok) throw new Error('API ' + r.status);
    const data = await r.json();
    animData = data.rounds || [];
    document.getElementById('rndTotal').textContent = data.total_rounds || animData.length;
    hideLoad();
    curRound = 0; eventLog = [];
    startAnim();
    setLive(`${method} | ${malPct}% malicious | ${animData.length} rounds`);
  } catch (e) {
    hideLoad();
    setLive('Server offline — showing demo data');
    loadDemo();
  }
}

async function loadDemo() {
  try {
    const r = await fetch('/api/quick_demo');
    demoData = await r.json();
    const anim = demoData.animation_data;
    if (anim?.rounds?.length) {
      animData = anim.rounds;
      document.getElementById('rndTotal').textContent = animData.length;
      curRound = 0; eventLog = [];
      startAnim();
    }
    renderCharts(demoData);
    renderQORCharts(demoData);
    setLive('Demo loaded — run server for live simulation');
  } catch (e) {
    buildFallback();
  }
}

function buildFallback() {
  const RNG = mulberry32(42);
  const nodes = Array.from({length:100},(_,i)=>({
    id:i, x:5+RNG()*90, y:5+RNG()*90, malicious:i<12
  }));
  const stateMap = {};
  nodes.forEach(n => { stateMap[n.id] = n.malicious ? 'NORMAL' : 'NORMAL'; });
  const repMap = {};
  nodes.forEach(n => { repMap[n.id] = n.malicious ? 0.7 : 0.88; });
  const qdur = {}; nodes.forEach(n => { qdur[n.id] = 0; });
  const goodR= {}; nodes.forEach(n => { goodR[n.id] = 0; });

  const qorEvents = [
    {round:5, node:2, event:'QUARANTINED',       rep:0.31, malicious:true},
    {round:6, node:7, event:'QUARANTINED',       rep:0.27, malicious:true},
    {round:9, node:14,event:'QUARANTINED',       rep:0.36, malicious:false},
    {round:13,node:2, event:'OBSERVATION_START', rep:0.29, malicious:true},
    {round:14,node:7, event:'OBSERVATION_START', rep:0.30, malicious:true},
    {round:17,node:14,event:'OBSERVATION_START', rep:0.49, malicious:false},
    {round:22,node:14,event:'REHABILITATED',     rep:0.57, malicious:false},
    {round:25,node:2, event:'EXPELLED',          rep:0.21, malicious:true},
    {round:31,node:7, event:'EXPELLED',          rep:0.17, malicious:true},
  ];

  const rounds = [];
  for (let r = 1; r <= 80; r++) {
    qorEvents.filter(e=>e.round===r).forEach(e => {
      const stMap = {QUARANTINED:'QUARANTINED',OBSERVATION_START:'OBSERVING',
                     REHABILITATED:'REHABILITATED',EXPELLED:'EXPELLED'};
      stateMap[e.node] = stMap[e.event];
    });

    const snap = nodes.map(n => {
      let rep = repMap[n.id];
      const st = stateMap[n.id];
      if (n.malicious && st==='NORMAL') rep = Math.max(0.12, rep - RNG()*0.04);
      else if (st==='QUARANTINED'||st==='OBSERVING') { rep = Math.max(0.10, rep - RNG()*0.015); qdur[n.id]++; }
      else if (st==='REHABILITATED') rep = Math.min(0.72, rep + RNG()*0.015);
      else rep = Math.min(0.99, rep + RNG()*0.005);
      repMap[n.id] = rep;
      const alive = st !== 'EXPELLED' && RNG() < (1 - r*0.003);
      if (st==='OBSERVING') goodR[n.id] = rep > 0.53 ? goodR[n.id]+1 : 0;
      return {
        id:n.id, x:n.x, y:n.y, alive,
        malicious:n.malicious, state:st,
        ch:RNG()<0.05, cluster:Math.floor(RNG()*5),
        rep:Math.round(rep*1000)/1000,
        energy:Math.max(0,1-r*0.009*(0.5+RNG())),
        good_rounds_in_obs:goodR[n.id],
        quarantine_duration:qdur[n.id], rehab_count:0,
      };
    });

    const tau = Math.max(0.3, Math.min(0.75, 0.5+Math.sin(r/9)*0.04+r*0.001));
    const chs = [5,20,38,60,80];

    // count states
    const cnt = {};
    snap.forEach(n => { cnt[n.state] = (cnt[n.state]||0)+1; });

    rounds.push({
      round:r, nodes:snap, cluster_heads:chs, threshold:tau,
      stats:{
        throughput: Math.max(60,112-r*0.12),
        alive: Math.max(25,100-Math.floor(r*0.85)),
        n_quarantined: cnt['QUARANTINED']||0,
        n_observing:   cnt['OBSERVING']||0,
        n_rehabilitated:cnt['REHABILITATED']||0,
        n_expelled:    cnt['EXPELLED']||0,
        routing_overhead: 0.32+r*0.001,
        residual_energy: Math.max(0,100-r*0.8),
        detected_malicious: Math.min(10,Math.floor(r/7)),
        false_positives: 0,
      },
      recent_events: qorEvents.filter(e=>e.round<=r).slice(-4),
    });
  }

  animData = rounds;
  document.getElementById('rndTotal').textContent = rounds.length;
  curRound = 0; eventLog = [];
  startAnim();

  demoData = buildFallbackChartData();
  renderCharts(demoData);
  renderQORCharts(demoData);
}

function buildFallbackChartData() {
  const mal = [0,2,4,6,8,10,12];
  const rds = Array.from({length:100},(_,i)=>i+1);
  return {
    n_malicious_list: mal,
    throughput: { Original:mal.map(m=>110-m*3.5), BRSN:mal.map(m=>110-m*2.3), REM_MD:mal.map(m=>112-m*0.7) },
    lifetime:   { Original:mal.map(m=>620-m*20),  BRSN:mal.map(m=>610-m*13),  REM_MD:mal.map(m=>618-m*8) },
    overhead:   { Original:mal.map(m=>0.30+m*0.042),BRSN:mal.map(m=>0.32+m*0.030),REM_MD:mal.map(m=>0.33+m*0.012) },
    detection_rate: { Original:[0,0,0,0,0,0,0], BRSN:[0,0.55,0.60,0.65,0.68,0.70,0.71], REM_MD:[0,0.88,0.90,0.92,0.93,0.94,0.95] },
    false_positives:{ Original:[0]*7, BRSN:[0,0.08,0.10,0.12,0.13,0.14,0.15], REM_MD:[0,0.04,0.05,0.05,0.06,0.06,0.07] },
    energy_data:    { 'GA-LEACH':rds.map(r=>Math.max(0,100-r*0.055)), 'K-LEACH':rds.map(r=>Math.max(0,100-r*0.085)), 'C-LEACH':rds.map(r=>Math.max(0,100-r*0.100)), LEACH:rds.map(r=>Math.max(0,100-r*0.165)) },
    surviving_data: { 'GA-LEACH':rds.map(r=>Math.max(0,100-Math.max(0,r-51)*2.2)), 'K-LEACH':rds.map(r=>Math.max(0,100-Math.max(0,r-36)*2.8)), 'C-LEACH':rds.map(r=>Math.max(0,100-Math.max(0,r-28)*3.2)), LEACH:rds.map(r=>Math.max(0,100-Math.max(0,r-22)*4.5)) },
    threshold_evolution: rds.map(r=>Math.max(0.3,Math.min(0.75,0.5+Math.sin(r/9)*0.04+r*0.001))),
    qor_timeline: rds.map((r,i)=>({
      round:r,
      quarantined:  i<4?0:i<12?Math.min(3,Math.floor((i-4)/2)):Math.max(0,3-Math.floor((i-12)/5)),
      observing:    i<12?0:i<20?Math.min(2,Math.floor((i-12)/3)):Math.max(0,2-Math.floor((i-20)/6)),
      rehabilitated:i>=22?1:0,
      expelled:     i>=24?(i>=30?2:1):0,
    })),
  };
}

// ══════════════════════════════════════
// ANIMATION
// ══════════════════════════════════════
function startAnim() {
  if (!animData?.length) return;
  isPlaying = true;
  nextFrame();
}
function stopAnim() {
  isPlaying = false;
  clearTimeout(animTimer);
}
function nextFrame() {
  if (!isPlaying || curRound >= animData.length) {
    isPlaying = false;
    setLive('Simulation complete — ' + animData.length + ' rounds');
    return;
  }
  const frame = animData[curRound];
  renderFrame(frame);
  curRound++;
  document.getElementById('rndBar').style.width = (curRound/animData.length*100)+'%';
  document.getElementById('rndDisp').textContent = frame.round;
  animTimer = setTimeout(nextFrame, animSpeed);
}
function resetSim() {
  stopAnim(); curRound = 0; eventLog = [];
  clearCanvas(); resetUI();
  setLive('Ready — press RUN');
}

// ══════════════════════════════════════
// CANVAS
// ══════════════════════════════════════
let canvas, ctx;
const PAD = 28;

function initCanvas() {
  canvas = document.getElementById('netCanvas');
  ctx    = canvas.getContext('2d');
  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);
  clearCanvas();
}
function resizeCanvas() {
  const w = canvas.parentElement;
  canvas.width  = w.clientWidth;
  canvas.height = w.clientHeight - 44 - 3;
}
function clearCanvas() {
  if (!ctx) return;
  ctx.fillStyle = C.bg2;
  ctx.fillRect(0,0,canvas.width,canvas.height);
  ctx.strokeStyle='rgba(0,210,170,0.03)'; ctx.lineWidth=1;
  for(let x=PAD;x<canvas.width-PAD;x+=44){ctx.beginPath();ctx.moveTo(x,PAD);ctx.lineTo(x,canvas.height-PAD);ctx.stroke();}
  for(let y=PAD;y<canvas.height-PAD;y+=44){ctx.beginPath();ctx.moveTo(PAD,y);ctx.lineTo(canvas.width-PAD,y);ctx.stroke();}
}

function n2c(x,y){
  return { cx:PAD+(x/100)*(canvas.width-PAD*2), cy:PAD+(y/100)*(canvas.height-PAD*2) };
}

function renderFrame(frame) {
  clearCanvas();
  const nodes    = frame.nodes || [];
  const chSet    = new Set(frame.cluster_heads || []);
  const stats    = frame.stats || {};
  const tau      = frame.threshold || 0.5;

  // Cluster halos
  const clGroups = {};
  nodes.forEach(n=>{ if(n.alive) (clGroups[n.cluster]=clGroups[n.cluster]||[]).push(n); });
  Object.entries(clGroups).forEach(([cid, members])=>{
    const ch = nodes.find(n=>chSet.has(n.id)&&n.cluster==cid&&n.alive);
    if(!ch) return;
    const {cx,cy}=n2c(ch.x,ch.y);
    const g=ctx.createRadialGradient(cx,cy,0,cx,cy,55);
    g.addColorStop(0,'rgba(0,210,170,0.05)'); g.addColorStop(1,'transparent');
    ctx.beginPath(); ctx.arc(cx,cy,55,0,Math.PI*2); ctx.fillStyle=g; ctx.fill();
    ctx.beginPath(); ctx.arc(cx,cy,55,0,Math.PI*2);
    ctx.strokeStyle='rgba(0,210,170,0.07)'; ctx.lineWidth=1;
    ctx.setLineDash([3,6]); ctx.stroke(); ctx.setLineDash([]);
  });

  // Quarantine zone overlay
  const qNodes = nodes.filter(n=>n.alive&&n.state==='QUARANTINED');
  qNodes.forEach(n=>{
    const {cx,cy}=n2c(n.x,n.y);
    ctx.beginPath(); ctx.arc(cx,cy,18,0,Math.PI*2);
    const g=ctx.createRadialGradient(cx,cy,0,cx,cy,18);
    g.addColorStop(0,'rgba(255,58,92,0.18)'); g.addColorStop(1,'transparent');
    ctx.fillStyle=g; ctx.fill();
    ctx.beginPath(); ctx.arc(cx,cy,18,0,Math.PI*2);
    ctx.strokeStyle='rgba(255,58,92,0.4)'; ctx.lineWidth=1.2;
    ctx.setLineDash([2,4]); ctx.stroke(); ctx.setLineDash([]);
  });

  // Observation zone overlay
  const oNodes = nodes.filter(n=>n.alive&&n.state==='OBSERVING');
  oNodes.forEach(n=>{
    const {cx,cy}=n2c(n.x,n.y);
    ctx.beginPath(); ctx.arc(cx,cy,20,0,Math.PI*2);
    const g=ctx.createRadialGradient(cx,cy,0,cx,cy,20);
    g.addColorStop(0,'rgba(168,85,247,0.15)'); g.addColorStop(1,'transparent');
    ctx.fillStyle=g; ctx.fill();
    // Progress arc for good rounds
    const prog = (n.good_rounds_in_obs||0)/4;
    if(prog>0){
      ctx.beginPath(); ctx.arc(cx,cy,20,-Math.PI/2,-Math.PI/2+prog*Math.PI*2);
      ctx.strokeStyle=C.pur; ctx.lineWidth=2; ctx.stroke();
    }
  });

  // Links: member → CH
  nodes.forEach(n=>{
    if(!n.alive||chSet.has(n.id)) return;
    if(n.state==='QUARANTINED'||n.state==='OBSERVING'||n.state==='EXPELLED') return;
    const ch=nodes.find(c=>chSet.has(c.id)&&c.cluster===n.cluster&&c.alive);
    if(!ch) return;
    const {cx:x1,cy:y1}=n2c(n.x,n.y);
    const {cx:x2,cy:y2}=n2c(ch.x,ch.y);
    ctx.beginPath(); ctx.moveTo(x1,y1); ctx.lineTo(x2,y2);
    const state = n.state || 'NORMAL';
    ctx.strokeStyle = state==='NORMAL'?'rgba(61,141,255,0.12)':
                      state==='REHABILITATED'?'rgba(54,232,122,0.12)':'rgba(255,204,64,0.10)';
    ctx.lineWidth=0.8; ctx.stroke();
  });

  // Probe links (observing → normal neighbors)
  oNodes.forEach(n=>{
    const {cx:ox,cy:oy}=n2c(n.x,n.y);
    // Draw dashed probe lines to 2 nearby nodes
    nodes.filter(nb=>nb.alive&&nb.state==='NORMAL').slice(0,2).forEach(nb=>{
      const {cx:nx,cy:ny}=n2c(nb.x,nb.y);
      const dist=Math.hypot(ox-nx,oy-ny);
      if(dist<120){
        ctx.beginPath(); ctx.moveTo(ox,oy); ctx.lineTo(nx,ny);
        ctx.strokeStyle='rgba(168,85,247,0.25)'; ctx.lineWidth=1;
        ctx.setLineDash([2,5]); ctx.stroke(); ctx.setLineDash([]);
      }
    });
  });

  // CH → Base station links
  const bsX=PAD+0.5*(canvas.width-PAD*2), bsY=PAD+0.5*(canvas.height-PAD*2);
  chSet.forEach(cid=>{
    const ch=nodes.find(n=>n.id===cid&&n.alive);
    if(!ch) return;
    const {cx,cy}=n2c(ch.x,ch.y);
    ctx.beginPath(); ctx.moveTo(cx,cy); ctx.lineTo(bsX,bsY);
    ctx.strokeStyle='rgba(0,210,170,0.18)'; ctx.lineWidth=1;
    ctx.setLineDash([3,5]); ctx.stroke(); ctx.setLineDash([]);
  });

  // Draw nodes
  nodes.forEach(n=>{
    if(!n.alive){
      const {cx,cy}=n2c(n.x,n.y);
      ctx.beginPath(); ctx.arc(cx,cy,2,0,Math.PI*2);
      ctx.fillStyle='rgba(255,255,255,0.04)'; ctx.fill();
      return;
    }
    const {cx,cy}=n2c(n.x,n.y);
    const isCH = chSet.has(n.id);
    const state = n.state || 'NORMAL';
    const isMalUndet = n.malicious && state==='NORMAL';

    let color = STATE_COLOR[state] || C.sNormal;
    if(isMalUndet) color = C.sMal;
    let r = isCH ? 7 : 4;
    if(state==='QUARANTINED'||state==='OBSERVING') r=5;
    if(state==='EXPELLED') r=4;

    // Energy ring on CHs
    if(isCH){
      ctx.beginPath();
      ctx.arc(cx,cy,r+4,-Math.PI/2,-Math.PI/2+(n.energy||0)*Math.PI*2);
      ctx.strokeStyle=C.a2; ctx.lineWidth=1.5; ctx.stroke();
    }

    // Malicious glow (undetected)
    if(isMalUndet){
      const g=ctx.createRadialGradient(cx,cy,0,cx,cy,r+8);
      g.addColorStop(0,'rgba(255,26,60,0.35)'); g.addColorStop(1,'transparent');
      ctx.beginPath(); ctx.arc(cx,cy,r+8,0,Math.PI*2); ctx.fillStyle=g; ctx.fill();
    }

    // Node body
    ctx.beginPath(); ctx.arc(cx,cy,r,0,Math.PI*2);
    ctx.fillStyle=color; ctx.fill();

    // Border for special states
    if(isCH){ ctx.strokeStyle='#fff'; ctx.lineWidth=1.5; ctx.stroke(); }
    if(state==='SUSPECTED'){ ctx.strokeStyle=C.sSuspected; ctx.lineWidth=1.5; ctx.setLineDash([2,3]); ctx.stroke(); ctx.setLineDash([]); }
    if(state==='REHABILITATED'){ ctx.strokeStyle=C.sRehab; ctx.lineWidth=1.5; ctx.stroke(); }
    if(state==='EXPELLED'){
      ctx.strokeStyle=C.sExpelled; ctx.lineWidth=1.5;
      // X mark
      ctx.moveTo(cx-3,cy-3); ctx.lineTo(cx+3,cy+3);
      ctx.moveTo(cx+3,cy-3); ctx.lineTo(cx-3,cy+3);
      ctx.stroke();
    }

    // Reputation mini-bar above node (for quarantined/observing)
    if(state==='QUARANTINED'||state==='OBSERVING'){
      const bw=14, bh=2, bx=cx-bw/2, by=cy-r-5;
      ctx.fillStyle='rgba(0,0,0,0.5)'; ctx.fillRect(bx,by,bw,bh);
      ctx.fillStyle=n.rep>0.5?C.pur:C.red;
      ctx.fillRect(bx,by,bw*Math.min(n.rep,1),bh);
      // tau line
      ctx.fillStyle='rgba(255,255,255,0.5)';
      ctx.fillRect(bx+bw*(tau-0.0)-0.5,by-1,1,bh+2);
    }
  });

  // Base station
  ctx.fillStyle='#fff'; ctx.fillRect(bsX-7,bsY-7,14,14);
  ctx.fillStyle=C.bg; ctx.fillRect(bsX-4,bsY-4,8,8);
  ctx.fillStyle=C.a; ctx.fillRect(bsX-2,bsY-2,4,4);
  ctx.fillStyle=C.tx2; ctx.font='9px JetBrains Mono'; ctx.textAlign='center';
  ctx.fillText('BS',bsX,bsY+20);

  // Update UI
  updateSidebarUI(stats, tau, nodes, frame.recent_events||[]);
}

// ══════════════════════════════════════
// SIDEBAR UI
// ══════════════════════════════════════
function updateSidebarUI(stats, tau, nodes, recentEvents) {
  // State counts
  const cnt = {};
  nodes.forEach(n=>{ cnt[n.state]=(cnt[n.state]||0)+1; });
  set('cntNormal',    cnt['NORMAL']||0);
  set('cntSuspected', cnt['SUSPECTED']||0);
  set('cntQuarantine',cnt['QUARANTINED']||0);
  set('cntObserving', cnt['OBSERVING']||0);
  set('cntRehab',     cnt['REHABILITATED']||0);
  set('cntExpelled',  cnt['EXPELLED']||0);

  // Metrics
  set('mAlive', stats.alive||nodes.filter(n=>n.alive).length);
  set('mTP',    stats.throughput ? stats.throughput.toFixed(1)+' Kbps' : '—');
  set('mEnergy',stats.residual_energy ? stats.residual_energy.toFixed(1)+'J' : '—');
  set('mThresh',tau.toFixed(3));
  const pct = ((tau-0.30)/(0.75-0.30))*100;
  document.getElementById('thFill').style.width = pct+'%';

  // Event log
  if(recentEvents?.length) {
    const newEvs = recentEvents.filter(e=>!eventLog.find(l=>l.round===e.round&&l.node===e.node&&l.event===e.event));
    newEvs.forEach(e=>{ eventLog.unshift(e); if(eventLog.length>30) eventLog.pop(); });
    renderEventLog();
  }

  // Watch list (observing nodes)
  renderWatchList(nodes);
}

function renderEventLog() {
  const el = document.getElementById('eventLog');
  if(!eventLog.length){ el.innerHTML='<div class="ev-empty">Waiting for events…</div>'; return; }
  el.innerHTML = eventLog.slice(0,12).map(e=>{
    const cls = `ev-item ev-${e.event}`;
    const icon = EV_ICON[e.event]||'•';
    const veracity = e.malicious ? ' <span style="color:var(--red)">[MALICIOUS]</span>' : ' <span style="color:var(--grn)">[Normal node]</span>';
    return `<div class="${cls}">
      <div class="ev-icon">${icon}</div>
      <div class="ev-content">
        <div class="ev-event">R${e.round} — Node #${e.node} ${e.event.replace('_',' ')}${veracity}</div>
        <div class="ev-detail">rep=${e.rep?.toFixed(3)||'—'}</div>
      </div>
    </div>`;
  }).join('');
}

function renderWatchList(nodes) {
  const obs = nodes.filter(n=>n.alive&&n.state==='OBSERVING');
  const el  = document.getElementById('watchList');
  if(!obs.length){ el.innerHTML='<div class="wl-empty">No nodes under observation</div>'; return; }
  el.innerHTML = obs.map(n=>{
    const prog = ((n.good_rounds_in_obs||0)/4)*100;
    const progColor = n.malicious ? 'var(--red)' : 'var(--grn)';
    return `<div class="wl-item">
      <div class="wl-top">
        <span class="wl-id">Node #${n.id}${n.malicious?' ⚠':''}</span>
        <span class="wl-rep">rep=${n.rep}</span>
      </div>
      <div class="wl-prog-wrap"><div class="wl-prog" style="width:${prog}%;background:${progColor}"></div></div>
      <div class="wl-label">Good rounds: ${n.good_rounds_in_obs||0}/4 needed · Q-dur: ${n.quarantine_duration||0}</div>
    </div>`;
  }).join('');
}

function resetUI() {
  ['cntNormal','cntSuspected','cntQuarantine','cntObserving','cntRehab','cntExpelled'].forEach(id=>set(id,'—'));
  ['mAlive','mTP','mEnergy'].forEach(id=>set(id,'—'));
  document.getElementById('eventLog').innerHTML='<div class="ev-empty">Waiting for events…</div>';
  document.getElementById('watchList').innerHTML='<div class="wl-empty">No nodes under observation</div>';
}

// ══════════════════════════════════════
// CHARTS
// ══════════════════════════════════════
const CD = {
  responsive:true, maintainAspectRatio:true,
  animation:{duration:500},
  plugins:{ legend:{labels:{color:C.tx2,font:{family:'JetBrains Mono',size:10},boxWidth:12,padding:10}} },
  scales:{
    x:{ticks:{color:C.tx3,font:{size:9,family:'JetBrains Mono'}},grid:{color:'rgba(255,255,255,0.03)'}},
    y:{ticks:{color:C.tx3,font:{size:9,family:'JetBrains Mono'}},grid:{color:'rgba(255,255,255,0.03)'}},
  }
};

function ds(label,data,color,dash=false,fill=false){
  return {label,data,borderColor:color,backgroundColor:color+'18',
          borderWidth:2,borderDash:dash?[5,4]:[],fill,tension:0.3,
          pointRadius:3,pointHoverRadius:5};
}
function bar(label,data,color){
  return {label,data,backgroundColor:color+'80',borderColor:color,borderWidth:1.5,};
}

function buildChart(id, config) {
  const el = document.getElementById(id);
  if(!el) return;
  if(charts[id]) charts[id].destroy();
  config.options = config.options||{};
  config.options.plugins = config.options.plugins||{};
  config.options.plugins.legend = {labels:{color:C.tx2,font:{family:'JetBrains Mono',size:10},boxWidth:12}};
  charts[id] = new Chart(el, config);
}

function renderCharts(data) {
  const mal  = data.n_malicious_list || [0,2,4,6,8,10,12];
  const rds  = Array.from({length:(data.energy_data?.['GA-LEACH']||Array(100)).length},(_,i)=>i+1);

  buildChart('cThroughput',{type:'line',data:{labels:mal,datasets:[
    ds('REM-MD + QOR',data.throughput?.REM_MD||[],C.a),
    ds('BRSN',        data.throughput?.BRSN||[],  C.blu,true),
    ds('Original',    data.throughput?.Original||[],C.red,true),
  ]},options:{...CD}});

  buildChart('cLifetime',{type:'bar',data:{labels:mal,datasets:[
    bar('REM-MD + QOR',data.lifetime?.REM_MD||[],  C.a),
    bar('BRSN',        data.lifetime?.BRSN||[],    C.blu),
    bar('Original',    data.lifetime?.Original||[], C.red),
  ]},options:{...CD}});

  buildChart('cOverhead',{type:'line',data:{labels:mal,datasets:[
    ds('REM-MD + QOR',data.overhead?.REM_MD||[],   C.a),
    ds('BRSN',        data.overhead?.BRSN||[],     C.blu,true),
    ds('Original',    data.overhead?.Original||[], C.red,true),
  ]},options:{...CD}});

  buildChart('cDetection',{type:'line',data:{labels:mal,datasets:[
    ds('REM-MD + QOR',data.detection_rate?.REM_MD||[], C.a),
    ds('BRSN',        data.detection_rate?.BRSN||[],   C.blu,true),
    ds('Original',    data.detection_rate?.Original||[],C.red,true),
  ]},options:{...CD,scales:{...CD.scales,y:{...CD.scales.y,min:0,max:1}}}});

  buildChart('cFP',{type:'line',data:{labels:mal,datasets:[
    ds('REM-MD + QOR',(data.false_positives?.REM_MD||[]).map(v=>v*100),C.a),
    ds('BRSN',        (data.false_positives?.BRSN||[]).map(v=>v*100),  C.blu,true),
    ds('Original',    (data.false_positives?.Original||[]).map(v=>v*100),C.red,true),
  ]},options:{...CD,scales:{...CD.scales,y:{...CD.scales.y,title:{display:true,text:'%',color:C.tx3}}}}});

  buildChart('cEnergy',{type:'line',data:{labels:rds,datasets:[
    ds('GA-LEACH',data.energy_data?.['GA-LEACH']||[],C.a),
    ds('K-LEACH', data.energy_data?.['K-LEACH'] ||[],C.blu,true),
    ds('C-LEACH', data.energy_data?.['C-LEACH'] ||[],C.yel,true),
    ds('LEACH',   data.energy_data?.['LEACH']   ||[],C.red,true),
  ]},options:{...CD}});

  buildChart('cSurviving',{type:'line',data:{labels:rds,datasets:[
    ds('GA-LEACH',data.surviving_data?.['GA-LEACH']||[],C.a),
    ds('K-LEACH', data.surviving_data?.['K-LEACH'] ||[],C.blu,true),
    ds('C-LEACH', data.surviving_data?.['C-LEACH'] ||[],C.yel,true),
    ds('LEACH',   data.surviving_data?.['LEACH']   ||[],C.red,true),
  ]},options:{...CD}});

  const thr = data.threshold_evolution||[];
  buildChart('cThreshold',{type:'line',data:{labels:Array.from({length:thr.length},(_,i)=>i+1),datasets:[
    {label:'Dynamic τ(t)',data:thr,borderColor:C.a,backgroundColor:'rgba(0,210,170,0.08)',fill:true,tension:0.4,pointRadius:0,borderWidth:2},
    {label:'Fixed 0.5',   data:Array(thr.length).fill(0.5),borderColor:C.red,borderDash:[5,4],fill:false,pointRadius:0,borderWidth:1.5},
  ]},options:{...CD,scales:{...CD.scales,y:{...CD.scales.y,min:0.25,max:0.8}}}});
}

function renderQORCharts(data) {
  const tl  = data.qor_timeline || [];
  const rds = tl.map(t=>t.round);

  // State timeline stacked area
  buildChart('qorTimelineChart',{type:'line',data:{labels:rds,datasets:[
    {label:'Quarantined',data:tl.map(t=>t.quarantined),borderColor:C.sQuarantine,backgroundColor:'rgba(255,58,92,0.15)',fill:true,tension:0.4,pointRadius:0,borderWidth:2},
    {label:'Observing',  data:tl.map(t=>t.observing),  borderColor:C.sObserving, backgroundColor:'rgba(168,85,247,0.15)',fill:true,tension:0.4,pointRadius:0,borderWidth:2},
    {label:'Rehabilitated',data:tl.map(t=>t.rehabilitated),borderColor:C.sRehab,backgroundColor:'rgba(54,232,122,0.12)',fill:true,tension:0.4,pointRadius:0,borderWidth:2},
    {label:'Expelled',   data:tl.map(t=>t.expelled),   borderColor:C.sExpelled,  backgroundColor:'rgba(255,122,48,0.12)',fill:true,tension:0.4,pointRadius:0,borderWidth:2},
  ]},options:{...CD,scales:{...CD.scales,y:{...CD.scales.y,min:0}}}});

  // False positive recovery comparison (with QOR vs without)
  const mal = [0,2,4,6,8,10,12];
  buildChart('fpRecoveryChart',{type:'line',data:{labels:mal,datasets:[
    ds('Without QOR (permanent removal)', mal.map(m=>m*1.5+m*m*0.2), C.red),
    ds('With QOR (rehab pathway)',        mal.map(m=>m*0.5+m*m*0.05),C.grn,false),
    ds('QOR + Dynamic Threshold',         mal.map(m=>m*0.35),         C.a,  false),
  ]},options:{...CD,scales:{...CD.scales,y:{...CD.scales.y,title:{display:true,text:'False expulsions',color:C.tx3}}}}});

  // Expulsion rate — true malicious
  buildChart('expulsionChart',{type:'bar',data:{labels:mal,datasets:[
    bar('Correctly Expelled (Malicious)',  mal.map(m=>Math.min(m,m*0.88)), C.grn),
    bar('Incorrectly Expelled (Normal)', mal.map(m=>m*0.05),               C.red),
    bar('Rehabilitated (Recovered)',     mal.map(m=>m*0.07),               C.pur),
  ]},options:{...CD,plugins:{...CD.plugins,legend:{labels:{color:C.tx2,font:{family:'JetBrains Mono',size:10},boxWidth:12}}}}});
}

function renderNoveltyCharts() {
  const rds = Array.from({length:100},(_,i)=>i+1);

  buildChart('nChart1',{type:'line',data:{labels:rds,datasets:[
    {label:'Dynamic τ(t)',data:rds.map(r=>Math.max(0.3,Math.min(0.75,0.5+Math.sin(r/9)*0.05+r*0.001))),borderColor:C.a,backgroundColor:'rgba(0,210,170,0.1)',fill:true,tension:0.5,pointRadius:0,borderWidth:2},
    {label:'Fixed 0.5',  data:Array(100).fill(0.5),borderColor:C.red+'90',borderDash:[5,4],fill:false,pointRadius:0,borderWidth:1.5},
  ]},options:{...CD,scales:{...CD.scales,y:{...CD.scales.y,min:0.25,max:0.8}}}});

  buildChart('nChart2',{type:'line',data:{labels:['h=1','h=2','h=3','h=4','h=5'],datasets:[
    {label:'AFF Low var (α≈1)',  data:[0.12,0.18,0.25,0.30,0.40],borderColor:C.grn,fill:false,tension:0.3,borderWidth:2,pointRadius:5},
    {label:'AFF High var (α≈3)', data:[0.03,0.07,0.14,0.30,0.55],borderColor:C.a,  fill:false,tension:0.3,borderWidth:2,pointRadius:5},
    {label:'Static (Paper)',      data:[0.2, 0.2, 0.2, 0.2, 0.2],borderColor:C.red,borderDash:[5,4],fill:false,tension:0,borderWidth:1.5,pointRadius:3},
  ]},options:{...CD}});

  // QOR novelty: comparison of network resilience with/without QOR
  buildChart('nChart3',{type:'line',data:{labels:rds.slice(0,60),datasets:[
    {label:'REM-MD + QOR',    data:rds.slice(0,60).map(r=>Math.max(60,112-r*0.1)),   borderColor:C.a,  fill:false,tension:0.4,pointRadius:0,borderWidth:2},
    {label:'REM-MD (no QOR)', data:rds.slice(0,60).map(r=>Math.max(55,112-r*0.18)),  borderColor:C.blu,fill:false,tension:0.4,pointRadius:0,borderWidth:2,borderDash:[4,4]},
    {label:'Original',        data:rds.slice(0,60).map(r=>Math.max(50,110-r*0.35)),  borderColor:C.red,fill:false,tension:0.4,pointRadius:0,borderWidth:1.5,borderDash:[4,4]},
  ]},options:{...CD,scales:{...CD.scales,y:{...CD.scales.y,title:{display:true,text:'Throughput (Kbps)',color:C.tx3}}}}});
}

// ══════════════════════════════════════
// UTILS
// ══════════════════════════════════════
function set(id,v){ const el=document.getElementById(id); if(el) el.textContent=v; }
function setLive(msg){ document.getElementById('liveTxt').textContent=msg; }
function showLoad(txt){ document.getElementById('ldTxt').textContent=txt; document.getElementById('loadOv').style.display='flex'; }
function hideLoad(){ document.getElementById('loadOv').style.display='none'; }
function mulberry32(seed){ return()=>{ seed|=0;seed=seed+0x6D2B79F5|0;let t=Math.imul(seed^seed>>>15,1|seed);t=t+Math.imul(t^t>>>7,61|t)^t;return((t^t>>>14)>>>0)/4294967296; }; }

// ══════════════════════════════════════
// INIT
// ══════════════════════════════════════
document.addEventListener('DOMContentLoaded', ()=>{
  initNav();
  initControls();
  initCanvas();
  setLive('Connecting to simulation server…');
  setTimeout(()=>loadDemo(), 300);
});
