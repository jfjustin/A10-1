"""Dashboard page served by the gateway at  http://127.0.0.1:8765/?token=<operator token>"""

PAGE = r"""<!doctype html><meta charset=utf-8><title>Agent Harness</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--bg:#111;--panel:#1b1b1b;--line:#2c2c2c;--fg:#eee;--dim:#999;--ok:#2ecc71;--bad:#ff5c5c;--ask:#f5b041}
*{box-sizing:border-box}body{font:14px system-ui,sans-serif;margin:0;padding:20px 24px;background:var(--bg);color:var(--fg)}
h1{margin:0;font-size:20px}h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);margin:22px 0 8px}
#top{display:flex;flex-wrap:wrap;gap:14px;align-items:center;justify-content:space-between}
.modes button{background:var(--panel);color:var(--fg);border:1px solid var(--line);padding:7px 14px;cursor:pointer}
.modes button:first-child{border-radius:6px 0 0 6px}.modes button:last-child{border-radius:0 6px 6px 0}
.modes button.on{background:#2d5b9a;border-color:#2d5b9a}
#stop{background:#c0392b;color:#fff;border:0;padding:9px 20px;font-size:15px;border-radius:6px;cursor:pointer;font-weight:600}
#sess{color:var(--dim)}#sess b{color:var(--fg)}
.card{background:var(--panel);border:1px solid var(--ask);border-radius:8px;padding:12px 14px;margin-bottom:10px}
.card .s{font-family:ui-monospace,monospace;word-break:break-all;margin:4px 0 8px}
.card button{border:0;border-radius:5px;padding:6px 12px;margin-right:6px;cursor:pointer;font-weight:600}
.a{background:var(--ok);color:#062}.A{background:#1e8449;color:#fff}.d{background:var(--bad);color:#300}
.card input{background:#111;border:1px solid var(--line);color:var(--fg);padding:5px 8px;border-radius:5px;width:240px}
.empty{color:var(--dim)}
table{border-collapse:collapse;width:100%}td,th{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--dim);font-weight:500}td.m{font-family:ui-monospace,monospace;word-break:break-all}
.ALLOW{color:var(--ok)}.BLOCK{color:var(--bad);font-weight:700}tr.b{background:#2a1515}
#audit{color:var(--dim)}#audit.bad{color:var(--bad);font-weight:700}
</style>
<div id=top>
  <h1>Agent Harness</h1>
  <div class=modes id=modes></div>
  <div id=sess>…</div>
  <button id=stop onclick="post('/api/stop',{})">STOP RUN</button>
</div>
<h2>Waiting for approval</h2><div id=pending></div>
<h2>Verdicts</h2>
<table><thead><tr><th>Time<th>Source<th>Verdict<th>Rule<th>Action<th>Reason</tr></thead><tbody id=rows></tbody></table>
<p id=audit></p>
<script>
const TOKEN=new URLSearchParams(location.search).get('token')||'';
const H={'Content-Type':'application/json','X-Operator-Token':TOKEN};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function post(u,b){await fetch(u,{method:'POST',headers:H,body:JSON.stringify(b)});tick()}
function decide(id,d){const r=document.getElementById('r'+id);post('/api/decide',{id,decision:d,reason:r?r.value:''})}
let typing=false;
async function tick(){
  const r=await fetch('/api/state',{headers:H});
  if(r.status==401){document.body.innerHTML='<p>Open the dashboard with the link the gateway printed (it includes ?token=…).</p>';return}
  const s=await r.json();
  document.getElementById('modes').innerHTML=['plan','default','auto'].map(m=>`<button class="${m==s.mode?'on':''}" onclick="post('/api/mode',{mode:'${m}'})">${m}</button>`).join('');
  const run=s.run||{};
  document.getElementById('sess').innerHTML=`Run <b>${esc(run.id||'—')}</b> · ${esc(run.status)}${run.cmd?' · '+esc(run.cmd):''}${s.stopped?' · <b style="color:var(--bad)">STOPPED</b>':''}`;
  if(!typing){
    document.getElementById('pending').innerHTML=s.pending.length?s.pending.map(p=>`<div class=card>
      <div>${esc(p.source)} · <b>${esc(p.rule)}</b> · ${esc(p.reason)} · <span class=empty>${p.seconds_left}s left</span></div>
      <div class=s>${esc(p.summary)}</div>
      <button class=a onclick="decide(${p.id},'a')">Approve once (a)</button>
      <button class=A onclick="decide(${p.id},'A')">Approve for run (A)</button>
      <input id=r${p.id} placeholder="reason (sent to the model)" onfocus="typing=true" onblur="typing=false">
      <button class=d onclick="decide(${p.id},'d')">Deny (d)</button></div>`).join(''):'<p class=empty>Nothing waiting.</p>';
  }
  document.getElementById('rows').innerHTML=s.events.map(e=>`<tr class="${e.verdict=='BLOCK'?'b':''}"><td>${esc(e.ts)}<td>${esc(e.source)}<td class=${esc(e.verdict)}>${esc(e.verdict)}<td>${esc(e.rule)}<td class=m>${esc(e.summary)}<td>${esc(e.reason)}</tr>`).join('');
  const a=s.audit||{};const el=document.getElementById('audit');
  el.textContent='Audit log: '+(a.message||'');el.className=a.ok===false?'bad':'';
}
setInterval(tick,1000);tick();
</script>"""
