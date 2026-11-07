"""Live dashboard + Stop button.   python dashboard.py  ->  http://localhost:5000"""
import os, json, signal
from flask import Flask, jsonify, Response
HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "state")
app = Flask(__name__)

def read(path, default):
    try:
        with open(path) as f: return f.read()
    except FileNotFoundError: return default

@app.get("/api/events")
def events():
    lines = read(os.path.join(STATE, "events.jsonl"), "").strip().splitlines()[-60:]
    return jsonify([json.loads(l) for l in reversed(lines)])

@app.get("/api/session")
def session():
    return jsonify(json.loads(read(os.path.join(STATE, "session.json"), '{"status":"no session"}')))

@app.post("/api/stop")
def stop():
    open(os.path.join(STATE, "STOP"), "w").close()          # 1) block all further traffic
    try:
        s = json.loads(read(os.path.join(STATE, "session.json"), "{}"))
        os.killpg(os.getpgid(s["pid"]), signal.SIGTERM)       # 2) kill the agent's process group
    except Exception as e:
        return jsonify({"stopped": True, "note": str(e)})
    return jsonify({"stopped": True})

PAGE = """<!doctype html><meta charset=utf-8><title>Agent Harness</title>
<style>body{font:14px system-ui;margin:24px;background:#111;color:#eee}
h1{margin:0 0 12px}#bar{display:flex;gap:16px;align-items:center;margin-bottom:16px}
button{background:#c0392b;color:#fff;border:0;padding:10px 20px;font-size:15px;border-radius:6px;cursor:pointer}
table{border-collapse:collapse;width:100%}td,th{padding:6px 10px;border-bottom:1px solid #333;text-align:left}
.ALLOWED{color:#2ecc71}.BLOCKED{color:#ff5c5c;font-weight:700}tr.b{background:#2a1515}</style>
<h1>Agent Harness</h1>
<div id=bar><div id=sess>...</div><button onclick="fetch('/api/stop',{method:'POST'})">STOP SESSION</button></div>
<table><thead><tr><th>Time<th>Verdict<th>Method<th>Host<th>Detail</tr></thead><tbody id=rows></tbody></table>
<script>
async function tick(){
 const s=await (await fetch('/api/session')).json();
 document.getElementById('sess').textContent='Session: '+s.status+(s.cmd?'  |  '+s.cmd:'');
 const ev=await (await fetch('/api/events')).json();
 document.getElementById('rows').innerHTML=ev.map(e=>`<tr class="${e.verdict=='BLOCKED'?'b':''}"><td>${e.ts}<td class=${e.verdict}>${e.verdict}<td>${e.method}<td>${e.host}<td>${e.detail}</tr>`).join('');
}
setInterval(tick,1000);tick();
</script>"""
@app.get("/")
def index(): return Response(PAGE, mimetype="text/html")

if __name__ == "__main__":
    app.run(port=5050)
