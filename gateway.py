"""Gateway + dashboard for the A10 Agent Harness (Prompt 2).

Stdlib only -- no pip install, works offline at the venue.
Every tool call routes through POST /tool-call, is judged by policy.py,
and is appended to a hash-chained audit log (same pattern as the
triage-bench audit trail: edit a historical line and verify() fails).
The network proxy (proxy.py) asks this gateway about every outbound
request, so egress is judged by the same policy.

Normally started by harness.py (one command). Manual run: python3 gateway.py
Then: open http://127.0.0.1:8000/ and, in another terminal, python3 agent.py

Endpoints:
  GET  /          dashboard (live traffic + pending approvals + Stop button)
  POST /tool-call {tool, args, agent} -> {verdict, reason}
         allow -> 200, block -> 403, pending -> 202 {pending_id}
  GET  /pending   open approval requests [{id, tool, args, reason}]
  GET  /verdict/<id>  {status: pending|approved|denied}
  POST /approve   {id, decision: approve|deny}
  GET  /events    JSON list of all judged calls this run
  GET  /audit     {ok, count} -- hash-chain verification
  GET  /status    {stopped, allow, block, pending_open}
  POST /stop      operator stops the run; further calls get 503 {verdict: stopped}
  POST /reset     clear events + pending + audit log (for a clean re-demo)
  GET  /api/status   stub API the demo agent looks up (via the proxy)
  POST /api/notes    stub API the demo agent uploads to (via the proxy)
"""
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from policy import evaluate

ROOT = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG = os.path.join(ROOT, "audit.log.jsonl")

_events = []
_pending = {}
_pending_seq = 0
_stopped = False
_lock = threading.Lock()


def _chain_hash(prev, payload_json):
    return hashlib.sha256((prev + payload_json).encode()).hexdigest()


def log_event(event_type, payload):
    with _lock:
        prev, seq = "GENESIS", 0
        if os.path.exists(AUDIT_LOG):
            with open(AUDIT_LOG) as f:
                lines = [ln for ln in f if ln.strip()]
            if lines:
                last = json.loads(lines[-1])
                prev, seq = last["hash"], last["seq"] + 1
        entry = {"seq": seq,
                 "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "type": event_type, "payload": payload, "prev": prev}
        entry["hash"] = _chain_hash(prev, json.dumps(entry, sort_keys=True))
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry


def verify_audit():
    if not os.path.exists(AUDIT_LOG):
        return True, 0
    prev, count = "GENESIS", 0
    with open(AUDIT_LOG) as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            check = dict(e)
            h = check.pop("hash")
            if e.get("prev") != prev or h != _chain_hash(
                    prev, json.dumps(check, sort_keys=True)):
                return False, count
            prev, count = h, count + 1
    return True, count


DASHBOARD = """<!doctype html><html><head><meta charset="utf-8">
<title>Agent Harness — live traffic</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2em auto;padding:0 1em}
.allow{color:green}.block{color:#c00;font-weight:bold}.pending{color:#c60;font-weight:bold}
table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #ddd;padding:6px;text-align:left}
button{font-size:16px;padding:8px 18px;background:#c00;color:#fff;border:0;border-radius:6px;cursor:pointer}
button.ok{background:#080}button.small{font-size:13px;padding:4px 10px}
#badge{font-weight:bold}</style></head><body>
<h1>🛡️ Agent Harness — live agent traffic</h1>
<p>Every tool call from the CLI agent routes through this gateway and is
judged before it runs; all network egress goes through the proxy, judged by
the same policy. <span id="badge">audit: checking…</span></p>
<p><button onclick="stopRun()">■ STOP RUN</button>
<button onclick="resetRun()" style="background:#555">Reset demo</button></p>
<p>Allowed: <b id="nAllow">0</b> &nbsp; Blocked: <b id="nBlock">0</b> &nbsp; Pending: <b id="nPend">0</b></p>
<div id="pendingBox"></div>
<table><thead><tr><th>Time</th><th>Tool</th><th>Args</th><th>Verdict</th><th>Reason</th></tr></thead>
<tbody id="rows"></tbody></table>
<script>
async function refresh(){
  const r = await fetch('/events'); const ev = await r.json();
  let a=0,b=0,p=0,html='';
  for (const e of ev){
    if(e.verdict==='allow')a++; if(e.verdict==='block')b++; if(e.verdict==='pending')p++;
    html += `<tr><td>${e.ts.slice(11,19)}</td><td>${e.tool}</td><td><code>${JSON.stringify(e.args)}</code></td><td class="${e.verdict}">${e.verdict.toUpperCase()}</td><td>${e.reason}</td></tr>`;
  }
  document.getElementById('rows').innerHTML = html;
  document.getElementById('nAllow').textContent = a;
  document.getElementById('nBlock').textContent = b;
  document.getElementById('nPend').textContent = p;
  const pd = await (await fetch('/pending')).json();
  let ph = '';
  if (pd.length){
    ph = '<h2>⏸ Waiting for operator approval</h2>';
    for (const q of pd){
      ph += `<p><code>${q.tool} ${JSON.stringify(q.args)}</code><br>${q.reason}<br>
      <button class="ok small" onclick="decide('${q.id}','approve')">Approve</button>
      <button class="small" onclick="decide('${q.id}','deny')">Deny</button></p>`;
    }
  }
  document.getElementById('pendingBox').innerHTML = ph;
  const au = await (await fetch('/audit')).json();
  document.getElementById('badge').textContent =
    au.ok ? `audit chain ✓ verified (${au.count} events)` : 'audit chain ✗ TAMPERED';
}
async function decide(id, decision){
  await fetch('/approve',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id, decision})});
  refresh();
}
async function stopRun(){ await fetch('/stop',{method:'POST'}); refresh(); }
async function resetRun(){ await fetch('/reset',{method:'POST'}); refresh(); }
setInterval(refresh, 800); refresh();
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _read_json(self):
        return json.loads(self._read_body() or b"{}")

    def do_GET(self):
        if self.path == "/":
            body = DASHBOARD.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/events":
            with _lock:
                self._json(list(_events))
        elif self.path == "/audit":
            ok, count = verify_audit()
            self._json({"ok": ok, "count": count})
        elif self.path == "/pending":
            with _lock:
                self._json([q for q in _pending.values()
                            if q["status"] == "pending"])
        elif self.path.startswith("/verdict/"):
            pid = self.path.split("/")[2]
            with _lock:
                q = _pending.get(pid)
            if q is None:
                self._json({"error": "unknown pending id"}, 404)
            else:
                self._json({"status": q["status"]})
        elif self.path == "/status":
            with _lock:
                a = sum(1 for e in _events if e["verdict"] == "allow")
                b = sum(1 for e in _events if e["verdict"] == "block")
                p = sum(1 for q in _pending.values()
                        if q["status"] == "pending")
                self._json({"stopped": _stopped, "allow": a,
                            "block": b, "pending_open": p})
        elif self.path == "/api/status":
            self._json({"project": "a10-harness", "status": "ok",
                        "notes_reviewed": True})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        global _stopped, _pending_seq
        if self.path == "/tool-call":
            data = self._read_json()
            tool, args = data.get("tool"), data.get("args") or {}
            with _lock:
                stopped = _stopped
            if stopped:
                verdict, reason = "stopped", "operator stopped the run"
                status = 503
                event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "tool": tool, "args": args, "verdict": verdict,
                         "reason": reason, "agent": data.get("agent", "?")}
                with _lock:
                    _events.append(event)
                log_event("tool_call", event)
                self._json({"verdict": verdict, "reason": reason}, status)
                return
            verdict, reason = evaluate(tool, args)
            if verdict == "pending":
                with _lock:
                    _pending_seq += 1
                    pid = f"p{_pending_seq}"
                    q = {"id": pid, "tool": tool, "args": args,
                         "reason": reason, "status": "pending",
                         "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                             time.gmtime())}
                    _pending[pid] = q
                event = {"ts": q["ts"], "tool": tool, "args": args,
                         "verdict": "pending", "reason": reason,
                         "agent": data.get("agent", "?"), "pending_id": pid}
                with _lock:
                    _events.append(event)
                log_event("tool_call", event)
                self._json({"verdict": "pending", "pending_id": pid,
                            "reason": reason}, 202)
                return
            status = 200 if verdict == "allow" else 403
            event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "tool": tool, "args": args, "verdict": verdict,
                     "reason": reason, "agent": data.get("agent", "?")}
            with _lock:
                _events.append(event)
            log_event("tool_call", event)
            self._json({"verdict": verdict, "reason": reason}, status)
        elif self.path == "/approve":
            data = self._read_json()
            pid, decision = data.get("id"), data.get("decision")
            with _lock:
                q = _pending.get(pid)
                if q is None or q["status"] != "pending":
                    self._json({"error": "unknown or decided pending id"}, 404)
                    return
                q["status"] = "approved" if decision == "approve" else "denied"
            log_event("approval", {"id": pid, "decision": q["status"],
                                   "tool": q["tool"], "args": q["args"]})
            self._json({"ok": True, "decision": q["status"]})
        elif self.path == "/stop":
            with _lock:
                _stopped = True
                for q in _pending.values():
                    if q["status"] == "pending":
                        q["status"] = "denied"
            log_event("operator_stop", {"by": "dashboard"})
            self._json({"stopped": True})
        elif self.path == "/reset":
            with _lock:
                _events.clear()
                _pending.clear()
                _stopped = False
            if os.path.exists(AUDIT_LOG):
                os.remove(AUDIT_LOG)
            self._json({"reset": True})
        elif self.path == "/api/notes":
            body = self._read_body()
            self._json({"ok": True, "received_bytes": len(body)})
        else:
            self._json({"error": "not found"}, 404)

    def log_message(self, *a):
        pass  # keep the terminal clean for the demo


if __name__ == "__main__":
    print("Gateway on http://127.0.0.1:8000/  (Ctrl-C to stop)")
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
