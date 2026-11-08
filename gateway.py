"""Gateway + dashboard for the A10 Agent Harness (Prompt 2).

Stdlib only, works offline. Every tool call (OpenHarness `pre_tool_use` HTTP
hook, or the scripted demo agent speaking the same format) and every proxied
network request is judged by the mode-table policy (policy.py), shown live on
the terminal console and the dashboard, and appended to a hash-chained audit
log (audit.py). "Ask" verdicts hold the request open until the operator
answers in the console or dashboard, up to --approval-wait seconds, then fail
closed.

Normally started by harness.py. Manual run:
  python3 gateway.py [--port 8000] [--mode default] [--demo-stubs]
Then open the printed dashboard URL (it carries the operator token in the
#fragment) and run `python3 harness.py watch` for the terminal console.

Endpoints (bound to 127.0.0.1; requests with a foreign Host header are refused):
  GET  /                 dashboard (read-only without the #token fragment)
  GET  /events?since=N   judged events with seq > N
  GET  /pending          open approval requests
  GET  /status           run id, mode, stopped, taint, overrides, counts, hosts
  GET  /audit            {ok, count, first_bad} hash-chain verification
  GET  /modes            the row table as JSON
  POST /hooks/oh         oh hook {"event": "pre_tool_use"|"post_tool_use",
                         "payload": {...}}; pre: 200 allow, 403 text otherwise
                         (header X-A10-Verdict: allow|block|deny|expired|stopped)
  POST /tool-call        {tool, args, agent}: 200 allow, 403 block/deny/expired,
                         503 stopped
  POST /net/judge        proxy judgement: 200 {"verdict": "allow"} or 403
  Operator only (header X-A10-Operator-Token, else 401):
  POST /approve          {id, decision: approve|approve_run|deny, reason?}
  POST /stop             stop the run, deny everything still pending
  POST /mode             {mode: plan|default|auto}
  POST /override         {row, confirm: "YES"}: that ⛔ row becomes ❓
  POST /reset            new run id, clear state, wipe the audit log
"""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import netcheck
import policy
from audit import AuditLog

HARNESS_ROOT = policy.HARNESS_ROOT
DEFAULT_AUDIT_LOG = os.path.join(HARNESS_ROOT, "audit.log.jsonl")
TOKEN_HEADER = "X-A10-Operator-Token"
VERDICT_HEADER = "X-A10-Verdict"
MAX_BODY = 8 * 1024 * 1024
MAX_EVENTS = 5000
TRUNCATE_AT = 500
JUDGED_KINDS = ("tool", "net", "decision")
COUNT_KEYS = ("allow", "ask", "approved", "block", "deny", "expired", "stopped")


def a10_home(environ=None):
    env = os.environ if environ is None else environ
    return os.path.realpath(os.path.expanduser(
        env.get("A10_HOME") or "~/.a10-harness"))


def read_token(a10_home_dir):
    try:
        with open(os.path.join(a10_home_dir, "operator.token")) as f:
            return f.read().strip() or None
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Redaction for events / audit
# ---------------------------------------------------------------------------


def _scrub_text(s):
    return netcheck.redact_header_text(netcheck.redact_text(s))


def _truncate(s):
    if len(s) <= TRUNCATE_AT:
        return s
    return {"truncated": True, "len": len(s),
            "sha256": hashlib.sha256(s.encode("utf-8", "replace")).hexdigest(),
            "head": s[:120]}


def sanitize(obj, depth=0):
    """Redact secrets and sensitive header values, truncate long strings."""
    if depth > 8:
        return "[nested too deep]"
    if isinstance(obj, str):
        return _truncate(_scrub_text(obj))
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            k = str(k)
            if k.lower() == "headers" and isinstance(v, dict):
                v = netcheck.redact_headers(v)
            elif netcheck.is_sensitive_header(k) and v is not None:
                v = netcheck.redact_headers({k: v})[k]
            out[k] = sanitize(v, depth + 1)
        return out
    if isinstance(obj, (list, tuple, set)):
        return [sanitize(v, depth + 1) for v in list(obj)[:200]]
    return _truncate(_scrub_text(str(obj)))


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _new_run_id():
    return time.strftime("run-%Y%m%d-%H%M%S-", time.gmtime()) + secrets.token_hex(3)


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------


class Result:
    """Outcome of one judgement: verdict allow|block|deny|expired|stopped."""

    def __init__(self, verdict, reason, row="", rows=None, pending_id=None,
                 decision=None, deny_reason=""):
        self.verdict = verdict
        self.reason = reason
        self.row = row
        self.rows = rows or []
        self.pending_id = pending_id
        self.decision = decision
        self.deny_reason = deny_reason

    def text(self, approval_wait):
        if self.verdict == "block":
            return "BLOCKED by A10 harness: %s" % self.reason
        if self.verdict == "deny":
            return "DENIED by the operator: %s (%s)" % (
                self.deny_reason or "no reason given", self.reason)
        if self.verdict == "expired":
            return ("EXPIRED: no operator decision within %d s, so the A10 "
                    "harness failed closed (%s)" % (approval_wait, self.reason))
        if self.verdict == "stopped":
            return "STOPPED by A10 harness: %s" % (
                self.reason or "operator stopped the run")
        return "ALLOWED by A10 harness: %s" % self.reason

    def as_json(self):
        out = {"verdict": self.verdict, "reason": self.reason, "row": self.row,
               "rows": self.rows}
        if self.pending_id:
            out["pending_id"] = self.pending_id
        if self.decision:
            out["decision"] = self.decision
        if self.deny_reason:
            out["deny_reason"] = self.deny_reason
        return out


def _rows_json(decision):
    return [{"row": r, "title": t, "verdict": v} for (r, t, v) in decision.rows]


class GatewayApp:
    def __init__(self, settings, audit_path=DEFAULT_AUDIT_LOG, token=None,
                 mode="default", approval_wait=590.0, demo_stubs=False,
                 allow_host_headers=(), pids_file=None):
        if mode not in policy.MODES:
            raise ValueError("unknown mode: %r" % mode)
        self.settings = settings
        self.initial_mode = mode
        self.audit_path = audit_path
        self.audit = AuditLog(audit_path)
        self.token = token
        self.approval_wait = float(approval_wait)
        self.demo_stubs = bool(demo_stubs)
        self.allow_host_headers = {h.lower() for h in allow_host_headers}
        self.port = None
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        self.events = []
        self.event_seq = 0
        self.pending = {}
        self._decisions = {}
        self.pending_seq = 0
        self.counts = dict.fromkeys(COUNT_KEYS, 0)
        self.closed = False
        if pids_file is None and settings.a10_home:
            pids_file = os.path.join(settings.a10_home, "run", "pids.json")
        self.pids_file = pids_file
        self._pids_mtime = None
        self.state = policy.RunState(run_id=_new_run_id(), mode=mode)
        with self.lock:
            self.audit.append("run_start", self._run_info())

    # -- helpers (caller holds self.lock) ---------------------------------

    def _run_info(self):
        s = self.settings
        return {"run_id": self.state.run_id, "mode": self.state.mode,
                "workspace": s.workspace, "cwd": s.cwd,
                "allowed_hosts": sorted(s.allowed_hosts),
                "provider_hosts": sorted(s.provider_hosts),
                "taint_tracking": s.taint_tracking, "clean_url": s.clean_url,
                "approval_wait": self.approval_wait}

    def _emit(self, kind, audit_type, verdict, reason="", source="gateway",
              tool="", args=None, rows=None, row="", **extra):
        self.event_seq += 1
        ev = {"seq": self.event_seq, "ts": _now_iso(), "t": time.time(),
              "run_id": self.state.run_id, "kind": kind, "source": source,
              "tool": tool, "args": args if args is not None else {},
              "rows": rows or [], "row": row, "verdict": verdict,
              "reason": reason}
        ev.update(extra)
        self.events.append(ev)
        if len(self.events) > MAX_EVENTS:
            del self.events[:len(self.events) - MAX_EVENTS]
        if kind in JUDGED_KINDS and verdict in self.counts:
            self.counts[verdict] += 1
        self.audit.append(audit_type, ev)
        return ev

    def _refresh_pids(self):
        pids = {os.getpid()}
        path = self.pids_file
        if path:
            try:
                mtime = os.stat(path).st_mtime
            except OSError:
                mtime = None
            if mtime is not None and mtime != self._pids_mtime:
                self._pids_mtime = mtime
                try:
                    with open(path) as f:
                        data = json.load(f)
                    self._file_pids = {int(v) for v in data.values()
                                       if str(v).isdigit()}
                except (OSError, ValueError, AttributeError):
                    self._file_pids = set()
            pids |= getattr(self, "_file_pids", set())
        self.settings.protected_pids = pids

    def _taint(self, decision, tool):
        if not decision.taint_sources:
            return
        reason = "allowed %s via %s" % (", ".join(decision.taint_sources), tool)
        if reason in self.state.taint_reasons:
            return
        policy.mark_taint(self.state, reason)
        self._emit("taint", "taint", "taint", reason=reason, tool=tool)

    # -- judgement -------------------------------------------------------

    def judge(self, action, kind, source, tool, args):
        s_args = sanitize(args)
        with self.cond:
            self._refresh_pids()
            decision = policy.decide(action, self.settings, self.state)
            rows = _rows_json(decision)
            common = {"source": source, "tool": tool, "args": s_args,
                      "rows": rows, "row": decision.row}
            audit_type = "net" if kind == "net" else "tool_call"
            if self.state.stopped or self.closed:
                reason = "operator stopped the run"
                self._emit(kind, audit_type, "stopped", reason=reason, **common)
                return Result("stopped", reason, decision.row, rows)
            if decision.verdict == "block":
                self._emit(kind, audit_type, "block", reason=decision.reason,
                           **common)
                return Result("block", decision.reason, decision.row, rows)
            if decision.verdict == "allow":
                if decision.approval_key in self.state.approved_keys:
                    # approve-for-run key: refresh the 30 s network passes
                    policy.record_approval(self.state, decision, for_run=False)
                self._emit(kind, audit_type, "allow", reason=decision.reason,
                           **common)
                self._taint(decision, tool)
                return Result("allow", decision.reason, decision.row, rows)

            # ask: hold the request until the operator decides
            self.pending_seq += 1
            pid = "p%d" % self.pending_seq
            now = time.time()
            item = {"id": pid, "kind": kind, "source": source, "tool": tool,
                    "args": s_args, "rows": rows, "row": decision.row,
                    "reason": decision.reason, "created": now,
                    "expires": now + self.approval_wait, "status": "pending",
                    "decision": None, "deny_reason": ""}
            self.pending[pid] = item
            self._decisions[pid] = (decision, tool)
            self._emit(kind, audit_type, "ask", reason=decision.reason,
                       pending_id=pid, **common)
            self.cond.notify_all()
            while item["status"] == "pending":
                remaining = item["expires"] - time.time()
                if remaining <= 0:
                    item["status"] = "expired"
                    self._emit("decision", "expired", "expired",
                               reason="no operator decision within %d s"
                               % self.approval_wait, pending_id=pid,
                               decision="expired", **common)
                    break
                self.cond.wait(min(remaining, 0.5))
            self._decisions.pop(pid, None)
            status = item["status"]
            if status == "approved":
                return Result("allow", decision.reason, decision.row, rows,
                              pid, item["decision"])
            if status == "denied":
                return Result("deny", decision.reason, decision.row, rows, pid,
                              "deny", item["deny_reason"])
            if status == "expired":
                return Result("expired", decision.reason, decision.row, rows,
                              pid, "expired")
            return Result("stopped", item.get("deny_reason")
                          or "operator stopped the run", decision.row, rows,
                          pid, "stopped")

    def post_tool(self, source, tool, output):
        if not isinstance(output, str):
            output = json.dumps(output, default=str)
        with self.lock:
            hits = netcheck.find_secrets(output)
            if hits:
                reason = "secret in %s output: %s" % (tool or "tool",
                                                      ", ".join(hits))
                policy.mark_taint(self.state, reason)
                self._emit("taint", "taint", "taint", reason=reason,
                           source=source, tool=tool)
            return hits

    # -- operator actions --------------------------------------------------

    def _oldest_pending(self):
        open_items = [q for q in self.pending.values()
                      if q["status"] == "pending"]
        return min(open_items, key=lambda q: q["created"]) if open_items else None

    def approve(self, pid, decision, reason=""):
        """-> (http_status, json)."""
        if decision not in ("approve", "approve_run", "deny"):
            return 400, {"error": "decision must be approve, approve_run or deny"}
        with self.cond:
            item = self.pending.get(pid) if pid else self._oldest_pending()
            if item is None or item["status"] != "pending":
                return 404, {"error": "unknown or already decided pending id"}
            pid = item["id"]
            dec, tool = self._decisions.get(pid, (None, item["tool"]))
            common = {"source": "operator", "tool": item["tool"],
                      "args": item["args"], "rows": item["rows"],
                      "row": item["row"], "pending_id": pid}
            reason = sanitize(str(reason or ""))
            if isinstance(reason, dict):
                reason = reason["head"]
            if decision in ("approve", "approve_run"):
                item["status"] = "approved"
                item["decision"] = decision
                if dec is not None:
                    policy.record_approval(self.state, dec,
                                           for_run=(decision == "approve_run"))
                label = ("approved for the rest of the run"
                         if decision == "approve_run" else "approved once")
                self._emit("decision", "approval", "approved",
                           reason="operator %s" % label, decision=decision,
                           **common)
                if dec is not None:
                    self._taint(dec, tool)
            else:
                item["status"] = "denied"
                item["decision"] = "deny"
                item["deny_reason"] = reason
                self._emit("decision", "approval", "deny",
                           reason="operator denied: %s" % (reason or "no reason given"),
                           decision="deny", deny_reason=reason, **common)
            self.cond.notify_all()
            return 200, {"ok": True, "id": pid, "decision": decision}

    def _release_pending(self, reason):
        for item in self.pending.values():
            if item["status"] == "pending":
                item["status"] = "stopped"
                item["deny_reason"] = reason
                self._emit("decision", "approval", "stopped", reason=reason,
                           source="operator", tool=item["tool"],
                           args=item["args"], rows=item["rows"],
                           row=item["row"], pending_id=item["id"],
                           decision="stopped")

    def stop(self):
        with self.cond:
            already = self.state.stopped
            self.state.stopped = True
            self._release_pending("operator stopped the run")
            if not already:
                self._emit("stop", "operator_stop", "stopped",
                           reason="operator stopped the run", source="operator")
            self.cond.notify_all()
            return {"stopped": True, "run_id": self.state.run_id}

    def change_mode(self, mode):
        with self.lock:
            old = self.state.mode
            try:
                policy.set_mode(self.state, mode)
            except ValueError as e:
                return 400, {"error": str(e)}
            self._emit("mode", "mode_change", "mode",
                       reason="mode %s -> %s" % (old, mode), source="operator",
                       args={"from": old, "to": mode})
            return 200, {"ok": True, "mode": mode, "previous": old}

    def override(self, row, confirm):
        row = str(row or "")
        if confirm != "YES":
            return 403, {"error": "override needs confirm exactly 'YES'"}
        with self.lock:
            if not policy.apply_override(self.state, row, confirm):
                return 400, {"error": "row %r cannot be overridden (unknown or "
                             "never ⛔)" % row}
            title = policy.ROWS[row].title
            self._emit("override", "override", "override",
                       reason="row %s (%s) overridden: ⛔ becomes ❓ for the rest "
                       "of the run" % (row, title), source="operator",
                       args={"row": row, "title": title}, row=row)
            return 200, {"ok": True, "row": row,
                         "overrides": sorted(self.state.overrides)}

    def reset(self):
        with self.cond:
            self._release_pending("operator reset the run")
            self.cond.notify_all()
            old = self.state.run_id
            self.events.clear()
            self.pending.clear()
            self._decisions.clear()
            self.counts = dict.fromkeys(COUNT_KEYS, 0)
            self.state = policy.RunState(run_id=_new_run_id(),
                                         mode=self.initial_mode)
            self.audit.wipe()
            self.audit.append("run_start", dict(self._run_info(),
                                                reset_from=old))
            self._emit("reset", "reset", "reset",
                       reason="run reset (previous run %s)" % old,
                       source="operator")
            return {"reset": True, "run_id": self.state.run_id}

    def close(self):
        with self.cond:
            self.closed = True
            self._release_pending("gateway shutting down")
            self.cond.notify_all()

    # -- read-only views ---------------------------------------------------

    def events_since(self, since):
        with self.lock:
            return [e for e in self.events if e["seq"] > since]

    def pending_list(self):
        with self.lock:
            out = []
            for q in self.pending.values():
                if q["status"] == "pending":
                    item = {k: q[k] for k in ("id", "kind", "source", "tool",
                                              "args", "rows", "row", "reason",
                                              "created", "expires")}
                    item["wait_s"] = max(0, int(q["expires"] - time.time()))
                    out.append(item)
            return sorted(out, key=lambda q: q["created"])

    def status(self):
        with self.lock:
            s = self.settings
            st = self.state
            return {"run_id": st.run_id, "mode": st.mode,
                    "stopped": st.stopped, "tainted": st.tainted,
                    "taint_reasons": list(st.taint_reasons),
                    "overrides": sorted(st.overrides),
                    "counts": dict(self.counts),
                    "pending_open": sum(1 for q in self.pending.values()
                                        if q["status"] == "pending"),
                    "provider_hosts": sorted(s.provider_hosts),
                    "allowed_hosts": sorted(s.allowed_hosts),
                    "workspace": s.workspace, "approval_wait": self.approval_wait,
                    "demo_stubs": self.demo_stubs,
                    "last_seq": self.event_seq}

    def audit_status(self):
        ok, count, bad = self.audit.verify()
        return {"ok": ok, "count": count, "first_bad": bad}

    @staticmethod
    def modes():
        rows = [{"id": r.id, "title": r.title, "plan": r.plan,
                 "default": r.default, "auto": r.auto, "why": r.why}
                for r in policy.ROWS.values()]
        return {"modes": list(policy.MODES), "rows": rows}


# ---------------------------------------------------------------------------
# Dashboard (all agent-controlled strings go through textContent)
# ---------------------------------------------------------------------------

DASHBOARD = """<!doctype html><html><head><meta charset="utf-8">
<title>A10 Agent Harness: live traffic</title>
<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:1.5em auto;padding:0 1em;color:#222}
.allow,.approved{color:#080}.block,.deny,.expired,.stopped{color:#c00;font-weight:bold}
.ask{color:#c60;font-weight:bold}.taint,.mode,.override,.reset{color:#555;font-style:italic}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{border-bottom:1px solid #ddd;padding:5px;text-align:left;vertical-align:top}
td.args{font-family:ui-monospace,monospace;word-break:break-all;max-width:420px}
button{font-size:15px;padding:7px 16px;background:#c00;color:#fff;border:0;border-radius:6px;cursor:pointer}
button.ok{background:#080}button.run{background:#056}button.small{font-size:13px;padding:4px 10px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;background:#eee;margin-right:6px}
.badge.bad{background:#fdd;color:#900}.badge.good{background:#dfd;color:#060}
#pendingBox .item{border:2px solid #c60;border-radius:8px;padding:8px;margin:8px 0;background:#fff8ee}
#pendingBox code{word-break:break-all}.muted{color:#777}</style></head><body>
<h1>🛡️ A10 Agent Harness: live agent traffic</h1>
<p>Every tool call and every proxied request is judged by the mode table before it runs.</p>
<p><span class="badge" id="mode">mode: ?</span><span class="badge" id="taint">taint: ?</span>
<span class="badge" id="audit">audit: checking...</span><span class="badge" id="run">run: ?</span>
<span class="badge" id="stopped"></span></p>
<p id="counters"></p>
<p>Overrides: <span id="overrides">none</span></p>
<p id="controls"></p>
<div id="pendingBox"></div>
<table><thead><tr><th>Time</th><th>Source</th><th>Tool</th><th>Args</th><th>Rows</th>
<th>Verdict</th><th>Reason</th></tr></thead><tbody id="rows"></tbody></table>
<script>
const TOKEN_KEY = 'a10-operator-token';
(function(){
  const m = location.hash.match(/token=([^&]+)/);
  if (m) {
    sessionStorage.setItem(TOKEN_KEY, decodeURIComponent(m[1]));
    history.replaceState(null, '', location.pathname);
  }
})();
const token = sessionStorage.getItem(TOKEN_KEY);
let lastSeq = 0, runId = null, pendingKey = '';

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function argsText(e) {
  const a = e.args || {};
  if (typeof a.command === 'string') return a.command;
  if (typeof a.url === 'string') return (a.method ? a.method + ' ' : '') + a.url;
  if (typeof a.path === 'string') return a.path;
  return JSON.stringify(a);
}
function rowsText(rows) {
  return (rows || []).map(r => r.row + ':' + r.verdict).join(' ');
}
async function getJSON(p) {
  const r = await fetch(p, {cache: 'no-store'});
  return r.json();
}
async function post(p, body) {
  return fetch(p, {method: 'POST', headers: {'Content-Type': 'application/json',
    'X-A10-Operator-Token': token || ''}, body: JSON.stringify(body || {})});
}
function addRow(e) {
  const tr = el('tr');
  tr.appendChild(el('td', '', (e.ts || '').slice(11, 19)));
  tr.appendChild(el('td', '', e.kind === 'net' ? 'NET ' + e.source : e.source));
  tr.appendChild(el('td', '', e.tool));
  tr.appendChild(el('td', 'args', argsText(e)));
  tr.appendChild(el('td', '', rowsText(e.rows)));
  const v = String(e.verdict || '');
  tr.appendChild(el('td', v, v.toUpperCase() + (e.pending_id ? ' ' + e.pending_id : '')));
  tr.appendChild(el('td', '', e.reason));
  document.getElementById('rows').appendChild(tr);
}
function renderControls() {
  const c = document.getElementById('controls');
  c.textContent = '';
  if (!token) {
    c.appendChild(el('span', 'muted', 'Read-only view. Open the URL printed by the harness (it ends in #token=...) to approve, deny or stop.'));
    return;
  }
  const b = el('button', '', '■ STOP RUN');
  b.addEventListener('click', async () => { await post('/stop', {}); refresh(); });
  c.appendChild(b);
  c.appendChild(el('span', 'muted', '  Mode changes and overrides are console-only.'));
}
function renderPending(pd) {
  const key = pd.map(q => q.id).join(',');
  if (key === pendingKey) return;
  pendingKey = key;
  const box = document.getElementById('pendingBox');
  box.textContent = '';
  if (!pd.length) return;
  box.appendChild(el('h2', '', '⏸ Waiting for operator approval'));
  for (const q of pd) {
    const d = el('div', 'item');
    d.appendChild(el('b', '', q.id + ' '));
    d.appendChild(el('code', '', q.tool + ' ' + argsText(q)));
    d.appendChild(el('div', '', q.reason));
    d.appendChild(el('div', 'muted', 'rows: ' + rowsText(q.rows)));
    if (token) {
      const once = el('button', 'ok small', 'Approve once');
      once.addEventListener('click', () => decide(q.id, 'approve'));
      const run = el('button', 'run small', 'Approve for run');
      run.addEventListener('click', () => decide(q.id, 'approve_run'));
      const why = el('input');
      why.placeholder = 'deny reason (optional)';
      const deny = el('button', 'small', 'Deny');
      deny.addEventListener('click', () => decide(q.id, 'deny', why.value));
      for (const x of [once, run, why, deny]) { d.appendChild(x); d.appendChild(document.createTextNode(' ')); }
    }
    box.appendChild(d);
  }
}
async function decide(id, decision, reason) {
  await post('/approve', {id: id, decision: decision, reason: reason || ''});
  pendingKey = '';
  refresh();
}
async function refresh() {
  try {
    const st = await getJSON('/status');
    if (st.run_id !== runId) {
      runId = st.run_id; lastSeq = 0; pendingKey = '';
      document.getElementById('rows').textContent = '';
    }
    const ev = await getJSON('/events?since=' + lastSeq);
    for (const e of ev) { addRow(e); lastSeq = Math.max(lastSeq, e.seq); }
    const c = st.counts || {};
    document.getElementById('counters').textContent =
      'Allowed: ' + (c.allow || 0) + '   Asked: ' + (c.ask || 0) + '   Approved: ' + (c.approved || 0) +
      '   Blocked: ' + (c.block || 0) + '   Denied: ' + (c.deny || 0) + '   Expired: ' + (c.expired || 0);
    document.getElementById('mode').textContent = 'mode: ' + st.mode;
    const t = document.getElementById('taint');
    t.textContent = st.tainted ? 'TAINTED: ' + (st.taint_reasons || []).join('; ') : 'not tainted';
    t.className = 'badge ' + (st.tainted ? 'bad' : 'good');
    document.getElementById('run').textContent = 'run: ' + st.run_id;
    const s = document.getElementById('stopped');
    s.textContent = st.stopped ? 'RUN STOPPED' : 'running';
    s.className = 'badge ' + (st.stopped ? 'bad' : 'good');
    document.getElementById('overrides').textContent =
      (st.overrides || []).length ? st.overrides.map(r => 'row ' + r).join(', ') : 'none';
    renderPending(await getJSON('/pending'));
    const au = await getJSON('/audit');
    const a = document.getElementById('audit');
    a.textContent = au.ok ? 'audit chain ✓ verified (' + au.count + ' entries)' : 'audit chain ✗ TAMPERED at seq ' + au.first_bad;
    a.className = 'badge ' + (au.ok ? 'good' : 'bad');
  } catch (err) {
    document.getElementById('stopped').textContent = 'gateway unreachable';
  }
}
renderControls();
setInterval(refresh, 800); refresh();
</script></body></html>"""


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "A10Gateway/2"

    @property
    def app(self):
        return self.server.app

    # -- response helpers --------------------------------------------------

    def _send(self, status, body, ctype, verdict=None, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if verdict:
            self.send_header(VERDICT_HEADER, verdict)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status=200, verdict=None):
        self._send(status, json.dumps(obj, default=str).encode(),
                   "application/json", verdict)

    def _text(self, text, status, verdict=None):
        self._send(status, text.encode("utf-8"), "text/plain; charset=utf-8",
                   verdict)

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None, "bad Content-Length"
        if n > MAX_BODY:
            return None, "request body too large"
        raw = self.rfile.read(n) if n > 0 else b""
        if not raw:
            return {}, None
        try:
            data = json.loads(raw)
        except ValueError:
            return None, "body is not valid JSON"
        if not isinstance(data, dict):
            return None, "body must be a JSON object"
        return data, None

    # -- guards ----------------------------------------------------------

    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip().lower()
        port = self.app.port
        allowed = {"127.0.0.1:%s" % port, "localhost:%s" % port}
        for h in self.app.allow_host_headers:
            allowed.add(h)
            allowed.add("%s:%s" % (h, port))
        return host in allowed

    def _operator_ok(self):
        given = self.headers.get(TOKEN_HEADER) or ""
        token = self.app.token
        if not token or not given:
            return False
        return hmac.compare_digest(given.encode("utf-8"), token.encode("utf-8"))

    # -- routing -----------------------------------------------------------

    def do_GET(self):
        if not self._host_ok():
            self._json({"error": "Host header not allowed"}, 403)
            return
        parts = urlsplit(self.path)
        path = parts.path
        app = self.app
        if path == "/":
            self._send(200, DASHBOARD.encode("utf-8"), "text/html; charset=utf-8",
                       extra={"X-Frame-Options": "DENY",
                              "Referrer-Policy": "no-referrer",
                              "Content-Security-Policy":
                                  "default-src 'none'; script-src 'unsafe-inline'; "
                                  "style-src 'unsafe-inline'; connect-src 'self'"})
        elif path == "/events":
            q = parse_qs(parts.query)
            try:
                since = int((q.get("since") or ["0"])[0])
            except ValueError:
                since = 0
            self._json(app.events_since(since))
        elif path == "/pending":
            self._json(app.pending_list())
        elif path == "/status":
            self._json(app.status())
        elif path == "/audit":
            self._json(app.audit_status())
        elif path == "/modes":
            self._json(app.modes())
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._host_ok():
            self._json({"error": "Host header not allowed"}, 403)
            return
        path = urlsplit(self.path).path
        data, err = self._read_json()
        if err:
            self._json({"error": err}, 400)
            return
        if path == "/hooks/oh":
            self._hook(data)
        elif path == "/tool-call":
            self._tool_call(data)
        elif path == "/net/judge":
            self._net_judge(data)
        elif path in ("/approve", "/stop", "/mode", "/override", "/reset"):
            if not self._operator_ok():
                self._json({"error": "operator token required "
                            "(header %s)" % TOKEN_HEADER}, 401)
                return
            self._operator(path, data)
        else:
            self._json({"error": "not found"}, 404)

    # -- endpoints -------------------------------------------------------

    def _hook(self, data):
        app = self.app
        payload = data.get("payload")
        if not isinstance(payload, dict):
            payload = {}
        event = data.get("event") or payload.get("event") or ""
        source = (self.headers.get("X-A10-Agent") or "oh")[:64]
        tool = str(payload.get("tool_name") or "")
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = {} if tool_input is None else {"value": tool_input}
        if event == "post_tool_use":
            app.post_tool(source, tool, payload.get("tool_output") or "")
            self._json({"ok": True})
            return
        if event != "pre_tool_use":
            self._json({"ok": True, "ignored": str(event)[:64]})
            return
        action = policy.Action(source="tool", tool=tool, input=tool_input)
        res = app.judge(action, "tool", source, tool, tool_input)
        if res.verdict == "allow":
            body = {"ok": True}
            if res.decision:
                body["decision"] = res.decision
            self._json(body, 200, verdict="allow")
        else:
            self._text(res.text(app.approval_wait), 403, verdict=res.verdict)

    def _tool_call(self, data):
        app = self.app
        tool = str(data.get("tool") or "")
        args = data.get("args")
        if not isinstance(args, dict):
            args = {}
        source = str(data.get("agent") or "tool-call")[:64]
        action = policy.Action(source="tool", tool=tool, input=args)
        res = app.judge(action, "tool", source, tool, args)
        status = {"allow": 200, "stopped": 503}.get(res.verdict, 403)
        self._json(res.as_json(), status, verdict=res.verdict)

    def _net_judge(self, data):
        app = self.app
        source = data.get("source")
        if source not in ("proxy-mitm", "proxy-stdlib"):
            source = "proxy-stdlib"
        url = str(data.get("url") or "")
        host = netcheck.normalize_host(str(data.get("host") or ""))
        port = data.get("port")
        try:
            port = int(port) if port not in (None, "") else None
        except (TypeError, ValueError):
            port = None
        if not host and url:
            host, p2 = netcheck.split_host_port(urlsplit(url).netloc)
            port = port or p2
        method = str(data.get("method") or "GET").upper()
        try:
            body_len = int(data.get("body_len") or 0)
        except (TypeError, ValueError):
            body_len = 1
        hits = [str(h) for h in (data.get("secret_hits") or [])]
        for h in netcheck.find_secrets(url):
            if h not in hits:
                hits.append(h)
        inp = {"host": host, "port": port, "method": method, "url": url or None,
               "body_len": body_len, "secret_hits": hits}
        shown = {"method": method, "url": url, "host": host, "port": port,
                 "headers": data.get("headers") if isinstance(
                     data.get("headers"), dict) else {},
                 "body_len": body_len, "secret_hits": hits,
                 "body_sample": str(data.get("body_sample") or "")[:200]}
        action = policy.Action(source=source, tool="net", input=inp)
        res = app.judge(action, "net", source, "net", shown)
        if res.verdict == "allow":
            self._json({"verdict": "allow", "row": res.row,
                        "reason": res.reason}, 200, verdict="allow")
        else:
            body = res.as_json()
            body["reason"] = res.text(app.approval_wait)
            self._json(body, 403, verdict=res.verdict)

    def _operator(self, path, data):
        app = self.app
        if path == "/approve":
            status, body = app.approve(data.get("id"), data.get("decision"),
                                       data.get("reason") or "")
            self._json(body, status)
        elif path == "/stop":
            self._json(app.stop())
        elif path == "/mode":
            status, body = app.change_mode(str(data.get("mode") or ""))
            self._json(body, status)
        elif path == "/override":
            status, body = app.override(data.get("row"), data.get("confirm"))
            self._json(body, status)
        elif path == "/reset":
            self._json(app.reset())

    def log_message(self, *a):
        pass  # keep the terminal clean for the demo


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(app, host="127.0.0.1", port=8000):
    server = GatewayServer((host, port), Handler)
    server.app = app
    app.port = server.server_address[1]
    return server


def build_settings(workspace, cwd, a10_home_dir, audit_log, allowed_hosts=None,
                   provider_hosts=None, taint=True, clean_url=True):
    return policy.Settings(
        workspace=os.path.realpath(os.path.expanduser(workspace)),
        cwd=os.path.realpath(os.path.expanduser(cwd)),
        harness_root=HARNESS_ROOT,
        a10_home=a10_home_dir,
        audit_log=os.path.realpath(os.path.expanduser(audit_log)),
        allowed_hosts=({netcheck.normalize_host(h) for h in allowed_hosts}
                       if allowed_hosts else {"api.example.com"}),
        provider_hosts={h.strip().lower() for h in (provider_hosts or [])},
        taint_tracking=taint,
        clean_url=clean_url,
    )


def main(argv=None):
    p = argparse.ArgumentParser(description="A10 harness gateway + dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--mode", default="default", choices=policy.MODES)
    p.add_argument("--workspace", default=os.path.join(HARNESS_ROOT, "demo-files"))
    p.add_argument("--cwd", default=HARNESS_ROOT)
    p.add_argument("--allowed-host", action="append", default=[])
    p.add_argument("--provider-host", action="append", default=[])
    p.add_argument("--approval-wait", type=float, default=590.0)
    p.add_argument("--audit-log", default=DEFAULT_AUDIT_LOG)
    p.add_argument("--no-taint", action="store_true")
    p.add_argument("--no-clean-url", action="store_true")
    p.add_argument("--demo-stubs", action="store_true",
                   help="report that the proxies serve the api.example.com stubs")
    p.add_argument("--allow-host-header", action="append", default=[])
    args = p.parse_args(argv)

    home = a10_home()
    from harness import ensure_operator_token  # lazy: avoids an import cycle
    token = ensure_operator_token(home)
    settings = build_settings(args.workspace, args.cwd, home, args.audit_log,
                              args.allowed_host, args.provider_host,
                              not args.no_taint, not args.no_clean_url)
    app = GatewayApp(settings, settings.audit_log, token, mode=args.mode,
                     approval_wait=args.approval_wait,
                     demo_stubs=args.demo_stubs or netcheck.demo_stubs_from_env(os.environ),
                     allow_host_headers=args.allow_host_header)
    server = make_server(app, args.host, args.port)
    print("Gateway on http://127.0.0.1:%d/  mode=%s  workspace=%s"
          % (app.port, args.mode, settings.workspace), flush=True)
    print("Dashboard (operator): http://127.0.0.1:%d/#token=%s" % (app.port, token),
          flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        app.close()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
