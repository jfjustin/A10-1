"""The decision flow from the architecture diagram.

    run stopped?                   -> BLOCK
    matches an always-on rule?     -> BLOCK   (G1–G5, approval can't override)
    operator approved for the run? -> ALLOW
    mode table                     -> ALLOW / BLOCK / ask
    ask: pause, show in console + dashboard
         a / A                     -> ALLOW
         d, or no answer in 60s    -> BLOCK

Every verdict is written to the hash-chained audit log.
"""
from __future__ import annotations

import itertools
import json
import os
import signal
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from . import modes
from .audit import AuditLog
from .config import MODES, Policy
from .redact import redact_text, summarize
from .rules import Analysis, Context, analyze_tool, has_secret, host_matches, internal_host, is_ollama


@dataclass
class Verdict:
    decision: str            # "allow" | "block"
    rule: str                # "G2", "row 6", "stopped", "approved for run", ...
    reason: str
    via: str = "policy"      # policy | operator | timeout | run-approval | host-pass

    @property
    def allowed(self) -> bool:
        return self.decision == modes.ALLOW

    def message(self) -> str:
        word = "Allowed" if self.allowed else "Blocked by Agent Harness"
        return f"{word} [{self.rule}]: {self.reason}"


@dataclass
class Pending:
    id: int
    source: str              # tool | network
    summary: str
    rule: str
    reason: str
    key: str
    hosts: list[str]
    created: float
    deadline: float
    decision: str | None = None
    note: str = ""
    event: threading.Event = field(default_factory=threading.Event, repr=False)

    def public(self) -> dict:
        d = {k: getattr(self, k) for k in ("id", "source", "summary", "rule", "reason", "hosts",
                                           "created", "deadline", "decision", "note")}
        d["seconds_left"] = max(0, round(self.deadline - time.time()))
        return d


class Gateway:
    def __init__(self, policy: Policy, audit: AuditLog | None = None, *, kill=os.killpg):
        self.policy = policy
        self.audit = audit or AuditLog(policy.audit_path)
        self.mode = policy.mode
        self.stopped = False
        self.run: dict = {"id": None, "status": "no run", "pid": None, "cmd": None}
        self.approved: set[str] = set()                 # "A" grants for this run
        self.host_passes: dict[str, float] = {}         # host -> expiry (time.time())
        self.pending: OrderedDict[int, Pending] = OrderedDict()
        self.events: deque[dict] = deque(maxlen=500)
        self.listeners: list = []                       # called with ("pending"|"event", data)
        self.ctx = Context(policy, protected_pids={os.getpid()})
        self._ids = itertools.count(1)
        self._lock = threading.RLock()
        self._kill = kill
        pid_file = policy.state_dir / "proxy.pid"
        if pid_file.exists():
            try:
                self.ctx.protected_pids.add(int(pid_file.read_text().strip()))
            except ValueError:
                pass

    # ── public checks ───────────────────────────────────────────────────────
    def check_tool(self, tool_name: str, tool_input: dict) -> Verdict:
        tool_input = tool_input if isinstance(tool_input, dict) else {}
        analysis = analyze_tool(tool_name, tool_input, self.ctx)
        key = "tool:" + json.dumps({"tool": tool_name, "input": tool_input}, sort_keys=True, default=str)
        summary = self._tool_summary(tool_name, tool_input)
        return self._decide("tool", key, analysis, summary, sorted(analysis.hosts))

    def check_network(self, host: str, port: int | None, method: str, path: str = "",
                      body: str = "") -> Verdict:
        p = self.policy
        host = (host or "").lower()
        a = Analysis(hosts={host})
        why = internal_host(host, port, p)
        if method == "CONNECT":
            # Tunnel setup: only the checks that don't need the decrypted request.
            # Each request inside the tunnel is judged (and logged) on its own.
            if self.stopped:
                return self._record("network", f"CONNECT {host}:{port}",
                                    Verdict(modes.BLOCK, "stopped", "the run was stopped by the operator"), time.time())
            if why:
                return self._record("network", f"CONNECT {host}:{port}",
                                    Verdict(modes.BLOCK, "G4", f"tunnel to {why} ({host})"), time.time())
            return Verdict(modes.ALLOW, "tunnel", "judged per request")
        is_llm = host_matches(host, p.llm_hosts) or is_ollama(host, port, p)
        if why:
            a.hit("G4", f"{method} to {why} ({host})")
        elif not is_llm and (has_secret(body or "", p) or has_secret(path or "", p)):
            a.hit("G3", f"secret pattern in a request to {host}")
        if is_llm:
            a.row(10, f"LLM provider {host}")
        elif host_matches(host, p.allowed_domains):
            a.row(8, f"allowlisted host {host}")
        else:
            a.row(9, f"unknown host {host}")
        summary = redact_text(f"{method} {host}{':' + str(port) if port not in (None, 80, 443) else ''}{path[:120]}",
                              p.secret_patterns)
        # Host passes and per-run approvals for network are by host, not by URL.
        return self._decide("network", "net:" + host, a, summary, [host], network_host=host)

    # ── the flow ────────────────────────────────────────────────────────────
    def _decide(self, source: str, key: str, a: Analysis, summary: str, hosts: list[str],
                network_host: str | None = None) -> Verdict:
        t0 = time.time()
        with self._lock:
            if self.stopped:
                v = Verdict(modes.BLOCK, "stopped", "the run was stopped by the operator")
                return self._record(source, summary, v, t0)
            if a.guard:
                v = Verdict(modes.BLOCK, str(a.guard.rule), a.guard.reason)
                return self._record(source, summary, v, t0)
            if key in self.approved:
                self._grant_passes(hosts)
                v = Verdict(modes.ALLOW, "approved for run", "operator approved this action for the run",
                            via="run-approval")
                return self._record(source, summary, v, t0)
            if network_host and self.host_passes.get(network_host, 0) > time.time():
                v = Verdict(modes.ALLOW, "host pass", "approved at the tool level in the last "
                            f"{int(self.policy.host_pass_seconds)}s", via="host-pass")
                return self._record(source, summary, v, t0)

            rows = [f.rule for f in a.rows] or [14]
            decision, row = modes.strictest(rows, self.mode)
            reason = next((f.reason for f in a.rows if f.rule == row), modes.TABLE[row][0])
            rule = f"row {row}"
            if decision != modes.ASK:
                return self._record(source, summary, Verdict(decision, rule, f"{reason} ({self.mode} mode)"), t0)

            item = Pending(id=next(self._ids), source=source, summary=summary, rule=rule, reason=reason,
                           key=key, hosts=hosts, created=t0,
                           deadline=t0 + self.policy.approval_timeout_seconds)
            self.pending[item.id] = item
        self._notify("pending", item.public())

        answered = item.event.wait(self.policy.approval_timeout_seconds)
        with self._lock:
            self.pending.pop(item.id, None)
            if not answered or item.decision is None:
                v = Verdict(modes.BLOCK, rule, f"no answer in {int(self.policy.approval_timeout_seconds)}s",
                            via="timeout")
            elif item.decision in ("a", "A"):
                if item.decision == "A":
                    self.approved.add(key)
                self._grant_passes(hosts)
                v = Verdict(modes.ALLOW, rule, "approved by operator" +
                            (" for the rest of the run" if item.decision == "A" else " once"), via="operator")
            elif item.decision == "stopped":
                v = Verdict(modes.BLOCK, "stopped", "the run was stopped by the operator", via="operator")
            else:
                v = Verdict(modes.BLOCK, rule, "denied by operator" + (f": {item.note}" if item.note else ""),
                            via="operator")
            return self._record(source, summary, v, t0)

    def _grant_passes(self, hosts: list[str]):
        expiry = time.time() + self.policy.host_pass_seconds
        for h in hosts:
            if h:
                self.host_passes[h] = expiry

    def _record(self, source: str, summary: str, v: Verdict, t0: float) -> Verdict:
        ev = {"ts": time.strftime("%H:%M:%S"), "source": source, "verdict": v.decision.upper(),
              "rule": v.rule, "via": v.via, "summary": summary, "reason": v.reason,
              "mode": self.mode, "ms": int((time.time() - t0) * 1000)}
        self.audit.append("verdict", run=self.run.get("id"), **{k: ev[k] for k in ev if k != "ts"})
        self.events.appendleft(ev)
        self._notify("event", ev)
        return v

    # ── operator actions ────────────────────────────────────────────────────
    def answer(self, pending_id: int | None, decision: str, note: str = "", actor: str = "console") -> bool:
        """decision: a (once), A (rest of run), d (deny)."""
        if decision not in ("a", "A", "d"):
            raise ValueError("decision must be a, A or d")
        with self._lock:
            if pending_id is None:              # console answers the oldest first
                pending_id = next(iter(self.pending), None)
            item = self.pending.get(pending_id) if pending_id is not None else None
            if item is None or item.decision is not None:
                return False
            item.decision, item.note = decision, redact_text(note)[:300]
            self.audit.append("approval", run=self.run.get("id"), actor=actor, pending=item.id,
                              decision=decision, note=item.note, summary=item.summary)
        item.event.set()
        return True

    def set_mode(self, mode: str, actor: str = "console") -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        with self._lock:
            old, self.mode = self.mode, mode
            self.audit.append("mode", run=self.run.get("id"), actor=actor, old=old, new=mode)
        self._notify("mode", {"mode": mode})

    def start_run(self, cmd: str, actor: str = "run_agent") -> str:
        with self._lock:
            for item in self.pending.values():
                item.decision = "stopped"
                item.event.set()
            self.stopped = False
            self.approved.clear()
            self.host_passes.clear()
            self.run = {"id": uuid.uuid4().hex[:8], "status": "starting", "pid": None,
                        "cmd": redact_text(cmd)[:300], "started": time.strftime("%H:%M:%S")}
            self.audit.append("run_start", run=self.run["id"], actor=actor, cmd=self.run["cmd"],
                              mode=self.mode, workspace=str(self.policy.workspace))
        self._notify("run", self.run)
        return self.run["id"]

    def set_pid(self, pid: int) -> None:
        with self._lock:
            self.run.update(pid=pid, status="running")
            self.audit.append("run_pid", run=self.run.get("id"), pid=pid)
        self._notify("run", self.run)

    def end_run(self, rc: int | None) -> None:
        with self._lock:
            if self.run.get("status") != "stopped":
                self.run["status"] = "finished"
            self.run["rc"] = rc
            self.audit.append("run_end", run=self.run.get("id"), rc=rc, status=self.run["status"])
        self._notify("run", self.run)

    def stop(self, actor: str = "console") -> str:
        """Kill switch: block everything from now on and kill the agent's process group."""
        with self._lock:
            self.stopped = True
            self.run["status"] = "stopped"
            for item in self.pending.values():
                item.decision = "stopped"
                item.event.set()
            pid = self.run.get("pid")
            note = "no agent process recorded"
            if pid:
                try:
                    self._kill(os.getpgid(pid), signal.SIGTERM)
                    note = f"sent SIGTERM to process group {pid}"
                    threading.Thread(target=self._force_kill, args=(pid,), daemon=True).start()
                except (ProcessLookupError, PermissionError, OSError) as exc:
                    note = f"could not signal {pid}: {exc}"
            self.audit.append("stop", run=self.run.get("id"), actor=actor, note=note)
        self._notify("run", self.run)
        return note

    def _force_kill(self, pid: int):
        time.sleep(3)
        try:
            self._kill(os.getpgid(pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    # ── helpers ─────────────────────────────────────────────────────────────
    def snapshot(self) -> dict:
        with self._lock:
            return {"mode": self.mode, "stopped": self.stopped, "run": dict(self.run),
                    "pending": [p.public() for p in self.pending.values()],
                    "events": list(self.events)[:200],
                    "approved_for_run": len(self.approved),
                    "workspace": str(self.policy.workspace)}

    def _tool_summary(self, name: str, tool_input: dict) -> str:
        brief = summarize(tool_input, self.policy.secret_patterns)
        if name == "bash":
            return f"bash: {brief.get('command', '')}"
        main = next((brief[k] for k in ("path", "file_path", "url", "query", "root", "pattern",
                                        "prompt", "action") if k in brief), None)
        return f"{name}: {main}" if main is not None else f"{name} {json.dumps(brief)[:200]}"

    def _notify(self, kind: str, data) -> None:
        for fn in list(self.listeners):
            try:
                fn(kind, data)
            except Exception:
                pass
