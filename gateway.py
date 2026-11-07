"""Agent Harness gateway: the single approver for tool calls and network traffic.

    python gateway.py [--mode default] [--workspace ./sandbox]

Serves, on 127.0.0.1:8765 by default:
  POST /hook            OpenHarness pre_tool_use HTTP hook (200 = allow, 403 = block)
  POST /check/network   verdicts for mitmproxy (addon.py)          [operator token]
  GET  /                dashboard                                  [?token=…]
  /api/state /api/decide /api/mode /api/stop /api/run/*            [operator token]

and runs the operator console on this terminal:
  a approve once · A approve for the rest of the run · d deny (with a reason)
  s stop the run · m change mode · v verify the audit log · h help
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import select
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from harness.audit import verify
from harness.config import MODES, load_policy
from harness.dashboard import PAGE
from harness.engine import Gateway

MAX_BODY = 2 * 1024 * 1024


class _AuditCache:
    def __init__(self, path):
        self.path, self.at, self.value = path, 0.0, {}

    def get(self):
        if time.time() - self.at > 5:
            ok, n, msg = verify(self.path)
            self.value, self.at = {"ok": ok, "entries": n, "message": msg}, time.time()
        return self.value


def make_handler(gw: Gateway, token: str):
    audit_cache = _AuditCache(gw.policy.audit_path)

    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentHarness/1.0"

        def log_message(self, *args):  # keep the console for the operator
            pass

        # ── helpers ──
        def _send(self, code: int, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else (
                json.dumps(body).encode() if ctype == "application/json" else str(body).encode())
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _json(self) -> dict:
            n = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
            raw = self.rfile.read(n) if n else b"{}"
            try:
                data = json.loads(raw or b"{}")
                return data if isinstance(data, dict) else {}
            except json.JSONDecodeError:
                return {}

        def _authed(self) -> bool:
            q = parse_qs(urlsplit(self.path).query)
            given = self.headers.get("X-Operator-Token") or (q.get("token") or [""])[0]
            return secrets.compare_digest(given, token)

        # ── routes ──
        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/health":
                return self._send(200, {"ok": True, "mode": gw.mode})
            if not self._authed():
                return self._send(401, {"error": "operator token required"})
            if path == "/":
                return self._send(200, PAGE.encode(), "text/html")
            if path == "/api/state":
                snap = gw.snapshot()
                snap["audit"] = audit_cache.get()
                return self._send(200, snap)
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            path = urlsplit(self.path).path
            if path == "/hook":
                return self._hook()
            if not self._authed():
                return self._send(401, {"error": "operator token required"})
            body = self._json()
            if path == "/check/network":
                v = gw.check_network(str(body.get("host", "")), body.get("port"),
                                     str(body.get("method", "GET")), str(body.get("path", "")),
                                     str(body.get("body", "")))
                return self._send(200, {"allow": v.allowed, "rule": v.rule, "message": v.message()})
            if path == "/api/decide":
                ok = gw.answer(body.get("id"), str(body.get("decision")), str(body.get("reason", "")),
                               actor="dashboard")
                return self._send(200 if ok else 409, {"ok": ok})
            if path == "/api/mode":
                try:
                    gw.set_mode(str(body.get("mode")), actor="dashboard")
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
                return self._send(200, {"mode": gw.mode})
            if path == "/api/stop":
                return self._send(200, {"stopped": True, "note": gw.stop(actor="dashboard")})
            if path == "/api/run/start":
                return self._send(200, {"run": gw.start_run(str(body.get("cmd", "")))})
            if path == "/api/run/pid":
                gw.set_pid(int(body["pid"]))
                return self._send(200, {"ok": True, "stopped": gw.stopped})
            if path == "/api/run/end":
                gw.end_run(body.get("rc"))
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})

        def _hook(self):
            body = self._json()
            event = body.get("event")
            payload = body.get("payload") or {}
            if event != "pre_tool_use":
                return self._send(200, "ok", "text/plain")
            v = gw.check_tool(str(payload.get("tool_name", "")), payload.get("tool_input") or {})
            # OpenHarness only treats a hook as blocking when the status is not 2xx,
            # and passes the response text back to the model as the tool result.
            return self._send(200 if v.allowed else 403, v.message(), "text/plain")

    return Handler


# ── operator console ────────────────────────────────────────────────────────
class Console:
    COLORS = {"ALLOW": "\033[32m", "BLOCK": "\033[31;1m", "ask": "\033[33;1m"}
    RESET = "\033[0m"

    def __init__(self, gw: Gateway, url: str):
        self.gw, self.url = gw, url
        self.out = threading.Lock()
        self.tty = sys.stdin.isatty()
        gw.listeners.append(self.on_event)

    def say(self, text: str):
        with self.out:
            sys.stdout.write("\r" + text + "\n")
            sys.stdout.flush()

    def on_event(self, kind, data):
        if kind == "event":
            c = self.COLORS.get(data["verdict"], "")
            self.say(f"{data['ts']}  {c}{data['verdict']:<5}{self.RESET}  {data['rule']:<16} "
                     f"{data['source']:<7} {data['summary'][:90]}  — {data['reason'][:80]}")
        elif kind == "pending":
            c = self.COLORS["ask"]
            self.say(f"{c}?? #{data['id']} {data['source']} {data['rule']}{self.RESET}  {data['summary'][:120]}\n"
                     f"   {data['reason']}  →  [a] once  [A] rest of run  [d] deny   "
                     f"({data['seconds_left']}s, then denied)")
        elif kind == "mode":
            self.say(f"== mode is now {data['mode']}")
        elif kind == "run":
            self.say(f"== run {data.get('id')} {data.get('status')} {data.get('cmd') or ''}")

    def help(self):
        self.say(f"Dashboard: {self.url}\n"
                 f"Mode: {self.gw.mode}.  Keys: a approve once · A approve for run · d deny · "
                 f"s stop · m mode · v verify audit · h help · Ctrl-C quit")

    def readline(self, prompt: str) -> str:
        with self.out:
            sys.stdout.write(prompt)
            sys.stdout.flush()
        if self.tty:
            import termios
            fd = sys.stdin.fileno()
            attrs = termios.tcgetattr(fd)
            attrs[3] |= termios.ICANON | termios.ECHO
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            try:
                return sys.stdin.readline().strip()
            finally:
                attrs[3] &= ~(termios.ICANON | termios.ECHO)
                termios.tcsetattr(fd, termios.TCSANOW, attrs)
        return sys.stdin.readline().strip()

    def handle(self, key: str):
        gw = self.gw
        if key in ("a", "A"):
            if not gw.answer(None, key, actor="console"):
                self.say("nothing is waiting for approval")
        elif key == "d":
            if not gw.pending:
                return self.say("nothing is waiting for approval")
            reason = self.readline("reason for the model (enter to skip): ")
            gw.answer(None, "d", reason, actor="console")
        elif key == "s":
            self.say("STOP: " + gw.stop(actor="console"))
        elif key == "m":
            mode = self.readline(f"mode {list(MODES)} (now {gw.mode}): ")
            if mode:
                try:
                    gw.set_mode(mode, actor="console")
                except ValueError as exc:
                    self.say(str(exc))
        elif key == "v":
            ok, _, msg = verify(gw.policy.audit_path)
            self.say(("audit OK: " if ok else "AUDIT TAMPERED: ") + msg)
        elif key in ("h", "?"):
            self.help()

    def loop(self):
        self.help()
        if not self.tty:
            self.say("(stdin is not a terminal: use the dashboard to approve)")
            while True:
                time.sleep(3600)
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                r, _, _ = select.select([sys.stdin], [], [], 0.5)
                if r:
                    key = sys.stdin.read(1)
                    if key:
                        self.handle(key)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", default=None, help="path to policy.json")
    ap.add_argument("--mode", choices=MODES, default=None)
    ap.add_argument("--workspace", default=None)
    ap.add_argument("--port", type=int, default=None)
    args = ap.parse_args(argv)

    policy = load_policy(args.policy, mode=args.mode, workspace=args.workspace, gateway_port=args.port)
    policy.state_dir.mkdir(parents=True, exist_ok=True)
    policy.workspace.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(24)
    fd = os.open(policy.token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)

    gw = Gateway(policy)
    gw.audit.append("gateway_start", mode=gw.mode, workspace=str(policy.workspace), pid=os.getpid())
    server = ThreadingHTTPServer((policy.gateway_host, policy.gateway_port), make_handler(gw, token))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()

    url = f"{policy.gateway_url}/?token={token}"
    print(f"[gateway] listening on {policy.gateway_url}  mode={gw.mode}  workspace={policy.workspace}")
    try:
        Console(gw, url).loop()
    except KeyboardInterrupt:
        pass
    finally:
        gw.audit.append("gateway_stop")
        print("\n[gateway] bye")


if __name__ == "__main__":
    main()
