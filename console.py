"""Terminal operator console for the A10 Agent Harness (Prompt 2).

Shows the agent's traffic live and answers approvals from the keyboard. Line
based (type a command and press Enter), so it works in any terminal and with
piped stdin.

  a [id]            approve once (oldest pending item when no id)
  A [id]            approve this exact action for the rest of the run
  d [id] [reason]   deny; the reason is sent back to the model (prompts if empty)
  s                 stop the run (the harness kills the agent)
  m [mode]          change mode: plan, default or auto (prompts if empty)
  override <row>    (alias: o <row>) then type exactly YES: that ⛔ row becomes ❓
  ? / status        run status
  h / help          this help
  q                 quit the console

Pending approvals ring the terminal bell and send a macOS notification
(disable with --no-notify or A10_NO_NOTIFY=1). The operator token is read from
A10_HOME/operator.token (default ~/.a10-harness) and never shown to the agent.

Run:  python3 harness.py watch      (or: python3 console.py [--gateway URL])
Stdlib only.
"""
import argparse
import json
import os
import re
import select
import subprocess
import sys
import threading
import time

import netcheck
import policy

TOKEN_HEADER = "X-A10-Operator-Token"
DEFAULT_GATEWAY = os.environ.get("A10_GATEWAY_URL") or "http://127.0.0.1:8000"

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]"          # CSI
                      r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC
                      r"|\x1b[@-Z\\-_]")                    # other ESC
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_PID_RE = re.compile(r"^p\d+$")

GLYPH = {"allow": "✅", "approved": "✅", "ask": "❓", "block": "⛔",
         "deny": "🚫", "expired": "⌛", "stopped": "■", "taint": "⚠",
         "mode": "⚙", "override": "⚠", "reset": "↺", "info": "ℹ"}
LABEL = {"allow": "ALLOW", "approved": "APPROVED", "ask": "ASK",
         "block": "BLOCK", "deny": "DENIED", "expired": "EXPIRED",
         "stopped": "STOPPED", "taint": "TAINTED", "mode": "MODE",
         "override": "OVERRIDE", "reset": "RESET", "info": "INFO"}
COLOR = {"allow": "32", "approved": "32", "ask": "33;1", "block": "31;1",
         "deny": "31;1", "expired": "31", "stopped": "31;1", "taint": "35",
         "mode": "36", "override": "35;1", "reset": "36", "info": "36"}

HELP = """Commands (press Enter after each):
  a [id]           approve once          A [id]   approve for the rest of the run
  d [id] [reason]  deny (reason goes back to the model)
  s                stop the run          m [mode] change mode (plan/default/auto)
  override <row>   then type YES: turn that ⛔ row into ❓ for this run (alias o)
  ? / status       run status            h / help this help      q  quit console"""

NOTIFY_SCRIPT = ["-e", "on run argv",
                 "-e", 'display notification (item 1 of argv) with title "A10 Harness"',
                 "-e", "end run"]


def clean(text, limit=220):
    """Strip ANSI escapes and control characters from agent-controlled text."""
    s = "" if text is None else str(text)
    s = _ANSI_RE.sub("", s)
    s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\t", " ")
    s = s.replace("\n", " ⏎ ")
    s = _CTRL_RE.sub("", s)
    if len(s) > limit:
        s = s[:limit] + "..."
    return s


def _str_arg(v):
    if isinstance(v, dict) and v.get("truncated"):
        return "%s... (%s chars)" % (v.get("head", ""), v.get("len"))
    return v if isinstance(v, str) else None


def args_summary(item):
    a = item.get("args")
    if not isinstance(a, dict):
        return "" if a is None else str(a)
    cmd = _str_arg(a.get("command"))
    if cmd is not None:
        return cmd
    url = _str_arg(a.get("url"))
    if url:
        return ("%s %s" % (a.get("method") or "", url)).strip()
    path = _str_arg(a.get("path"))
    if path is not None:
        return path
    return json.dumps(a, sort_keys=True, default=str)


def rows_summary(rows):
    return " ".join("%s:%s" % (r.get("row"), r.get("verdict")) for r in rows or [])


def a10_home(environ=None):
    env = os.environ if environ is None else environ
    return os.path.realpath(os.path.expanduser(
        env.get("A10_HOME") or "~/.a10-harness"))


def read_token(home):
    try:
        with open(os.path.join(home, "operator.token")) as f:
            return f.read().strip() or None
    except OSError:
        return None


class Console:
    def __init__(self, gateway_url, token, out=sys.stdout, notify=True,
                 color="auto", runner=subprocess.run, poll_interval=0.5,
                 exit_on_stop=False):
        self.gateway_url = gateway_url.rstrip("/")
        self.token = token
        self.out = out
        self.notify_enabled = bool(notify)
        if color == "auto":
            isatty = getattr(out, "isatty", lambda: False)
            color = bool(isatty()) and not os.environ.get("NO_COLOR")
        self.color = bool(color)
        self.runner = runner
        self.poll_interval = poll_interval
        self.exit_on_stop = exit_on_stop
        self.platform = sys.platform
        self.quit = False
        self.last_seq = 0
        self.seen_pending = set()
        self.last_status = None
        self._awaiting = None
        self._print_lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._thread = None
        self._down = False

    # -- gateway I/O -------------------------------------------------------

    def _get(self, path):
        return netcheck.ask_gateway(self.gateway_url, path, None, timeout=5)

    def _post(self, path, payload):
        return netcheck.ask_gateway(self.gateway_url, path, payload, timeout=10,
                                    headers={TOKEN_HEADER: self.token or ""})

    # -- output ------------------------------------------------------------

    def _paint(self, text, verdict):
        code = COLOR.get(verdict)
        if not self.color or not code:
            return text
        return "\x1b[%sm%s\x1b[0m" % (code, text)

    def write(self, text):
        with self._print_lock:
            self.out.write(text + "\n")
            try:
                self.out.flush()
            except Exception:  # noqa: BLE001
                pass

    def bell(self):
        with self._print_lock:
            self.out.write("\a")
            try:
                self.out.flush()
            except Exception:  # noqa: BLE001
                pass

    def format_event(self, ev):
        t = ev.get("t")
        ts = time.strftime("%H:%M:%S", time.localtime(t if isinstance(
            t, (int, float)) else time.time()))
        v = str(ev.get("verdict") or "")
        kind = ev.get("kind")
        glyph = GLYPH.get(v, "•")
        label = LABEL.get(v, v.upper())
        row = clean(ev.get("row") or "", 8)
        rowtxt = " [row %s]" % row if row else ""
        reason = clean(ev.get("reason"), 200)
        pid = clean(ev.get("pending_id") or "", 12)
        if kind in ("tool", "net"):
            who = "NET" if kind == "net" else clean(ev.get("tool"), 40) + ":"
            line = "%s %s %s%s %s %s" % (ts, glyph, label, rowtxt, who,
                                         clean(args_summary(ev), 160))
            if v == "ask":
                line += "   (%s waiting for you: a / A / d)" % pid
            elif v in ("block", "stopped"):
                line += "   <- %s" % reason
        elif kind == "decision":
            line = "%s %s %s %s %s: %s   (%s)" % (
                ts, glyph, label, pid, clean(ev.get("tool"), 40),
                clean(args_summary(ev), 120), reason)
        else:
            line = "%s %s %s %s" % (ts, glyph, label, reason)
        return self._paint(line, v)

    def format_pending(self, q):
        bar = "═" * 60
        lines = [
            "╔═ APPROVAL NEEDED %s %s" % (clean(q.get("id"), 12), bar[:40]),
            "║ tool:  %s   (from %s)" % (clean(q.get("tool"), 40),
                                        clean(q.get("source"), 40)),
            "║ args:  %s" % clean(args_summary(q), 300),
            "║ rows:  %s" % clean(rows_summary(q.get("rows")), 120),
            "║ why:   %s" % clean(q.get("reason"), 300),
            "║ waits: %s s, then fails closed" % q.get("wait_s", "?"),
            "║ a = approve once   A = approve for run   d = deny [reason]   s = stop",
            "╚" + bar,
        ]
        return self._paint("\n".join(lines), "ask")

    def notify(self, msg):
        """macOS notification in argv form (no AppleScript injection).
        Returns the argv used, or None when skipped."""
        if (not self.notify_enabled or self.platform != "darwin"
                or os.environ.get("A10_NO_NOTIFY") == "1"):
            return None
        argv = ["osascript"] + NOTIFY_SCRIPT + ["--", clean(msg, 200)]
        try:
            self.runner(argv, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=5, check=False)
        except Exception:  # noqa: BLE001
            pass
        return argv

    # -- polling -------------------------------------------------------

    def poll_once(self):
        st, evs = self._get("/events?since=%d" % self.last_seq)
        if st != 200 or not isinstance(evs, list):
            if not self._down:
                self._down = True
                self.write("(gateway unreachable at %s)" % self.gateway_url)
            return
        self._down = False
        for ev in evs:
            if not isinstance(ev, dict):
                continue
            self.last_seq = max(self.last_seq, int(ev.get("seq") or 0))
            self.write(self.format_event(ev))
        st, pend = self._get("/pending")
        if st == 200 and isinstance(pend, list):
            for q in pend:
                qid = q.get("id")
                if qid and qid not in self.seen_pending:
                    self.seen_pending.add(qid)
                    self.write(self.format_pending(q))
                    self.bell()
                    self.notify("Approval needed: %s %s" % (
                        q.get("tool"), args_summary(q)))
        st, status = self._get("/status")
        if st == 200 and isinstance(status, dict):
            self.last_status = status

    def _loop(self):
        while not self._stop_evt.is_set():
            try:
                self.poll_once()
            except Exception as e:  # noqa: BLE001
                self.write("(console poll error: %s)" % clean(e, 120))
            self._stop_evt.wait(self.poll_interval)

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self):
        self._stop_evt.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    # -- commands ------------------------------------------------------

    def _oldest_pending(self):
        st, pend = self._get("/pending")
        if st == 200 and isinstance(pend, list) and pend:
            return pend[0].get("id")
        return None

    @staticmethod
    def _explain(st, body):
        if st == 0:
            return body.get("reason", "gateway unreachable")
        if st == 401:
            return "operator token rejected by the gateway"
        if isinstance(body, dict) and body.get("error"):
            return "%s (HTTP %s)" % (body["error"], st)
        return "HTTP %s" % st

    def _decide(self, pid, decision, reason=""):
        st, body = self._post("/approve", {"id": pid, "decision": decision,
                                           "reason": reason})
        if st != 200:
            return "%s: %s" % (pid, self._explain(st, body))
        if decision == "approve":
            return "✅ approved %s once" % pid
        if decision == "approve_run":
            return "✅ approved %s for the rest of the run" % pid
        return "🚫 denied %s%s" % (pid, (": " + reason) if reason else "")

    def _approve_cmd(self, rest, decision):
        pid = rest.strip() or self._oldest_pending()
        if not pid:
            return "nothing is waiting for approval"
        return self._decide(pid, decision)

    def _stop(self):
        st, body = self._post("/stop", {})
        if st != 200:
            return "stop failed: %s" % self._explain(st, body)
        if self.exit_on_stop:
            self.quit = True
        return "■ run stopped; pending requests denied, the agent is being killed"

    def _mode(self, mode):
        st, body = self._post("/mode", {"mode": mode})
        if st != 200:
            return "mode not changed: %s" % self._explain(st, body)
        return "⚙ mode is now %s (was %s)" % (body.get("mode"), body.get("previous"))

    def _override(self, row):
        st, body = self._post("/override", {"row": row, "confirm": "YES"})
        if st != 200:
            return "override failed: %s" % self._explain(st, body)
        return "⚠ row %s overridden: ⛔ is now ❓ for the rest of this run" % row

    def _status_text(self):
        st, s = self._get("/status")
        if st != 200 or not isinstance(s, dict):
            return "status unavailable: %s" % self._explain(st, s if isinstance(
                s, dict) else {})
        c = s.get("counts") or {}
        lines = [
            "run %s  mode %s  %s" % (s.get("run_id"), s.get("mode"),
                                     "STOPPED" if s.get("stopped") else "running"),
            "tainted: %s" % ("yes: " + "; ".join(clean(r, 120) for r in
                                                  s.get("taint_reasons") or [])
                             if s.get("tainted") else "no"),
            "overrides: %s" % (", ".join(s.get("overrides") or []) or "none"),
            "counts: " + ", ".join("%s %s" % (k, c.get(k, 0)) for k in (
                "allow", "ask", "approved", "block", "deny", "expired",
                "stopped")),
            "pending: %s   workspace: %s" % (s.get("pending_open"),
                                             s.get("workspace")),
        ]
        return "\n".join(lines)

    @staticmethod
    def _split_id(rest):
        parts = rest.strip().split(None, 1)
        if parts and _PID_RE.match(parts[0]):
            return parts[0], (parts[1] if len(parts) > 1 else "").strip()
        return None, rest.strip()

    def handle_line(self, line):
        """Run one console command; returns the text to show the operator."""
        line = (line or "").rstrip("\r\n")
        s = line.strip()
        if self._awaiting is not None:
            kind, arg = self._awaiting
            self._awaiting = None
            if kind == "override":
                if s == "YES":
                    return self._override(arg)
                return "override of row %s cancelled (you typed %r, not YES)" % (
                    arg, clean(s, 40))
            if kind == "deny":
                return self._decide(arg, "deny", s)
            if kind == "mode":
                return self._mode(s) if s else "mode unchanged"
        if not s:
            return ""
        parts = s.split(None, 1)
        cmd, rest = parts[0], (parts[1] if len(parts) > 1 else "")
        if cmd == "a":
            return self._approve_cmd(rest, "approve")
        if cmd == "A":
            return self._approve_cmd(rest, "approve_run")
        if cmd == "d":
            pid, reason = self._split_id(rest)
            pid = pid or self._oldest_pending()
            if not pid:
                return "nothing is waiting for approval"
            if not reason:
                self._awaiting = ("deny", pid)
                return ("Reason for denying %s (sent back to the model; "
                        "Enter for none):" % pid)
            return self._decide(pid, "deny", reason)
        if cmd == "s":
            return self._stop()
        if cmd == "m":
            if not rest.strip():
                self._awaiting = ("mode", None)
                return "New mode (%s):" % "/".join(policy.MODES)
            return self._mode(rest.strip())
        if cmd in ("override", "o"):
            row = rest.strip()
            if row not in policy.ROWS:
                return "usage: override <row>  (row ids: %s)" % ", ".join(policy.ROWS)
            self._awaiting = ("override", row)
            return ("Type YES to turn row %s (%s) from ⛔ into ❓ for the rest of "
                    "this run (anything else cancels):" % (
                        row, policy.ROWS[row].title))
        if cmd in ("?", "status"):
            return self._status_text()
        if cmd in ("h", "help"):
            return HELP
        if cmd == "q":
            self.quit = True
            return "console closed"
        return "unknown command %r (h for help)" % clean(cmd, 20)

    # -- input loop ------------------------------------------------------

    def run(self, stdin=None, exit_on_eof=True):
        """Poll in the background and read commands until q (or EOF when
        exit_on_eof). Uses select() on the raw fd so another thread can end
        the loop by setting `quit`."""
        stdin = stdin or sys.stdin
        self.start()
        self.write(HELP)
        try:
            fd = stdin.fileno()
        except (AttributeError, OSError, ValueError):
            fd = None
        buf = b""
        eof = False
        try:
            while not self.quit:
                if fd is None:
                    line = stdin.readline()
                    if not line:
                        if exit_on_eof:
                            break
                        eof = True
                        fd = -1
                        continue
                    self._handle_and_show(line)
                    continue
                if eof or fd < 0:
                    time.sleep(0.25)
                    continue
                ready, _, _ = select.select([fd], [], [], 0.25)
                if not ready:
                    continue
                chunk = os.read(fd, 4096)
                if not chunk:
                    eof = True
                    if buf:
                        self._handle_and_show(buf.decode("utf-8", "replace"))
                        buf = b""
                    if exit_on_eof:
                        break
                    continue
                buf += chunk
                while b"\n" in buf and not self.quit:
                    raw, buf = buf.split(b"\n", 1)
                    self._handle_and_show(raw.decode("utf-8", "replace"))
        finally:
            self.stop()

    def _handle_and_show(self, line):
        out = self.handle_line(line)
        if out:
            self.write(out)


def main(argv=None):
    p = argparse.ArgumentParser(description="A10 harness operator console")
    p.add_argument("--gateway", default=DEFAULT_GATEWAY)
    p.add_argument("--no-notify", action="store_true")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)
    home = a10_home()
    token = read_token(home)
    if not token:
        print("No operator token at %s; start the harness first "
              "(python3 harness.py demo)." % os.path.join(home, "operator.token"))
        return 2
    c = Console(args.gateway, token, notify=not args.no_notify,
                color=False if args.no_color else "auto")
    try:
        c.run(exit_on_eof=True)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
