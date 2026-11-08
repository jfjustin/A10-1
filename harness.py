"""One-command launcher for the A10 Agent Harness (Prompt 2).

  python3 harness.py demo [--mode default] [--proxy auto|stdlib] [--no-notify]
      gateway + stdlib proxy (with the offline api.example.com stubs) + the
      scripted demo agent, with the terminal console in the foreground.
      Type `a` at the pending summary write, watch the blocks, type `s` to stop:
      the agent is killed and the run summary verifies the audit chain.
  python3 harness.py watch [--gateway URL]
      the terminal console only (e.g. in a second terminal)
  python3 harness.py verify [audit.log.jsonl]
      verify a hash-chained audit log offline (exit 1 when broken)

`python3 harness.py` with no subcommand runs the demo.

Scope: CLI agents. The operator token lives in A10_HOME/operator.token
(default ~/.a10-harness, dir 0700, file 0600) and is stripped from the agent's
environment; the agent's HTTP(S)_PROXY points at the harness proxy and
NO_PROXY keeps only 127.0.0.1/localhost direct (for the hook calls).
Stdlib only.
"""
import argparse
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

import audit
import netcheck
from console import Console, clean

HARNESS_ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_AUDIT_LOG = os.path.join(HARNESS_ROOT, "audit.log.jsonl")
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
NO_PROXY_VALUE = "127.0.0.1,localhost"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def a10_home(environ=None):
    env = os.environ if environ is None else environ
    return os.path.realpath(os.path.expanduser(
        env.get("A10_HOME") or "~/.a10-harness"))


def _fix_mode(path, mode):
    if (os.stat(path).st_mode & 0o777) != mode:
        os.chmod(path, mode)


def ensure_operator_token(a10_home_dir):
    """Create A10_HOME (0700) and operator.token (0600) if missing, tighten
    wider permissions, and return the token."""
    os.makedirs(a10_home_dir, mode=0o700, exist_ok=True)
    _fix_mode(a10_home_dir, 0o700)
    path = os.path.join(a10_home_dir, "operator.token")
    if os.path.islink(path):
        raise RuntimeError("refusing to use a symlinked operator token: %s" % path)
    token = ""
    if os.path.exists(path):
        with open(path) as f:
            token = f.read().strip()
    if not token:
        token = secrets.token_urlsafe(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                     0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token + "\n")
    _fix_mode(path, 0o600)
    return token


def build_agent_env(base_env, proxy_url, ca_bundle=None, node_ca=None):
    """Environment for the agent process: no operator token, all proxy vars
    pointing at the harness proxy, NO_PROXY only for the local gateway."""
    env = {}
    for k, v in dict(base_env).items():
        up = k.upper()
        if "OPERATOR_TOKEN" in up or up.startswith("A10_OPERATOR"):
            continue
        env[k] = v
    for k in PROXY_VARS:
        env[k] = proxy_url
    env["NO_PROXY"] = NO_PROXY_VALUE
    env["no_proxy"] = NO_PROXY_VALUE
    if ca_bundle:
        for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            env[k] = ca_bundle
    if node_ca:
        env["NODE_EXTRA_CA_CERTS"] = node_ca
    return env


def _children_libproc(pid):
    """macOS fallback when pgrep cannot list processes (e.g. sandboxed)."""
    if sys.platform != "darwin":
        return []
    try:
        import ctypes
        lib = ctypes.CDLL("/usr/lib/libproc.dylib")
        buf = (ctypes.c_int * 4096)()
        n = lib.proc_listchildpids(int(pid), buf, ctypes.sizeof(buf))
    except (OSError, AttributeError, ValueError):
        return []
    if n <= 0:
        return []
    if n > len(buf):  # some releases return bytes instead of a count
        n = min(len(buf), n // ctypes.sizeof(ctypes.c_int))
    return [p for p in buf[:n] if p > 0]


def _children(pid):
    try:
        out = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True,
                             text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return _children_libproc(pid)
    if out.returncode > 1:  # 1 = no children; >1 = pgrep itself failed
        return _children_libproc(pid)
    return [int(x) for x in out.stdout.split() if x.isdigit()]


def _descendants(pid):
    found, stack = [], [pid]
    while stack:
        for c in _children(stack.pop()):
            if c not in found:
                found.append(c)
                stack.append(c)
    return found


def _alive(pid):
    try:
        wpid, _ = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            return False  # our child, now reaped
    except ChildProcessError:
        pass
    except OSError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_all(pids, group, sig):
    if group is not None:
        try:
            os.killpg(group, sig)
        except (ProcessLookupError, PermissionError):
            pass
    for p in pids:
        try:
            os.kill(p, sig)
        except (ProcessLookupError, PermissionError):
            pass


def kill_tree(pid, grace=3.0):
    """SIGTERM `pid` and all its descendants (found with `pgrep -P`
    recursively, libproc when pgrep is unavailable), then SIGKILL whatever is
    still alive after `grace` s. When `pid` leads its own process group (the
    harness starts the agent with start_new_session=True) the whole group is
    signalled too, which also catches children that were not listed.
    Returns the list of PIDs signalled."""
    pids = [pid] + _descendants(pid)
    try:
        group = pid if os.getpgid(pid) == pid else None
    except (ProcessLookupError, PermissionError):
        group = None
    _signal_all(pids, group, signal.SIGTERM)
    deadline = time.time() + grace
    while time.time() < deadline:
        if not any(_alive(p) for p in pids):
            return pids
        time.sleep(0.1)
    _signal_all([p for p in pids if _alive(p)], group, signal.SIGKILL)
    deadline = time.time() + 2
    while time.time() < deadline and any(_alive(p) for p in pids):
        time.sleep(0.05)
    return pids


def write_pids(a10_home_dir, pids):
    run_dir = os.path.join(a10_home_dir, "run")
    os.makedirs(run_dir, mode=0o700, exist_ok=True)
    path = os.path.join(run_dir, "pids.json")
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(pids, f)
    os.replace(tmp, path)
    return path


def _get(url, path):
    st, body = netcheck.ask_gateway(url, path, None, timeout=3)
    return body if st == 200 and isinstance(body, dict) else None


def _wait_http(url, path, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _get(url, path) is not None:
            return True
        time.sleep(0.2)
    return False


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _stop_proc(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _raise_interrupt(signum, frame):
    raise KeyboardInterrupt


def summary_line(audit_result, status):
    ok, count, bad = audit_result
    c = (status or {}).get("counts") or {}
    chain = ("audit chain ✓ verified (%d entries)" % count if ok else
             "audit chain ✗ BROKEN at seq %s (%d entries verified)" % (bad, count))
    return ("Run summary: %s: %d allowed, %d asked, %d approved, %d blocked, "
            "%d denied, %d expired." % (chain, c.get("allow", 0), c.get("ask", 0),
                                        c.get("approved", 0), c.get("block", 0),
                                        c.get("deny", 0), c.get("expired", 0)))


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_demo(args):
    home = a10_home()
    token = ensure_operator_token(home)
    if args.proxy == "mitm":
        print("--proxy mitm is not wired into this build yet; use --proxy stdlib.")
        return 2
    if args.proxy == "auto":
        if shutil.which("mitmdump"):
            print("note: mitmdump found, but the demo uses the stdlib proxy in "
                  "this build.")
        else:
            print("warning: mitmdump not on PATH; using the stdlib proxy "
                  "(plain HTTP is inspected, HTTPS is judged by host only).")
    py = sys.executable
    gw_url = "http://127.0.0.1:%d" % args.port
    proxy_url = "http://127.0.0.1:%d" % args.proxy_port
    audit_log = os.path.realpath(args.audit_log or DEFAULT_AUDIT_LOG)
    child_env = dict(os.environ, A10_HOME=home)
    signal.signal(signal.SIGTERM, _raise_interrupt)

    print("🛡️  A10 Agent Harness demo: gateway + proxy + CLI agent + console")
    gateway = proxy = agent = None
    console = None
    done = threading.Event()
    status = None
    try:
        gateway = subprocess.Popen(
            [py, os.path.join(HARNESS_ROOT, "gateway.py"), "--port", str(args.port),
             "--mode", args.mode, "--workspace",
             os.path.join(HARNESS_ROOT, "demo-files"), "--cwd", HARNESS_ROOT,
             "--demo-stubs", "--audit-log", audit_log,
             "--approval-wait", str(args.approval_wait)],
            cwd=HARNESS_ROOT, env=child_env, stdout=subprocess.DEVNULL,
            start_new_session=True)
        if not _wait_http(gw_url, "/status"):
            print("gateway failed to start on port %d" % args.port)
            return 1
        proxy = subprocess.Popen(
            [py, os.path.join(HARNESS_ROOT, "proxy.py"), "--port",
             str(args.proxy_port), "--gateway", gw_url, "--demo-stubs"],
            cwd=HARNESS_ROOT, env=child_env, stdout=subprocess.DEVNULL,
            start_new_session=True)
        if not _wait_port(args.proxy_port):
            print("proxy failed to start on port %d" % args.proxy_port)
            return 1
        write_pids(home, {"harness": os.getpid(), "gateway": gateway.pid,
                          "proxy": proxy.pid})
        print("gateway:   %s  (mode %s, audit %s)" % (gw_url, args.mode, audit_log))
        print("proxy:     %s  (stdlib, demo stubs for api.example.com)" % proxy_url)
        print("dashboard: %s/#token=%s" % (gw_url, token))

        agent = subprocess.Popen(
            [py, os.path.join(HARNESS_ROOT, "agent.py"), "--gateway", gw_url,
             "--delay", str(args.delay)],
            cwd=HARNESS_ROOT, env=build_agent_env(os.environ, proxy_url),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            bufsize=1, start_new_session=True)
        print("agent:     launched behind the gateway + proxy (pid %d)\n" % agent.pid)

        console = Console(gw_url, token, notify=not args.no_notify,
                          exit_on_stop=True)

        def stream():
            for line in agent.stdout:
                console.write("agent │ " + clean(line.rstrip("\n"), 2000))
            code = agent.wait()
            if not done.is_set():
                console.write("agent │ (agent exited with code %s; type s to stop "
                              "the run and print the summary)" % code)

        def watch():
            while not done.is_set():
                st = _get(gw_url, "/status")
                if st and st.get("stopped"):
                    if agent.poll() is None:
                        killed = kill_tree(agent.pid)
                        console.write("harness │ run stopped: killed the agent "
                                      "process tree %s" % killed)
                    console.quit = True
                    return
                done.wait(0.5)

        threading.Thread(target=stream, daemon=True).start()
        threading.Thread(target=watch, daemon=True).start()
        console.run(exit_on_eof=False)
    except KeyboardInterrupt:
        print("\nCtrl-C: shutting down.")
    finally:
        done.set()
        if console is not None:
            console.stop()
        status = _get(gw_url, "/status") if gateway is not None else None
        if agent is not None and agent.poll() is None:
            killed = kill_tree(agent.pid)
            print("harness │ stopped: killed the agent process tree %s" % killed)
        _stop_proc(proxy)
        _stop_proc(gateway)
        try:
            os.remove(os.path.join(home, "run", "pids.json"))
        except OSError:
            pass
        if gateway is not None:
            print("\n" + summary_line(audit.verify_file(audit_log), status))
            print("Shutdown complete. Verify again any time: "
                  "python3 harness.py verify %s" % audit_log)
    return 0


def cmd_watch(args):
    token = ensure_operator_token(a10_home())
    console = Console(args.gateway, token, notify=not args.no_notify)
    try:
        console.run(exit_on_eof=True)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_verify(args):
    path = args.path or DEFAULT_AUDIT_LOG
    if not os.path.exists(path):
        print("no audit log at %s" % path)
        return 1
    ok, count, bad = audit.verify_file(path)
    if ok:
        print("audit chain ✓ verified (%d entries): %s" % (count, path))
        return 0
    print("audit chain ✗ BROKEN at seq %s (%d entries verified before it): %s"
          % (bad, count, path))
    return 1


def build_parser():
    p = argparse.ArgumentParser(description="A10 CLI agent harness")
    sub = p.add_subparsers(dest="cmd")
    d = sub.add_parser("demo", help="offline demo: gateway + proxy + agent + console")
    d.add_argument("--mode", default="default", choices=("plan", "default", "auto"))
    d.add_argument("--proxy", default="auto", choices=("auto", "stdlib", "mitm"))
    d.add_argument("--port", type=int, default=8000)
    d.add_argument("--proxy-port", type=int, default=8080)
    d.add_argument("--no-notify", action="store_true")
    d.add_argument("--delay", type=float, default=1.2,
                   help="seconds between agent steps")
    d.add_argument("--approval-wait", type=float, default=590.0)
    d.add_argument("--audit-log", default=None)
    w = sub.add_parser("watch", help="terminal operator console only")
    w.add_argument("--gateway", default=os.environ.get("A10_GATEWAY_URL")
                   or "http://127.0.0.1:8000")
    w.add_argument("--no-notify", action="store_true")
    v = sub.add_parser("verify", help="verify an audit log offline")
    v.add_argument("path", nargs="?", default=None)
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help")):
        argv = ["demo"] + argv
    args = build_parser().parse_args(argv)
    return {"demo": cmd_demo, "watch": cmd_watch, "verify": cmd_verify}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
