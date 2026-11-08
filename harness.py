"""One-command launcher for the A10 Agent Harness (Prompt 2).

  python3 harness.py demo [--mode default] [--proxy auto|mitm|stdlib] [--no-notify]
      gateway + proxy (with the offline api.example.com stubs) + the scripted
      demo agent, with the terminal console in the foreground.
      Type `a` at the pending summary write, watch the blocks, type `s` to stop:
      the agent is killed and the run summary verifies the audit chain.
  python3 harness.py oh [--workspace DIR] [--mode M] [--proxy P] [--exit-with-agent] -- <oh args>
      OpenHarness under the gateway: every tool call goes through oh's
      pre_tool_use HTTP hook, every request through the proxy. oh runs with
      --permission-mode full_auto so the gateway is the only approver.
      Approve in a second terminal with `python3 harness.py watch`.
  python3 harness.py run [--workspace DIR] [--provider-host H] [--proxy P] -- <cmd...>
      any CLI agent (claude, codex, ...) behind the proxy: network monitoring
      only, no tool hooks. Pass --provider-host for the agent's LLM API host.
  python3 harness.py watch [--gateway URL]
      the terminal console only (e.g. in a second terminal)
  python3 harness.py verify [audit.log.jsonl]
      verify a hash-chained audit log offline (exit 1 when broken)

`python3 harness.py` with no subcommand runs the demo.

Proxy: `--proxy mitm` runs mitmdump with mitm_addon.py (HTTPS decrypted and
judged per request); `stdlib` runs proxy.py (plain HTTP inspected, HTTPS judged
by host only); `auto` (default) picks mitm when mitmdump is on PATH. The mitm
CA is trusted by the agent process only, through SSL_CERT_FILE,
REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE (A10_HOME/ca-bundle.pem = base bundle + mitm
CA) and NODE_EXTRA_CA_CERTS; the macOS keychain is never changed.

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
import oh_setup
from console import Console, clean

HARNESS_ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_AUDIT_LOG = os.path.join(HARNESS_ROOT, "audit.log.jsonl")
MITM_ADDON = os.path.join(HARNESS_ROOT, "mitm_addon.py")
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
NO_PROXY_VALUE = "127.0.0.1,localhost"
CA_FILE_VARS = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")
SYSTEM_CA_BUNDLES = ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt",
                     "/etc/pki/tls/certs/ca-bundle.crt")
MITM_CA_NAME = "mitmproxy-ca-cert.pem"
MITM_MISSING = ("mitmdump not found; using the stdlib proxy (no HTTPS "
                "decryption). Install with: pip install mitmproxy")
MITM_REQUIRED = ("mitmdump not found. Install with: pip install mitmproxy "
                 "(or use --proxy stdlib)")
OH_MISSING = "oh not found. Install OpenHarness with: pip install openharness-ai"


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
        for k in CA_FILE_VARS:
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


def _wait_http(url, path, timeout=10, proc=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            return False
        if _get(url, path) is not None:
            return True
        time.sleep(0.2)
    return False


def _wait_port(port, timeout=10, proc=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _wait_file(path, timeout=10, proc=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return True
        if proc is not None and proc.poll() is not None:
            return False
        time.sleep(0.2)
    return os.path.isfile(path)


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


def _ignore_signal(signum, frame):
    """SIGINT while an interactive agent runs: the agent handles Ctrl-C. A
    Python handler (not SIG_IGN) so the child starts with the default
    disposition after exec."""


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
# Proxy selection, mitmproxy and the agent-only CA bundle
# ---------------------------------------------------------------------------


def resolve_proxy(choice, which=shutil.which):
    """-> (kind, mitmdump_path, message_to_print_or_None). kind is None when
    --proxy mitm was requested but mitmdump is not on PATH."""
    if choice == "stdlib":
        return "stdlib", None, None
    path = which("mitmdump")
    if path:
        return "mitm", path, None
    if choice == "mitm":
        return None, None, MITM_REQUIRED
    return "stdlib", None, MITM_MISSING


def mitm_command(mitmdump, port, confdir, addon=MITM_ADDON):
    """argv for mitmdump running the harness addon (spec 5.9)."""
    return [mitmdump, "--listen-host", "127.0.0.1", "--listen-port", str(port),
            "--set", "confdir=%s" % confdir,
            "--set", "connection_strategy=lazy", "-q", "-s", addon]


def mitm_env(base_env, gateway_url, demo_stubs=False, approval_wait=590.0):
    """Environment for mitmdump: the addon's settings, no operator token."""
    env = {k: v for k, v in dict(base_env).items()
           if "OPERATOR_TOKEN" not in k.upper()
           and not k.upper().startswith("A10_OPERATOR")}
    env["A10_GATEWAY_URL"] = gateway_url
    env["A10_DEMO_STUBS"] = "1" if demo_stubs else "0"
    env["A10_APPROVAL_WAIT"] = str(approval_wait)
    return env


def base_ca_bundle():
    """certifi's bundle when certifi is importable (optional), else the
    system bundle, else None."""
    try:
        import certifi
        path = certifi.where()
        if path and os.path.isfile(path):
            return path
    except Exception:  # noqa: BLE001 - certifi is optional
        pass
    for path in SYSTEM_CA_BUNDLES:
        if os.path.isfile(path):
            return path
    return None


def build_ca_bundle(a10_home_dir, mitm_ca, base_bundle=None):
    """Write A10_HOME/ca-bundle.pem = base bundle + the mitm CA certificate
    (rebuilt every run) and return its path. Only the agent's environment
    points at it; nothing is installed system-wide or in the keychain."""
    with open(mitm_ca, encoding="utf-8", errors="replace") as f:
        ca = f.read().strip()
    if "-----BEGIN CERTIFICATE-----" not in ca:
        raise ValueError("not a PEM certificate: %s" % mitm_ca)
    if base_bundle is None:
        base_bundle = base_ca_bundle()
    base = ""
    if base_bundle:
        with open(base_bundle, encoding="utf-8", errors="replace") as f:
            base = f.read().strip()
    out = os.path.join(a10_home_dir, "ca-bundle.pem")
    tmp = out + ".tmp"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        if base:
            f.write(base + "\n\n")
        f.write("# A10 harness mitmproxy CA (trusted by the agent process only)\n")
        f.write(ca + "\n")
    os.replace(tmp, out)
    return out


class Services:
    """Gateway + proxy subprocesses for one run, and the agent's env."""

    def __init__(self, home, port, proxy_port, kind, mitmdump=None,
                 demo_stubs=False, approval_wait=590.0, audit_log=None):
        self.home = home
        self.port = port
        self.proxy_port = proxy_port
        self.kind = kind
        self.mitmdump = mitmdump
        self.demo_stubs = bool(demo_stubs)
        self.approval_wait = approval_wait
        self.audit_log = os.path.realpath(audit_log or DEFAULT_AUDIT_LOG)
        self.gw_url = "http://127.0.0.1:%d" % port
        self.proxy_url = "http://127.0.0.1:%d" % proxy_port
        self.child_env = dict(os.environ, A10_HOME=home)
        self.gateway = None
        self.proxy = None
        self.ca_bundle = None
        self.mitm_ca = None
        self.mitm_log = None

    def start_gateway(self, mode, workspace, cwd, allowed_hosts=(),
                      provider_hosts=()):
        cmd = [sys.executable, os.path.join(HARNESS_ROOT, "gateway.py"),
               "--port", str(self.port), "--mode", mode,
               "--workspace", workspace, "--cwd", cwd,
               "--audit-log", self.audit_log,
               "--approval-wait", str(self.approval_wait)]
        if self.demo_stubs:
            cmd.append("--demo-stubs")
        for h in allowed_hosts or ():
            cmd += ["--allowed-host", h]
        for h in provider_hosts or ():
            cmd += ["--provider-host", h]
        self.gateway = subprocess.Popen(
            cmd, cwd=HARNESS_ROOT, env=self.child_env,
            stdout=subprocess.DEVNULL, start_new_session=True)
        if not _wait_http(self.gw_url, "/status", proc=self.gateway):
            print("gateway failed to start on port %d" % self.port)
            return False
        return True

    def start_proxy(self):
        try:
            if self.kind == "mitm":
                return self._start_mitm()
            cmd = [sys.executable, os.path.join(HARNESS_ROOT, "proxy.py"),
                   "--port", str(self.proxy_port), "--gateway", self.gw_url]
            if self.demo_stubs:
                cmd.append("--demo-stubs")
            self.proxy = subprocess.Popen(
                cmd, cwd=HARNESS_ROOT, env=self.child_env,
                stdout=subprocess.DEVNULL, start_new_session=True)
        except OSError as e:
            print("proxy failed to start: %s" % e)
            return False
        if not _wait_port(self.proxy_port, 10, self.proxy):
            print("proxy failed to start on port %d" % self.proxy_port)
            return False
        return True

    def _start_mitm(self):
        confdir = os.path.join(self.home, "mitmproxy")
        run_dir = os.path.join(self.home, "run")
        for d in (confdir, run_dir):
            os.makedirs(d, mode=0o700, exist_ok=True)
        self.mitm_log = os.path.join(run_dir, "mitmdump.log")
        with open(self.mitm_log, "w") as log:
            self.proxy = subprocess.Popen(
                mitm_command(self.mitmdump, self.proxy_port, confdir),
                cwd=HARNESS_ROOT,
                env=mitm_env(self.child_env, self.gw_url, self.demo_stubs,
                             self.approval_wait),
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                start_new_session=True)
        cert = os.path.join(confdir, MITM_CA_NAME)
        if not (_wait_port(self.proxy_port, 30, self.proxy)
                and _wait_file(cert, 10, self.proxy)):
            print("mitmdump failed to start on port %d; log: %s"
                  % (self.proxy_port, self.mitm_log))
            return False
        try:
            self.ca_bundle = build_ca_bundle(self.home, cert)
        except (OSError, ValueError) as e:
            print("could not build the agent CA bundle: %s" % e)
            return False
        self.mitm_ca = cert
        return True

    def write_pids(self):
        pids = {"harness": os.getpid(), "gateway": self.gateway.pid,
                "proxy": self.proxy.pid}
        if self.kind == "mitm":
            pids["mitmdump"] = self.proxy.pid
        return write_pids(self.home, pids)

    def agent_env(self, base_env):
        return build_agent_env(base_env, self.proxy_url, self.ca_bundle,
                               self.mitm_ca)

    def proxy_label(self):
        stubs = ", demo stubs for api.example.com" if self.demo_stubs else ""
        if self.kind == "mitm":
            return ("mitmproxy: HTTPS decrypted, CA trusted by the agent only%s"
                    % stubs)
        return "stdlib: plain HTTP inspected, HTTPS judged by host%s" % stubs

    def status(self):
        return _get(self.gw_url, "/status") if self.gateway is not None else None

    def shutdown(self):
        _stop_proc(self.proxy)
        _stop_proc(self.gateway)
        try:
            os.remove(os.path.join(self.home, "run", "pids.json"))
        except OSError:
            pass

    def print_summary(self, status):
        if self.gateway is None:
            return
        print("\n" + summary_line(audit.verify_file(self.audit_log), status))
        print("Shutdown complete. Verify again any time: "
              "python3 harness.py verify %s" % self.audit_log)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_demo(args):
    home = a10_home()
    token = ensure_operator_token(home)
    kind, mitmdump, msg = resolve_proxy(args.proxy)
    if msg:
        print(msg)
    if kind is None:
        return 2
    svc = Services(home, args.port, args.proxy_port, kind, mitmdump,
                   demo_stubs=True, approval_wait=args.approval_wait,
                   audit_log=args.audit_log)
    py = sys.executable
    signal.signal(signal.SIGTERM, _raise_interrupt)

    print("🛡️  A10 Agent Harness demo: gateway + proxy + CLI agent + console")
    agent = None
    console = None
    done = threading.Event()
    status = None
    try:
        if not svc.start_gateway(args.mode,
                                 os.path.join(HARNESS_ROOT, "demo-files"),
                                 HARNESS_ROOT):
            return 1
        if not svc.start_proxy():
            return 1
        svc.write_pids()
        gw_url = svc.gw_url
        print("gateway:   %s  (mode %s, audit %s)" % (gw_url, args.mode,
                                                     svc.audit_log))
        print("proxy:     %s  (%s)" % (svc.proxy_url, svc.proxy_label()))
        print("dashboard: %s/#token=%s" % (gw_url, token))

        agent = subprocess.Popen(
            [py, os.path.join(HARNESS_ROOT, "agent.py"), "--gateway", gw_url,
             "--delay", str(args.delay)],
            cwd=HARNESS_ROOT, env=svc.agent_env(os.environ),
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
        status = svc.status()
        if agent is not None and agent.poll() is None:
            killed = kill_tree(agent.pid)
            print("harness │ stopped: killed the agent process tree %s" % killed)
        svc.shutdown()
        svc.print_summary(status)
    return 0


def _watch_hint(gw_url, port):
    hint = "Run `python3 harness.py watch` in a second terminal for approvals"
    if port != 8000:
        hint += " (add --gateway %s)" % gw_url
    return hint


def _stop_watcher(svc, agent, done, stopped):
    """Kill the agent's process tree as soon as the run is stopped."""
    while not done.is_set() and agent.poll() is None:
        st = svc.status()
        if st and st.get("stopped"):
            stopped.set()
            if agent.poll() is None:
                killed = kill_tree(agent.pid)
                print("\nharness │ run stopped: killed the agent process tree %s"
                      % killed, flush=True)
            return
        done.wait(0.5)


def _wait_until_stopped(svc):
    while True:
        st = svc.status()
        if st is None or st.get("stopped"):
            return
        time.sleep(0.5)


def _run_agent(args, cmd, providers, label, provider_desc, prepare=None,
               notes=()):
    """Shared lifecycle of `oh` and `run`: gateway + proxy, the agent in the
    foreground with the inherited terminal, stop handling, summary."""
    home = a10_home()
    token = ensure_operator_token(home)
    kind, mitmdump, msg = resolve_proxy(args.proxy)
    if msg:
        print(msg)
    if kind is None:
        return 2
    workspace = os.path.realpath(os.path.expanduser(args.workspace or os.getcwd()))
    if not os.path.isdir(workspace):
        print("workspace is not a directory: %s" % workspace)
        return 2
    svc = Services(home, args.port, args.proxy_port, kind, mitmdump,
                   demo_stubs=args.demo_stubs, approval_wait=args.approval_wait,
                   audit_log=args.audit_log)
    signal.signal(signal.SIGTERM, _raise_interrupt)
    old_int = signal.getsignal(signal.SIGINT)
    agent = None
    code = None
    done = threading.Event()
    stopped = threading.Event()
    status = None
    print("🛡️  A10 Agent Harness: %s behind the gateway + proxy" % label)
    try:
        if not svc.start_gateway(args.mode, workspace, workspace,
                                 args.allowed_host, providers):
            return 1
        if not svc.start_proxy():
            return 1
        svc.write_pids()
        env = svc.agent_env(os.environ)
        env.pop("OPENHARNESS_WEB_PROXY", None)
        if prepare is not None:
            try:
                env.update(prepare(svc))
            except (OSError, ValueError) as e:
                print("could not prepare the agent config: %s" % e)
                return 1
        print("gateway:   %s  (mode %s, audit %s)" % (svc.gw_url, args.mode,
                                                     svc.audit_log))
        print("workspace: %s" % workspace)
        print("proxy:     %s  (%s)" % (svc.proxy_url, svc.proxy_label()))
        print("provider:  %s" % provider_desc)
        for note in notes:
            print("note:      %s" % note)
        print("dashboard: %s/#token=%s" % (svc.gw_url, token))
        print(_watch_hint(svc.gw_url, svc.port))
        print("agent:     %s\n" % " ".join(cmd), flush=True)

        signal.signal(signal.SIGINT, _ignore_signal)
        try:
            agent = subprocess.Popen(cmd, cwd=workspace, env=env)
        except OSError as e:
            print("could not start %s: %s" % (label, e))
            return 1
        watcher = threading.Thread(target=_stop_watcher,
                                   args=(svc, agent, done, stopped), daemon=True)
        watcher.start()
        code = agent.wait()
        signal.signal(signal.SIGINT, old_int)
        watcher.join(10)  # let a stop-triggered kill_tree finish and report
        st = svc.status()
        if st and st.get("stopped"):
            stopped.set()
        if not stopped.is_set() and not args.exit_with_agent:
            print("\nharness │ %s exited with code %s. The gateway stays up for "
                  "the console and dashboard: stop the run (s in `python3 "
                  "harness.py watch`) or press Ctrl-C to shut down."
                  % (label, code), flush=True)
            _wait_until_stopped(svc)
    except KeyboardInterrupt:
        print("\nCtrl-C: shutting down.")
    finally:
        signal.signal(signal.SIGINT, old_int)
        done.set()
        status = svc.status()
        if agent is not None and agent.poll() is None:
            killed = kill_tree(agent.pid)
            print("harness │ stopped: killed the agent process tree %s" % killed)
        svc.shutdown()
        svc.print_summary(status)
    if code is None or code < 0 or stopped.is_set():
        return 0
    return code


def cmd_oh(args):
    oh = shutil.which("oh")
    if not oh:
        print(OH_MISSING)
        return 2
    user_dir = oh_setup.user_config_dir(os.environ)
    if args.provider_host:
        providers = list(args.provider_host)
        source = "--provider-host"
    else:
        settings = oh_setup.load_user_settings(user_dir)
        name, _ = oh_setup.active_profile(settings, os.environ)
        providers = sorted(oh_setup.provider_hosts(settings, os.environ))
        source = "oh profile '%s' in %s" % (name, user_dir)
    desc = "%s (row 10, from %s)" % (", ".join(providers) or "none", source)

    def prepare(svc):
        return oh_setup.prepare_config_dir(svc.home, svc.gw_url, user_dir)

    notes = ("oh's pre_tool_use/post_tool_use HTTP hooks call the gateway; "
             "your oh settings are copied, never modified",
             "oh's web_fetch/web_search ignore the proxy; the gateway judges "
             "them at the tool level")
    cmd = [oh, "--permission-mode", "full_auto"] + list(args.agent_args)
    return _run_agent(args, cmd, providers, "oh", desc, prepare, notes)


def cmd_run(args):
    cmd = list(args.agent_args)
    if not cmd:
        print("usage: python3 harness.py run [options] -- <command> [args...]")
        return 2
    exe = shutil.which(cmd[0])
    if not exe:
        print("command not found: %s" % cmd[0])
        return 2
    providers = list(args.provider_host)
    if providers:
        desc = "%s (row 10, from --provider-host)" % ", ".join(providers)
    else:
        desc = ("none: the agent's LLM API host (e.g. api.anthropic.com) is "
                "judged like any other host; pass --provider-host to allow it "
                "(row 10)")
    notes = ("tool calls of `%s` are not hooked: only its network traffic is "
             "judged (through the proxy)" % cmd[0],)
    return _run_agent(args, [exe] + cmd[1:], providers, cmd[0], desc, None,
                      notes)


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


def _add_agent_flags(sp, provider_help):
    sp.add_argument("--workspace", default=None,
                    help="directory the agent may work in (default: current dir)")
    sp.add_argument("--mode", default="default", choices=("plan", "default", "auto"))
    sp.add_argument("--proxy", default="auto", choices=("auto", "mitm", "stdlib"))
    sp.add_argument("--port", type=int, default=8000, help="gateway port")
    sp.add_argument("--proxy-port", type=int, default=8080)
    sp.add_argument("--provider-host", action="append", default=[],
                    help=provider_help)
    sp.add_argument("--allowed-host", action="append", default=[],
                    help="row 8 allowlist host (repeatable; replaces the "
                    "default api.example.com)")
    sp.add_argument("--exit-with-agent", action="store_true",
                    help="shut down when the agent exits (default: keep the "
                    "gateway up until the run is stopped or Ctrl-C)")
    sp.add_argument("--demo-stubs", action="store_true",
                    help="answer api.example.com from the proxy's offline stubs")
    sp.add_argument("--approval-wait", type=float, default=590.0)
    sp.add_argument("--audit-log", default=None)


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
    o = sub.add_parser(
        "oh", help="OpenHarness under the gateway (tool hooks + proxy)",
        usage="%(prog)s [options] -- <oh args>")
    _add_agent_flags(o, "LLM provider host for row 10 (repeatable); default: "
                     "detected from oh's active profile")
    r = sub.add_parser(
        "run", help="any CLI agent behind the proxy (network monitoring only)",
        usage="%(prog)s [options] -- <command> [args...]")
    _add_agent_flags(r, "the agent's LLM API host for row 10, e.g. "
                     "api.anthropic.com (repeatable); without it the agent's "
                     "own API calls are judged like any other host")
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
    agent_args = []
    if argv[0] in ("oh", "run") and "--" in argv:
        i = argv.index("--")
        argv, agent_args = argv[:i], argv[i + 1:]
    args = build_parser().parse_args(argv)
    args.agent_args = agent_args
    return {"demo": cmd_demo, "oh": cmd_oh, "run": cmd_run, "watch": cmd_watch,
            "verify": cmd_verify}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
