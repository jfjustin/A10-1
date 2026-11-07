"""One-command launcher for the A10 Agent Harness (Prompt 2).

  python3 harness.py

Starts, in order: the gateway (policy + dashboard + audit log), the
network proxy (all agent egress judged by the gateway), then the CLI
agent behind both. The agent's output streams live here; its traffic
streams live on the dashboard at http://127.0.0.1:8000/.

Scope: CLI agents only -- desktop apps are out of scope for this build.
STOP (dashboard button) or Ctrl-C here kills the agent, then the proxy
and gateway, and prints the run summary from the audit log.
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
GATEWAY_URL = "http://127.0.0.1:8000"
PROXY_PORT = 8080


def _wait_http(url, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return True
        except Exception:
            time.sleep(0.3)
    return False


def _wait_port(host, port, timeout=10):
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def _get_json(url):
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _stop(proc, name):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def main():
    print("🛡️  Agent Harness — one command: gateway + proxy + CLI agent")
    print("Scope: CLI agents only (desktop apps out of scope for this build).")

    gateway = subprocess.Popen([sys.executable, "gateway.py"], cwd=ROOT)
    if not _wait_http(GATEWAY_URL + "/audit"):
        print("gateway failed to start")
        _stop(gateway, "gateway")
        return 1
    print("gateway up:  http://127.0.0.1:8000/  (dashboard + approvals)")

    proxy = subprocess.Popen([sys.executable, "proxy.py"], cwd=ROOT)
    if not _wait_port("127.0.0.1", PROXY_PORT):
        print("proxy failed to start")
        _stop(proxy, "proxy")
        _stop(gateway, "gateway")
        return 1
    print("proxy up:    http://127.0.0.1:8080/  (all agent egress judged here)")

    env = dict(os.environ)
    # Both cases: curl honours lowercase first, and the sandbox sets a
    # lowercase http_proxy to its own egress proxy.
    env["HTTP_PROXY"] = f"http://127.0.0.1:{PROXY_PORT}"
    env["HTTPS_PROXY"] = f"http://127.0.0.1:{PROXY_PORT}"
    env["http_proxy"] = f"http://127.0.0.1:{PROXY_PORT}"
    env["https_proxy"] = f"http://127.0.0.1:{PROXY_PORT}"
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = "127.0.0.1,localhost"
    agent = subprocess.Popen([sys.executable, "agent.py"], cwd=ROOT, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
    print("agent launched behind the gateway + proxy — streaming its output:\n")

    try:
        for line in agent.stdout:
            print(line, end="", flush=True)
        agent.wait()
        print(f"\nAgent finished (exit {agent.returncode}). Dashboard still up —")
        print("hit STOP on the dashboard or Ctrl-C here to shut everything down.")
        while True:
            st = _get_json(GATEWAY_URL + "/status")
            if st and st.get("stopped"):
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nCtrl-C — shutting down.")
    finally:
        audit = _get_json(GATEWAY_URL + "/audit") or {}
        status = _get_json(GATEWAY_URL + "/status") or {}
        print(f"\nRun summary: audit chain "
              f"{'✓ verified' if audit.get('ok') else '✗ TAMPERED'} "
              f"({audit.get('count', '?')} events) — "
              f"{status.get('allow', '?')} allowed, "
              f"{status.get('block', '?')} blocked, "
              f"{status.get('pending_open', '?')} pending.")
        _stop(agent, "agent")
        _stop(proxy, "proxy")
        _stop(gateway, "gateway")
        print("Shutdown complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
