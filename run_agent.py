"""Launch an agent through the harness.

    python run_agent.py -- oh -p "summarize the notes in this folder"
    python run_agent.py --workspace ./sandbox -- <any agent command ...>

- Registers a new run with the gateway (clears per-run approvals and STOP).
- Runs the agent in the workspace, in its own process group so STOP can kill it.
- Routes its traffic through mitmproxy. The mitmproxy CA is trusted only by this
  process tree, through environment variables; nothing changes in the system keychain.
- For OpenHarness (`oh`): checks the pre_tool_use hook is installed and adds
  `--permission-mode full_auto`, because headless oh can't prompt anyone, so the
  gateway has to be the only approver. oh's own sensitive-path check still runs.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import urllib.request

from harness.config import load_policy, oh_config_dir

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(policy, path: str, body: dict | None = None, token: str = "") -> dict:
    req = urllib.request.Request(policy.gateway_url + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", "X-Operator-Token": token})
    with _opener.open(req, timeout=10) as resp:
        return json.loads(resp.read())


def hook_installed(policy) -> bool:
    try:
        settings = json.loads((oh_config_dir() / "settings.json").read_text())
    except (OSError, json.JSONDecodeError):
        return False
    for hook in settings.get("hooks", {}).get("pre_tool_use", []):
        if hook.get("type") == "http" and hook.get("url", "").startswith(policy.gateway_url) \
                and hook.get("block_on_failure"):
            return True
    return False


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[argv.index("--") + 1:] if "--" in argv else []
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", default=None, help="folder the agent works in (default: policy.json)")
    ap.add_argument("--policy", default=None)
    ap.add_argument("--no-hook-check", action="store_true", help="run oh even if the hook isn't installed")
    args = ap.parse_args(argv[:argv.index("--")] if "--" in argv else argv)
    if not cmd:
        ap.error("usage: python run_agent.py [options] -- <agent command ...>")

    policy = load_policy(args.policy, workspace=args.workspace)
    policy.workspace.mkdir(parents=True, exist_ok=True)
    try:
        token = policy.token_path.read_text().strip()
        call(policy, "/api/state", None, token)          # also checks the token
    except Exception as exc:
        sys.exit(f"[harness] gateway not reachable at {policy.gateway_url} ({exc}). Start it first: python gateway.py")

    is_oh = os.path.basename(cmd[0]) in ("oh", "openharness")
    if is_oh:
        if not hook_installed(policy) and not args.no_hook_check:
            sys.exit("[harness] the OpenHarness pre_tool_use hook isn't installed, so tool calls would skip "
                     "the gateway. Run: python install_hook.py")
        if "--permission-mode" not in cmd and "--dangerously-skip-permissions" not in cmd:
            cmd += ["--permission-mode", "full_auto"]
            print("[harness] added --permission-mode full_auto: the gateway is the approver")

    proxy = f"http://127.0.0.1:{policy.proxy_port}"
    ca = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
    if not os.path.exists(ca):
        print(f"[harness] warning: {ca} not found. Start mitmdump once to create it.")
    env = dict(os.environ,
               HTTP_PROXY=proxy, HTTPS_PROXY=proxy, http_proxy=proxy, https_proxy=proxy,
               ALL_PROXY=proxy, all_proxy=proxy,
               SSL_CERT_FILE=ca, REQUESTS_CA_BUNDLE=ca, NODE_EXTRA_CA_CERTS=ca, CURL_CA_BUNDLE=ca)
    for k in ("NO_PROXY", "no_proxy"):          # everything, including localhost, goes through the proxy
        env.pop(k, None)

    run_id = call(policy, "/api/run/start", {"cmd": " ".join(cmd)}, token)["run"]
    p = subprocess.Popen(cmd, env=env, cwd=policy.workspace, start_new_session=True)
    state = call(policy, "/api/run/pid", {"pid": p.pid}, token)
    if state.get("stopped"):
        os.killpg(p.pid, signal.SIGTERM)
    session = policy.state_dir / "session.json"
    session.write_text(json.dumps({"run": run_id, "pid": p.pid, "cmd": " ".join(cmd), "status": "running"}))
    print(f"[harness] run {run_id}: pid={p.pid} cwd={policy.workspace}\n[harness] {' '.join(cmd)}")

    try:
        rc = p.wait()
    except KeyboardInterrupt:
        os.killpg(p.pid, signal.SIGTERM)
        rc = p.wait()
    try:
        call(policy, "/api/run/end", {"rc": rc}, token)
    except Exception:
        pass
    session.write_text(json.dumps({"run": run_id, "pid": p.pid, "cmd": " ".join(cmd),
                                   "status": "stopped" if rc < 0 else "finished", "rc": rc}))
    print(f"[harness] run {run_id} exited rc={rc}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
