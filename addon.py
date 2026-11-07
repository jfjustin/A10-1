"""mitmproxy addon: sends every request the agent makes to the gateway for a verdict.

    mitmdump -p 8080 -s addon.py          # first run creates ~/.mitmproxy/mitmproxy-ca-cert.pem

The gateway decides (G3 secrets in bodies, G4 internal addresses, allowlist,
mode table, approvals). If the gateway can't be reached, the request is blocked
(block_on_failure). Secret headers never leave this process.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mitmproxy import ctx, http  # noqa: E402

from harness.config import load_policy  # noqa: E402

POLICY = load_policy()
BODY_LIMIT = 256 * 1024
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never proxy ourselves


def _token() -> str:
    try:
        return POLICY.token_path.read_text().strip()
    except OSError:
        return ""


def ask_gateway(host: str, port: int, method: str, path: str, body: str) -> tuple[bool, str]:
    req = urllib.request.Request(
        POLICY.gateway_url + "/check/network",
        data=json.dumps({"host": host, "port": port, "method": method, "path": path, "body": body}).encode(),
        headers={"Content-Type": "application/json", "X-Operator-Token": _token()},
        method="POST")
    try:
        with _opener.open(req, timeout=POLICY.approval_timeout_seconds + 15) as resp:
            v = json.loads(resp.read())
            return bool(v.get("allow")), v.get("message", "")
    except Exception as exc:
        if POLICY.block_on_failure:
            return False, f"Blocked by Agent Harness: gateway unreachable ({exc.__class__.__name__})"
        return True, "gateway unreachable, allowed (block_on_failure is off)"


def _is_hook_call(flow: http.HTTPFlow) -> bool:
    """oh's own pre_tool_use hook goes through the proxy too (it honors HTTP_PROXY)."""
    r = flow.request
    return (r.host in (POLICY.gateway_host, "localhost", "127.0.0.1") and r.port == POLICY.gateway_port
            and r.path.split("?")[0] == "/hook" and r.method == "POST")


def _deny(flow: http.HTTPFlow, message: str):
    flow.response = http.Response.make(403, message, {"Content-Type": "text/plain"})


class Harness:
    def load(self, loader):
        POLICY.state_dir.mkdir(parents=True, exist_ok=True)
        (POLICY.state_dir / "proxy.pid").write_text(str(os.getpid()))

    async def http_connect(self, flow: http.HTTPFlow):
        # HTTPS tunnels: the decrypted requests are judged in request(); only refuse
        # tunnels to internal addresses early so nothing reaches them.
        if flow.request.port == POLICY.gateway_port and flow.request.host in ("127.0.0.1", "localhost"):
            _deny(flow, "Blocked by Agent Harness [G4]: the gateway is not reachable from the agent")
            return
        ok, msg = await asyncio.to_thread(ask_gateway, flow.request.pretty_host, flow.request.port,
                                          "CONNECT", "", "")
        if not ok:
            _deny(flow, msg)

    async def request(self, flow: http.HTTPFlow):
        if flow.request.method == "CONNECT":
            return
        if _is_hook_call(flow):
            return
        r = flow.request
        body = (r.get_text(strict=False) or "")[:BODY_LIMIT] if r.raw_content else ""
        ok, msg = await asyncio.to_thread(ask_gateway, r.pretty_host, r.port, r.method, r.path, body)
        if not ok:
            _deny(flow, msg)
            ctx.log.info(msg)


addons = [Harness()]
