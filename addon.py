"""mitmproxy addon: policy enforcement + event log + kill switch.
Run:  mitmdump -p 8080 -s addon.py
"""
import json, time, os
from mitmproxy import http

HERE = os.path.dirname(os.path.abspath(__file__))
EVENTS = os.path.join(HERE, "state", "events.jsonl")
STOP = os.path.join(HERE, "state", "STOP")      # exists => session stopped, block everything
POLICY = os.path.join(HERE, "policy.json")

def policy():
    with open(POLICY) as f:       # re-read each time: edit rules live during the demo
        return json.load(f)

def log(verdict, host, detail, method=""):
    ev = {"ts": time.strftime("%H:%M:%S"), "verdict": verdict, "host": host, "method": method, "detail": detail}
    with open(EVENTS, "a") as f:
        f.write(json.dumps(ev) + "\n")

def host_allowed(host, p):
    if p["mode"] != "allowlist":
        return True
    return any(host == d or host.endswith("." + d) for d in p["allowed_domains"])

def deny(flow, reason):
    flow.response = http.Response.make(403, f"Blocked by Agent Harness: {reason}", {"Content-Type": "text/plain"})

class Harness:
    # HTTPS: decided at CONNECT time from the hostname, no TLS interception needed
    def http_connect(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        if os.path.exists(STOP):
            deny(flow, "session stopped"); log("BLOCKED", host, "session stopped", "CONNECT"); return
        if not host_allowed(host, policy()):
            deny(flow, "domain not allowed"); log("BLOCKED", host, "domain not on allowlist", "CONNECT"); return
        log("ALLOWED", host, "tunnel opened", "CONNECT")

    # Decrypted / plain HTTP: also inspect the body for dangerous patterns
    def request(self, flow: http.HTTPFlow):
        if flow.request.method == "CONNECT":
            return
        host, p = flow.request.pretty_host, policy()
        if os.path.exists(STOP):
            deny(flow, "session stopped"); log("BLOCKED", host, "session stopped", flow.request.method); return
        if not host_allowed(host, p):
            deny(flow, "domain not allowed"); log("BLOCKED", host, "domain not on allowlist", flow.request.method); return
        text = flow.request.get_text(strict=False) or ""
        for pat in p["blocked_patterns"]:
            if pat in text or pat in flow.request.pretty_url:
                deny(flow, f"matched rule '{pat}'"); log("BLOCKED", host, f"matched rule '{pat}'", flow.request.method); return
        log("ALLOWED", host, flow.request.path[:80], flow.request.method)

addons = [Harness()]
