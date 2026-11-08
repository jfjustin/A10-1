"""mitmproxy addon for the A10 Agent Harness (Prompt 2).

harness.py starts mitmdump with this script for `--proxy mitm` (and for
`--proxy auto` when mitmdump is on PATH):

  mitmdump --listen-host 127.0.0.1 --listen-port 8080 \\
      --set confdir=~/.a10-harness/mitmproxy --set connection_strategy=lazy \\
      -q -s mitm_addon.py

Every decrypted request is sent to the gateway (POST /net/judge, source
"proxy-mitm") before mitmproxy opens the upstream connection (lazy strategy),
so a blocked request never leaves the machine:

  allow  -> the request goes upstream unchanged, or gets the offline demo stub
            for api.example.com when demo stubs are on
  block, deny, expired, stopped, or the gateway is unreachable
         -> 403 JSON {"blocked": true, "verdict", "reason", "row"} (fails closed)

Authorization, Proxy-Authorization, x-api-key and cookie values are redacted
before they reach the gateway. The request is judged by the host mitmproxy
will actually connect to (flow.request.host), not by the Host header, which
the agent controls.

Raw TCP through the proxy (non-HTTP data in a CONNECT tunnel) is judged by
host, like the stdlib proxy's CONNECT, and its data is dropped when blocked.
A TLS handshake the client rejects (certificate pinning, or a client that
ignores the CA env vars) is reported to the gateway as an informational event
(POST /net/note); mitmproxy has already closed that connection.

Environment: A10_GATEWAY_URL (default http://127.0.0.1:8000), A10_DEMO_STUBS=1
(serve api.example.com offline after the gateway allows it), A10_APPROVAL_WAIT
(seconds the gateway may hold an "ask"; the addon waits a little longer).

This is the only harness module that uses mitmproxy, and it imports it lazily,
so `python3 -c 'import mitm_addon'` works without mitmproxy installed. Gateway
calls run in a worker thread (asyncio.to_thread) so a pending approval does
not block mitmproxy's event loop.
"""
import asyncio
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import netcheck  # noqa: E402

SOURCE = "proxy-mitm"
DEFAULT_GATEWAY = "http://127.0.0.1:8000"
DEFAULT_APPROVAL_WAIT = 590.0
WAIT_MARGIN = 15.0      # extra seconds on top of the gateway's approval wait
NOTE_TIMEOUT = 3.0
SAMPLE_LEN = 200
BLOCK_KEY = "a10_blocked"


def _mitm_make_response(status, body, headers):
    from mitmproxy import http  # lazy: only available inside mitmdump
    return http.Response.make(status, body, headers)


def _text(value):
    if isinstance(value, bytes):
        return value.decode("latin-1", "replace")
    return "" if value is None else str(value)


def headers_dict(headers):
    """Plain dict from mitmproxy Headers (or any mapping). Repeated fields are
    joined with ', ' so none of them escapes redaction."""
    out = {}
    if headers is None:
        return out
    try:
        items = headers.items(multi=True)
    except TypeError:
        items = headers.items()
    for k, v in items:
        k, v = _text(k), _text(v)
        out[k] = out[k] + ", " + v if k in out else v
    return out


def _body(req):
    """Request body bytes, or None when mitmproxy did not buffer it."""
    try:
        data = req.get_content(strict=False)
    except Exception:  # noqa: BLE001 - undecodable content: use the raw bytes
        data = getattr(req, "raw_content", None)
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return data


def verdict_of(status, body):
    """(allowed, verdict_dict) from an ask_gateway() result. Anything other
    than HTTP 200 with verdict "allow" is a block."""
    if not isinstance(body, dict):
        body = {"verdict": "block", "reason": _text(body)[:300]}
    if status == 200 and body.get("verdict") == "allow":
        return True, body
    body = dict(body)
    if body.get("verdict") in (None, "", "allow"):
        body["verdict"] = "block"
    body.setdefault("reason", "gateway refused (HTTP %s)" % status)
    return False, body


class A10Gate:
    """mitmproxy addon: judge each request at the gateway, fail closed."""

    def __init__(self, gateway_url=None, demo_stubs=None, approval_wait=None,
                 ask=None, make_response=None, environ=None):
        env = os.environ if environ is None else environ
        self.gateway_url = (gateway_url or env.get("A10_GATEWAY_URL")
                            or DEFAULT_GATEWAY)
        self.demo_stubs = (netcheck.demo_stubs_from_env(env)
                           if demo_stubs is None else bool(demo_stubs))
        wait = approval_wait if approval_wait is not None else env.get(
            "A10_APPROVAL_WAIT")
        try:
            wait = float(wait)
        except (TypeError, ValueError):
            wait = DEFAULT_APPROVAL_WAIT
        self.timeout = max(wait, 1.0) + WAIT_MARGIN
        self.ask = ask or netcheck.ask_gateway
        self.make_response = make_response or _mitm_make_response

    # -- gateway calls -------------------------------------------------------

    async def _call(self, path, payload, timeout):
        try:
            return await asyncio.to_thread(self.ask, self.gateway_url, path,
                                           payload, timeout=timeout)
        except Exception as e:  # noqa: BLE001 - fail closed
            return 0, {"verdict": "block", "row": "",
                       "reason": "gateway unreachable: %s" % e}

    async def judge(self, payload):
        status, body = await self._call("/net/judge", payload, self.timeout)
        return verdict_of(status, body)

    # -- payloads ------------------------------------------------------------

    def payload_for(self, req):
        method = _text(getattr(req, "method", "") or "GET").upper()
        host = netcheck.normalize_host(_text(
            getattr(req, "host", "") or getattr(req, "pretty_host", "")))
        port = getattr(req, "port", None)
        url = _text(getattr(req, "url", "") or getattr(req, "pretty_url", ""))
        body = _body(req)
        unknown_body = body is None
        body = body or b""
        text = body.decode("latin-1", "replace")
        return {
            "source": SOURCE, "method": method, "url": url, "host": host,
            "port": port,
            "headers": netcheck.redact_headers(headers_dict(
                getattr(req, "headers", None))),
            # a body mitmproxy did not buffer counts as present (fail closed)
            "body_len": 1 if unknown_body else len(body),
            "secret_hits": netcheck.find_secrets(url + "\n" + text),
            "body_sample": netcheck.redact_header_text(netcheck.redact_text(
                body[:SAMPLE_LEN].decode("utf-8", "replace"))),
        }

    def _json_response(self, status, obj, extra=None):
        headers = {"Content-Type": "application/json"}
        headers.update(extra or {})
        return self.make_response(status, json.dumps(obj).encode(), headers)

    def blocked_response(self, verdict):
        return self._json_response(403, {
            "blocked": True, "verdict": verdict.get("verdict", "block"),
            "reason": verdict.get("reason", "blocked"),
            "row": verdict.get("row", "")})

    # -- mitmproxy hooks -----------------------------------------------------

    async def request(self, flow):
        req = flow.request
        payload = self.payload_for(req)
        try:
            ok, verdict = await self.judge(payload)
            if not ok:
                flow.response = self.blocked_response(verdict)
                return
            stub = netcheck.demo_stub(payload["host"], payload["method"],
                                      payload["url"], _body(req) or b"",
                                      self.demo_stubs)
            if stub is not None:
                status, data = stub
                flow.response = self.make_response(
                    status, data, {"Content-Type": "application/json",
                                   "X-A10-Demo-Stub": "1"})
        except Exception as e:  # noqa: BLE001 - never let a request through on error
            flow.response = self.blocked_response(
                {"verdict": "block", "row": "",
                 "reason": "harness addon error: %s" % e})

    async def tcp_start(self, flow):
        """Raw TCP in a CONNECT tunnel: judge by host (row 9 semantics, the
        method is unknown); on block kill the flow and drop its data."""
        addr = getattr(getattr(flow, "server_conn", None), "address", None)
        host, port = (addr[0], addr[1]) if addr else ("", None)
        host = netcheck.normalize_host(_text(host))
        payload = {"source": SOURCE, "method": "CONNECT",
                   "url": "tcp://%s:%s" % (host, port), "host": host,
                   "port": port, "headers": {}, "body_len": 0,
                   "secret_hits": netcheck.find_secrets(host),
                   "body_sample": ""}
        try:
            ok, verdict = await self.judge(payload)
        except Exception as e:  # noqa: BLE001
            ok, verdict = False, {"reason": "harness addon error: %s" % e}
        if not ok:
            metadata = getattr(flow, "metadata", None)
            if isinstance(metadata, dict):
                metadata[BLOCK_KEY] = verdict.get("reason", "blocked")
            try:
                flow.kill()
            except Exception:  # noqa: BLE001 - data is still dropped below
                pass

    def tcp_message(self, flow):
        """Drop every message of a TCP flow the gateway blocked."""
        metadata = getattr(flow, "metadata", None)
        if isinstance(metadata, dict) and metadata.get(BLOCK_KEY):
            messages = getattr(flow, "messages", None) or []
            if messages:
                messages[-1].content = b""

    async def tls_failed_client(self, data):
        """Informational: the client rejected our certificate. Not a block
        (mitmproxy already closed the connection), just visible to the
        operator."""
        try:
            ctx = getattr(data, "context", None)
            client = getattr(ctx, "client", None) or getattr(data, "conn", None)
            host = _text(getattr(client, "sni", None))
            if not host:
                addr = getattr(getattr(ctx, "server", None), "address", None)
                host = _text(addr[0]) if addr else "unknown host"
            err = _text(getattr(getattr(data, "conn", None), "error", None))
            msg = ("TLS interception failed for %s: the client did not accept "
                   "the harness CA (certificate pinning, or it ignores "
                   "SSL_CERT_FILE / NODE_EXTRA_CA_CERTS); the connection was "
                   "closed" % netcheck.normalize_host(host))
            if err:
                msg += " (%s)" % err[:160]
            await self._call("/net/note", {"source": SOURCE, "host": host,
                                           "message": msg}, NOTE_TIMEOUT)
        except Exception:  # noqa: BLE001 - informational only
            pass


addons = [A10Gate()]
