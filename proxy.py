"""Stdlib fallback network proxy for the A10 Agent Harness (Prompt 2).

The harness points the agent's HTTP_PROXY/HTTPS_PROXY at this proxy. The proxy
makes no policy decisions itself: for every request it asks the gateway
(POST /net/judge) and only forwards on "allow". mitmproxy (mitm_addon.py) is
the preferred proxy because it can decrypt HTTPS; this one is install-free.

  plain http://host/path  -> judged with method, URL, redacted headers, body
                             length, secret-pattern hits and a redacted body
                             sample; then forwarded, or 403 JSON with the reason
  CONNECT host:port       -> judged by host only (row 9 semantics: it cannot
                             see the method inside TLS); tunnel or 403

Gateway unreachable -> 403 (fails closed). With --demo-stubs (or
A10_DEMO_STUBS=1) requests to api.example.com are answered offline by
netcheck.demo_stub() after the gateway allows them.

Run:  python3 proxy.py [--port 8080] [--gateway http://127.0.0.1:8000] [--demo-stubs]
Stdlib only.
"""
import argparse
import json
import os
import socket
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import netcheck

DEFAULT_GATEWAY = os.environ.get("A10_GATEWAY_URL") or "http://127.0.0.1:8000"
JUDGE_TIMEOUT = 600  # the gateway may hold an "ask" for up to ~590 s
SOURCE = "proxy-stdlib"

_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate",
               "proxy-authorization", "te", "trailers", "trailer",
               "transfer-encoding", "upgrade", "proxy-connection"}
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _relay(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "A10Proxy/2"

    # -- helpers -----------------------------------------------------------

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _deny(self, verdict):
        self._send_json(403, {"blocked": True,
                              "verdict": verdict.get("verdict", "block"),
                              "reason": verdict.get("reason", "blocked"),
                              "row": verdict.get("row", "")})

    def _read_body(self):
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            chunks = []
            while True:
                line = self.rfile.readline(65537)
                if not line:
                    break
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    # consume trailers up to the blank line
                    while True:
                        t = self.rfile.readline(65537)
                        if not t or t in (b"\r\n", b"\n"):
                            break
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.readline(65537)  # CRLF after each chunk
            return b"".join(chunks)
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _judge(self, payload):
        status, body = netcheck.ask_gateway(self.server.gateway_url, "/net/judge",
                                            payload, timeout=JUDGE_TIMEOUT)
        if not isinstance(body, dict):
            body = {"verdict": "block", "reason": str(body)[:300]}
        if status != 200 or body.get("verdict") != "allow":
            body.setdefault("verdict", "block")
            if body["verdict"] == "allow":
                body["verdict"] = "block"
            body.setdefault("reason", "gateway refused (HTTP %s)" % status)
            return False, body
        return True, body

    # -- plain HTTP (absolute-URI) requests ---------------------------------

    def _forward(self):
        method = self.command
        parts = urlsplit(self.path)
        if not parts.scheme or not parts.hostname:
            self.send_error(400, "proxy requests need an absolute URI")
            return
        host = netcheck.normalize_host(parts.hostname)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        try:
            body = self._read_body()
        except (ValueError, OSError):
            self.send_error(400, "could not read request body")
            return
        text = body.decode("latin-1", "replace")
        hits = netcheck.find_secrets(self.path + "\n" + text)
        headers = {k: v for k, v in self.headers.items()}
        payload = {
            "source": SOURCE, "method": method, "url": self.path,
            "host": host, "port": port,
            "headers": netcheck.redact_headers(headers),
            "body_len": len(body), "secret_hits": hits,
            "body_sample": netcheck.redact_header_text(netcheck.redact_text(
                body[:200].decode("utf-8", "replace"))),
        }
        ok, verdict = self._judge(payload)
        if not ok:
            self._deny(verdict)
            return
        stub = netcheck.demo_stub(host, method, self.path, body,
                                  self.server.demo_stubs)
        if stub is not None:
            status, data = stub
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-A10-Demo-Stub", "1")
            self.send_header("Connection", "close")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(data)
            self.close_connection = True
            return
        req = urllib.request.Request(self.path, data=body if body else None,
                                     method=method)
        for k, v in headers.items():
            if k.lower() in _HOP_BY_HOP or k.lower() in ("host", "content-length"):
                continue
            req.add_header(k, v)
        try:
            with _NO_PROXY_OPENER.open(req, timeout=30) as resp:
                self._relay_response(resp.status, resp.headers, resp.read())
        except urllib.error.HTTPError as e:
            self._relay_response(e.code, e.headers, e.read())
        except Exception as e:  # noqa: BLE001
            self.send_error(502, "forward failed: %s" % e)

    def _relay_response(self, status, headers, data):
        self.send_response(status)
        for k, v in (headers.items() if headers else []):
            if k.lower() in _HOP_BY_HOP or k.lower() == "content-length":
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = \
        _forward

    # -- CONNECT tunnels -------------------------------------------------

    def do_CONNECT(self):
        host, port = netcheck.split_host_port(self.path)
        port = port or 443
        if not host:
            self.send_error(400, "bad CONNECT target")
            return
        payload = {"source": SOURCE, "method": "CONNECT",
                   "url": "https://%s" % host, "host": host, "port": port,
                   "headers": netcheck.redact_headers(dict(self.headers.items())),
                   "body_len": 0, "secret_hits": netcheck.find_secrets(host),
                   "body_sample": ""}
        ok, verdict = self._judge(payload)
        if not ok:
            self._deny(verdict)
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError as e:
            self.send_error(502, "upstream connect failed: %s" % e)
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self.close_connection = True
        t1 = threading.Thread(target=_relay, args=(self.connection, upstream),
                              daemon=True)
        t2 = threading.Thread(target=_relay, args=(upstream, self.connection),
                              daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        upstream.close()

    def log_message(self, *a):
        pass  # keep the terminal clean for the demo


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(gateway_url=DEFAULT_GATEWAY, host="127.0.0.1", port=8080,
                demo_stubs=False):
    server = ProxyServer((host, port), ProxyHandler)
    server.gateway_url = gateway_url
    server.demo_stubs = bool(demo_stubs)
    return server


def main(argv=None):
    p = argparse.ArgumentParser(description="A10 harness stdlib proxy")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--gateway", default=DEFAULT_GATEWAY)
    p.add_argument("--demo-stubs", action="store_true")
    args = p.parse_args(argv)
    demo = args.demo_stubs or netcheck.demo_stubs_from_env(os.environ)
    server = make_server(args.gateway, args.host, args.port, demo)
    print("Proxy on http://%s:%d/  gateway=%s  demo_stubs=%s"
          % (args.host, server.server_address[1], args.gateway, demo), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
