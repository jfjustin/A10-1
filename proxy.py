"""Network proxy for the A10 Agent Harness (Prompt 2).

Stdlib only. The CLI agent's egress runs through here (the harness sets
HTTP_PROXY/HTTPS_PROXY for the agent). The proxy does NOT make policy
decisions itself -- for every outbound request it asks the gateway
(POST /tool-call, tool "http_proxy"), which judges the host against the
same allowlist as tool calls. Allow -> forward; block -> 403 with reason.

  plain http://host/path  -> judged, then forwarded (or 403)
  CONNECT host:port      -> judged; allow opens a TCP tunnel, block closes

Run:  python3 proxy.py        (normally started by harness.py)
Listens on http://127.0.0.1:8080/
"""
import json
import socket
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

GATEWAY = "http://127.0.0.1:8000/tool-call"


def _judge(host, method="GET"):
    """Ask the gateway about a host. Direct call -- must bypass this proxy."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        GATEWAY,
        data=json.dumps({"tool": "http_proxy",
                         "args": {"host": host, "method": method},
                         "agent": "proxy"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with opener.open(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read() or b"{}")
        except Exception:
            return {"verdict": "block", "reason": "gateway judge failed"}
    except Exception as e:
        return {"verdict": "block", "reason": f"gateway unreachable: {e}"}


def _relay(src, dst):
    try:
        while True:
            data = src.recv(8192)
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
    def _deny(self, reason):
        body = json.dumps({"blocked": True, "reason": reason}).encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _forward(self, method):
        parts = urlsplit(self.path)
        host = parts.hostname
        if not host:
            self.send_error(400, "proxy requests need an absolute URI")
            return
        verdict = _judge(host, method)
        if verdict.get("verdict") != "allow":
            self._deny(verdict.get("reason", "blocked"))
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(self.path, data=body, method=method)
        for header in ("User-Agent", "Accept", "Content-Type"):
            if self.headers.get(header):
                req.add_header(header, self.headers.get(header))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=10) as resp:
                data = resp.read()
                self.send_response(resp.status)
                if resp.headers.get("Content-Type"):
                    self.send_header("Content-Type",
                                     resp.headers.get("Content-Type"))
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_error(502, f"forward failed: {e}")

    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def do_PUT(self):
        self._forward("PUT")

    def do_DELETE(self):
        self._forward("DELETE")

    def do_CONNECT(self):
        hostport = self.path
        host = hostport.split(":")[0]
        port = int(hostport.split(":")[1]) if ":" in hostport else 443
        verdict = _judge(host, "CONNECT")
        if verdict.get("verdict") != "allow":
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except Exception:
            self.send_error(502, "upstream connect failed")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        # This connection is now a raw tunnel; keep the handler from
        # trying to parse another request on it.
        self.close_connection = True
        t1 = threading.Thread(target=_relay,
                              args=(self.connection, upstream), daemon=True)
        t2 = threading.Thread(target=_relay,
                              args=(upstream, self.connection), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        upstream.close()

    def log_message(self, *a):
        pass  # keep the terminal clean for the demo


if __name__ == "__main__":
    print("Proxy on http://127.0.0.1:8080/  (Ctrl-C to stop)")
    ThreadingHTTPServer(("127.0.0.1", 8080), ProxyHandler).serve_forever()
