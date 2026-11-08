"""Shared fixtures for the gateway / proxy / console / e2e tests.

Everything runs in-process on ephemeral ports (port 0) with a temp A10_HOME,
a temp audit log and a temp copy of demo-files. Never touches ports 8000/8080,
~/.a10-harness or the repo's audit.log.jsonl.
"""
import http.client
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS_DIR)
for _p in (ROOT, TESTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gateway  # noqa: E402
import proxy  # noqa: E402

TOKEN = "test-operator-token-0123456789"
HARNESS = os.path.join(ROOT, "harness.py")


def free_port():
    """An ephemeral port that is free right now (for harness subprocesses,
    which need the port number up front)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def write_executable(path, text):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o755)
    return path


def read_audit(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


class Response:
    def __init__(self, status, headers, text):
        self.status = status
        self.headers = headers
        self.text = text

    @property
    def verdict(self):
        return self.headers.get("x-a10-verdict", "")

    def json(self):
        return json.loads(self.text or "null")


def request(port, method, path, payload=None, headers=None, host=None,
            timeout=30):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    hdrs = {"Content-Type": "application/json"}
    if host is not None:
        hdrs["Host"] = host
    hdrs.update(headers or {})
    body = None if payload is None else json.dumps(payload)
    try:
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        text = resp.read().decode("utf-8", "replace")
        return Response(resp.status, {k.lower(): v for k, v in resp.getheaders()},
                        text)
    finally:
        conn.close()


class GatewayFixture:
    def __init__(self, mode="default", approval_wait=30.0, token=TOKEN):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = os.path.realpath(self._tmp.name)
        self.a10_home = os.path.join(self.base, "a10home")
        os.makedirs(self.a10_home, mode=0o700)
        self.cwd = os.path.join(self.base, "work")
        self.workspace = os.path.join(self.cwd, "demo-files")
        os.makedirs(self.workspace)
        shutil.copy(os.path.join(ROOT, "demo-files", "notes.txt"),
                    os.path.join(self.workspace, "notes.txt"))
        self.audit_path = os.path.join(self.base, "audit.log.jsonl")
        self.token = token
        settings = gateway.build_settings(self.workspace, self.cwd, self.a10_home,
                                          self.audit_path)
        self.app = gateway.GatewayApp(settings, self.audit_path, token, mode=mode,
                                      approval_wait=approval_wait)
        self.server = gateway.make_server(self.app, "127.0.0.1", 0)
        self.port = self.app.port
        self.url = "http://127.0.0.1:%d" % self.port
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        kwargs={"poll_interval": 0.05},
                                        daemon=True)
        self._thread.start()

    def close(self):
        self.app.close()
        self.server.shutdown()
        self.server.server_close()
        self._tmp.cleanup()

    # -- HTTP helpers ------------------------------------------------------

    def get(self, path, **kw):
        return request(self.port, "GET", path, **kw)

    def post(self, path, payload=None, token=None, **kw):
        headers = dict(kw.pop("headers", {}) or {})
        if token:
            headers["X-A10-Operator-Token"] = token
        return request(self.port, "POST", path, payload or {}, headers=headers,
                       **kw)

    def op(self, path, payload=None):
        return self.post(path, payload, token=self.token)

    def hook(self, tool, tool_input, event="pre_tool_use", **extra):
        payload = {"tool_name": tool, "tool_input": tool_input, "event": event}
        payload.update(extra)
        return self.post("/hooks/oh", {"event": event, "payload": payload},
                         headers={"X-A10-Agent": "test-agent"})

    def bash(self, command):
        return self.hook("bash", {"command": command})

    def write(self, rel, content="x"):
        return self.hook("write_file", {"path": "demo-files/" + rel,
                                        "content": content})

    def events(self):
        return self.get("/events?since=0").json()

    def status(self):
        return self.get("/status").json()

    def pending(self):
        return self.get("/pending").json()

    def wait_pending(self, count=1, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            items = self.pending()
            if len(items) >= count:
                return items
            time.sleep(0.02)
        raise AssertionError("no pending item after %s s" % timeout)

    def in_thread(self, fn, *args):
        """Run fn(*args) in a thread; returns (thread, result_holder)."""
        box = {}

        def target():
            box["result"] = fn(*args)

        t = threading.Thread(target=target, daemon=True)
        t.start()
        return t, box


class ProxyFixture:
    def __init__(self, gateway_url, demo_stubs=True):
        self.server = proxy.make_server(gateway_url, "127.0.0.1", 0, demo_stubs)
        self.port = self.server.server_address[1]
        self.url = "http://127.0.0.1:%d" % self.port
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        kwargs={"poll_interval": 0.05},
                                        daemon=True)
        self._thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def request(self, method, url, body=None, headers=None, timeout=30):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request(method, url, body=body, headers=headers or {})
            resp = conn.getresponse()
            text = resp.read().decode("utf-8", "replace")
            return Response(resp.status,
                            {k.lower(): v for k, v in resp.getheaders()}, text)
        finally:
            conn.close()
