"""mitm_addon.A10Gate with fake mitmproxy flow objects (mitmproxy is not
installed here): demo stubs, blocks with the gateway's reason, header
redaction, fail-closed on gateway errors, judging by the real destination
host, the non-blocking gateway call, raw TCP and TLS-failure hooks, plus an
end-to-end variant against an in-thread gateway with the real
netcheck.ask_gateway. A test that uses mitmproxy's own test helpers is
skipped unless mitmproxy is importable.
"""
import asyncio
import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _support import ROOT, GatewayFixture  # noqa: E402

import mitm_addon  # noqa: E402

HAVE_MITMPROXY = importlib.util.find_spec("mitmproxy") is not None
SECRET_HEADERS = {"Authorization": "Bearer tok-authz-5f1e2d3c4b",
                  "x-api-key": "xkey-9a8b7c6d5e4f",
                  "Cookie": "session=cookieval-123abc"}
SECRET_VALUES = ("tok-authz-5f1e2d3c4b", "xkey-9a8b7c6d5e4f", "cookieval-123abc")
ALLOW = (200, {"verdict": "allow", "row": "8", "reason": "row 8"})
BLOCK_20 = (403, {"verdict": "block", "row": "20",
                  "reason": "BLOCKED by A10 harness: row 20 (Send data to a "
                            "non-allowlisted host) is ⛔ in default mode"})


class FakeRequest:
    """The attributes of mitmproxy.http.Request the addon reads."""

    def __init__(self, method, url, headers=None, content=b"", host_header=None):
        parts = urlsplit(url)
        self.method = method
        self.url = url
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.pretty_host = host_header or self.host
        self.pretty_url = (url.replace(self.host, host_header, 1)
                           if host_header else url)
        self.headers = dict(headers or {})
        if host_header:
            self.headers["Host"] = host_header
        self._content = content

    def get_content(self, strict=True):
        return self._content


class FakeResponse:
    def __init__(self, status, body, headers):
        self.status = status
        self.body = body
        self.headers = dict(headers)

    def json(self):
        return json.loads(self.body)


class FakeFlow:
    def __init__(self, request):
        self.request = request
        self.response = None


class FakeAsk:
    def __init__(self, result=ALLOW, exc=None, delay=0.0, log=None):
        self.result = result
        self.exc = exc
        self.delay = delay
        self.log = log
        self.calls = []

    def __call__(self, gateway_url, path, payload=None, timeout=10, **kw):
        self.calls.append({"url": gateway_url, "path": path,
                           "payload": payload, "timeout": timeout})
        if self.delay:
            time.sleep(self.delay)
        if self.log is not None:
            self.log.append("ask-done")
        if self.exc is not None:
            raise self.exc
        return self.result


def make_response(status, body, headers):
    return FakeResponse(status, body, headers)


def gate(ask, demo_stubs=True, **kw):
    return mitm_addon.A10Gate(gateway_url="http://127.0.0.1:1",
                              demo_stubs=demo_stubs, approval_wait=5, ask=ask,
                              make_response=make_response, **kw)


def run_request(addon, method, url, **kw):
    flow = FakeFlow(FakeRequest(method, url, **kw))
    asyncio.run(addon.request(flow))
    return flow


class ImportTest(unittest.TestCase):
    def test_imports_without_mitmproxy(self):
        r = subprocess.run(
            [sys.executable, "-c",
             "import sys, mitm_addon; print(len(mitm_addon.addons), "
             "'mitmproxy' in sys.modules)"],
            cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split(), ["1", "False"])
        self.assertIsInstance(mitm_addon.addons[0], mitm_addon.A10Gate)

    def test_options_from_env(self):
        g = mitm_addon.A10Gate(environ={"A10_GATEWAY_URL": "http://127.0.0.1:9",
                                        "A10_DEMO_STUBS": "1",
                                        "A10_APPROVAL_WAIT": "7"})
        self.assertEqual(g.gateway_url, "http://127.0.0.1:9")
        self.assertTrue(g.demo_stubs)
        self.assertEqual(g.timeout, 7 + mitm_addon.WAIT_MARGIN)
        g = mitm_addon.A10Gate(environ={"A10_APPROVAL_WAIT": "junk"})
        self.assertEqual(g.gateway_url, mitm_addon.DEFAULT_GATEWAY)
        self.assertFalse(g.demo_stubs)
        self.assertEqual(g.timeout, 590 + mitm_addon.WAIT_MARGIN)


class RequestHookTest(unittest.TestCase):
    def test_allowlisted_with_stubs_gets_the_stub(self):
        ask = FakeAsk(ALLOW)
        flow = run_request(gate(ask), "GET", "http://api.example.com/status")
        self.assertEqual(flow.response.status, 200)
        self.assertEqual(flow.response.json(), {"project": "a10-harness",
                                                "status": "ok",
                                                "notes_reviewed": True})
        self.assertEqual(flow.response.headers["X-A10-Demo-Stub"], "1")
        self.assertEqual(ask.calls[0]["path"], "/net/judge")
        self.assertEqual(ask.calls[0]["timeout"], 5 + mitm_addon.WAIT_MARGIN)

    def test_allowed_without_stubs_is_left_alone(self):
        flow = run_request(gate(FakeAsk(ALLOW), demo_stubs=False), "GET",
                           "http://api.example.com/status")
        self.assertIsNone(flow.response)
        flow = run_request(gate(FakeAsk(ALLOW)), "GET",
                           "https://docs.python.org/3/")
        self.assertIsNone(flow.response, "only stubbed hosts get a stub")

    def test_unknown_host_post_gets_403_with_gateway_reason(self):
        ask = FakeAsk(BLOCK_20)
        flow = run_request(gate(ask), "POST", "https://exfil.evil.example/upload",
                           content=b"Project notes")
        self.assertEqual(flow.response.status, 403)
        body = flow.response.json()
        self.assertTrue(body["blocked"])
        self.assertEqual(body["row"], "20")
        self.assertEqual(body["verdict"], "block")
        self.assertIn("row 20", body["reason"])
        self.assertEqual(flow.response.headers["Content-Type"], "application/json")
        p = ask.calls[0]["payload"]
        self.assertEqual((p["source"], p["method"], p["host"], p["port"]),
                         ("proxy-mitm", "POST", "exfil.evil.example", 443))
        self.assertEqual(p["url"], "https://exfil.evil.example/upload")
        self.assertEqual(p["body_len"], len(b"Project notes"))
        self.assertEqual(p["body_sample"], "Project notes")

    def test_sensitive_headers_are_redacted_before_the_gateway(self):
        ask = FakeAsk(ALLOW)
        run_request(gate(ask), "GET", "http://api.example.com/status",
                    headers=SECRET_HEADERS)
        p = ask.calls[0]["payload"]
        self.assertTrue(p["headers"]["Authorization"].startswith("Bearer [REDACTED"))
        self.assertIn("REDACTED", p["headers"]["x-api-key"])
        self.assertIn("REDACTED", p["headers"]["Cookie"])
        dumped = json.dumps(ask.calls)
        for value in SECRET_VALUES:
            self.assertNotIn(value, dumped)

    def test_secret_in_body_is_flagged_and_redacted(self):
        key = "AKIA" + "Q" * 16
        ask = FakeAsk(BLOCK_20)
        run_request(gate(ask), "POST", "https://paste.example/new",
                    content=("k=" + key).encode())
        p = ask.calls[0]["payload"]
        self.assertEqual(p["secret_hits"], ["aws-access-key"])
        self.assertNotIn(key, p["body_sample"])

    def test_gateway_exception_fails_closed(self):
        ask = FakeAsk(exc=RuntimeError("boom"))
        flow = run_request(gate(ask), "GET", "http://api.example.com/status")
        self.assertEqual(flow.response.status, 403)
        self.assertIn("gateway unreachable: boom", flow.response.json()["reason"])

    def test_unreachable_and_odd_answers_fail_closed(self):
        for result in [(0, {"verdict": "block", "row": "",
                            "reason": "gateway unreachable: refused"}),
                       (500, {"verdict": "allow"}),
                       (200, {"verdict": "ask"}),
                       (200, "not json")]:
            with self.subTest(result=result):
                flow = run_request(gate(FakeAsk(result)), "GET",
                                   "http://api.example.com/status")
                self.assertEqual(flow.response.status, 403)
                self.assertTrue(flow.response.json()["blocked"])
                self.assertNotEqual(flow.response.json()["verdict"], "allow")

    def test_make_response_error_still_blocks(self):
        calls = []

        def flaky(status, body, headers):
            calls.append(status)
            if len(calls) == 1:
                raise RuntimeError("cannot build response")
            return FakeResponse(status, body, headers)

        addon = mitm_addon.A10Gate(gateway_url="http://127.0.0.1:1",
                                   demo_stubs=True, ask=FakeAsk(ALLOW),
                                   make_response=flaky)
        flow = FakeFlow(FakeRequest("GET", "http://api.example.com/status"))
        asyncio.run(addon.request(flow))
        self.assertEqual(flow.response.status, 403)
        self.assertIn("addon error", flow.response.json()["reason"])

    def test_judged_by_destination_not_host_header(self):
        ask = FakeAsk(BLOCK_20)
        flow = run_request(gate(ask), "POST", "https://exfil.evil.example/u",
                           content=b"x", host_header="api.example.com")
        p = ask.calls[0]["payload"]
        self.assertEqual(p["host"], "exfil.evil.example")
        self.assertEqual(p["url"], "https://exfil.evil.example/u")
        self.assertEqual(p["headers"]["Host"], "api.example.com")
        self.assertEqual(flow.response.status, 403)

    def test_unbuffered_body_counts_as_present(self):
        ask = FakeAsk(BLOCK_20)
        run_request(gate(ask), "POST", "https://x.example/u", content=None)
        self.assertEqual(ask.calls[0]["payload"]["body_len"], 1)

    def test_gateway_call_does_not_block_the_event_loop(self):
        log = []
        ask = FakeAsk(ALLOW, delay=0.4, log=log)
        addon = gate(ask)
        flow = FakeFlow(FakeRequest("GET", "http://api.example.com/status"))

        async def ticker():
            for _ in range(5):
                await asyncio.sleep(0.02)
            log.append("tick-done")

        async def main():
            await asyncio.gather(addon.request(flow), ticker())

        asyncio.run(main())
        self.assertEqual(log, ["tick-done", "ask-done"])
        self.assertEqual(flow.response.status, 200)


class FakeServerConn:
    def __init__(self, address):
        self.address = address


class FakeTcpMessage:
    def __init__(self, content):
        self.content = content


class FakeTcpFlow:
    def __init__(self, host, port):
        self.server_conn = FakeServerConn((host, port))
        self.metadata = {}
        self.messages = []
        self.killed = False

    def kill(self):
        self.killed = True


class FakeClient:
    def __init__(self, sni):
        self.sni = sni
        self.error = "certificate unknown"


class FakeContext:
    def __init__(self, sni, address):
        self.client = FakeClient(sni)
        self.server = FakeServerConn(address)


class FakeTlsData:
    def __init__(self, sni, address=("203.0.113.9", 443)):
        self.context = FakeContext(sni, address)
        self.conn = self.context.client


class OtherHooksTest(unittest.TestCase):
    def test_blocked_raw_tcp_is_killed_and_its_data_dropped(self):
        ask = FakeAsk((403, {"verdict": "block", "row": "9",
                             "reason": "row 9 asks; denied"}))
        flow = FakeTcpFlow("git.example.org", 22)
        asyncio.run(gate(ask).tcp_start(flow))
        p = ask.calls[0]["payload"]
        self.assertEqual((p["method"], p["host"], p["port"]),
                         ("CONNECT", "git.example.org", 22))
        self.assertTrue(flow.killed)
        flow.messages.append(FakeTcpMessage(b"SSH-2.0-client"))
        gate(ask).tcp_message(flow)
        self.assertEqual(flow.messages[-1].content, b"")

    def test_allowed_raw_tcp_passes(self):
        flow = FakeTcpFlow("api.example.com", 443)
        asyncio.run(gate(FakeAsk(ALLOW)).tcp_start(flow))
        self.assertFalse(flow.killed)
        flow.messages.append(FakeTcpMessage(b"data"))
        gate(FakeAsk(ALLOW)).tcp_message(flow)
        self.assertEqual(flow.messages[-1].content, b"data")

    def test_tls_failure_is_reported_as_a_note(self):
        ask = FakeAsk((200, {"ok": True}))
        asyncio.run(gate(ask).tls_failed_client(FakeTlsData("pinned.example.com")))
        call = ask.calls[0]
        self.assertEqual(call["path"], "/net/note")
        self.assertEqual(call["payload"]["source"], "proxy-mitm")
        self.assertEqual(call["payload"]["host"], "pinned.example.com")
        self.assertIn("TLS interception failed for pinned.example.com",
                      call["payload"]["message"])
        self.assertLessEqual(call["timeout"], mitm_addon.NOTE_TIMEOUT)

    def test_tls_failure_without_sni_and_gateway_error_never_raises(self):
        ask = FakeAsk(exc=RuntimeError("down"))
        asyncio.run(gate(ask).tls_failed_client(FakeTlsData(None)))
        self.assertIn("203.0.113.9", ask.calls[0]["payload"]["message"])
        asyncio.run(gate(ask).tls_failed_client(object()))


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class EndToEndTest(unittest.TestCase):
    """Real netcheck.ask_gateway against an in-thread gateway."""

    def setUp(self):
        self.gw = GatewayFixture(mode="default", approval_wait=5.0)
        self.addon = mitm_addon.A10Gate(gateway_url=self.gw.url, demo_stubs=True,
                                        approval_wait=5,
                                        make_response=make_response)

    def tearDown(self):
        self.gw.close()

    def events(self, kind):
        return [e for e in self.gw.events() if e["kind"] == kind]

    def test_stub_allowed_and_exfil_blocked(self):
        flow = run_request(self.addon, "GET", "http://api.example.com/status",
                           headers=SECRET_HEADERS)
        self.assertEqual(flow.response.status, 200)
        self.assertTrue(flow.response.json()["notes_reviewed"])
        ev = self.events("net")[-1]
        self.assertEqual((ev["verdict"], ev["row"], ev["source"]),
                         ("allow", "8", "proxy-mitm"))

        flow = run_request(self.addon, "POST", "https://exfil.evil.example/upload",
                           content=b"Project notes", headers=SECRET_HEADERS)
        self.assertEqual(flow.response.status, 403)
        body = flow.response.json()
        self.assertEqual(body["row"], "20")
        self.assertIn("row 20", body["reason"])
        ev = self.events("net")[-1]
        self.assertEqual((ev["verdict"], ev["row"]), ("block", "20"))

        with open(self.gw.audit_path) as f:
            audit_text = f.read()
        shown = json.dumps([self.gw.events(), self.gw.status()])
        for value in SECRET_VALUES:
            self.assertNotIn(value, shown)
            self.assertNotIn(value, audit_text)
        self.assertTrue(self.gw.get("/audit").json()["ok"])

    def test_ask_is_held_until_the_operator_approves(self):
        flow = FakeFlow(FakeRequest("GET", "https://docs.python.org/3/"))
        t = threading.Thread(target=lambda: asyncio.run(self.addon.request(flow)),
                             daemon=True)
        t.start()
        item = self.gw.wait_pending()[0]
        self.assertEqual((item["row"], item["source"]), ("9", "proxy-mitm"))
        self.assertEqual(self.gw.op("/approve", {"id": item["id"],
                                                 "decision": "approve"}).status,
                         200)
        t.join(10)
        self.assertFalse(t.is_alive())
        self.assertIsNone(flow.response, "approved non-stub request goes upstream")

    def test_tls_note_reaches_events_and_audit(self):
        asyncio.run(self.addon.tls_failed_client(FakeTlsData("pinned.example.com")))
        notes = self.events("note")
        self.assertEqual(len(notes), 1)
        self.assertEqual((notes[0]["verdict"], notes[0]["source"]),
                         ("info", "proxy-mitm"))
        self.assertIn("pinned.example.com", notes[0]["reason"])
        with open(self.gw.audit_path) as f:
            self.assertIn('"net_note"', f.read())
        self.assertEqual(self.gw.status()["counts"]["block"], 0)

    def test_gateway_down_fails_closed(self):
        addon = mitm_addon.A10Gate(gateway_url="http://127.0.0.1:%d" % closed_port(),
                                   demo_stubs=True, make_response=make_response)
        flow = run_request(addon, "GET", "http://api.example.com/status")
        self.assertEqual(flow.response.status, 403)
        self.assertIn("gateway unreachable", flow.response.json()["reason"])


class NetNoteEndpointTest(unittest.TestCase):
    def setUp(self):
        self.gw = GatewayFixture()

    def tearDown(self):
        self.gw.close()

    def test_note_is_capped_scrubbed_and_rate_limited(self):
        key = "AKIA" + "Z" * 16
        r = self.gw.post("/net/note", {"source": "proxy-mitm", "host": "X.Example.",
                                       "message": key + " " + "m" * 1000})
        self.assertEqual(r.status, 200)
        ev = [e for e in self.gw.events() if e["kind"] == "note"][-1]
        self.assertEqual(ev["args"]["host"], "x.example")
        self.assertLessEqual(len(ev["reason"]), 300)
        self.assertNotIn(key, ev["reason"])
        r = self.gw.post("/net/note", {"source": "evil", "message": "x"})
        self.assertEqual(r.status, 200)
        self.assertEqual([e for e in self.gw.events()
                          if e["kind"] == "note"][-1]["source"], "proxy-stdlib")
        statuses = [self.gw.post("/net/note", {"message": "n%d" % i}).status
                    for i in range(40)]
        self.assertIn(429, statuses)
        self.assertLessEqual(len([e for e in self.gw.events()
                                  if e["kind"] == "note"]), 30)
        self.assertFalse(self.gw.status()["stopped"])


@unittest.skipUnless(HAVE_MITMPROXY, "mitmproxy not installed (pip install mitmproxy)")
class RealMitmproxyTest(unittest.TestCase):
    """Loads mitm_addon.py the way mitmdump does and uses real mitmproxy flows
    and http.Response.make. Needs `pip install mitmproxy`."""

    def test_script_blocks_with_real_flow_objects(self):
        from mitmproxy.test import taddons, tflow

        async def go():
            with taddons.context() as tctx:
                addon = tctx.script(os.path.join(ROOT, "mitm_addon.py"))
                addon.ask = FakeAsk(BLOCK_20)
                f = tflow.tflow()
                f.request.method = "POST"
                f.request.host = "exfil.evil.example"
                f.request.headers["Authorization"] = "Bearer tok-authz-5f1e2d3c4b"
                f.request.content = b"Project notes"
                await addon.request(f)
                return f, addon.ask

        f, ask = asyncio.run(go())
        self.assertEqual(f.response.status_code, 403)
        self.assertEqual(json.loads(f.response.content)["row"], "20")
        payload = ask.calls[0]["payload"]
        self.assertEqual(payload["host"], "exfil.evil.example")
        self.assertNotIn("tok-authz-5f1e2d3c4b", json.dumps(payload))

    def test_stub_with_real_flow_objects(self):
        from mitmproxy.test import taddons, tflow

        async def go():
            with taddons.context():
                addon = mitm_addon.A10Gate(gateway_url="http://127.0.0.1:1",
                                           demo_stubs=True, ask=FakeAsk(ALLOW))
                f = tflow.tflow()
                f.request.host = "api.example.com"
                f.request.path = "/status"
                await addon.request(f)
                return f

        f = asyncio.run(go())
        self.assertEqual(f.response.status_code, 200)
        self.assertTrue(json.loads(f.response.content)["notes_reviewed"])


if __name__ == "__main__":
    unittest.main()
