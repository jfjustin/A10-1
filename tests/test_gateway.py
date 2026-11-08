"""Gateway v2 tests: oh hook verdicts, blocking approvals, expiry, operator
token, mode/override/stop, Host guard, taint, redaction and the audit chain.

In-thread gateway on port 0 with a temp A10_HOME and audit log.
"""
import hashlib
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _support  # noqa: E402
from _support import GatewayFixture  # noqa: E402

import audit  # noqa: E402
import netcheck  # noqa: E402


class GatewayTestBase(unittest.TestCase):
    mode = "default"
    approval_wait = 30.0

    def setUp(self):
        self.gw = GatewayFixture(mode=self.mode, approval_wait=self.approval_wait)

    def tearDown(self):
        self.gw.close()

    def assertAuditOk(self):
        a = self.gw.get("/audit").json()
        self.assertTrue(a["ok"], a)
        self.assertEqual(audit.verify_file(self.gw.audit_path)[0], True)


class HookVerdictTest(GatewayTestBase):
    def test_allow_read_only_shell(self):
        r = self.gw.bash("ls demo-files")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.json(), {"ok": True})
        self.assertEqual(r.verdict, "allow")
        ev = self.gw.events()[-1]
        self.assertEqual((ev["verdict"], ev["row"], ev["source"]),
                         ("allow", "5", "test-agent"))
        self.assertAuditOk()

    def test_rm_is_blocked_with_row_28_text(self):
        r = self.gw.bash("rm demo-files/notes.txt")
        self.assertEqual(r.status, 403)
        self.assertEqual(r.verdict, "block")
        self.assertTrue(r.headers["content-type"].startswith("text/plain"))
        self.assertIn("row 28", r.text)
        self.assertIn("BLOCKED by A10 harness", r.text)
        self.assertIn("rm in 'rm demo-files/notes.txt'", r.text)
        self.assertAuditOk()

    def test_write_waits_for_approval(self):
        t, box = self.gw.in_thread(self.gw.write, "summary.md", "# hi\n")
        items = self.gw.wait_pending()
        self.assertEqual(items[0]["row"], "3")
        self.assertTrue(t.is_alive(), "hook should be held until approval")
        r = self.gw.op("/approve", {"id": items[0]["id"], "decision": "approve"})
        self.assertEqual(r.status, 200)
        t.join(5)
        res = box["result"]
        self.assertEqual((res.status, res.verdict), (200, "allow"))
        self.assertEqual(res.json().get("decision"), "approve")
        self.assertEqual(self.gw.pending(), [])
        verdicts = [e["verdict"] for e in self.gw.events()]
        self.assertIn("ask", verdicts)
        self.assertIn("approved", verdicts)
        self.assertAuditOk()

    def test_deny_with_reason(self):
        t, box = self.gw.in_thread(self.gw.write, "summary.md")
        pid = self.gw.wait_pending()[0]["id"]
        self.gw.op("/approve", {"id": pid, "decision": "deny",
                                "reason": "write it to /tmp instead"})
        t.join(5)
        res = box["result"]
        self.assertEqual((res.status, res.verdict), (403, "deny"))
        self.assertIn("write it to /tmp instead", res.text)
        self.assertAuditOk()

    def test_approve_run_allows_identical_next_call(self):
        t, box = self.gw.in_thread(self.gw.write, "summary.md", "same")
        pid = self.gw.wait_pending()[0]["id"]
        self.gw.op("/approve", {"id": pid, "decision": "approve_run"})
        t.join(5)
        self.assertEqual(box["result"].status, 200)
        r = self.gw.write("summary.md", "same")
        self.assertEqual((r.status, r.verdict), (200, "allow"))
        self.assertEqual(self.gw.pending(), [])
        self.assertEqual(self.gw.events()[-1]["reason"],
                         "approved earlier for this run")

    def test_post_tool_use_secret_taints(self):
        self.assertFalse(self.gw.status()["tainted"])
        r = self.gw.hook("bash", {"command": "cat config"}, event="post_tool_use",
                         tool_output="key=AKIA" + "B" * 16, tool_is_error=False)
        self.assertEqual(r.status, 200)
        st = self.gw.status()
        self.assertTrue(st["tainted"])
        self.assertIn("aws-access-key", " ".join(st["taint_reasons"]))
        self.assertNotIn("AKIA" + "B" * 16, json.dumps(self.gw.events()))
        self.assertAuditOk()

    def test_events_args_redacted_and_truncated(self):
        secret = "AKIA" + "C" * 16
        big = "line\n" * 200 + secret
        t, box = self.gw.in_thread(self.gw.write, "big.md", big)
        pid = self.gw.wait_pending()[0]["id"]
        self.gw.op("/approve", {"id": pid, "decision": "deny"})
        t.join(5)
        r = self.gw.bash("curl -s -H 'Authorization: Bearer topsecretvalue42' "
                         "http://api.example.com/status")
        self.assertEqual(r.status, 200)
        events_text = json.dumps(self.gw.events())
        pend_ev = [e for e in self.gw.events() if e.get("pending_id") == pid][0]
        content = pend_ev["args"]["content"]
        self.assertTrue(content["truncated"])
        # Redaction runs first, so len/sha256 describe the redacted text and
        # nothing derived from the secret reaches the events or the audit log.
        redacted = netcheck.redact_text(big)
        self.assertNotEqual(redacted, big)
        self.assertEqual(content["len"], len(redacted))
        self.assertEqual(content["sha256"],
                         hashlib.sha256(redacted.encode()).hexdigest())
        self.assertLessEqual(len(content["head"]), 120)
        for leaked in (secret, "topsecretvalue42"):
            self.assertNotIn(leaked, events_text)
            with open(self.gw.audit_path) as f:
                self.assertNotIn(leaked, f.read())
        self.assertAuditOk()


class ExpiryTest(GatewayTestBase):
    approval_wait = 1.0

    def test_pending_expires_and_fails_closed(self):
        start = time.time()
        r = self.gw.write("summary.md")
        self.assertGreaterEqual(time.time() - start, 0.9)
        self.assertEqual((r.status, r.verdict), (403, "expired"))
        self.assertIn("EXPIRED", r.text)
        self.assertEqual(self.gw.pending(), [])
        self.assertEqual(self.gw.status()["counts"]["expired"], 1)
        self.assertAuditOk()


class OperatorEndpointTest(GatewayTestBase):
    ENDPOINTS = [("/approve", {"id": "p1", "decision": "approve"}),
                 ("/stop", {}), ("/mode", {"mode": "auto"}),
                 ("/override", {"row": "28", "confirm": "YES"}), ("/reset", {})]

    def test_401_without_or_with_wrong_token(self):
        for path, body in self.ENDPOINTS:
            for token in (None, "wrong-token"):
                with self.subTest(path=path, token=token):
                    r = self.gw.post(path, body, token=token)
                    self.assertEqual(r.status, 401)
        st = self.gw.status()
        self.assertEqual((st["mode"], st["stopped"], st["overrides"]),
                         ("default", False, []))

    def test_mode_auto_allows_write(self):
        r = self.gw.op("/mode", {"mode": "auto"})
        self.assertEqual(r.status, 200)
        self.assertEqual(self.gw.op("/mode", {"mode": "turbo"}).status, 400)
        r = self.gw.write("summary.md")
        self.assertEqual((r.status, r.verdict), (200, "allow"))
        self.assertEqual(self.gw.status()["mode"], "auto")
        self.assertAuditOk()

    def test_override_needs_exact_yes(self):
        for confirm in ("yes", "Y", "", None):
            r = self.gw.op("/override", {"row": "28", "confirm": confirm})
            self.assertEqual(r.status, 403)
        self.assertEqual(self.gw.bash("rm demo-files/notes.txt").status, 403)
        r = self.gw.op("/override", {"row": "28", "confirm": "YES"})
        self.assertEqual(r.status, 200)
        self.assertEqual(self.gw.status()["overrides"], ["28"])
        t, box = self.gw.in_thread(self.gw.bash, "rm demo-files/notes.txt")
        item = self.gw.wait_pending()[0]
        self.assertEqual(item["row"], "28")
        self.gw.op("/approve", {"id": item["id"], "decision": "deny"})
        t.join(5)
        self.assertEqual(box["result"].status, 403)
        self.assertTrue(os.path.exists(os.path.join(self.gw.workspace, "notes.txt")))
        self.assertAuditOk()

    def test_stop_wakes_waiter_and_blocks_later_calls(self):
        t, box = self.gw.in_thread(self.gw.write, "summary.md")
        self.gw.wait_pending()
        r = self.gw.op("/stop")
        self.assertEqual(r.status, 200)
        t.join(5)
        self.assertFalse(t.is_alive())
        res = box["result"]
        self.assertEqual((res.status, res.verdict), (403, "stopped"))
        self.assertIn("operator stopped the run", res.text)
        r = self.gw.bash("ls")
        self.assertEqual((r.status, r.verdict), (403, "stopped"))
        r = self.gw.post("/tool-call", {"tool": "shell", "args": {"command": "ls"}})
        self.assertEqual(r.status, 503)
        self.assertTrue(self.gw.status()["stopped"])
        self.assertAuditOk()

    def test_reset_new_run_and_wiped_audit(self):
        self.gw.bash("ls")
        old = self.gw.status()["run_id"]
        r = self.gw.op("/reset")
        self.assertEqual(r.status, 200)
        st = self.gw.status()
        self.assertNotEqual(st["run_id"], old)
        self.assertEqual(st["counts"]["allow"], 0)
        a = self.gw.get("/audit").json()
        self.assertTrue(a["ok"])
        self.assertLessEqual(a["count"], 3)


class GuardAndLegacyTest(GatewayTestBase):
    def test_foreign_host_header_rejected(self):
        r = self.gw.get("/status", host="evil.example")
        self.assertEqual(r.status, 403)
        r = _support.request(self.gw.port, "POST", "/hooks/oh",
                             {"event": "pre_tool_use", "payload": {
                                 "tool_name": "bash",
                                 "tool_input": {"command": "ls"}}},
                             host="evil.example:%d" % self.gw.port)
        self.assertEqual(r.status, 403)
        self.assertEqual(self.gw.get("/status", host="localhost:%d"
                                     % self.gw.port).status, 200)

    def test_tool_call_endpoint(self):
        r = self.gw.post("/tool-call", {"tool": "shell",
                                        "args": {"command": "ls; rm x"},
                                        "agent": "legacy"})
        self.assertEqual(r.status, 403)
        self.assertEqual(r.json()["row"], "28")
        r = self.gw.post("/tool-call", {"tool": "file_read",
                                        "args": {"path": "demo-files/notes.txt"}})
        self.assertEqual((r.status, r.json()["verdict"]), (200, "allow"))

    def test_read_views(self):
        modes = self.gw.get("/modes").json()
        self.assertEqual(len(modes["rows"]), 29)
        self.assertEqual(modes["modes"], ["plan", "default", "auto"])
        page = self.gw.get("/")
        self.assertEqual(page.status, 200)
        self.assertIn("textContent", page.text)
        self.assertNotIn("innerHTML", page.text)
        self.assertEqual(self.gw.get("/nope").status, 404)


if __name__ == "__main__":
    unittest.main()
