"""Hash-chained audit log (audit.py): append/verify, tamper detection with the
first bad seq, wipe, and compatibility with logs written by the starter
gateway (same entry format and hash formula).

Replaces the starter's tests/test_starter_smoke.py. Temp files only.
"""
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit  # noqa: E402


def starter_log_event(path, event_type, payload):
    """Verbatim logic of the starter gateway's log_event() (commit 76b8f0f)."""
    prev, seq = "GENESIS", 0
    if os.path.exists(path):
        with open(path) as f:
            lines = [ln for ln in f if ln.strip()]
        if lines:
            last = json.loads(lines[-1])
            prev, seq = last["hash"], last["seq"] + 1
    entry = {"seq": seq, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "type": event_type, "payload": payload, "prev": prev}
    entry["hash"] = hashlib.sha256(
        (prev + json.dumps(entry, sort_keys=True)).encode()).hexdigest()
    with open(path, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


class AuditLogTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "audit.log.jsonl")

    def tearDown(self):
        self._tmp.cleanup()

    def lines(self):
        with open(self.path) as f:
            return [json.loads(ln) for ln in f if ln.strip()]

    def write_lines(self, entries):
        with open(self.path, "w") as f:
            for e in entries:
                f.write(json.dumps(e, sort_keys=True) + "\n")

    def test_append_and_verify(self):
        log = audit.AuditLog(self.path)
        e0 = log.append("tool_call", {"tool": "bash", "verdict": "allow"})
        e1 = log.append("tool_call", {"tool": "bash", "verdict": "block"})
        self.assertEqual((e0["seq"], e0["prev"]), (0, audit.GENESIS))
        self.assertEqual((e1["seq"], e1["prev"]), (1, e0["hash"]))
        self.assertEqual(set(e0), {"seq", "ts", "type", "payload", "prev", "hash"})
        check = dict(e1)
        h = check.pop("hash")
        self.assertEqual(h, hashlib.sha256(
            (e0["hash"] + json.dumps(check, sort_keys=True)).encode()).hexdigest())
        self.assertEqual(log.verify(), (True, 2, None))
        self.assertEqual(audit.verify_file(self.path), (True, 2, None))

    def test_missing_file_verifies_empty(self):
        self.assertEqual(audit.verify_file(self.path), (True, 0, None))

    def test_reopen_continues_the_chain(self):
        audit.AuditLog(self.path).append("a", {"n": 1})
        audit.AuditLog(self.path).append("b", {"n": 2})
        entries = self.lines()
        self.assertEqual([e["seq"] for e in entries], [0, 1])
        self.assertEqual(audit.verify_file(self.path), (True, 2, None))

    def test_tamper_reports_first_bad_seq(self):
        log = audit.AuditLog(self.path)
        for i in range(5):
            log.append("tool_call", {"i": i, "verdict": "allow"})
        entries = self.lines()
        entries[2]["payload"]["verdict"] = "block"
        self.write_lines(entries)
        self.assertEqual(audit.verify_file(self.path), (False, 2, 2))

    def test_deleted_line_detected(self):
        log = audit.AuditLog(self.path)
        for i in range(4):
            log.append("e", {"i": i})
        entries = self.lines()
        del entries[1]
        self.write_lines(entries)
        ok, count, bad = audit.verify_file(self.path)
        self.assertFalse(ok)
        self.assertEqual((count, bad), (1, 2))

    def test_garbage_line_detected(self):
        log = audit.AuditLog(self.path)
        log.append("e", {"i": 0})
        with open(self.path, "a") as f:
            f.write("not json\n")
        self.assertEqual(audit.verify_file(self.path), (False, 1, 1))

    def test_wipe_restarts_at_genesis(self):
        log = audit.AuditLog(self.path)
        log.append("e", {"i": 0})
        log.wipe()
        self.assertFalse(os.path.exists(self.path))
        e = log.append("run_start", {})
        self.assertEqual((e["seq"], e["prev"]), (0, audit.GENESIS))
        self.assertEqual(log.verify(), (True, 1, None))

    def test_thread_safe_appends(self):
        log = audit.AuditLog(self.path)

        def work(n):
            for i in range(25):
                log.append("e", {"t": n, "i": i})

        threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(audit.verify_file(self.path), (True, 100, None))
        self.assertEqual([e["seq"] for e in self.lines()], list(range(100)))

    def test_starter_format_logs_verify_and_extend(self):
        starter_log_event(self.path, "tool_call", {"tool": "shell", "verdict": "allow"})
        starter_log_event(self.path, "tool_call", {"tool": "shell", "verdict": "block"})
        self.assertEqual(audit.verify_file(self.path), (True, 2, None))
        # The new AuditLog continues a starter log seamlessly...
        audit.AuditLog(self.path).append("tool_call", {"tool": "bash"})
        self.assertEqual(audit.verify_file(self.path), (True, 3, None))
        # ...and the starter's tamper example is still caught.
        entries = self.lines()
        entries[0]["payload"]["verdict"] = "block"
        self.write_lines(entries)
        self.assertEqual(audit.verify_file(self.path)[0], False)


if __name__ == "__main__":
    unittest.main()
