"""Smoke test for the imported starter: the audit hash chain round-trips.

Placeholder until FEAT-003 replaces it with the real audit tests. It exists
to prove both test commands (unittest discover and pytest) work offline.
Run:  python3 -m unittest discover -s tests -v   or   python3 -m pytest -q tests
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gateway  # noqa: E402
import policy  # noqa: E402,F401  (import check only)


class StarterAuditChainTest(unittest.TestCase):
    def setUp(self):
        self._orig_log = gateway.AUDIT_LOG
        self._tmp = tempfile.TemporaryDirectory()
        gateway.AUDIT_LOG = os.path.join(self._tmp.name, "audit.log.jsonl")

    def tearDown(self):
        gateway.AUDIT_LOG = self._orig_log
        self._tmp.cleanup()

    def test_chain_verifies_then_detects_tampering(self):
        gateway.log_event("tool_call", {"tool": "shell", "verdict": "allow"})
        gateway.log_event("tool_call", {"tool": "shell", "verdict": "block"})
        self.assertEqual(gateway.verify_audit(), (True, 2))

        with open(gateway.AUDIT_LOG) as f:
            lines = f.read().splitlines()
        first = json.loads(lines[0])
        first["payload"]["verdict"] = "block"
        lines[0] = json.dumps(first, sort_keys=True)
        with open(gateway.AUDIT_LOG, "w") as f:
            f.write("\n".join(lines) + "\n")

        ok, _count = gateway.verify_audit()
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
