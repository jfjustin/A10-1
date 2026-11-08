"""harness.py helpers: operator token creation and permissions, the agent
environment (no token, all proxy vars, NO_PROXY), kill_tree() on a process
tree, and the `verify` subcommand. Temp A10_HOME only.
"""
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import audit  # noqa: E402
import harness  # noqa: E402


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class OperatorTokenTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = os.path.join(self._tmp.name, "a10home")

    def tearDown(self):
        self._tmp.cleanup()

    def test_creates_dir_0700_and_file_0600(self):
        token = harness.ensure_operator_token(self.home)
        path = os.path.join(self.home, "operator.token")
        self.assertGreaterEqual(len(token), 32)
        self.assertEqual(mode_of(self.home), 0o700)
        self.assertEqual(mode_of(path), 0o600)
        with open(path) as f:
            self.assertEqual(f.read().strip(), token)

    def test_idempotent(self):
        t1 = harness.ensure_operator_token(self.home)
        t2 = harness.ensure_operator_token(self.home)
        self.assertEqual(t1, t2)

    def test_fixes_wider_permissions(self):
        harness.ensure_operator_token(self.home)
        path = os.path.join(self.home, "operator.token")
        os.chmod(path, 0o644)
        os.chmod(self.home, 0o755)
        harness.ensure_operator_token(self.home)
        self.assertEqual(mode_of(path), 0o600)
        self.assertEqual(mode_of(self.home), 0o700)

    def test_refuses_symlinked_token(self):
        os.makedirs(self.home, mode=0o700)
        target = os.path.join(self._tmp.name, "elsewhere")
        with open(target, "w") as f:
            f.write("x\n")
        os.symlink(target, os.path.join(self.home, "operator.token"))
        with self.assertRaises(RuntimeError):
            harness.ensure_operator_token(self.home)


class AgentEnvTest(unittest.TestCase):
    def test_strips_token_vars_and_sets_proxy_vars(self):
        base = {"PATH": "/usr/bin", "HOME": "/Users/x",
                "A10_OPERATOR_TOKEN": "secret1", "MY_OPERATOR_TOKEN": "secret2",
                "a10_operator_x": "secret3", "HTTP_PROXY": "http://old:1",
                "NO_PROXY": "*", "A10_HOME": "/tmp/a10"}
        env = harness.build_agent_env(base, "http://127.0.0.1:9999")
        for k in ("A10_OPERATOR_TOKEN", "MY_OPERATOR_TOKEN", "a10_operator_x"):
            self.assertNotIn(k, env)
        self.assertNotIn("secret1", " ".join(env.values()))
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            self.assertEqual(env[k], "http://127.0.0.1:9999")
        self.assertEqual(env["NO_PROXY"], "127.0.0.1,localhost")
        self.assertEqual(env["no_proxy"], "127.0.0.1,localhost")
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertNotIn("SSL_CERT_FILE", env)
        self.assertEqual(base["NO_PROXY"], "*", "base env must not be mutated")

    def test_ca_vars(self):
        env = harness.build_agent_env({}, "http://p:1", ca_bundle="/a/ca.pem",
                                      node_ca="/a/mitm.pem")
        for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            self.assertEqual(env[k], "/a/ca.pem")
        self.assertEqual(env["NODE_EXTRA_CA_CERTS"], "/a/mitm.pem")


class KillTreeTest(unittest.TestCase):
    def test_kills_parent_and_children(self):
        proc = subprocess.Popen(["bash", "-c", "sleep 30 & sleep 30"],
                                start_new_session=True)
        try:
            deadline = time.time() + 5
            kids = []
            while time.time() < deadline and len(kids) < 2:
                kids = harness._descendants(proc.pid)
                time.sleep(0.05)
            self.assertGreaterEqual(len(kids), 2, "bash should have 2 sleeps")
            start = time.time()
            killed = harness.kill_tree(proc.pid, grace=3.0)
            self.assertLess(time.time() - start, 6)
            self.assertIn(proc.pid, killed)
            for k in kids:
                self.assertIn(k, killed)
            proc.wait(timeout=5)
            for k in kids:
                self.assertFalse(harness._alive(k), "pid %d survived" % k)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


class VerifyCommandTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "audit.log.jsonl")

    def tearDown(self):
        self._tmp.cleanup()

    def run_verify(self):
        return subprocess.run([sys.executable, os.path.join(ROOT, "harness.py"),
                               "verify", self.path], capture_output=True,
                              text=True, timeout=30, cwd=ROOT)

    def test_ok_then_broken(self):
        log = audit.AuditLog(self.path)
        log.append("a", {"i": 1})
        log.append("b", {"i": 2})
        r = self.run_verify()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("audit chain ✓ verified (2 entries)", r.stdout)
        with open(self.path) as f:
            text = f.read()
        with open(self.path, "w") as f:
            f.write(text.replace('"i": 1', '"i": 7'))
        r = self.run_verify()
        self.assertEqual(r.returncode, 1)
        self.assertIn("BROKEN at seq 0", r.stdout)

    def test_summary_line(self):
        line = harness.summary_line((True, 12, None), {"counts": {
            "allow": 4, "ask": 1, "approved": 1, "block": 3}})
        self.assertIn("audit chain ✓ verified (12 entries)", line)
        self.assertIn("4 allowed", line)
        self.assertIn("3 blocked", line)


if __name__ == "__main__":
    unittest.main()
