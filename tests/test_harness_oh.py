"""`harness.py oh` with a fake `oh` first on PATH (OpenHarness is not
installed here). The fake records its argv and env, reads the generated
$OPENHARNESS_CONFIG_DIR/settings.json and POSTs oh-format pre_tool_use
payloads to the configured hook URL, exactly as oh's http hook would (urllib
honors *_PROXY and NO_PROXY like oh's httpx client). Also: the install hint
when oh is missing, keeping the gateway up after oh exits until the run is
stopped, and STOP killing a running oh.

Temp A10_HOME, temp OPENHARNESS_CONFIG_DIR, temp audit log, ephemeral ports.
A live test with the real `oh` runs only with A10_LIVE_OH=1 (needs a
configured provider and network).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _support import (HARNESS, ROOT, free_port, read_audit, request,  # noqa: E402
                      write_executable)

PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
USER_HOOK = {"type": "command", "command": "echo user-hook", "priority": 1}
USER_SETTINGS = {
    "active_profile": "claude-api",
    "profiles": {"claude-api": {"label": "Claude API", "provider": "anthropic"},
                 "local": {"provider": "ollama",
                           "base_url": "http://localhost:11434/v1"}},
    "hooks": {"pre_tool_use": [USER_HOOK]},
}

FAKE_OH = '''#!@PYTHON@
"""Fake `oh` for tests."""
import json, os, sys, time, urllib.error, urllib.request

rec = {"argv": sys.argv[1:], "env": dict(os.environ), "cwd": os.getcwd(),
       "calls": []}
try:
    cfg = os.environ["OPENHARNESS_CONFIG_DIR"]
    with open(os.path.join(cfg, "settings.json")) as f:
        rec["settings"] = json.load(f)
    url = rec["settings"]["hooks"]["pre_tool_use"][0]["url"]
    with urllib.request.urlopen(url.rsplit("/hooks/oh", 1)[0] + "/status",
                                timeout=10) as r:
        rec["status"] = json.load(r)
    for command in ("rm demo-files/notes.txt", "ls"):
        payload = {"tool_name": "bash", "tool_input": {"command": command},
                   "event": "pre_tool_use"}
        body = json.dumps({"event": "pre_tool_use", "payload": payload}).encode()
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                call = {"status": r.status, "body": r.read().decode()}
        except urllib.error.HTTPError as e:
            call = {"status": e.code, "body": e.read().decode()}
        call["command"] = command
        rec["calls"].append(call)
except Exception as e:
    rec["error"] = repr(e)
with open(os.environ["FAKE_OH_RECORD"], "w") as f:
    json.dump(rec, f)
time.sleep(float(os.environ.get("FAKE_OH_SLEEP") or 0))
'''


def snapshot(path):
    out = {}
    for base, dirs, files in os.walk(path):
        for name in dirs + files:
            p = os.path.join(base, name)
            st = os.lstat(p)
            data = None
            if os.path.isfile(p) and not os.path.islink(p):
                with open(p, "rb") as f:
                    data = f.read()
            out[os.path.relpath(p, path)] = (data, st.st_mtime_ns)
    return out


class HarnessOhTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = os.path.realpath(self._tmp.name)
        self.bin = os.path.join(base, "bin")
        os.makedirs(self.bin)
        write_executable(os.path.join(self.bin, "oh"),
                         FAKE_OH.replace("@PYTHON@", sys.executable))
        self.home = os.path.join(base, "a10home")
        self.user_dir = os.path.join(base, "user-openharness")
        os.makedirs(self.user_dir)
        with open(os.path.join(self.user_dir, "settings.json"), "w") as f:
            json.dump(USER_SETTINGS, f)
        with open(os.path.join(self.user_dir, "credentials.json"), "w") as f:
            f.write("{}")
        self.ws = os.path.join(base, "ws")
        os.makedirs(os.path.join(self.ws, "demo-files"))
        shutil.copy(os.path.join(ROOT, "demo-files", "notes.txt"),
                    os.path.join(self.ws, "demo-files", "notes.txt"))
        self.record = os.path.join(base, "record.json")
        self.audit = os.path.join(base, "audit.log.jsonl")
        self.port = free_port()
        self.proxy_port = free_port()
        while self.proxy_port == self.port:
            self.proxy_port = free_port()
        self.env = dict(os.environ, PATH=self.bin + os.pathsep + "/usr/bin:/bin",
                        A10_HOME=self.home, A10_NO_NOTIFY="1",
                        OPENHARNESS_CONFIG_DIR=self.user_dir,
                        FAKE_OH_RECORD=self.record,
                        OPENHARNESS_WEB_PROXY="http://127.0.0.1:9/should-go",
                        A10_OPERATOR_TOKEN="leak-me-not")
        for k in ("OPENHARNESS_PROFILE", "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"):
            self.env.pop(k, None)

    def tearDown(self):
        self._tmp.cleanup()

    def argv(self, *extra, oh_args=("-p", "hi")):
        return [sys.executable, HARNESS, "oh", "--proxy", "stdlib",
                "--port", str(self.port), "--proxy-port", str(self.proxy_port),
                "--workspace", self.ws, "--audit-log", self.audit,
                *extra, "--", *oh_args]

    def run_harness(self, *extra):
        return subprocess.run(self.argv("--exit-with-agent", *extra),
                              env=self.env, cwd=ROOT, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=90)

    def popen_harness(self, *extra):
        return subprocess.Popen(self.argv(*extra), env=self.env, cwd=ROOT,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)

    def record_json(self):
        with open(self.record) as f:
            return json.load(f)

    def wait_record(self, proc, timeout=45):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(self.record) and os.path.getsize(self.record):
                return self.record_json()
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        self.fail("fake oh never wrote its record")

    def token(self):
        with open(os.path.join(self.home, "operator.token")) as f:
            return f.read().strip()

    def stop_run(self):
        r = request(self.port, "POST", "/stop", {},
                    headers={"X-A10-Operator-Token": self.token()})
        self.assertEqual(r.status, 200, r.text)

    def test_oh_runs_under_the_gateway(self):
        user_before = snapshot(self.user_dir)
        r = self.run_harness()
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, out)
        rec = self.record_json()
        self.assertNotIn("error", rec, rec.get("error"))

        self.assertEqual(rec["argv"], ["--permission-mode", "full_auto", "-p", "hi"])
        self.assertEqual(os.path.realpath(rec["cwd"]), self.ws)
        env = rec["env"]
        for k in PROXY_VARS:
            self.assertEqual(env[k], "http://127.0.0.1:%d" % self.proxy_port)
        self.assertIn("127.0.0.1", env["NO_PROXY"].split(","))
        self.assertIn("127.0.0.1", env["no_proxy"].split(","))
        self.assertEqual(env["OPENHARNESS_CONFIG_DIR"],
                         os.path.join(self.home, "oh-config"))
        self.assertNotIn("OPENHARNESS_WEB_PROXY", env)
        self.assertNotIn("SSL_CERT_FILE", env, "no CA vars with the stdlib proxy")
        token = self.token()
        for k, v in env.items():
            self.assertNotIn("OPERATOR_TOKEN", k.upper())
            self.assertNotIn(token, v)
            self.assertNotIn("leak-me-not", v)

        calls = {c["command"]: c for c in rec["calls"]}
        rm = calls["rm demo-files/notes.txt"]
        self.assertEqual(rm["status"], 403)
        self.assertIn("row 28", rm["body"])
        self.assertEqual(calls["ls"]["status"], 200)
        self.assertTrue(os.path.exists(os.path.join(self.ws, "demo-files",
                                                    "notes.txt")))

        pre = rec["settings"]["hooks"]["pre_tool_use"]
        self.assertEqual(pre[0], {"type": "http",
                                  "url": "http://127.0.0.1:%d/hooks/oh" % self.port,
                                  "timeout_seconds": 600,
                                  "block_on_failure": True, "priority": 1000})
        self.assertEqual(pre[1:], [USER_HOOK])
        self.assertEqual(rec["settings"]["hooks"]["post_tool_use"][0]["priority"],
                         1000)
        st = rec["status"]
        self.assertEqual(st["provider_hosts"], ["api.anthropic.com"])
        self.assertEqual(st["workspace"], self.ws)
        self.assertEqual(st["mode"], "default")

        self.assertIn("/#token=%s" % token, out)
        self.assertIn("in a second terminal for approvals", out)
        self.assertIn("api.anthropic.com (row 10, from oh profile 'claude-api'", out)
        self.assertIn("audit chain ✓ verified", out)

        tool = [e["payload"] for e in read_audit(self.audit)
                if e["type"] == "tool_call"]
        self.assertTrue(any(p["row"] == "28" and p["verdict"] == "block"
                            and p["source"] == "oh" for p in tool), tool)
        self.assertTrue(any(p["row"] == "5" and p["verdict"] == "allow"
                            for p in tool), tool)
        self.assertEqual(snapshot(self.user_dir), user_before)
        self.assertFalse(os.path.exists(os.path.join(self.home, "run", "pids.json")))

    def test_provider_host_flag_overrides_detection(self):
        r = self.run_harness("--provider-host", "llm.example.org")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.record_json()["status"]["provider_hosts"],
                         ["llm.example.org"])
        self.assertIn("llm.example.org (row 10, from --provider-host)", r.stdout)

    def test_active_profile_from_settings_and_profile_env_ignored(self):
        settings = dict(USER_SETTINGS, active_profile="local")
        with open(os.path.join(self.user_dir, "settings.json"), "w") as f:
            json.dump(settings, f)
        self.env["OPENHARNESS_PROFILE"] = "codex"  # oh 0.1.9 never reads it
        r = self.run_harness()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.record_json()["status"]["provider_hosts"],
                         ["localhost:11434"])
        self.assertIn("localhost:11434 (row 10, from oh profile 'local'",
                      r.stdout)

    def test_missing_oh_exits_2_with_install_hint(self):
        empty = os.path.join(self._tmp.name, "empty-bin")
        os.makedirs(empty)
        self.env["PATH"] = empty + os.pathsep + "/usr/bin:/bin"
        r = subprocess.run([sys.executable, HARNESS, "oh", "--", "-p", "hi"],
                           env=self.env, cwd=ROOT, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2)
        self.assertIn("pip install openharness-ai", r.stdout)
        self.assertFalse(os.path.exists(self.home), "nothing is set up")

    def test_gateway_stays_up_after_oh_exits_until_stop(self):
        proc = self.popen_harness()
        try:
            self.wait_record(proc)
            time.sleep(1.0)
            self.assertIsNone(proc.poll(), "harness must keep running")
            self.assertEqual(request(self.port, "GET", "/status").status, 200)
            self.stop_run()
            out, _ = proc.communicate(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 0, out)
        self.assertIn("The gateway stays up", out)
        self.assertIn("audit chain ✓ verified", out)

    def test_stop_kills_a_running_oh(self):
        self.env["FAKE_OH_SLEEP"] = "60"
        proc = self.popen_harness("--exit-with-agent")
        try:
            self.wait_record(proc)
            start = time.time()
            self.stop_run()
            out, _ = proc.communicate(timeout=30)
            self.assertLess(time.time() - start, 20)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 0, out)
        self.assertIn("run stopped: killed the agent process tree", out)


@unittest.skipUnless(shutil.which("oh") and os.environ.get("A10_LIVE_OH") == "1",
                     "needs the real oh (pip install openharness-ai), a "
                     "configured provider, network and A10_LIVE_OH=1")
class LiveOhTest(unittest.TestCase):
    def test_real_oh_rm_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            ws = os.path.join(d, "ws")
            os.makedirs(os.path.join(ws, "demo-files"))
            shutil.copy(os.path.join(ROOT, "demo-files", "notes.txt"),
                        os.path.join(ws, "demo-files", "notes.txt"))
            audit_path = os.path.join(d, "audit.log.jsonl")
            env = dict(os.environ, A10_HOME=os.path.join(d, "a10home"),
                       A10_NO_NOTIFY="1")
            r = subprocess.run(
                [sys.executable, HARNESS, "oh", "--exit-with-agent",
                 "--port", str(free_port()), "--proxy-port", str(free_port()),
                 "--workspace", ws, "--audit-log", audit_path, "--",
                 "-p", "Use the bash tool to run exactly: rm demo-files/notes.txt"],
                env=env, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True,
                text=True, timeout=600)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue(os.path.exists(os.path.join(ws, "demo-files",
                                                        "notes.txt")))
            rows = [e["payload"].get("row") for e in read_audit(audit_path)
                    if e["type"] == "tool_call"
                    and e["payload"].get("verdict") == "block"]
            self.assertIn("28", rows)


if __name__ == "__main__":
    unittest.main()
