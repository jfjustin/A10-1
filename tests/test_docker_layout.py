"""Offline static checks of the Docker layout in docker/ (the row 6 gap).

No Docker and no PyYAML: compose.yml is read as text with a small
indentation-based reader, one service block at a time. These tests only show
that the files say what docker/README.md promises (agent on an internal
network only, no operator token or docker.sock, console port on loopback,
hooks pointing at the gateway). They do not show that Docker behaves that
way; docker/README.md is marked UNVERIFIED for that reason.
"""
import contextlib
import io
import json
import os
import re
import shlex
import sys
import tempfile
import threading
import unittest
from urllib.parse import urlsplit

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS_DIR)
for _p in (ROOT, TESTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _support  # noqa: E402
import gateway  # noqa: E402
import harness  # noqa: E402
import oh_setup  # noqa: E402

DOCKER = os.path.join(ROOT, "docker")
COMPOSE = os.path.join(DOCKER, "compose.yml")
DOCKERFILE = os.path.join(DOCKER, "Dockerfile.agent")
OH_SETTINGS = os.path.join(DOCKER, "oh-settings.json")
DOCKER_README = os.path.join(DOCKER, "README.md")
GATEWAY_URL = "http://gateway:8000"
CA_CERT = "/a10/mitm-ca/mitmproxy-ca-cert.pem"
BANNER = "UNVERIFIED: written on 2026-11-07 without Docker or network"


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _strip_comment(line):
    s = line.rstrip("\n")
    if s.lstrip().startswith("#"):
        return ""
    i = s.find(" #")
    return (s[:i] if i >= 0 else s).rstrip()


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def compose_lines():
    with open(COMPOSE, encoding="utf-8") as f:
        return [s for s in (_strip_comment(x) for x in f) if s.strip()]


def section(lines, key, indent=0):
    """The lines nested under `key:` at `indent` (comments removed)."""
    out = None
    for line in lines:
        if out is None:
            if _indent(line) == indent and line.strip() == key + ":":
                out = []
            continue
        if _indent(line) <= indent:
            break
        out.append(line)
    if out is None:
        raise AssertionError("no %r key at indent %d" % (key, indent))
    return out


def has_key(lines, key, indent):
    return any(_indent(s) == indent and s.strip().split(":", 1)[0] == key
               for s in lines)


def service(name):
    return section(section(compose_lines(), "services"), name, 2)


def items(block, key, indent=4):
    """Block-style list items directly under `key:` (quotes removed)."""
    out = []
    for line in section(block, key, indent):
        s = line.strip()
        if _indent(line) == indent + 2 and s.startswith("- "):
            out.append(s[2:].strip().strip('"'))
    return out


def mapping(block, key, indent=4):
    """`name: value` pairs directly under `key:` (quotes removed)."""
    out = {}
    for line in section(block, key, indent):
        if _indent(line) != indent + 2:
            continue
        k, _, v = line.strip().partition(":")
        out[k.strip()] = v.strip().strip('"')
    return out


def with_defaults(value):
    """Apply compose ${VAR:-default} defaults (as with an empty shell)."""
    return re.sub(r"\$\{[A-Z0-9_]+:-([^}]*)\}", r"\1", value)


def gateway_flags():
    return set(re.findall(r'add_argument\(\s*"(--[a-z0-9-]+)"',
                          _read(os.path.join(ROOT, "gateway.py"))))


class NetworkTest(unittest.TestCase):
    def test_agentnet_is_internal_and_egress_is_not(self):
        nets = section(compose_lines(), "networks")
        agentnet = [s.strip() for s in section(nets, "agentnet", 2)]
        self.assertIn("internal: true", agentnet)
        egress = [s.strip() for s in section(nets, "egress", 2)]
        self.assertNotIn("internal: true", egress)

    def test_agent_is_on_agentnet_only(self):
        agent = service("agent")
        self.assertEqual(items(agent, "networks"), ["agentnet"])
        for key in ("network_mode", "ports", "expose", "extra_hosts"):
            self.assertFalse(has_key(agent, key, 4), key)

    def test_gateway_and_mitm_reach_both_networks(self):
        for name in ("gateway", "mitm"):
            self.assertEqual(sorted(items(service(name), "networks")),
                             ["agentnet", "egress"], name)

    def test_only_the_gateway_publishes_and_only_on_loopback(self):
        ports = items(service("gateway"), "ports")
        self.assertEqual(ports, ["127.0.0.1:8000:8000"])
        self.assertFalse(has_key(service("mitm"), "ports", 4))


class AgentServiceTest(unittest.TestCase):
    def test_no_operator_token_docker_sock_or_harness_code(self):
        text = "\n".join(service("agent"))
        for needle in ("operator.token", "docker.sock", "privileged",
                       "/harness", "mitm-conf", "A10_HOME"):
            self.assertNotIn(needle, text)

    def test_hardening_and_build(self):
        agent = service("agent")
        self.assertEqual(items(agent, "cap_drop"), ["ALL"])
        self.assertEqual(items(agent, "security_opt"),
                         ["no-new-privileges:true"])
        build = mapping(agent, "build")
        self.assertEqual(build["dockerfile"], "Dockerfile.agent")
        self.assertTrue(os.path.isfile(
            os.path.join(DOCKER, build["context"], build["dockerfile"])))

    def test_proxy_and_ca_environment(self):
        env = mapping(service("agent"), "environment")
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            self.assertEqual(env[k], "http://mitm:8080", k)
        for k in ("NO_PROXY", "no_proxy"):
            self.assertIn("gateway", env[k].split(","), k)
            self.assertNotIn("mitm", env[k].split(","), k)
        for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
                  "NODE_EXTRA_CA_CERTS"):
            self.assertEqual(env[k], CA_CERT, k)
        self.assertEqual(env["OPENHARNESS_CONFIG_DIR"], "/a10/oh-config")
        self.assertNotIn("OPENHARNESS_WEB_PROXY", env)
        for k in env:
            self.assertNotIn("OPERATOR", k.upper())

    def test_mounts(self):
        vols = items(service("agent"), "volumes")
        self.assertIn("${A10_WORKSPACE:-../demo-files}:/workspace", vols)
        self.assertIn("./oh-settings.json:/a10/oh-config/settings.json:ro", vols)
        self.assertIn("mitm-ca:/a10/mitm-ca:ro", vols)
        self.assertEqual(len(vols), 3, vols)
        self.assertTrue(os.path.isdir(os.path.join(DOCKER, "../demo-files")))

    def test_dockerfile(self):
        text = _read(DOCKERFILE)
        self.assertIn(BANNER, " ".join(text.replace("#", " ").split()))
        self.assertRegex(text, r"(?m)^FROM python:3\.11-slim\s*$")
        self.assertRegex(text, r"(?m)pip install .*\bopenharness-ai\b")
        users = re.findall(r"(?m)^USER\s+(\S+)", text)
        self.assertEqual(users, ["agent"])
        self.assertRegex(text, r"(?m)^WORKDIR /workspace\s*$")
        entry = re.findall(r"(?m)^ENTRYPOINT\s+(.+)$", text)
        self.assertEqual(len(entry), 1)
        self.assertEqual(json.loads(entry[0]),
                         ["oh", "--permission-mode", "full_auto"])


class GatewayServiceTest(unittest.TestCase):
    def command(self):
        return [with_defaults(a) for a in items(service("gateway"), "command")]

    def test_command_uses_real_gateway_flags(self):
        cmd = self.command()
        self.assertEqual(cmd[:2], ["python3", "/harness/gateway.py"])
        flags = [a for a in cmd if a.startswith("--")]
        self.assertTrue(set(flags) <= gateway_flags(),
                        set(flags) - gateway_flags())

        def value(flag):
            return cmd[cmd.index(flag) + 1]

        self.assertEqual(value("--host"), "0.0.0.0")
        self.assertEqual(value("--port"), "8000")
        self.assertEqual(value("--allow-host-header"), "gateway:8000")
        self.assertEqual(value("--workspace"), "/workspace")
        self.assertEqual(value("--cwd"), "/workspace")
        self.assertEqual(value("--audit-log"), "/data/audit.log.jsonl")
        self.assertIn(value("--mode"), ("plan", "default", "auto"))
        self.assertEqual(value("--provider-host"), "api.anthropic.com")

    def test_token_mounted_read_only_and_environment(self):
        gw = service("gateway")
        text = "\n".join(gw)
        self.assertRegex(text, r"source: \"\$\{A10_HOME:\?[^}]*\}/operator\.token\"")
        self.assertIn("target: /a10/operator.token", text)
        self.assertIn("read_only: true", text)
        self.assertIn("create_host_path: false", text)
        self.assertIn("..:/harness:ro", items(gw, "volumes"))
        self.assertIn("${A10_WORKSPACE:-../demo-files}:/workspace:ro",
                      items(gw, "volumes"))
        env = mapping(gw, "environment")
        self.assertEqual(env["A10_HOME"], "/a10")
        self.assertEqual(env["HOME"], "/home/agent")
        self.assertTrue(os.path.isfile(os.path.join(DOCKER, "..", "gateway.py")))

    def test_gateway_accepts_the_docker_host_header(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = os.path.realpath(tmp.name)
        ws = os.path.join(base, "workspace")
        os.makedirs(ws)
        audit = os.path.join(base, "audit.log.jsonl")
        settings = gateway.build_settings(ws, ws, os.path.join(base, "a10"),
                                          audit)
        app = gateway.GatewayApp(settings, audit, _support.TOKEN,
                                 allow_host_headers=["Gateway:8000"])
        server = gateway.make_server(app, "127.0.0.1", 0)
        t = threading.Thread(target=server.serve_forever,
                             kwargs={"poll_interval": 0.05}, daemon=True)
        t.start()

        def cleanup():
            app.close()
            server.shutdown()
            server.server_close()
        self.addCleanup(cleanup)
        port = app.port
        ok = _support.request(port, "GET", "/status", host="gateway:8000")
        self.assertEqual(ok.status, 200)
        self.assertEqual(_support.request(
            port, "GET", "/status", host="127.0.0.1:%d" % port).status, 200)
        for bad in ("evil.example:8000", "gateway.evil:8000", "gateway:9000"):
            self.assertEqual(_support.request(
                port, "GET", "/status", host=bad).status, 403, bad)
        # The agent reaches the gateway but not its control endpoints.
        r = _support.request(port, "POST", "/stop", {}, host="gateway:8000")
        self.assertEqual(r.status, 401)


class MitmServiceTest(unittest.TestCase):
    def test_mitmdump_command_matches_the_harness(self):
        entry = " ".join(s.strip() for s in
                         section(service("mitm"), "entrypoint", 4))
        self.assertIn("exec mitmdump ", entry)
        argv = shlex.split(entry.split("exec ", 1)[1])
        expected = harness.mitm_command("mitmdump", 8080,
                                        "/home/mitmproxy/.mitmproxy",
                                        "/harness/mitm_addon.py")
        expected[expected.index("--listen-host") + 1] = "0.0.0.0"
        self.assertEqual(argv, expected)

    def test_only_the_public_cert_is_shared(self):
        mitm = service("mitm")
        vols = items(mitm, "volumes")
        self.assertIn("mitm-conf:/home/mitmproxy/.mitmproxy", vols)
        self.assertIn("mitm-ca:/ca", vols)
        entry = " ".join(s.strip() for s in section(mitm, "entrypoint", 4))
        self.assertIn("/ca/mitmproxy-ca-cert.pem", entry)
        self.assertNotIn("mitmproxy-ca.pem", entry)
        self.assertEqual(os.path.basename(CA_CERT), "mitmproxy-ca-cert.pem")
        health = " ".join(s.strip() for s in section(mitm, "healthcheck", 4))
        self.assertIn("/ca/mitmproxy-ca-cert.pem", health)

    def test_addon_environment(self):
        env = mapping(service("mitm"), "environment")
        self.assertEqual(env["A10_GATEWAY_URL"], GATEWAY_URL)
        for k in env:
            self.assertNotIn("OPERATOR", k.upper())

    def test_agent_waits_for_ca_and_gateway(self):
        dep = "\n".join(section(service("agent"), "depends_on", 4))
        self.assertRegex(dep, r"gateway:\s+condition: service_healthy")
        self.assertRegex(dep, r"mitm:\s+condition: service_healthy")


class OhSettingsTest(unittest.TestCase):
    def test_hooks_match_oh_setup(self):
        with open(OH_SETTINGS) as f:
            data = json.load(f)
        self.assertEqual(data["hooks"], oh_setup.hook_settings(GATEWAY_URL))
        pre = data["hooks"]["pre_tool_use"][0]
        self.assertEqual(pre["url"], GATEWAY_URL + "/hooks/oh")
        self.assertIs(pre["block_on_failure"], True)
        self.assertEqual(pre["timeout_seconds"], 600)
        self.assertEqual(pre["priority"], 1000)
        self.assertIs(data["hooks"]["post_tool_use"][0]["block_on_failure"],
                      False)
        # The hook's Host header is one the gateway is told to accept.
        cmd = items(service("gateway"), "command")
        allowed = cmd[cmd.index("--allow-host-header") + 1]
        self.assertEqual(urlsplit(pre["url"]).netloc, allowed)

    def test_file_is_what_the_cli_prints(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = oh_setup.main(["--print-hooks", "--gateway-url", GATEWAY_URL])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), _read(OH_SETTINGS))

    def test_cli_needs_print_hooks(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(oh_setup.main([]), 2)
        self.assertIn("--print-hooks", err.getvalue())


class DocsTest(unittest.TestCase):
    def test_docker_readme_is_marked_unverified_with_checks(self):
        text = _read(DOCKER_README)
        self.assertIn("**%s.**" % BANNER, " ".join(
            text.replace(">", " ").split()))
        for cmd in ("docker compose -f docker/compose.yml up --build",
                    "python3 harness.py watch",
                    "socket.create_connection(('1.1.1.1', 443), 3)",
                    "--entrypoint curl agent -s https://example.com",
                    "--entrypoint getent agent hosts example.com"):
            self.assertIn(cmd, text)

    def test_compose_is_marked_unverified(self):
        flat = " ".join(_read(COMPOSE).replace("#", " ").split())
        self.assertIn(BANNER, flat)

    def test_main_docs_link_the_docker_readme(self):
        for name in ("README.md", "MODES.md"):
            text = _read(os.path.join(ROOT, name))
            self.assertIn("(docker/README.md)", text, name)
            near = text[text.index("(docker/README.md)") - 400:
                        text.index("(docker/README.md)") + 400]
            self.assertIn("unverified", near.lower(), name)

    def test_no_em_dashes(self):
        for path in (COMPOSE, DOCKERFILE, DOCKER_README, OH_SETTINGS):
            self.assertNotIn("\u2014", _read(path), path)


if __name__ == "__main__":
    unittest.main()
