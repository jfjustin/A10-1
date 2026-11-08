"""oh_setup: the generated OPENHARNESS_CONFIG_DIR (gateway hooks first in each
list, the user's settings and hooks kept, settings.json 0600, other entries
symlinked, the user's dir never written, idempotent) and provider-host
detection from oh's active profile (row 10). OhSourceTest repeats the key
checks against the installed openharness package when it is importable. Temp
dirs only; never touches the real ~/.openharness.
"""
import asyncio
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS_DIR)
for _p in (ROOT, TESTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _support  # noqa: E402
import harness  # noqa: E402
import oh_setup  # noqa: E402

GW = "http://127.0.0.1:18765"
HOOK_URL = GW + "/hooks/oh"
USER_PRE_HOOK = {"type": "command", "command": "echo user-pre", "priority": 5}
USER_POST_HOOK = {"type": "http", "url": "https://hooks.example/post"}
USER_SETTINGS = {
    "active_profile": "claude-api",
    "profiles": {
        "claude-api": {"label": "Claude API", "provider": "anthropic",
                       "api_format": "anthropic", "auth_source": "api_key",
                       "default_model": "claude-sonnet-4"},
        "local": {"label": "Ollama", "provider": "openai",
                  "base_url": "http://localhost:11434/v1"},
    },
    "theme": "dark",
    "hooks": {"pre_tool_use": [USER_PRE_HOOK],
              "post_tool_use": [USER_POST_HOOK],
              "session_start": [{"type": "command", "command": "echo hi"}]},
}


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def snapshot(path):
    """{relative path: (is_link, bytes_or_target, mtime_ns)} of a tree."""
    out = {}
    for base, dirs, files in os.walk(path):
        for name in dirs + files:
            p = os.path.join(base, name)
            rel = os.path.relpath(p, path)
            st = os.lstat(p)
            if os.path.islink(p):
                out[rel] = (True, os.readlink(p), st.st_mtime_ns)
            elif os.path.isfile(p):
                with open(p, "rb") as f:
                    out[rel] = (False, f.read(), st.st_mtime_ns)
            else:
                out[rel] = (False, None, st.st_mtime_ns)
    return out


class PrepareConfigDirTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = os.path.realpath(self._tmp.name)
        self.user_dir = os.path.join(base, "user-openharness")
        self.home = os.path.join(base, "a10home")
        os.makedirs(os.path.join(self.user_dir, "data"))
        os.makedirs(self.home, mode=0o700)
        with open(os.path.join(self.user_dir, "settings.json"), "w") as f:
            json.dump(USER_SETTINGS, f)
        with open(os.path.join(self.user_dir, "credentials.json"), "w") as f:
            f.write('{"anthropic": "sk-ant-test"}')
        with open(os.path.join(self.user_dir, "data", "history.json"), "w") as f:
            f.write("[]")
        self.out = os.path.join(self.home, "oh-config")

    def tearDown(self):
        self._tmp.cleanup()

    def prepare(self, gw=GW):
        return oh_setup.prepare_config_dir(self.home, gw, self.user_dir)

    def settings(self):
        with open(os.path.join(self.out, "settings.json")) as f:
            return json.load(f)

    def test_hooks_first_with_priority_1000_and_user_hooks_kept(self):
        env = self.prepare()
        self.assertEqual(env, {"OPENHARNESS_CONFIG_DIR": self.out})
        s = self.settings()
        pre, post = s["hooks"]["pre_tool_use"], s["hooks"]["post_tool_use"]
        self.assertEqual(pre[0], {"type": "http", "url": HOOK_URL,
                                  "timeout_seconds": 600,
                                  "block_on_failure": True, "priority": 1000})
        self.assertEqual(pre[1:], [USER_PRE_HOOK])
        self.assertEqual(post[0], {"type": "http", "url": HOOK_URL,
                                   "timeout_seconds": 10,
                                   "block_on_failure": False, "priority": 1000})
        self.assertEqual(post[1:], [USER_POST_HOOK])
        self.assertEqual(s["hooks"]["session_start"],
                         USER_SETTINGS["hooks"]["session_start"])
        for key in ("active_profile", "profiles", "theme"):
            self.assertEqual(s[key], USER_SETTINGS[key])

    def test_permissions(self):
        self.prepare()
        self.assertEqual(mode_of(os.path.join(self.out, "settings.json")), 0o600)
        self.assertEqual(mode_of(self.out), 0o700)

    def test_other_entries_are_symlinked_not_copied(self):
        self.prepare()
        cred = os.path.join(self.out, "credentials.json")
        self.assertTrue(os.path.islink(cred))
        self.assertEqual(os.readlink(cred),
                         os.path.join(self.user_dir, "credentials.json"))
        self.assertTrue(os.path.islink(os.path.join(self.out, "data")))
        self.assertFalse(os.path.islink(os.path.join(self.out, "settings.json")))

    def test_user_dir_is_never_written(self):
        before = snapshot(self.user_dir)
        self.prepare()
        self.prepare("http://127.0.0.1:18766")
        self.assertEqual(snapshot(self.user_dir), before)

    def test_idempotent(self):
        self.prepare()
        first = snapshot(self.out)
        first_settings = self.settings()
        self.prepare()
        self.assertEqual(self.settings(), first_settings)
        self.assertEqual(sorted(snapshot(self.out)), sorted(first))
        self.prepare("http://127.0.0.1:18766")
        pre = self.settings()["hooks"]["pre_tool_use"]
        self.assertEqual([h.get("url") for h in pre if h.get("type") == "http"],
                         ["http://127.0.0.1:18766/hooks/oh"])
        self.assertEqual(len(pre), 2)

    def test_user_settings_already_containing_our_hook_is_not_duplicated(self):
        s = dict(USER_SETTINGS)
        s["hooks"] = oh_setup.hook_settings(GW)
        with open(os.path.join(self.user_dir, "settings.json"), "w") as f:
            json.dump(s, f)
        self.prepare()
        self.assertEqual(len(self.settings()["hooks"]["pre_tool_use"]), 1)

    def test_missing_user_dir(self):
        env = oh_setup.prepare_config_dir(self.home, GW,
                                          os.path.join(self.home, "nope"))
        s = self.settings()
        self.assertEqual(env["OPENHARNESS_CONFIG_DIR"], self.out)
        self.assertEqual(sorted(s), ["hooks"])
        self.assertEqual(sorted(os.listdir(self.out)), ["settings.json"])

    def test_stale_links_removed_and_real_entries_kept(self):
        self.prepare()
        os.makedirs(os.path.join(self.out, "logs"))  # created by oh earlier
        os.remove(os.path.join(self.user_dir, "credentials.json"))
        with open(os.path.join(self.user_dir, "copilot_auth.json"), "w") as f:
            f.write("{}")
        os.makedirs(os.path.join(self.user_dir, "logs"))
        self.prepare()
        names = os.listdir(self.out)
        self.assertNotIn("credentials.json", names)
        self.assertTrue(os.path.islink(os.path.join(self.out, "copilot_auth.json")))
        self.assertFalse(os.path.islink(os.path.join(self.out, "logs")),
                         "a real entry of ours is never clobbered")

    def test_symlinked_settings_is_replaced_not_followed(self):
        os.makedirs(self.out, mode=0o700)
        victim = os.path.join(self.home, "victim.txt")
        with open(victim, "w") as f:
            f.write("keep me")
        os.symlink(victim, os.path.join(self.out, "settings.json"))
        self.prepare()
        with open(victim) as f:
            self.assertEqual(f.read(), "keep me")
        self.assertFalse(os.path.islink(os.path.join(self.out, "settings.json")))

    def test_refuses_to_use_its_own_dir_as_the_user_dir(self):
        with self.assertRaises(ValueError):
            oh_setup.prepare_config_dir(self.home, GW, self.out)

    def test_user_config_dir(self):
        self.assertEqual(oh_setup.user_config_dir({"OPENHARNESS_CONFIG_DIR":
                                                   self.user_dir}),
                         self.user_dir)
        self.assertEqual(oh_setup.user_config_dir({}),
                         os.path.expanduser("~/.openharness"))

    def test_load_user_settings_missing_or_invalid(self):
        self.assertEqual(oh_setup.load_user_settings(self.home), {})
        with open(os.path.join(self.home, "settings.json"), "w") as f:
            f.write("{not json")
        self.assertEqual(oh_setup.load_user_settings(self.home), {})
        self.assertEqual(oh_setup.load_user_settings(self.user_dir)["theme"],
                         "dark")


def prof(name, **fields):
    return {"active_profile": name, "profiles": {name: fields}}


class ProviderHostsTest(unittest.TestCase):
    """Expected hosts follow oh 0.1.9's profile resolution and client choice
    (see oh_setup.provider_hosts); OhSourceTest checks the same cases against
    the installed openharness when it is importable."""

    CASES = [
        ("claude-api", prof("claude-api", provider="anthropic",
                            api_format="anthropic"),
         {}, {"api.anthropic.com"}),
        ("claude-subscription", prof("claude-subscription",
                                     provider="anthropic_claude",
                                     api_format="anthropic"),
         {}, {"api.anthropic.com"}),
        ("openai-compatible custom base_url",
         prof("openai-compatible", provider="openai", api_format="openai",
              base_url="https://llm.example.org:8443/v1"),
         {}, {"llm.example.org:8443"}),
        ("base_url without port",
         prof("openrouter", provider="openai", api_format="openai",
              base_url="https://OpenRouter.ai/api/v1"),
         {}, {"openrouter.ai"}),
        ("openai default", prof("openai-compatible", provider="openai",
                                api_format="openai"),
         {}, {"api.openai.com"}),
        ("codex", prof("codex", provider="openai_codex", api_format="openai"),
         {}, {"chatgpt.com"}),
        ("copilot", prof("copilot", provider="copilot", api_format="copilot"),
         {}, {"api.githubcopilot.com"}),
        ("copilot ignores the profile base_url",
         prof("copilot", provider="copilot", api_format="copilot",
              base_url="https://elsewhere.example"),
         {}, {"api.githubcopilot.com"}),
        ("ollama base_url", prof("local", provider="openai", api_format="openai",
                                 base_url="http://localhost:11434/v1"),
         {}, {"localhost:11434"}),
        ("built-in profile, empty profiles",
         {"active_profile": "codex", "profiles": {}}, {}, {"chatgpt.com"}),
        ("built-in profile with a base_url",
         {"active_profile": "gemini", "profiles": {}}, {},
         {"generativelanguage.googleapis.com"}),
        ("user profile inherits the built-in base_url",
         prof("qwen", provider="dashscope", api_format="openai"), {},
         {"dashscope.aliyuncs.com"}),
        ("active_profile without profiles is ignored by oh",
         {"active_profile": "codex"}, {}, {"api.anthropic.com"}),
        ("unknown active profile falls back to the flat keys",
         {"active_profile": "nope", "profiles": {},
          "provider": "openai_codex"}, {}, {"chatgpt.com"}),
        ("flat base_url", {"provider": "openai", "api_format": "openai",
                           "base_url": "https://api.together.xyz/v1",
                           "model": "x"}, {}, {"api.together.xyz"}),
        ("flat openai without api_format uses the Anthropic client",
         {"provider": "openai", "model": "gpt"}, {}, {"api.anthropic.com"}),
        ("flat openai format", {"provider": "openai", "api_format": "openai"},
         {}, {"api.openai.com"}),
        ("flat codex", {"provider": "openai_codex"}, {}, {"chatgpt.com"}),
        ("flat copilot format", {"api_format": "copilot"}, {},
         {"api.githubcopilot.com"}),
        ("missing file", {}, {}, {"api.anthropic.com"}),
        ("ANTHROPIC_BASE_URL", prof("claude-api", provider="anthropic",
                                    api_format="anthropic"),
         {"ANTHROPIC_BASE_URL": "https://llm-gw.example:4000"},
         {"llm-gw.example:4000"}),
        ("OPENAI_BASE_URL", prof("openai-compatible", provider="openai",
                                 api_format="openai"),
         {"OPENAI_BASE_URL": "http://localhost:11434/v1"}, {"localhost:11434"}),
        ("the profile base_url beats the SDK variable",
         prof("custom", provider="openai", api_format="openai",
              base_url="https://llm.example.org/v1"),
         {"OPENAI_BASE_URL": "https://other.example/v1"}, {"llm.example.org"}),
        ("OPENAI_BASE_URL does not apply to codex",
         prof("codex", provider="openai_codex", api_format="openai"),
         {"OPENAI_BASE_URL": "https://other.example/v1"}, {"chatgpt.com"}),
        ("OPENHARNESS_PROFILE is not read by oh", USER_SETTINGS,
         {"OPENHARNESS_PROFILE": "local"}, {"api.anthropic.com"}),
        ("unknown provider uses the Anthropic client",
         prof("weird", provider="mystery", api_format="anthropic"), {},
         {"api.anthropic.com"}),
        ("unparseable base_url", prof("x", provider="openai",
                                      api_format="openai", base_url="https://"),
         {}, set()),
    ]

    def test_cases(self):
        for label, settings, env, expected in self.CASES:
            with self.subTest(label):
                self.assertEqual(oh_setup.provider_hosts(settings, env), expected)

    def test_only_the_active_profile_host(self):
        hosts = oh_setup.provider_hosts(USER_SETTINGS, {})
        self.assertEqual(hosts, {"api.anthropic.com"})
        self.assertNotIn("localhost:11434", hosts)
        local = dict(USER_SETTINGS, active_profile="local")
        self.assertEqual(oh_setup.provider_hosts(local, {}), {"localhost:11434"})

    def test_active_profile_name(self):
        self.assertEqual(oh_setup.active_profile({})[0], "claude-api")
        self.assertEqual(oh_setup.active_profile(
            dict(USER_SETTINGS, active_profile="local"))[0], "local")
        name, p = oh_setup.active_profile(USER_SETTINGS)
        self.assertEqual((name, p["provider"]), ("claude-api", "anthropic"))
        self.assertEqual(oh_setup.active_profile(
            {"provider": "openai", "base_url": "https://api.together.xyz/v1"}
        )[0], "v1", "oh names a flat base_url profile after its last segment")

    def test_settings_file_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "settings.json"), "w") as f:
                json.dump(prof("ollama", provider="openai", api_format="openai",
                               base_url="http://localhost:11434/v1"), f)
            s = oh_setup.load_user_settings(d)
            self.assertEqual(oh_setup.provider_hosts(s, {}), {"localhost:11434"})


def _valid_profile(**fields):
    """A profile oh's ProviderProfile model accepts (label, auth_source and
    default_model are required there)."""
    out = {"label": "Test", "auth_source": "anthropic_api_key",
           "default_model": "test-model"}
    out.update(fields)
    return out


OH_USER_SETTINGS = {
    "active_profile": "claude-api",
    "profiles": {
        "claude-api": _valid_profile(provider="anthropic",
                                     api_format="anthropic"),
        "local": _valid_profile(provider="openai", api_format="openai",
                                auth_source="openai_api_key",
                                base_url="http://localhost:11434/v1"),
    },
    "theme": "dark",
    "hooks": {"pre_tool_use": [USER_PRE_HOOK],
              "post_tool_use": [USER_POST_HOOK],
              "session_start": [{"type": "command", "command": "echo hi"}]},
}

FAKE_KEYS = {"ANTHROPIC_API_KEY": "sk-ant-test-not-a-real-key",
             "OPENAI_API_KEY": "sk-test-not-a-real-key"}


def clean_env(config_dir, **extra):
    """A minimal environment for calling into openharness: its config dir is
    a temp dir and no provider or proxy variable leaks in from the shell."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "HOME": config_dir, "OPENHARNESS_CONFIG_DIR": config_dir}
    env.update(extra)
    return env


@unittest.skipUnless(importlib.util.find_spec("openharness"),
                     "openharness not installed (pip install openharness-ai)")
class OhSourceTest(unittest.TestCase):
    """Checks against the installed openharness package (0.1.9 when written)
    without a provider, network or LLM call: oh's own settings loader reads
    the generated settings.json, oh's own HookExecutor (httpx) calls a live
    in-thread gateway, and oh's own client factory picks the API host that
    provider_hosts() predicts. Temp OPENHARNESS_CONFIG_DIR and HOME only."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = os.path.realpath(self._tmp.name)
        self.user_dir = os.path.join(base, "user-openharness")
        self.home = os.path.join(base, "a10home")
        os.makedirs(self.user_dir)
        os.makedirs(self.home, mode=0o700)
        self.out = os.path.join(self.home, "oh-config")

    def tearDown(self):
        self._tmp.cleanup()

    def write_user(self, settings):
        with open(os.path.join(self.user_dir, "settings.json"), "w") as f:
            json.dump(settings, f)

    def oh_settings(self):
        from openharness.config import load_settings
        from openharness.config.paths import get_config_file_path
        self.assertEqual(str(get_config_file_path()),
                         os.path.join(self.out, "settings.json"))
        return load_settings()

    def test_generated_settings_load_with_ohs_loader(self):
        from openharness.hooks.events import HookEvent
        from openharness.hooks.loader import load_hook_registry
        from openharness.hooks.schemas import (CommandHookDefinition,
                                               HttpHookDefinition)
        self.write_user(OH_USER_SETTINGS)
        oh_setup.prepare_config_dir(self.home, GW, self.user_dir)
        with mock.patch.dict(os.environ, clean_env(self.out), clear=True):
            s = self.oh_settings()
        self.assertEqual((s.active_profile, s.theme), ("claude-api", "dark"))
        reg = load_hook_registry(s)
        pre = reg.get(HookEvent.PRE_TOOL_USE)
        post = reg.get(HookEvent.POST_TOOL_USE)
        self.assertIsInstance(pre[0], HttpHookDefinition)
        self.assertEqual((pre[0].url, pre[0].timeout_seconds,
                          pre[0].block_on_failure, pre[0].matcher,
                          pre[0].headers), (HOOK_URL, 600, True, None, {}))
        self.assertNotIn("priority", pre[0].model_dump(),
                         "oh 0.1.9 drops the priority key; list order counts")
        self.assertIsInstance(pre[1], CommandHookDefinition)
        self.assertEqual(pre[1].command, "echo user-pre")
        self.assertIsInstance(post[0], HttpHookDefinition)
        self.assertEqual((post[0].url, post[0].timeout_seconds,
                          post[0].block_on_failure), (HOOK_URL, 10, False))
        self.assertEqual(post[1].url, USER_POST_HOOK["url"])
        self.assertEqual(len(reg.get(HookEvent.SESSION_START)), 1)

    def test_settings_without_a_user_file_load(self):
        from openharness.hooks.events import HookEvent
        from openharness.hooks.loader import load_hook_registry
        oh_setup.prepare_config_dir(self.home, GW,
                                    os.path.join(self.home, "nope"))
        with mock.patch.dict(os.environ, clean_env(self.out), clear=True):
            s = self.oh_settings()
        self.assertEqual(s.active_profile, "claude-api")
        self.assertEqual([h.url for h in
                          load_hook_registry(s).get(HookEvent.PRE_TOOL_USE)],
                         [HOOK_URL])

    def executor(self, gateway_url):
        """oh's HookExecutor for our generated config, with the environment
        harness.py gives oh (proxy variables pointing at a dead proxy, so a
        hook call that ignored NO_PROXY would fail)."""
        from openharness.hooks.executor import (HookExecutionContext,
                                                HookExecutor)
        from openharness.hooks.loader import load_hook_registry
        env = oh_setup.prepare_config_dir(self.home, gateway_url,
                                          os.path.join(self.home, "nope"))
        agent_env = harness.build_agent_env(
            clean_env(self.out), "http://127.0.0.1:%d" % _support.free_port())
        agent_env.update(env)
        patcher = mock.patch.dict(os.environ, agent_env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        ctx = HookExecutionContext(cwd=Path(self.home), api_client=None,
                                   default_model="test-model")
        return HookExecutor(load_hook_registry(self.oh_settings()), ctx)

    @staticmethod
    def pre(executor, tool, tool_input):
        from openharness.hooks.events import HookEvent
        payload = {"tool_name": tool, "tool_input": tool_input,
                   "event": HookEvent.PRE_TOOL_USE.value}
        return asyncio.run(executor.execute(HookEvent.PRE_TOOL_USE, payload))

    def test_ohs_http_hook_against_the_gateway(self):
        from openharness.hooks.events import HookEvent
        gw = _support.GatewayFixture(approval_wait=30)
        self.addCleanup(gw.close)
        ex = self.executor(gw.url)
        self.assertIn("127.0.0.1", os.environ["NO_PROXY"].split(","))
        self.assertTrue(os.environ["HTTPS_PROXY"].startswith("http://127.0.0.1:"))

        blocked = self.pre(ex, "bash", {"command": "rm demo-files/notes.txt"})
        self.assertTrue(blocked.blocked)
        self.assertIn("row 28", blocked.reason)
        self.assertEqual(blocked.results[0].metadata["status_code"], 403)

        allowed = self.pre(ex, "bash", {"command": "ls demo-files"})
        self.assertFalse(allowed.blocked, allowed.reason)
        self.assertEqual(allowed.results[0].metadata["status_code"], 200)

        # A row 3 ask is held open until the operator approves it.
        t, box = gw.in_thread(self.pre, ex, "write_file",
                              {"path": "demo-files/summary.md",
                               "content": "x"})
        item = gw.wait_pending()[0]
        self.assertEqual(gw.op("/approve", {"id": item["id"],
                                            "decision": "approve"}).status, 200)
        t.join(30)
        self.assertFalse(box["result"].blocked, box["result"].reason)

        post = asyncio.run(ex.execute(HookEvent.POST_TOOL_USE, {
            "tool_name": "read_file", "tool_input": {"path": ".env"},
            "tool_output": "KEY=AKIA" + "ABCDEFGHIJKLMNOP",
            "tool_is_error": False, "event": "post_tool_use"}))
        self.assertFalse(post.blocked)
        self.assertTrue(gw.status()["tainted"])

        tools = [(e["tool"], e["verdict"], e["source"]) for e in gw.events()
                 if e.get("kind") == "tool"]
        self.assertIn(("bash", "block", "oh"), tools)
        self.assertIn(("bash", "allow", "oh"), tools)

    def test_ohs_http_hook_fails_closed_when_the_gateway_is_down(self):
        ex = self.executor("http://127.0.0.1:%d" % _support.free_port())
        res = self.pre(ex, "bash", {"command": "ls"})
        self.assertTrue(res.blocked)

    def test_builtin_catalog_and_default_hosts_match(self):
        from openharness.api.codex_client import DEFAULT_CODEX_BASE_URL
        from openharness.api.copilot_auth import copilot_api_base
        from openharness.config.settings import default_provider_profiles
        catalog = {n: {k: v for k, v in (("provider", p.provider),
                                         ("api_format", p.api_format),
                                         ("base_url", p.base_url)) if v}
                   for n, p in default_provider_profiles().items()}
        self.assertEqual(catalog, oh_setup.BUILTIN_PROFILES)
        self.assertEqual(urlsplit(DEFAULT_CODEX_BASE_URL).hostname,
                         oh_setup.CODEX_HOST)
        self.assertEqual(urlsplit(copilot_api_base(None)).hostname,
                         oh_setup.COPILOT_HOST)

    def test_provider_hosts_match_ohs_client_choice(self):
        """For API-key profiles, build oh's real API client offline (fake
        keys, no request is sent) and compare its base URL host with
        provider_hosts()."""
        from openharness.config import load_settings
        from openharness.ui.runtime import _resolve_api_client_from_settings
        cases = [
            {},
            {"active_profile": "openai-compatible", "profiles": {}},
            {"active_profile": "gemini", "profiles": {}},
            {"active_profile": "codex"},
            dict(OH_USER_SETTINGS, active_profile="local"),
            OH_USER_SETTINGS,
            {"active_profile": "custom", "profiles": {"custom": _valid_profile(
                provider="openai", api_format="openai",
                auth_source="openai_api_key",
                base_url="https://llm.example.org:8443/v1")}},
            {"provider": "openai", "model": "gpt"},
            {"provider": "openai", "api_format": "openai"},
            {"provider": "openai", "api_format": "openai",
             "base_url": "https://api.together.xyz/v1"},
        ]
        envs = [{}, {"ANTHROPIC_BASE_URL": "https://llm-gw.example:4000"},
                {"OPENAI_BASE_URL": "https://oai-gw.example/v1"}]
        path = os.path.join(self.user_dir, "settings.json")
        for settings in cases:
            for extra in envs:
                with self.subTest(settings=settings, env=extra):
                    self.write_user(settings)
                    env = clean_env(self.user_dir, **FAKE_KEYS, **extra)
                    with mock.patch.dict(os.environ, env, clear=True):
                        client = _resolve_api_client_from_settings(
                            load_settings(Path(path)))
                    url = urlsplit(str(client._client.base_url))
                    host = url.hostname + (":%d" % url.port if url.port else "")
                    self.assertEqual(oh_setup.provider_hosts(settings, extra),
                                     {host}, type(client).__name__)


if __name__ == "__main__":
    unittest.main()
