"""oh_setup: the generated OPENHARNESS_CONFIG_DIR (gateway hooks first at
priority 1000, the user's settings and hooks kept, settings.json 0600, other
entries symlinked, the user's dir never written, idempotent) and provider-host
detection from oh's active profile (row 10). Temp dirs only; never touches
the real ~/.openharness.
"""
import json
import os
import stat
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

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
    CASES = [
        ("claude-api", prof("claude-api", provider="anthropic"),
         {}, {"api.anthropic.com"}),
        ("claude-subscription", prof("claude-subscription",
                                     provider="anthropic_claude"),
         {}, {"api.anthropic.com"}),
        ("openai-compatible custom base_url",
         prof("openai-compatible", provider="openai",
              base_url="https://llm.example.org:8443/v1"),
         {}, {"llm.example.org:8443"}),
        ("openai-compatible base_url without port",
         prof("openai-compatible", provider="openai",
              base_url="https://OpenRouter.ai/api/v1"),
         {}, {"openrouter.ai"}),
        ("openai default", prof("openai-compatible", provider="openai"),
         {}, {"api.openai.com"}),
        ("codex", prof("codex", provider="openai_codex"), {}, {"chatgpt.com"}),
        ("copilot", prof("copilot", provider="copilot"), {},
         {"api.githubcopilot.com"}),
        ("ollama base_url", prof("ollama", provider="openai",
                                 base_url="http://localhost:11434/v1"),
         {}, {"localhost:11434"}),
        ("ollama provider without base_url", prof("local", provider="ollama"),
         {}, {"localhost:11434"}),
        ("built-in profile not in settings", {"active_profile": "codex"}, {},
         {"chatgpt.com"}),
        ("flat settings", {"provider": "openai",
                           "base_url": "https://api.together.xyz/v1",
                           "model": "x"}, {}, {"api.together.xyz"}),
        ("flat provider only", {"provider": "openai", "model": "gpt"}, {},
         {"api.openai.com"}),
        ("OPENHARNESS_PROFILE override", USER_SETTINGS,
         {"OPENHARNESS_PROFILE": "local"}, {"localhost:11434"}),
        ("override to a built-in profile", USER_SETTINGS,
         {"OPENHARNESS_PROFILE": "codex"}, {"chatgpt.com"}),
        ("override beats flat keys", {"provider": "openai"},
         {"OPENHARNESS_PROFILE": "claude-api"}, {"api.anthropic.com"}),
        ("missing file", {}, {}, {"api.anthropic.com"}),
        ("unknown provider", prof("weird", provider="mystery"), {}, set()),
    ]

    def test_cases(self):
        for label, settings, env, expected in self.CASES:
            with self.subTest(label):
                self.assertEqual(oh_setup.provider_hosts(settings, env), expected)

    def test_only_the_active_profile_host(self):
        hosts = oh_setup.provider_hosts(USER_SETTINGS, {})
        self.assertEqual(hosts, {"api.anthropic.com"})
        self.assertNotIn("localhost:11434", hosts)

    def test_active_profile_name(self):
        self.assertEqual(oh_setup.active_profile({}, {})[0], "claude-api")
        self.assertEqual(oh_setup.active_profile(USER_SETTINGS,
                                                 {"OPENHARNESS_PROFILE": "local"})[0],
                         "local")
        name, p = oh_setup.active_profile(USER_SETTINGS, {})
        self.assertEqual((name, p["provider"]), ("claude-api", "anthropic"))

    def test_settings_file_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "settings.json"), "w") as f:
                json.dump(prof("ollama", provider="ollama",
                               base_url="http://localhost:11434/v1"), f)
            s = oh_setup.load_user_settings(d)
            self.assertEqual(oh_setup.provider_hosts(s, {}), {"localhost:11434"})


if __name__ == "__main__":
    unittest.main()
