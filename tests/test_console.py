"""Terminal operator console (console.py) against an in-thread gateway:
a / A / d / m / override+YES / s, the argv-form macOS notification, and
stripping of ANSI escapes and control characters from agent-controlled text.
"""
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _support import GatewayFixture  # noqa: E402

import console  # noqa: E402


class FakeRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append(argv)


class ConsoleTest(unittest.TestCase):
    def setUp(self):
        self.gw = GatewayFixture(mode="default", approval_wait=30.0)
        self.out = io.StringIO()
        self.runner = FakeRunner()
        self.c = console.Console(self.gw.url, self.gw.token, out=self.out,
                                 notify=False, color=False, runner=self.runner)

    def tearDown(self):
        self.c.stop()
        self.gw.close()

    def held_write(self, name="summary.md", content="x"):
        t, box = self.gw.in_thread(self.gw.write, name, content)
        item = self.gw.wait_pending()[-1]
        return t, box, item

    def test_a_approves_oldest_pending_once(self):
        self.assertEqual(self.c.handle_line("a"), "nothing is waiting for approval")
        t, box, item = self.held_write()
        msg = self.c.handle_line("a")
        self.assertIn("approved %s once" % item["id"], msg)
        t.join(5)
        self.assertEqual(box["result"].status, 200)
        self.assertEqual(box["result"].json().get("decision"), "approve")

    def test_A_approves_for_the_run(self):
        t, box, item = self.held_write(content="same")
        msg = self.c.handle_line("A %s" % item["id"])
        self.assertIn("for the rest of the run", msg)
        t.join(5)
        self.assertEqual(box["result"].status, 200)
        r = self.gw.write("summary.md", "same")
        self.assertEqual(r.status, 200)
        self.assertEqual(self.gw.pending(), [])

    def test_d_with_id_and_reason(self):
        t, box, item = self.held_write()
        msg = self.c.handle_line("d %s please do not write files" % item["id"])
        self.assertIn("denied %s" % item["id"], msg)
        t.join(5)
        res = box["result"]
        self.assertEqual((res.status, res.verdict), (403, "deny"))
        self.assertIn("please do not write files", res.text)

    def test_d_without_reason_prompts(self):
        t, box, item = self.held_write()
        prompt = self.c.handle_line("d")
        self.assertIn("Reason for denying %s" % item["id"], prompt)
        self.assertTrue(t.is_alive())
        self.c.handle_line("use /tmp")
        t.join(5)
        self.assertIn("use /tmp", box["result"].text)

    def test_m_changes_mode(self):
        self.assertIn("mode is now auto", self.c.handle_line("m auto"))
        self.assertEqual(self.gw.status()["mode"], "auto")
        self.assertIn("New mode", self.c.handle_line("m"))
        self.assertIn("mode is now plan", self.c.handle_line("plan"))
        self.assertIn("mode not changed", self.c.handle_line("m turbo"))
        self.assertEqual(self.gw.status()["mode"], "plan")

    def test_override_requires_typed_YES(self):
        prompt = self.c.handle_line("override 28")
        self.assertIn("Type YES", prompt)
        self.assertIn("cancelled", self.c.handle_line("no"))
        self.assertEqual(self.gw.status()["overrides"], [])
        self.c.handle_line("o 28")
        self.assertIn("cancelled", self.c.handle_line("yes"))
        self.assertEqual(self.gw.status()["overrides"], [])
        self.c.handle_line("override 28")
        self.assertIn("row 28 overridden", self.c.handle_line("YES"))
        self.assertEqual(self.gw.status()["overrides"], ["28"])
        self.assertIn("usage", self.c.handle_line("override 99"))

    def test_s_stops_the_run(self):
        t, box, _item = self.held_write()
        self.assertIn("run stopped", self.c.handle_line("s"))
        t.join(5)
        self.assertEqual(box["result"].verdict, "stopped")
        self.assertTrue(self.gw.status()["stopped"])

    def test_status_help_quit(self):
        self.assertIn("mode default", self.c.handle_line("?"))
        self.assertIn("approve once", self.c.handle_line("h"))
        self.assertIn("unknown command", self.c.handle_line("zz"))
        self.c.handle_line("q")
        self.assertTrue(self.c.quit)

    def test_wrong_token_is_reported(self):
        bad = console.Console(self.gw.url, "wrong", out=io.StringIO(),
                              notify=False, color=False)
        self.assertIn("token rejected", bad.handle_line("s"))
        self.assertFalse(self.gw.status()["stopped"])

    def test_poller_prints_events_and_pending_block(self):
        self.gw.bash("ls demo-files")
        t, box, item = self.held_write()
        self.c.poll_once()
        text = self.out.getvalue()
        self.assertIn("ALLOW [row 5] bash: ls demo-files", text)
        self.assertIn("APPROVAL NEEDED %s" % item["id"], text)
        self.assertIn("\a", text)
        self.c.handle_line("a")
        t.join(5)

    def test_control_characters_are_stripped(self):
        # Quoted, so it stays one read-only `echo` segment (row 5, allowed).
        evil = "echo '\x1b[2J\x1b]0;pwned\x07\x1b[31mred\x00\x08\rdone'"
        r = self.gw.bash(evil)
        self.assertEqual(r.status, 200)
        self.c.poll_once()
        text = self.out.getvalue()
        self.assertIn("ALLOW [row 5] bash: echo", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x00", text)
        self.assertNotIn("\x08", text)
        self.assertNotIn("\x07", text)
        self.assertIn("red", text)
        self.assertEqual(console.clean("a\x1b[1mb\x9bc\td"), "ab" + "c d")


class NotifyTest(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.pop("A10_NO_NOTIFY", None)

    def tearDown(self):
        if self._old is not None:
            os.environ["A10_NO_NOTIFY"] = self._old

    def make(self, notify=True):
        runner = FakeRunner()
        c = console.Console("http://127.0.0.1:1", "t", out=io.StringIO(),
                            notify=notify, color=False, runner=runner)
        c.platform = "darwin"
        return c, runner

    def test_argv_form_with_message_as_separate_element(self):
        c, runner = self.make()
        msg = 'x" & do shell script "touch /tmp/pwned" & "'
        argv = c.notify(msg)
        self.assertEqual(runner.calls, [argv])
        self.assertEqual(argv[0], "osascript")
        self.assertEqual(argv[-2], "--")
        self.assertEqual(argv[-1], msg)
        script = " ".join(argv[1:-2])
        self.assertIn("on run argv", script)
        self.assertIn("item 1 of argv", script)
        self.assertNotIn("pwned", script)

    def test_not_called_when_disabled(self):
        c, runner = self.make(notify=False)
        self.assertIsNone(c.notify("hello"))
        self.assertEqual(runner.calls, [])

    def test_not_called_off_darwin_or_with_env(self):
        c, runner = self.make()
        c.platform = "linux"
        self.assertIsNone(c.notify("hello"))
        c.platform = "darwin"
        os.environ["A10_NO_NOTIFY"] = "1"
        try:
            self.assertIsNone(c.notify("hello"))
        finally:
            del os.environ["A10_NO_NOTIFY"]
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
