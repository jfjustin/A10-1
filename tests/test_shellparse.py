"""Tests for the quote-aware shell splitter (shellparse.py)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shellparse  # noqa: E402


def verbs(res):
    return [shellparse.verb_of(s) for s in res.segments]


class ShellParseTest(unittest.TestCase):
    def test_semicolon_two_segments(self):
        res = shellparse.parse("ls; rm x")
        self.assertIsNone(res.error)
        self.assertEqual(len(res.segments), 2)
        self.assertEqual(res.segments[0].argv, ["ls"])
        self.assertEqual(res.segments[1].argv, ["rm", "x"])

    def test_pipeline_ids(self):
        res = shellparse.parse("a && b || c | d")
        self.assertIsNone(res.error)
        self.assertEqual(verbs(res), ["a", "b", "c", "d"])
        pids = [s.pipeline_id for s in res.segments]
        # a, b, c each start their own pipeline; d continues c's pipeline.
        self.assertEqual(pids[3], pids[2])
        self.assertNotEqual(pids[0], pids[1])
        self.assertNotEqual(pids[1], pids[2])
        self.assertEqual(res.segments[2].pipeline_pos, 0)
        self.assertEqual(res.segments[3].pipeline_pos, 1)

    def test_command_substitution_extracted(self):
        res = shellparse.parse("echo $(rm x)")
        self.assertIsNone(res.error)
        self.assertIn("rm", verbs(res))
        inner = [s for s in res.segments if s.from_substitution]
        self.assertTrue(any(s.argv[:1] == ["rm"] for s in inner))

    def test_backtick_substitution_extracted(self):
        res = shellparse.parse("echo `rm x`")
        self.assertIsNone(res.error)
        inner = [s for s in res.segments if s.from_substitution]
        self.assertTrue(any(s.argv[:1] == ["rm"] for s in inner))

    def test_substitution_inside_double_quotes(self):
        res = shellparse.parse('echo "$(rm x)"')
        self.assertIsNone(res.error)
        inner = [s for s in res.segments if s.from_substitution]
        self.assertTrue(any(s.argv[:1] == ["rm"] for s in inner))

    def test_quote_removal_gives_rm(self):
        self.assertEqual(shellparse.parse("'r'm x").segments[0].argv, ["rm", "x"])
        self.assertEqual(shellparse.parse("r\\m x").segments[0].argv, ["rm", "x"])

    def test_write_redirect_target(self):
        res = shellparse.parse("echo hi > out.txt")
        seg = res.segments[0]
        self.assertEqual(seg.argv, ["echo", "hi"])
        self.assertEqual(seg.write_targets, ["out.txt"])

    def test_fd_redirects_are_not_write_targets(self):
        self.assertEqual(shellparse.parse("ls 2>/dev/null").segments[0].write_targets, [])
        self.assertEqual(shellparse.parse("ls 2>&1").segments[0].write_targets, [])
        self.assertEqual(shellparse.parse("ls >&2").segments[0].write_targets, [])

    def test_append_and_clobber_redirects(self):
        self.assertEqual(shellparse.parse("echo x >> f").segments[0].write_targets, ["f"])
        self.assertEqual(shellparse.parse("echo x >| f").segments[0].write_targets, ["f"])
        self.assertEqual(shellparse.parse("echo x &> f").segments[0].write_targets, ["f"])

    def test_background_flag(self):
        res = shellparse.parse("sleep 5 &")
        self.assertTrue(res.segments[0].background)

    def test_heredoc_body_is_data(self):
        res = shellparse.parse("cat <<EOF\nrm x\nEOF\n")
        self.assertIsNone(res.error)
        self.assertNotIn("rm", verbs(res))
        self.assertEqual(res.segments[0].argv, ["cat"])

    def test_leading_assignments(self):
        res = shellparse.parse("HTTPS_PROXY= curl https://x.example")
        seg = res.segments[0]
        self.assertEqual(seg.assignments, ["HTTPS_PROXY="])
        self.assertEqual(seg.argv[0], "curl")

    def test_env_assignment_is_argv_not_leading(self):
        res = shellparse.parse("env FOO=1 ls")
        seg = res.segments[0]
        self.assertEqual(seg.assignments, [])
        self.assertEqual(seg.argv, ["env", "FOO=1", "ls"])

    def test_unbalanced_quote_sets_error(self):
        self.assertIsNotNone(shellparse.parse('"abc').error)
        self.assertIsNotNone(shellparse.parse("'abc").error)

    def test_unbalanced_paren_sets_error(self):
        self.assertIsNotNone(shellparse.parse("echo $(rm x").error)


if __name__ == "__main__":
    unittest.main()
