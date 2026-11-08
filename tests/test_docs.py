"""Repo hygiene checks: no merge-conflict markers in tracked text files, the
README starts with the harness title, and .gitignore has no duplicate lines.

A merge (9cd92cc) once committed README.md with its conflict markers, so this
guards every tracked *.md, *.py, *.yml and *.json file. The file list comes
from `git ls-files` when the checkout is a git repo, else from a walk of the
tree (for a downloaded archive).
"""
import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXTENSIONS = (".md", ".py", ".yml", ".json")
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache"}
# Built from parts so this file never contains a marker line itself.
OPEN, MIDDLE, CLOSE = "<" * 7 + " ", "=" * 7, ">" * 7 + " "
TITLE = "# A10 Agent Harness: a control layer for CLI agents"


def conflict_lines(text):
    """1-based numbers of lines that are git conflict markers."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith((OPEN, CLOSE)) or line == MIDDLE:
            out.append(n)
    return out


def tracked_files():
    try:
        r = subprocess.run(["git", "-C", ROOT, "ls-files", "-z"],
                           capture_output=True, timeout=30)
        names = [n for n in r.stdout.decode("utf-8", "replace").split("\0") if n]
        if r.returncode == 0 and names:
            return sorted(names)
    except (OSError, subprocess.SubprocessError):
        pass
    names = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            names.append(os.path.relpath(os.path.join(base, name), ROOT))
    return sorted(names)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as f:
        return f.read()


class ConflictMarkerTest(unittest.TestCase):
    def test_detector_finds_a_committed_merge_conflict(self):
        sample = "\n".join([OPEN + "HEAD", TITLE, "", MIDDLE, "# A10-1",
                            "A10Hackathon", CLOSE + "ebb9e11", ""])
        self.assertEqual(conflict_lines(sample), [1, 4, 7])
        # Markdown rules and setext underlines of other lengths are fine.
        self.assertEqual(conflict_lines("Title\n=====\n---\n======== x\n"), [])

    def test_no_conflict_markers_in_tracked_files(self):
        files = [f for f in tracked_files() if f.endswith(EXTENSIONS)]
        self.assertIn("README.md", files)
        bad = {}
        for rel in files:
            path = os.path.join(ROOT, rel)
            if not os.path.isfile(path):
                continue  # deleted in the working tree
            hits = conflict_lines(read(rel))
            if hits:
                bad[rel] = hits
        self.assertEqual(bad, {}, "conflict markers (file: line numbers)")

    def test_readme_starts_with_the_harness_title(self):
        self.assertEqual(read("README.md").splitlines()[0], TITLE)


class GitignoreTest(unittest.TestCase):
    def test_no_duplicate_lines(self):
        lines = [s.strip() for s in read(".gitignore").splitlines()]
        lines = [s for s in lines if s and not s.startswith("#")]
        dupes = sorted({s for s in lines if lines.count(s) > 1})
        self.assertEqual(dupes, [])
        self.assertIn("audit.log.jsonl", lines)


if __name__ == "__main__":
    unittest.main()
