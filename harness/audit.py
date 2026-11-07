"""Hash-chained audit log.

Each line is a JSON object with `prev` (hash of the previous line) and `hash`
(sha256 of `prev` + the canonical JSON of the entry without `hash`). Changing,
removing or reordering any line breaks the chain from that point on.

    python -m harness.audit verify [state/audit.jsonl]
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


def _digest(prev: str, entry: dict) -> str:
    body = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev + body).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev, self._seq = GENESIS, 0
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    e = json.loads(line)
                    self._prev, self._seq = e["hash"], e["seq"]

    def append(self, kind: str, **fields) -> dict:
        with self._lock:
            entry = {"seq": self._seq + 1, "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                     "kind": kind, **fields, "prev": self._prev}
            entry["hash"] = _digest(self._prev, entry)
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._prev, self._seq = entry["hash"], entry["seq"]
            return entry


def verify(path: str | os.PathLike) -> tuple[bool, int, str]:
    """Return (ok, entries_checked, message)."""
    prev, n = GENESIS, 0
    p = Path(path)
    if not p.exists():
        return True, 0, "no audit log yet"
    for lineno, line in enumerate(p.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            return False, n, f"line {lineno}: not valid JSON"
        claimed = e.pop("hash", None)
        if e.get("prev") != prev:
            return False, n, f"line {lineno}: chain broken (prev hash doesn't match line {lineno - 1})"
        if _digest(prev, e) != claimed:
            return False, n, f"line {lineno}: entry was modified"
        prev, n = claimed, n + 1
    return True, n, f"chain intact ({n} entries)"


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "verify":
        from .config import STATE_DIR
        target = sys.argv[2] if len(sys.argv) > 2 else STATE_DIR / "audit.jsonl"
        ok, _, msg = verify(target)
        print(("OK: " if ok else "TAMPERED: ") + msg)
        sys.exit(0 if ok else 1)
    print(__doc__)
