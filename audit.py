"""Hash-chained audit log for the A10 Agent Harness (Prompt 2).

Same entry format and hash formula as the starter gateway, so logs written by
the starter still verify:

  {"seq": N, "ts": "...Z", "type": "...", "payload": {...}, "prev": "<hash>",
   "hash": sha256(prev + json.dumps(entry_without_hash, sort_keys=True))}

The first entry's prev is "GENESIS". Editing, deleting or reordering any line
breaks the chain from that line on, and verify() reports the first bad seq.

Verify a log offline:  python3 harness.py verify [path]
Stdlib only.
"""
import hashlib
import json
import os
import threading
import time

GENESIS = "GENESIS"

__all__ = ["AuditLog", "verify_file", "chain_hash", "GENESIS"]


def chain_hash(prev, entry_without_hash):
    body = json.dumps(entry_without_hash, sort_keys=True, default=str)
    return hashlib.sha256((prev + body).encode()).hexdigest()


def _verify_lines(lines):
    """-> (ok, count, first_bad_seq|None) for an iterable of JSONL lines."""
    prev, count = GENESIS, 0
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            check = dict(entry)
            h = check.pop("hash")
        except (ValueError, TypeError, KeyError, AttributeError):
            return False, count, count
        seq = entry.get("seq", count) if isinstance(entry, dict) else count
        if entry.get("prev") != prev or h != chain_hash(prev, check):
            return False, count, seq
        prev, count = h, count + 1
    return True, count, None


def verify_file(path):
    """Verify an audit log file. A missing file verifies as (True, 0, None)."""
    if not path or not os.path.exists(path):
        return True, 0, None
    with open(path, encoding="utf-8") as f:
        return _verify_lines(f)


class AuditLog:
    """Append-only, thread-safe, hash-chained JSONL log."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._loaded = False
        self._prev = GENESIS
        self._seq = 0

    def _load(self):
        self._prev, self._seq = GENESIS, 0
        if os.path.exists(self.path):
            last = None
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        last = line
            if last is not None:
                entry = json.loads(last)
                self._prev, self._seq = entry["hash"], entry["seq"] + 1
        self._loaded = True

    def append(self, event_type, payload):
        with self._lock:
            if not self._loaded:
                self._load()
            entry = {"seq": self._seq,
                     "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "type": event_type, "payload": payload, "prev": self._prev}
            entry["hash"] = chain_hash(self._prev, entry)
            d = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(d, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
            self._prev, self._seq = entry["hash"], self._seq + 1
            return entry

    def verify(self):
        """-> (ok, count, first_bad_seq|None)."""
        with self._lock:
            return verify_file(self.path)

    def wipe(self):
        with self._lock:
            if os.path.exists(self.path):
                os.remove(self.path)
            self._prev, self._seq = GENESIS, 0
            self._loaded = True
