"""Hide secrets before anything reaches the console, the dashboard or the audit log."""
from __future__ import annotations

import hashlib
import re
from typing import Any

SECRET_HEADERS = {"authorization", "proxy-authorization", "x-api-key", "cookie", "set-cookie",
                  "x-goog-api-key", "api-key"}

_BUILTIN = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    re.compile(r"xox[abpr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}"),
]
MAX_FIELD = 300


def redact_text(text: str, extra: list[re.Pattern] | None = None) -> str:
    for pat in _BUILTIN + list(extra or []):
        text = pat.sub("[REDACTED]", text)
    return text


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: ("[REDACTED]" if k.lower() in SECRET_HEADERS else v) for k, v in headers.items()}


def summarize(value: Any, extra: list[re.Pattern] | None = None) -> Any:
    """Redact and shorten a tool input so it is safe and readable in the log."""
    if isinstance(value, dict):
        return {k: summarize(v, extra) for k, v in value.items()}
    if isinstance(value, list):
        return [summarize(v, extra) for v in value[:50]]
    if isinstance(value, str):
        clean = redact_text(value, extra)
        if len(clean) > MAX_FIELD:
            digest = hashlib.sha256(value.encode()).hexdigest()[:16]
            clean = f"{clean[:MAX_FIELD]}… [{len(value)} chars, sha256:{digest}]"
        return clean
    return value
