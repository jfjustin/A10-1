"""Pure network helpers shared by the policy engine and the proxies.

Host classification, the row-9 "clean URL" test, secret-pattern detection, and
redaction of secrets in text and headers. No I/O: everything here is a pure
function so it can be unit-tested offline. (The non-pure `ask_gateway()` client
and demo stubs are added in a later feature.)

Stdlib only.
"""
import re
from urllib.parse import urlsplit

__all__ = [
    "normalize_host", "split_host_port", "is_local_or_metadata", "host_class",
    "is_clean_url", "has_random_token", "SECRET_PATTERNS", "find_secrets",
    "redact_text", "redact_headers", "urls_in_text", "hosts_in_args",
]

# Local / metadata hosts (row 19).
_METADATA_HOSTS = {
    "localhost", "0.0.0.0", "::1", "169.254.169.254",
    "metadata.google.internal", "host.docker.internal",
}

# Header names whose values are redacted before display / audit.
_SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "x-api-key", "cookie", "set-cookie",
}

# (kind, compiled regex) in priority order.
SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("openai-key", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("github-token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
]

_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>|]+")
_SCP_RE = re.compile(r"^(?:([\w.-]+)@)?([a-zA-Z0-9.\-]+):(?!//)")
_SSH_USER_HOST_RE = re.compile(r"^(?:[\w.-]+@)([a-zA-Z0-9.\-]+)$")


def normalize_host(host):
    if not host:
        return ""
    h = host.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h.endswith(".") and len(h) > 1:
        h = h[:-1]
    return h


def split_host_port(netloc):
    """Return (host, port_or_None) from a netloc, which may include user@ and
    an IPv6 literal in brackets."""
    if not netloc:
        return "", None
    nl = netloc
    if "@" in nl:
        nl = nl.rsplit("@", 1)[1]
    port = None
    if nl.startswith("["):
        end = nl.find("]")
        host = nl[1:end] if end > 0 else nl
        rest = nl[end + 1:] if end > 0 else ""
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    elif ":" in nl and nl.count(":") == 1:
        host, p = nl.split(":", 1)
        if p.isdigit():
            port = int(p)
        else:
            host = nl
    else:
        host = nl
    return normalize_host(host), port


def is_local_or_metadata(host, port=None):
    h = normalize_host(host)
    if h in _METADATA_HOSTS:
        return True
    parts = h.split(".")
    if len(parts) == 4 and parts[0] == "127" and all(p.isdigit() for p in parts):
        return True
    return False


def host_class(host, port, settings):
    """-> 'provider' | 'allowlisted' | 'local' | 'public'."""
    h = normalize_host(host)
    hp = "%s:%s" % (h, port) if port else h
    provs = getattr(settings, "provider_hosts", None) or set()
    if h in provs or hp in provs:
        return "provider"
    allowed = getattr(settings, "allowed_hosts", None) or set()
    if h in allowed or hp in allowed:
        return "allowlisted"
    if is_local_or_metadata(h, port):
        return "local"
    return "public"


def has_random_token(text):
    """True if `text` looks like a long opaque token (hex or base64-ish),
    the row-9 clean-URL test applied to a single segment or host label."""
    t = text or ""
    if len(t) <= 16:
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", t):
        return True
    if (re.fullmatch(r"[A-Za-z0-9+/=_-]+", t)
            and re.search(r"[A-Za-z]", t)
            and re.search(r"\d", t)):
        return True
    return False


def is_clean_url(url):
    """Row-9 clean-URL test. -> (bool, reason)."""
    u = url or ""
    if "://" not in u:
        u = "https://" + u
    parts = urlsplit(u)
    if parts.query:
        return False, "has a query string"
    if parts.fragment:
        return False, "has a URL fragment"
    for seg in parts.path.split("/"):
        if not seg:
            continue
        if len(seg) > 32:
            return False, "path segment longer than 32 chars"
        if has_random_token(seg):
            return False, "random-looking path segment '%s'" % seg
    host = normalize_host(parts.hostname or "")
    for label in host.split("."):
        if has_random_token(label):
            return False, "random-looking host label '%s'" % label
    return True, "clean"


def find_secrets(text):
    """Return the list of secret kinds found in `text` (unique, in order)."""
    if not text:
        return []
    found = []
    for kind, rx in SECRET_PATTERNS:
        if rx.search(text) and kind not in found:
            found.append(kind)
    return found


def redact_text(text):
    if not text:
        return text
    out = text
    for kind, rx in SECRET_PATTERNS:
        out = rx.sub("[REDACTED:%s]" % kind, out)
    return out


def redact_headers(headers):
    """Return a copy of `headers` with sensitive values redacted. An auth
    scheme word (e.g. `Bearer`) is kept; the value becomes `[REDACTED len=N]`."""
    out = {}
    for name, value in dict(headers or {}).items():
        if name.lower() in _SENSITIVE_HEADERS and value is not None:
            sval = str(value)
            parts = sval.split(" ", 1)
            if (len(parts) == 2 and parts[0]
                    and re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]*", parts[0])):
                out[name] = "%s [REDACTED len=%d]" % (parts[0], len(parts[1]))
            else:
                out[name] = "[REDACTED len=%d]" % len(sval)
        else:
            out[name] = value
    return out


def urls_in_text(text):
    if not text:
        return []
    return _URL_RE.findall(text)


def hosts_in_args(argv):
    """Hosts referenced by an argv: URLs plus scp/rsync/ssh `user@host:` and
    bare `user@host` forms. Returns a list of host strings (order preserved)."""
    hosts = []

    def add(h):
        h = normalize_host(h)
        if h and h not in hosts:
            hosts.append(h)

    for tok in argv or []:
        if not tok or tok.startswith("-"):
            continue
        if "://" in tok:
            host, _ = split_host_port(urlsplit(tok).netloc)
            add(host)
            continue
        m = _SCP_RE.match(tok)
        if m:
            add(m.group(2))
            continue
        m = _SSH_USER_HOST_RE.match(tok)
        if m:
            add(m.group(1))
    return hosts
