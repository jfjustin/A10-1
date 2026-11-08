"""Network helpers shared by the policy engine, the gateway and the proxies.

Pure part: host classification, the row-9 "clean URL" test, secret-pattern
detection, and redaction of secrets in text and headers.

Non-pure part (bottom of the file): `ask_gateway()`, a small JSON client that
always bypasses proxies and fails closed, and `demo_stub()`, the offline
responses for the demo API host api.example.com (only when the caller enables
demo stubs with --demo-stubs or A10_DEMO_STUBS=1).

Stdlib only.
"""
import json
import ipaddress
import re
import socket
import struct
import urllib.error
import urllib.request
from urllib.parse import urlsplit

__all__ = [
    "normalize_host", "split_host_port", "is_local_or_metadata", "host_class",
    "is_clean_url", "has_random_token", "SECRET_PATTERNS", "find_secrets",
    "redact_text", "redact_headers", "urls_in_text", "hosts_in_args",
    "ask_gateway", "DEMO_STUBS", "demo_stub", "demo_stubs_from_env",
]

# Local / metadata hosts (row 19).
_METADATA_HOSTS = {
    "metadata.google.internal", "host.docker.internal",
}
# Metadata IPs as 32-bit ints, so every numeric spelling of the cloud metadata
# endpoint (169.254.169.254) is caught, not just the dotted-quad. The spec
# names only 169.254.169.254.
_METADATA_IPV4_INTS = frozenset(
    struct.unpack("!I", socket.inet_aton(ip))[0]
    for ip in ("169.254.169.254",)
)

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


def _ipv4_to_int(h):
    """Parse an IPv4 address written in any form the C resolver accepts
    (dotted quad, short `127.1`, octal `0177.0.0.1`, hex `0x7f000001`, a single
    decimal `2130706433`) to a 32-bit int, or None if `h` is not a numeric IPv4
    address. Uses the platform `inet_aton`, so curl, wget and the resolver see
    the same value."""
    if not h or any(c in h for c in " \t/\\%"):
        return None
    try:
        packed = socket.inet_aton(h)
    except (OSError, UnicodeError):
        return None
    return struct.unpack("!I", packed)[0]


def _parse_ipv6(h):
    """Return an IPv6Address for `h`, or None if it is not one."""
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return None
    return ip if ip.version == 6 else None


def _is_loopback_int(val):
    # 127.0.0.0/8 or 0.0.0.0.
    return (val >> 24) == 127 or val == 0


def _is_loopback_ipv4(h):
    val = _ipv4_to_int(h)
    if val is None:
        return False
    return _is_loopback_int(val)


def is_local_or_metadata(host, port=None):
    h = normalize_host(host)
    if not h:
        return False
    if h in _METADATA_HOSTS:
        return True
    # RFC 6761 reserves *.localhost for loopback.
    if h == "localhost" or h.endswith(".localhost"):
        return True
    # IPv6 literals (brackets already stripped by normalize_host), including
    # the uncompressed loopback 0:0:0:0:0:0:0:1 and IPv4-mapped forms such as
    # ::ffff:127.0.0.1 and ::ffff:169.254.169.254.
    if ":" in h:
        ip6 = _parse_ipv6(h)
        if ip6 is not None:
            if ip6.is_loopback or ip6.is_unspecified:
                return True
            mapped = ip6.ipv4_mapped
            if mapped is not None:
                v = int(mapped)
                if _is_loopback_int(v) or v in _METADATA_IPV4_INTS:
                    return True
            return False
    # Dotted/short/octal/hex/decimal IPv4 loopback (127.0.0.0/8), 0.0.0.0 and
    # the metadata endpoint in any numeric spelling.
    v = _ipv4_to_int(h)
    if v is not None:
        if _is_loopback_int(v) or v in _METADATA_IPV4_INTS:
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


def is_sensitive_header(name):
    return (name or "").lower() in _SENSITIVE_HEADERS


_HEADER_TEXT_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|x-api-key|cookie|set-cookie)"
    r"(\s*:\s*)(?:([A-Za-z][A-Za-z0-9._-]*)\s+)?([^\s'\"\r\n][^'\"\r\n]*)")


def redact_header_text(text):
    """Redact `Authorization: Bearer xyz`-style header lines inside free text
    (e.g. a `curl -H '...'` command). Keeps the header name and scheme word."""
    if not text:
        return text

    def sub(m):
        name, sep, scheme, value = m.group(1), m.group(2), m.group(3), m.group(4)
        if scheme and value:
            return "%s%s%s [REDACTED len=%d]" % (name, sep, scheme, len(value))
        return "%s%s[REDACTED len=%d]" % (name, sep, len((scheme or "") + (value or "")))

    return _HEADER_TEXT_RE.sub(sub, text)


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


# ---------------------------------------------------------------------------
# Non-pure helpers
# ---------------------------------------------------------------------------

_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _parse_body(raw, content_type):
    text = raw.decode("utf-8", "replace")
    if "json" in (content_type or "") or text[:1] in ("{", "["):
        try:
            return json.loads(text)
        except ValueError:
            pass
    return text


def ask_gateway(gateway_url, path, payload=None, timeout=10, headers=None,
                method=None):
    """Call the gateway directly (never through a proxy).

    POSTs `payload` as JSON (GET when payload is None). Returns
    (status, parsed_json_or_text). An HTTP error status is returned as-is; any
    other failure fails closed as (0, {"verdict": "block", "reason":
    "gateway unreachable: ..."}).
    """
    url = gateway_url.rstrip("/") + path
    data = None if payload is None else json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(
        url, data=data, headers=hdrs,
        method=method or ("GET" if payload is None else "POST"))
    try:
        with _NO_PROXY_OPENER.open(req, timeout=timeout) as resp:
            return resp.status, _parse_body(resp.read(),
                                            resp.headers.get("Content-Type"))
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, _parse_body(body, e.headers.get("Content-Type")
                                   if e.headers else "")
    except Exception as e:  # noqa: BLE001 - fail closed on anything else
        return 0, {"verdict": "block", "row": "",
                   "reason": "gateway unreachable: %s" % e}


def _stub_status(method, path, body):
    if method in ("GET", "HEAD") and path == "/status":
        return 200, {"project": "a10-harness", "status": "ok",
                     "notes_reviewed": True}
    if method == "POST" and path == "/notes":
        return 200, {"ok": True, "received_bytes": len(body or b"")}
    return 404, {"error": "not found", "path": path}


# host -> handler(method, path, body_bytes) -> (status, json_obj)
DEMO_STUBS = {"api.example.com": _stub_status}


def demo_stubs_from_env(environ):
    return (environ.get("A10_DEMO_STUBS") or "").strip() == "1"


def demo_stub(host, method, url_or_path, body=b"", demo_stubs=False):
    """Offline response for a stubbed demo host, or None.

    Returns (status, json_bytes) when demo stubs are enabled and `host` is in
    DEMO_STUBS; None otherwise (the caller then forwards for real).
    """
    if not demo_stubs:
        return None
    handler = DEMO_STUBS.get(normalize_host(host))
    if handler is None:
        return None
    path = url_or_path or "/"
    if "://" in path:
        path = urlsplit(path).path or "/"
    path = path.split("?", 1)[0] or "/"
    status, obj = handler((method or "GET").upper(), path, body)
    return status, json.dumps(obj).encode()
