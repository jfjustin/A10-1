"""Mode-table policy engine for the A10 Agent Harness (Prompt 2).

Replaces the starter's four-rule, first-word-only policy with the approved
28-row mode table (see MODES.md / spec section 3). Every action is classified
against every row; the strictest verdict wins. Shell commands are split with a
quote-aware parser (shellparse.py) so `ls; rm demo-files/notes.txt` can no
longer hide a destructive verb behind a harmless first word.

Verdicts: 'allow' | 'ask' | 'block'. The legacy `evaluate(tool, args)` wrapper
at the bottom keeps the starter gateway/proxy/agent importable and running
(ask -> 'pending') until they are rewired in a later feature.

Pure logic, stdlib only (plus shellparse and netcheck).
"""
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

import netcheck
import shellparse

HARNESS_ROOT = os.path.dirname(os.path.abspath(__file__))

MODES = ("plan", "default", "auto")

# ---------------------------------------------------------------------------
# Row table (spec section 3). Verdicts: 'allow' (✅), 'ask' (❓), 'block' (⛔).
# Row 9's auto cell is stored as 'allow'; decide() applies the clean-URL and
# taint adjustments.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Row:
    id: str
    title: str
    plan: str
    default: str
    auto: str
    why: str


_A, _Q, _B = "allow", "ask", "block"

_ROW_DATA = [
    ("1", "Read inside the workspace", _A, _A, _A,
     "The agent can't work without reading"),
    ("2", "Read outside the workspace", _Q, _Q, _A,
     "Marks the run as tainted"),
    ("3", "Write or edit inside the workspace", _B, _Q, _A,
     "Main difference between modes"),
    ("4a", "Write to persistence paths", _B, _B, _B,
     "Runs code at next login/shell"),
    ("4b", "Other writes outside the workspace", _B, _B, _Q,
     "Outside the workspace"),
    ("5", "Read-only shell commands", _A, _A, _A, "Same as row 1"),
    ("6", "Other shell commands", _B, _Q, _A,
     "Scripts can open sockets / read ~/.ssh without tool calls"),
    ("7", "Package installs / running downloaded code", _B, _Q, _Q,
     "Supply-chain risk"),
    ("8", "Request to an allowlisted host", _A, _A, _A, ""),
    ("9", "GET from an unknown public host", _Q, _Q, _A,
     "Lethal trifecta; auto allows only a clean URL in an untainted run"),
    ("10", "The configured LLM provider", _A, _A, _A,
     "Each extra allowed host is a way out"),
    ("11", "Subagents and background tasks", _B, _B, _B,
     "Fail closed until the subagent test passes"),
    ("12", "Scheduled or remote actions", _B, _B, _Q,
     "Keep running after STOP"),
    ("13", "MCP tools", _Q, _Q, _Q, "External code"),
    ("14", "Unknown tools", _B, _Q, _Q, ""),
    ("15", "Housekeeping tools", _A, _A, _A, "No side effects"),
    ("16", "Credential stores", _B, _B, _B, "Never needed for coding"),
    ("17", "Secret files and env vars", _B, _Q, _Q,
     "Secret enters context; marks run tainted"),
    ("18", "Tampering with the harness", _B, _B, _B,
     "Applies inside the workspace too"),
    ("19", "Local and metadata endpoints", _B, _B, _B,
     "Control endpoints need the operator token"),
    ("20", "Send data to a non-allowlisted host", _B, _B, _B, "Exfiltration"),
    ("21", "Leaves the machine, can't undo", _B, _Q, _Q,
     "Affects other people"),
    ("22", "Destroys uncommitted work", _B, _Q, _Q,
     "No rm, so a verb check misses it"),
    ("23", "Workspace files that run code later", _B, _B, _Q,
     "Runs outside the harness"),
    ("24", "Shell persistence", _B, _B, _Q, "Like row 12 via the shell"),
    ("25", "Inline or hidden code", _B, _Q, _Q, "Hides the real action"),
    ("26", "Privilege escalation, pipe-to-shell", _B, _B, _B,
     "Never appropriate"),
    ("27", "Desktop and computer use", _Q, _Q, _Q,
     "Covers the desktop part of the prompt"),
    ("28", "Destructive file/system commands", _B, _B, _B,
     "Keeps the demo's rm beat a block"),
]

ROWS: Dict[str, Row] = {r[0]: Row(*r) for r in _ROW_DATA}


# ---------------------------------------------------------------------------
# Settings / state / action / results
# ---------------------------------------------------------------------------


@dataclass
class Settings:
    workspace: str = os.path.join(HARNESS_ROOT, "demo-files")
    cwd: str = HARNESS_ROOT
    harness_root: str = HARNESS_ROOT
    a10_home: Optional[str] = None
    audit_log: Optional[str] = None
    home: str = field(default_factory=lambda: os.path.expanduser("~"))
    allowed_hosts: Set[str] = field(default_factory=lambda: {"api.example.com"})
    provider_hosts: Set[str] = field(default_factory=set)
    taint_tracking: bool = True
    clean_url: bool = True
    protected_pids: Set[int] = field(default_factory=set)


@dataclass
class RunState:
    run_id: str = "run"
    mode: str = "default"
    stopped: bool = False
    tainted: bool = False
    taint_reasons: List[str] = field(default_factory=list)
    overrides: Set[str] = field(default_factory=set)
    approved_keys: Set[str] = field(default_factory=set)
    net_passes: Dict[str, float] = field(default_factory=dict)
    clock: Callable[[], float] = time.time

    def now(self) -> float:
        return self.clock()


@dataclass
class Action:
    source: str = "tool"
    tool: str = ""
    input: dict = field(default_factory=dict)
    cwd: Optional[str] = None


@dataclass
class Match:
    row: str
    detail: str = ""
    meta: dict = field(default_factory=dict)


@dataclass
class Decision:
    verdict: str
    rows: List[Tuple[str, str, str]] = field(default_factory=list)
    reason: str = ""
    approval_key: str = ""
    hosts: List[str] = field(default_factory=list)
    taint_sources: List[str] = field(default_factory=list)
    row: str = ""  # the deciding (strictest) row id, '' when none matched


# ---------------------------------------------------------------------------
# Tool tables (spec 5.3)
# ---------------------------------------------------------------------------

LEGACY_TOOL_ALIASES = {
    "shell": "bash",
    "file_read": "read_file",
    "file_write": "write_file",
    "http_get": "web_fetch",
}

_READ_TOOLS = {"read_file", "glob", "grep", "lsp", "image_to_text"}
_WRITE_TOOLS = {"write_file", "edit_file", "notebook_edit"}
_ROW11_TOOLS = {"agent", "team_create", "team_delete", "send_message",
                "task_create", "task_stop", "task_update"}
_ROW12_TOOLS = {"cron_create", "cron_delete", "cron_toggle", "remote_trigger"}
_ROW15_TOOLS = {"task_get", "task_list", "task_output", "todo_write", "brief",
                "sleep", "skill", "tool_search", "ask_user_question",
                "enter_plan_mode", "exit_plan_mode", "cron_list"}
_ROW6_TOOLS = {"enter_worktree", "exit_worktree"}
_MCP_DESKTOP_RE = re.compile(
    r"screenshot|screen|click|type|keyboard|mouse|computer|clipboard")

_READ_PATH_KEYS = ("path", "file_path", "notebook_path", "root")
_GLOB_MAGIC = re.compile(r"[*?\[]")

# ---------------------------------------------------------------------------
# Shell verb tables (spec 5.4)
# ---------------------------------------------------------------------------

_READONLY_VERBS = {
    "ls", "cat", "pwd", "wc", "head", "tail", "grep", "egrep", "fgrep", "rg",
    "echo", "printf", "which", "type", "file", "stat", "du", "df", "tree",
    "uniq", "cut", "tr", "diff", "cmp", "basename", "dirname", "realpath",
    "date", "whoami", "id", "uname", "hostname", "true", "false", "test", "[",
    "cd", "less", "more", "jq", "column", "nl", "od", "xxd", "md5", "shasum",
    "sha256sum",
}
_DESTRUCTIVE_VERBS = {
    "rm", "rmdir", "unlink", "dd", "mkfs", "shred", "srm", "shutdown",
    "reboot", "halt", "poweroff",
}
_DESKTOP_VERBS = {"screencapture", "pbpaste", "pbcopy", "cliclick"}
_SENDER_VERBS = {"scp", "sftp", "rsync", "ssh", "nc", "ncat", "netcat",
                 "socat", "telnet", "ftp", "mail", "sendmail"}
# scp/sftp/rsync are local copies unless they carry a remote `host:` argument.
_COPY_SENDERS = {"scp", "sftp", "rsync"}
_NETWORK_VERBS = {"curl", "wget", "http", "https"}
_READONLY_GIT = {"status", "diff", "log", "show", "rev-parse", "ls-files",
                 "blame", "remote", "describe", "shortlog", "branch"}
_PROXY_VAR_EXACT = {
    "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS", "NO_PROXY", "NODE_TLS_REJECT_UNAUTHORIZED",
}
_CURL_DATA_FLAGS = {
    "-d", "--data", "--data-binary", "--data-ascii", "--data-raw",
    "--data-urlencode", "-F", "--form", "--form-string", "-T",
    "--upload-file", "--json",
}
# curl/wget flags whose next argv entry is a value, not the URL.
_CURL_VALUE_FLAGS = {
    "-H", "--header", "-A", "--user-agent", "-e", "--referer", "-u", "--user",
    "-b", "--cookie", "-c", "--cookie-jar", "-m", "--max-time",
    "--connect-timeout", "-w", "--write-out", "-r", "--range", "--retry",
    "-E", "--cert", "--key", "--cacert", "--capath", "-K", "--config",
    "--resolve", "--connect-to", "--limit-rate", "-y", "-Y", "-z",
    "--interface", "--dns-servers", "--max-filesize", "--oauth2-bearer",
    "--header-file", "-U", "--proxy-user",
}


def _is_shell_interp(verb):
    return verb in {"sh", "bash", "zsh", "dash", "node", "perl", "ruby"} \
        or verb.startswith("python")


def _is_proxy_var(name):
    u = (name or "").upper()
    return u.endswith("_PROXY") or u in _PROXY_VAR_EXACT


# ---------------------------------------------------------------------------
# Path helpers (spec 5.2)
# ---------------------------------------------------------------------------


def _expand(p, settings):
    if p and p.startswith("~"):
        if p == "~" or p.startswith("~/"):
            return settings.home + p[1:]
    return p


def resolve_path(p, cwd, settings):
    p = _expand(p, settings)
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)
    return os.path.realpath(p)


def _inside(path, base):
    try:
        return os.path.commonpath([path, base]) == base
    except ValueError:
        return False


def _real(p):
    return os.path.realpath(p) if p else p


def in_workspace(path, settings):
    ws = _real(settings.workspace)
    return path == ws or _inside(path, ws)


def is_persistence_path(rp, settings):
    h = _real(settings.home)
    for nm in (".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile",
               ".profile"):
        if rp == os.path.join(h, nm):
            return True
    if rp == os.path.join(h, ".ssh", "authorized_keys"):
        return True
    if rp == os.path.join(h, ".config", "fish", "config.fish"):
        return True
    la = os.path.join(h, "Library", "LaunchAgents")
    if rp == la or _inside(rp, la):
        return True
    return False


def is_credential_path(rp, settings):
    h = _real(settings.home)
    dirs = [".ssh", ".aws", os.path.join(".config", "gh"),
            os.path.join(".config", "gcloud"), ".azure", ".gnupg",
            os.path.join("Library", "Keychains")]
    for d in dirs:
        base = os.path.join(h, d)
        if rp == base or _inside(rp, base):
            return True
    files = [os.path.join(".docker", "config.json"),
             os.path.join(".kube", "config"), ".netrc", ".git-credentials",
             os.path.join(".claude", ".credentials.json"),
             os.path.join(".codex", "auth.json"),
             os.path.join(".openharness", "credentials.json"),
             os.path.join(".openharness", "copilot_auth.json")]
    for f in files:
        if rp == os.path.join(h, f):
            return True
    browser = [os.path.join("Library", "Application Support", "Google", "Chrome"),
               os.path.join("Library", "Application Support", "Firefox", "Profiles"),
               os.path.join("Library", "Application Support", "BraveSoftware"),
               os.path.join("Library", "Application Support", "Microsoft Edge"),
               os.path.join("Library", "Safari"),
               os.path.join("Library", "Cookies")]
    for b in browser:
        base = os.path.join(h, b)
        if rp == base or _inside(rp, base):
            return True
    if settings.a10_home:
        if rp == os.path.join(_real(settings.a10_home), "operator.token"):
            return True
    return False


def is_secret_path(rp):
    b = os.path.basename(rp)
    if b == ".env":
        return True
    if b.startswith(".env.") and b not in (".env.example", ".env.sample",
                                            ".env.template"):
        return True
    for ext in (".pem", ".key", ".p12", ".pfx"):
        if b.endswith(ext):
            return True
    return False


def is_protected_path(rp, settings):
    hr = _real(settings.harness_root)
    ws = _real(settings.workspace)
    if rp == hr or _inside(rp, hr):
        if ws != hr and _inside(ws, hr):
            # Workspace strictly inside the harness (the demo): only the
            # workspace itself is writable.
            if not (rp == ws or _inside(rp, ws)):
                return True
        elif ws == hr or _inside(hr, ws):
            # Workspace equals or contains the harness root (e.g.
            # `harness.py oh --workspace .` from the repo): only demo-files
            # stays writable, the harness code itself is still protected.
            demo = os.path.join(hr, "demo-files")
            if not (rp == demo or _inside(rp, demo)):
                return True
        else:
            # Workspace elsewhere: the whole harness is protected.
            return True
    if settings.a10_home:
        ah = _real(settings.a10_home)
        if rp == ah or _inside(rp, ah):
            return True
    if rp == os.path.join(_real(settings.home), ".openharness", "settings.json"):
        return True
    if settings.audit_log and rp == _real(settings.audit_log):
        return True
    return False


def is_code_later_path(rp):
    parts = rp.split(os.sep)
    b = os.path.basename(rp)
    if b == ".envrc":
        return True
    if b == "tasks.json" and len(parts) >= 2 and parts[-2] == ".vscode":
        return True
    if ".git" in parts:
        gi = parts.index(".git")
        rest = parts[gi + 1:]
        if rest[:1] == ["hooks"]:
            return True
        if rest == ["config"]:
            return True
    return False


def _path_rows(rp, matches, mode, settings):
    """mode in ('read', 'write', 'wtarget')."""
    if is_credential_path(rp, settings):
        matches.append(Match("16", rp))
    if is_secret_path(rp):
        matches.append(Match("17", rp))
    if mode in ("write", "wtarget"):
        if is_protected_path(rp, settings):
            matches.append(Match("18", rp))
        if is_code_later_path(rp):
            matches.append(Match("23", rp))
    if mode == "wtarget":
        if is_persistence_path(rp, settings):
            matches.append(Match("4a", rp))


def _is_path_token(tok):
    if not tok or tok.startswith("-"):
        return False
    if "/" in tok or tok.startswith("~") or tok.startswith("."):
        return True
    if tok == ".env" or tok.startswith(".env.") \
            or tok.endswith((".pem", ".key", ".p12", ".pfx")):
        return True
    return False


def _path_tokens(argv):
    out = []
    for a in argv[1:]:
        if "://" in a:
            continue
        if a.startswith("@"):
            out.append(a[1:])
            continue
        if a.startswith("--") and "=" in a:
            v = a.split("=", 1)[1]
            if _is_path_token(v) and "://" not in v:
                out.append(v)
            continue
        if a.startswith("-"):
            continue
        if _is_path_token(a):
            out.append(a)
    return out


def _canon_tool(tool):
    return LEGACY_TOOL_ALIASES.get(tool, tool)


def _short(text, limit=120):
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "..."


# ---------------------------------------------------------------------------
# Network classification (spec 5.5)
# ---------------------------------------------------------------------------


def _net_rows(host, port, method, has_body, secret_hits, settings, url=None,
              proxy=False):
    cls = netcheck.host_class(host, port, settings)
    method = (method or "GET").upper()
    is_get = method in ("GET", "HEAD", "OPTIONS", "CONNECT") and not has_body
    rows = []
    if cls == "provider":
        rows.append(Match("10", host or "", {"host": host}))
    elif cls == "local":
        rows.append(Match("19", host or "", {"host": host}))
    elif cls == "allowlisted":
        rows.append(Match("8", host or "", {"host": host}))
        # Spec 5.5: any method is row 8 at the proxy level; at the tool level
        # a sender to an allowlisted host also gets row 6.
        if not is_get and not proxy:
            rows.append(Match("6", "sender to allowlisted host"))
    else:  # public
        if (not is_get) or secret_hits:
            rows.append(Match("20", host or "", {"host": host,
                                                 "secret": bool(secret_hits)}))
        else:
            clean = True
            if url is not None:
                clean = netcheck.is_clean_url(url)[0]
            rows.append(Match("9", host or "", {"host": host, "clean": clean}))
    return rows


def _host_from_token(token):
    if not token:
        return None, None
    if "://" in token:
        from urllib.parse import urlsplit
        return netcheck.split_host_port(urlsplit(token).netloc)
    m = netcheck._SCP_RE.match(token)
    if m:
        return netcheck.normalize_host(m.group(2)), None
    # bare host[:port]/path
    hp = token.split("/", 1)[0]
    host, port = netcheck.split_host_port(hp)
    if host and ("." in host or host in ("localhost",)):
        return host, port
    return None, None


def _is_dev_socket(target):
    """True for a bash /dev/tcp or /dev/udp pseudo-path, which opens an outbound
    socket that honours no proxy variable and never reaches mitmproxy."""
    t = target or ""
    return t.startswith("/dev/tcp/") or t.startswith("/dev/udp/")


def _dev_socket_hostport(target):
    # /dev/tcp/<host>/<port>
    parts = (target or "").split("/")
    host = parts[3] if len(parts) > 3 else ""
    port = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else None
    return netcheck.normalize_host(host), port


def _flag_proxy_assignments(seg, matches):
    """Flag proxy/CA-variable assignments on a segment (row 18). Called for
    assignment-only segments (empty argv), which the normal per-segment path
    skips, so `HTTPS_PROXY= ; curl ...` cannot silently unset the proxy."""
    for asg in seg.assignments:
        name = asg.split("=", 1)[0]
        if _is_proxy_var(name):
            m = Match("18", "sets %s" % name)
            m.meta["segment"] = seg.raw or asg
            matches.append(m)


# ---------------------------------------------------------------------------
# Shell handlers (spec 5.4)
# ---------------------------------------------------------------------------


def _skip_flags(args):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 1
    return args[i:]


def _timeout_inner(args):
    # timeout [opts] DURATION CMD ...
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] in ("-s", "--signal", "-k", "--kill-after"):
            i += 2
        else:
            i += 1
    if i < len(args):  # skip the duration
        i += 1
    return args[i:]


def _xargs_inner(args):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] in ("-I", "-n", "-P", "-d", "-E", "-s", "-L"):
            i += 2
        else:
            i += 1
    return args[i:]


def _find_c_flag(args):
    for i, a in enumerate(args):
        if a == "-c" and i + 1 < len(args):
            return args[i + 1]
    return None


def _chmod_setuid(args):
    for a in args:
        if a.startswith("-"):
            continue
        if "+s" in a:
            return True
        if re.fullmatch(r"[0-7]{4}", a) and a[0] in "2467":
            return True
    return False


def _is_pkg_install(verb, args):
    if verb in ("pip", "pip3") and "install" in args:
        return True
    if verb in ("npm", "yarn", "pnpm", "bun") \
            and any(x in args for x in ("install", "i", "ci", "add")):
        return True
    if verb in ("npx", "bunx", "uvx"):
        return True
    if verb == "uv" and (("pip" in args and "install" in args)
                         or ("tool" in args and ("install" in args or "run" in args))
                         or "add" in args):
        return True
    if verb == "pipx" and ("run" in args or "install" in args):
        return True
    if verb == "cargo" and "install" in args:
        return True
    if verb == "go" and ("install" in args or "get" in args):
        return True
    if verb == "brew" and any(x in args for x in ("install", "upgrade", "tap",
                                                  "reinstall")):
        return True
    if verb == "gem" and "install" in args:
        return True
    if verb in ("apt", "apt-get") and "install" in args:
        return True
    if verb in ("conda", "mamba") and "install" in args:
        return True
    return False


def _leave_machine(verb, args):
    if verb == "gh" and args:
        sub = args[0]
        sub2 = args[1] if len(args) > 1 else ""
        if sub == "pr" and sub2 in ("create", "merge", "comment"):
            return True
        if sub == "issue" and sub2 in ("create", "comment"):
            return True
        if sub == "release" and sub2 == "create":
            return True
        if sub == "repo" and sub2 in ("create", "delete"):
            return True
        if sub == "gist" and sub2 == "create":
            return True
    if verb in ("npm", "yarn", "pnpm") and "publish" in args:
        return True
    if verb == "cargo" and "publish" in args:
        return True
    if verb == "twine" and "upload" in args:
        return True
    if verb == "terraform" and any(x in args for x in ("apply", "destroy")):
        return True
    if verb == "kubectl" and any(x in args for x in ("apply", "create",
                                                     "delete", "patch")):
        return True
    if verb == "helm" and any(x in args for x in ("install", "upgrade")):
        return True
    if verb == "docker" and "push" in args:
        return True
    return False


def _handle_env(rest, seg, settings, cwd, matches):
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("-i", "--ignore-environment", "-", "-0"):
            i += 1
            continue
        if a == "-u":
            if i + 1 < len(rest) and _is_proxy_var(rest[i + 1]):
                matches.append(Match("18", "env -u %s" % rest[i + 1]))
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        if shellparse._ASSIGN_RE.match(a):
            if _is_proxy_var(a.split("=", 1)[0]):
                matches.append(Match("18", "env sets %s" % a.split("=", 1)[0]))
            i += 1
            continue
        break
    inner = rest[i:]
    if inner:
        return _classify_verb(inner, seg, settings, cwd, matches)
    matches.append(Match("17", "env (dumps environment variables)"))
    return False


def _handle_git(rest, seg, settings, cwd, matches):
    i = 0
    opts = []
    sub = None
    subargs = []
    while i < len(rest):
        a = rest[i]
        if a == "-C" and i + 1 < len(rest):
            i += 2
            continue
        if a == "-c" and i + 1 < len(rest):
            opts.append(rest[i + 1])
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        sub = a
        subargs = rest[i + 1:]
        break
    for o in opts:
        if o.startswith("core.hooksPath") or o.startswith("core.fsmonitor"):
            matches.append(Match("23", "git -c %s" % o))
    if sub is None:
        matches.append(Match("6", "git"))
        return False
    if sub == "config":
        joined = " ".join(subargs)
        if "core.hooksPath" in joined or "core.fsmonitor" in joined:
            matches.append(Match("23", "git config hooks path"))
        else:
            matches.append(Match("6", "git config"))
        return False
    if sub == "push":
        matches.append(Match("21", "git push"))
        return False
    if sub == "reset" and "--hard" in subargs:
        matches.append(Match("22", "git reset --hard"))
        return False
    if sub == "clean" and any(a.startswith("-") and "f" in a for a in subargs):
        matches.append(Match("22", "git clean -f"))
        return False
    if sub == "checkout" and ("--" in subargs or "." in subargs):
        matches.append(Match("22", "git checkout --"))
        return False
    if sub == "restore" and "--staged" not in subargs:
        matches.append(Match("22", "git restore"))
        return False
    if sub == "stash" and ("drop" in subargs or "clear" in subargs):
        matches.append(Match("22", "git stash drop/clear"))
        return False
    if sub in _READONLY_GIT:
        if sub == "branch" and any(a in ("-d", "-D", "-m", "-M")
                                   for a in subargs):
            matches.append(Match("6", "git branch -d"))
            return False
        matches.append(Match("5", "git %s" % sub))
        return True
    matches.append(Match("6", "git %s" % sub))
    return False


def _bare_sender_host(rest):
    """First bare, non-flag, non-numeric token of a sender command (the host in
    `nc evil.example 4444` / `ssh evil.example cmd`). Returns None if none."""
    for tok in rest:
        if tok.startswith("-"):
            continue
        if tok.isdigit():   # a bare port, not a host
            continue
        return tok.split("/", 1)[0]
    return None


def _handle_sender(verb, rest, seg, settings, cwd, matches):
    hosts = netcheck.hosts_in_args([verb] + rest)
    if not hosts and verb not in _COPY_SENDERS:
        # ssh/nc/telnet/... take the host as a bare positional argument that
        # hosts_in_args (URL/scp/user@host only) does not see.
        h = _bare_sender_host(rest)
        if h:
            hosts = [h]
    if not hosts:
        if verb in _COPY_SENDERS:
            # Local copy with no remote host (e.g. `rsync -a a b`).
            matches.append(Match("6", verb))
        else:
            # A sender reaching an unidentified host is not allowlisted, so the
            # safe reading is "send to an unknown host" (row 20), not row 6.
            matches.append(Match("20", verb, {"host": ""}))
        return False
    for h in hosts:
        host, port = netcheck.split_host_port(h)
        for m in _net_rows(host, port, "POST", True, [], settings):
            matches.append(m)
    return False


def _handle_curl(verb, rest, seg, settings, cwd, matches):
    has_body = False
    method = "GET"
    url = None
    out_path = None
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in _CURL_DATA_FLAGS:
            has_body = True
            i += 2 if i + 1 < len(rest) else 1
            continue
        if a.startswith("--data") or a.startswith("--form"):
            has_body = True
            i += 1
            continue
        if a in ("-X", "--request"):
            if i + 1 < len(rest):
                method = rest[i + 1].upper()
                i += 2
                continue
            i += 1
            continue
        if a == "--method":
            if i + 1 < len(rest):
                method = rest[i + 1].upper()
                i += 2
                continue
            i += 1
            continue
        if a in ("--post-data", "--post-file"):
            has_body = True
            method = "POST"
            i += 2 if i + 1 < len(rest) else 1
            continue
        if a == "--unix-socket":
            matches.append(Match("19", "curl --unix-socket"))
            i += 2 if i + 1 < len(rest) else 1
            continue
        if a in ("--noproxy", "-x", "--proxy"):
            matches.append(Match("18", "curl %s (bypass proxy)" % a))
            i += 2 if i + 1 < len(rest) else 1
            continue
        if a in ("-o", "--output"):
            if i + 1 < len(rest):
                out_path = rest[i + 1]
                i += 2
                continue
            i += 1
            continue
        if a == "-O":
            i += 1
            continue
        if a == "--url":
            if i + 1 < len(rest) and url is None:
                url = rest[i + 1]
            i += 2
            continue
        if a in _CURL_VALUE_FLAGS:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        if url is None:
            url = a
        i += 1

    if out_path:
        matches.append(Match("6", "%s output file" % verb))
    elif verb == "wget" and "-O" not in rest:
        matches.append(Match("6", "wget writes a file"))

    if url is None:
        matches.append(Match("6", "%s (no url)" % verb))
        return False
    host, port = _host_from_token(url)
    if host is None:
        matches.append(Match("6", "%s (no host)" % verb))
        return False
    secret_hits = netcheck.find_secrets(url)
    for m in _net_rows(host, port, method, has_body, secret_hits, settings, url):
        matches.append(m)
    return False


def _handle_kill(verb, rest, seg, settings, matches):
    joined = " ".join(rest)
    if re.search(r"mitmdump|mitmproxy|gateway\.py|proxy\.py|harness\.py", joined):
        matches.append(Match("18", "kill harness/proxy process"))
        return False
    if "-1" in rest:
        matches.append(Match("18", "kill -1 (all processes)"))
        return False
    for a in rest:
        token = a.lstrip("-")
        if token.isdigit() and int(token) in settings.protected_pids:
            matches.append(Match("18", "kill protected pid %s" % token))
            return False
    matches.append(Match("6", verb))
    return False


def _classify_subcommand(cmd, seg, settings, cwd, matches):
    res = shellparse.parse(cmd)
    if res.error:
        matches.append(Match("25", "unparseable -c string"))
        return
    for s in res.segments:
        if s.argv and s.argv[0]:
            _classify_segment(s, settings, cwd, matches)
        else:
            _flag_proxy_assignments(s, matches)


def _classify_verb(argv, seg, settings, cwd, matches):
    """Classify one command's verb chain. Returns True if read-only (row 5)."""
    if not argv or argv[0] == "":
        return True
    raw0 = argv[0]
    verb = os.path.basename(raw0)
    rest = argv[1:]

    if raw0.startswith("$") or raw0.startswith("${"):
        matches.append(Match("25", "command is a variable expansion"))
        return False

    if verb in ("sudo", "su", "doas"):
        matches.append(Match("26", verb))
        inner = _skip_flags(rest)
        return _classify_verb(inner, seg, settings, cwd, matches) if inner else False
    if verb in ("nohup", "setsid", "disown"):
        matches.append(Match("24", verb))
        inner = _skip_flags(rest)
        if inner:
            _classify_verb(inner, seg, settings, cwd, matches)
        return False
    if verb in ("command", "builtin"):
        # `command -v/-V rm` and `builtin -v` only resolve a name; they run
        # nothing, so treat them as read-only instead of classifying the inner
        # verb (otherwise `command -v rm` is wrongly blocked as row 28).
        if any(a in ("-v", "-V") for a in rest):
            matches.append(Match("5", "%s -v (introspection)" % verb))
            return True
        inner = _skip_flags(rest)
        return _classify_verb(inner, seg, settings, cwd, matches) if inner else False
    if verb == "exec":
        inner = _skip_flags(rest)
        return _classify_verb(inner, seg, settings, cwd, matches) if inner else False
    if verb in ("time", "nice"):
        inner = _skip_flags(rest)
        return _classify_verb(inner, seg, settings, cwd, matches) if inner else False
    if verb == "timeout":
        inner = _timeout_inner(rest)
        return _classify_verb(inner, seg, settings, cwd, matches) if inner else False
    if verb == "xargs":
        matches.append(Match("6", "xargs"))
        inner = _xargs_inner(rest)
        if inner:
            _classify_verb(inner, seg, settings, cwd, matches)
        return False
    if verb == "env":
        return _handle_env(rest, seg, settings, cwd, matches)

    if verb in ("sh", "bash", "zsh", "dash"):
        c = _find_c_flag(rest)
        if c is not None:
            matches.append(Match("25", "%s -c inline code" % verb))
            _classify_subcommand(c, seg, settings, cwd, matches)
            return False
        matches.append(Match("6", verb))
        return False
    if verb.startswith("python"):
        if any(a == "-c" for a in rest):
            matches.append(Match("25", "%s -c inline code" % verb))
            return False
        if "pip" in rest and "install" in rest:
            matches.append(Match("7", "python -m pip install"))
            return False
        matches.append(Match("6", verb))
        return False
    if verb == "node":
        if any(a in ("-e", "--eval", "-p", "--print") for a in rest):
            matches.append(Match("25", "node inline code"))
            return False
        matches.append(Match("6", verb))
        return False
    if verb in ("ruby", "perl"):
        if any(a in ("-e", "-E") for a in rest):
            matches.append(Match("25", "%s inline code" % verb))
            return False
        matches.append(Match("6", verb))
        return False
    if verb == "eval":
        matches.append(Match("25", "eval"))
        return False
    if verb in (".", "source"):
        if any(a.startswith("<(") for a in rest) or seg.from_substitution:
            matches.append(Match("25", "source of a substitution"))
        else:
            matches.append(Match("6", verb))
        return False

    if verb == "osascript":
        matches.append(Match("27", "osascript"))
        if any(a == "-e" or a.startswith("-e") for a in rest):
            matches.append(Match("25", "osascript -e inline code"))
        return False
    if verb in _DESKTOP_VERBS:
        matches.append(Match("27", verb))
        return False

    if verb == "security":
        matches.append(Match("16", "security (keychain)"))
        if "add-trusted-cert" in rest:
            matches.append(Match("18", "add trusted CA cert"))
        return False
    if verb in ("update-ca-certificates",) or (verb == "trust" and "anchor" in rest):
        matches.append(Match("18", "add CA cert"))
        return False

    if verb == "unset":
        if any(_is_proxy_var(a) for a in rest):
            matches.append(Match("18", "unset proxy/CA var"))
        else:
            matches.append(Match("6", "unset"))
        return False
    if verb == "export":
        assigns = [a for a in rest if "=" in a]
        for a in assigns:
            if _is_proxy_var(a.split("=", 1)[0]):
                matches.append(Match("18", "export %s" % a.split("=", 1)[0]))
        if not rest or ("-p" in rest and not assigns):
            matches.append(Match("17", "export -p (dumps env)"))
            return False
        if not any(_is_proxy_var(a.split("=", 1)[0]) for a in assigns):
            matches.append(Match("6", "export"))
        return False
    if verb == "set":
        if not rest:
            matches.append(Match("17", "set (dumps env)"))
        else:
            matches.append(Match("6", "set"))
        return False
    if verb == "declare":
        assigns = [a for a in rest if "=" in a]
        for a in assigns:
            if _is_proxy_var(a.split("=", 1)[0]):
                matches.append(Match("18", "declare %s" % a.split("=", 1)[0]))
        if "-x" in rest and not assigns:
            matches.append(Match("17", "declare -x (dumps env)"))
        elif not assigns:
            matches.append(Match("6", "declare"))
        return False
    if verb == "printenv":
        matches.append(Match("17", "printenv"))
        return False

    if verb in ("kill", "pkill", "killall"):
        return _handle_kill(verb, rest, seg, settings, matches)
    if verb in ("crontab", "at", "launchctl", "systemctl"):
        matches.append(Match("24", verb))
        return False

    if verb == "chmod":
        if _chmod_setuid(rest):
            matches.append(Match("26", "chmod setuid/setgid"))
        else:
            matches.append(Match("6", "chmod"))
        return False
    if verb == "tee":
        matches.append(Match("6", "tee"))
        return False

    if verb == "git":
        return _handle_git(rest, seg, settings, cwd, matches)
    if verb in _SENDER_VERBS:
        return _handle_sender(verb, rest, seg, settings, cwd, matches)
    if verb in _NETWORK_VERBS:
        return _handle_curl(verb, rest, seg, settings, cwd, matches)

    if _leave_machine(verb, rest):
        matches.append(Match("21", "%s %s" % (verb, " ".join(rest[:2]))))
        return False
    if _is_pkg_install(verb, rest):
        matches.append(Match("7", "%s install" % verb))
        return False

    if verb in _DESTRUCTIVE_VERBS or verb.startswith("mkfs"):
        matches.append(Match("28", verb))
        return False

    if verb == "sed":
        if any(a == "-i" or a.startswith("-i") or a == "--in-place"
               for a in rest):
            matches.append(Match("6", "sed -i"))
            return False
        matches.append(Match("5", "sed"))
        return True
    if verb == "sort":
        if any(a in ("-o", "--output") or a.startswith("-o")
               or a.startswith("--output") for a in rest):
            matches.append(Match("6", "sort -o"))
            return False
        matches.append(Match("5", "sort"))
        return True
    if verb == "find":
        if any(a in ("-delete",) or a.startswith("-exec") or a.startswith("-ok")
               or a.startswith("-fprint") or a == "-fls" for a in rest):
            matches.append(Match("6", "find %s" % next(
                (a for a in rest if a.startswith("-exec") or a in ("-delete", "-ok")),
                "-exec")))
            # classify the -exec command too
            for flag in ("-exec", "-execdir", "-ok", "-okdir"):
                if flag in rest:
                    idx = rest.index(flag)
                    inner = []
                    for a in rest[idx + 1:]:
                        if a in (";", "+", "\\;"):
                            break
                        inner.append(a)
                    if inner:
                        _classify_verb(inner, seg, settings, cwd, matches)
            return False
        matches.append(Match("5", "find"))
        return True

    if verb in _READONLY_VERBS:
        matches.append(Match("5", verb))
        return True

    matches.append(Match("6", verb))
    return False


def _collect_write_targets(seg, settings, cwd):
    wt = list(seg.write_targets)
    argv = seg.argv
    if not argv:
        return wt
    verb = os.path.basename(argv[0]) if argv[0] else ""
    args = argv[1:]
    nonflag = [a for a in args if not a.startswith("-")]
    if verb == "tee":
        wt += nonflag
    elif verb in ("cp", "mv", "ln", "install") and nonflag:
        wt.append(nonflag[-1])
    elif verb == "touch":
        wt += nonflag
    elif verb == "sed" and any(a == "-i" or a.startswith("-i")
                               or a == "--in-place" for a in args):
        wt += [a for a in nonflag if _is_path_token(a)]
    if verb not in _NETWORK_VERBS:
        for i, a in enumerate(args):
            if a.startswith("--output="):
                wt.append(a.split("=", 1)[1])
            elif a in ("--output", "-o") and i + 1 < len(args):
                wt.append(args[i + 1])
    return wt


def _classify_segment(seg, settings, cwd, matches):
    argv = seg.argv
    if not argv or argv[0] == "":
        return
    first = len(matches)
    try:
        _classify_segment_inner(seg, settings, cwd, matches)
    finally:
        # Remember which shell segment produced each match so the block/ask
        # reason can quote it (inner `bash -c` segments keep their own text).
        for m in matches[first:]:
            m.meta.setdefault("segment", seg.raw or " ".join(argv))


def _classify_segment_inner(seg, settings, cwd, matches):
    argv = seg.argv
    for asg in seg.assignments:
        name = asg.split("=", 1)[0]
        if _is_proxy_var(name):
            matches.append(Match("18", "sets %s" % name))

    before = len(matches)
    readonly = _classify_verb(argv, seg, settings, cwd, matches)
    rows_added = {m.row for m in matches[before:]}

    has_output_flag = any(a == "--output" or a.startswith("--output=")
                          or a == "-o" for a in argv[1:])
    verb = os.path.basename(argv[0])
    if readonly and (seg.write_targets or (has_output_flag
                                           and verb not in _NETWORK_VERBS)):
        matches.append(Match("6", "write redirect / output flag"))
        readonly = False

    write_targets = _collect_write_targets(seg, settings, cwd)
    for wt in write_targets:
        if _is_dev_socket(wt):
            # A redirect into /dev/tcp/<host>/<port> is an outbound send.
            host, port = _dev_socket_hostport(wt)
            for m in _net_rows(host, port, "POST", True, [], settings):
                matches.append(m)
            continue
        rp = resolve_path(wt, cwd, settings)
        _path_rows(rp, matches, "wtarget", settings)

    wt_set = set(write_targets)
    for tok in _path_tokens(argv):
        if tok in wt_set:
            continue
        rp = resolve_path(tok, cwd, settings)
        _path_rows(rp, matches, "read" if readonly else "write", settings)

    # docker.sock anywhere -> row 19
    if any("docker.sock" in a for a in argv):
        if "19" not in rows_added:
            matches.append(Match("19", "docker socket"))


def _classify_shell(command, settings, base_cwd, matches):
    res = shellparse.parse(command)
    if res.error:
        matches.append(Match("25", "shell parse failed: %s" % res.error))
        return
    segs = res.segments
    _detect_pipelines(segs, matches)
    cur_cwd = base_cwd
    for seg in segs:
        if not seg.argv or seg.argv[0] == "":
            _flag_proxy_assignments(seg, matches)
            if seg.background:
                matches.append(Match("24", "background &"))
            continue
        cwd_here = base_cwd if seg.from_substitution else cur_cwd
        _classify_segment(seg, settings, cwd_here, matches)
        if seg.background:
            matches.append(Match("24", "background &"))
        if (not seg.from_substitution) and os.path.basename(seg.argv[0]) == "cd" \
                and len(seg.argv) > 1:
            cur_cwd = resolve_path(seg.argv[1], cur_cwd, settings)


def _detect_pipelines(segs, matches):
    groups = {}
    for s in segs:
        groups.setdefault(s.pipeline_id, []).append(s)
    for members in groups.values():
        if len(members) < 2:
            continue
        members = sorted(members, key=lambda s: s.pipeline_pos)
        for idx, s in enumerate(members):
            verb = shellparse.verb_of(s)
            if idx > 0 and _is_shell_interp(verb):
                earlier = members[:idx]
                if any(shellparse.verb_of(e) in ("curl", "wget") for e in earlier):
                    matches.append(Match("26", "download piped into a shell"))
                else:
                    matches.append(Match("25", "output piped into an interpreter"))


# ---------------------------------------------------------------------------
# Tool-level classification (spec 5.3)
# ---------------------------------------------------------------------------


def _read_path_strings(tool, inp):
    paths = []
    for key in _READ_PATH_KEYS:
        v = inp.get(key)
        if isinstance(v, str) and v:
            paths.append(v)
    if tool == "glob":
        pat = inp.get("pattern")
        if isinstance(pat, str) and (os.path.isabs(pat) or pat.startswith("~")):
            # take the part before the first glob-magic segment
            head = pat
            m = _GLOB_MAGIC.search(pat)
            if m:
                head = pat[:m.start()]
                head = head.rsplit("/", 1)[0] if "/" in head else head
            if head:
                paths.append(head)
    return paths


def _classify_read_tool(tool, inp, settings, cwd, matches):
    paths = _read_path_strings(tool, inp)
    if not paths:
        paths = [cwd]
    for p in paths:
        rp = resolve_path(p, cwd, settings)
        if in_workspace(rp, settings):
            matches.append(Match("1", rp))
        else:
            matches.append(Match("2", rp, {"taint": "read outside workspace"}))
        _path_rows(rp, matches, "read", settings)


def _classify_write_tool(tool, inp, settings, cwd, matches):
    p = None
    for key in _READ_PATH_KEYS:
        v = inp.get(key)
        if isinstance(v, str) and v:
            p = v
            break
    if p is None:
        p = cwd
    rp = resolve_path(p, cwd, settings)
    if is_persistence_path(rp, settings):
        matches.append(Match("4a", rp))
    elif in_workspace(rp, settings):
        matches.append(Match("3", rp))
    else:
        matches.append(Match("4b", rp))
    _path_rows(rp, matches, "write", settings)


def _classify_network_tool(tool, inp, settings, matches):
    if tool == "web_search":
        query = inp.get("query") or ""
        clean = not any(netcheck.has_random_token(t) for t in query.split())
        matches.append(Match("9", _short(query), {"clean": clean}))
        return
    url = inp.get("url") or ""
    host, port = _host_from_token(url)
    if host is None:
        matches.append(Match("6", "web_fetch (no host)"))
        return
    secret_hits = netcheck.find_secrets(url)
    for m in _net_rows(host, port, "GET", False, secret_hits, settings, url):
        matches.append(m)


def classify(action, settings):
    """Return the list of Match (rows that the action touches)."""
    matches = []
    tool = _canon_tool(action.tool)
    inp = action.input or {}
    cwd = action.cwd or settings.cwd
    if tool == "bash":
        if isinstance(inp.get("cwd"), str) and inp.get("cwd"):
            cwd = resolve_path(inp["cwd"], settings.cwd, settings)
        _classify_shell(inp.get("command") or "", settings, cwd, matches)
        return matches
    if tool in _READ_TOOLS:
        _classify_read_tool(tool, inp, settings, cwd, matches)
        return matches
    if tool in _WRITE_TOOLS:
        _classify_write_tool(tool, inp, settings, cwd, matches)
        return matches
    if tool in ("web_fetch", "web_search"):
        _classify_network_tool(tool, inp, settings, matches)
        return matches
    if tool.startswith("mcp__") or tool in ("mcp_auth", "read_mcp_resource",
                                            "list_mcp_resources"):
        matches.append(Match("13", tool))
        if _MCP_DESKTOP_RE.search(tool):
            matches.append(Match("27", tool))
        return matches
    if tool == "config":
        matches.append(Match("18", "config (rewrites harness settings)"))
        return matches
    if tool in _ROW11_TOOLS:
        matches.append(Match("11", tool))
        return matches
    if tool in _ROW12_TOOLS:
        matches.append(Match("12", tool))
        return matches
    if tool in _ROW15_TOOLS:
        matches.append(Match("15", tool))
        return matches
    if tool in _ROW6_TOOLS:
        matches.append(Match("6", tool))
        return matches
    # Proxy-level network judgement.
    if action.source in ("proxy-mitm", "proxy-stdlib") or tool in ("net", "http_proxy"):
        host = inp.get("host") or ""
        port = inp.get("port")
        method = inp.get("method") or "GET"
        body_len = inp.get("body_len") or 0
        secret_hits = inp.get("secret_hits") or []
        url = inp.get("url")
        host = netcheck.normalize_host(host)
        for m in _net_rows(host, port, method, bool(body_len), secret_hits,
                           settings, url, proxy=True):
            matches.append(m)
        return matches
    matches.append(Match("14", tool))
    return matches


# ---------------------------------------------------------------------------
# decide() (spec 5.6)
# ---------------------------------------------------------------------------


def _row9_verdict(mode, meta, settings, state):
    if mode != "auto":
        return "ask"
    if settings.taint_tracking and state.tainted:
        return "ask"
    if not settings.clean_url:
        return "allow"
    return "allow" if meta.get("clean") else "ask"


def _approval_key(action, settings):
    tool = _canon_tool(action.tool)
    inp = action.input or {}
    cwd = action.cwd or settings.cwd
    if tool == "bash":
        return "bash:" + (inp.get("command") or "")
    if tool in _READ_TOOLS or tool in _WRITE_TOOLS:
        p = None
        for key in _READ_PATH_KEYS:
            if isinstance(inp.get(key), str) and inp.get(key):
                p = inp[key]
                break
        if p is None and tool == "glob" and isinstance(inp.get("pattern"), str):
            p = inp["pattern"]
        if p is None:
            p = cwd
        return "%s:%s" % (tool, resolve_path(p, cwd, settings))
    if tool == "web_fetch" or action.source in ("proxy-mitm", "proxy-stdlib") \
            or tool in ("net", "http_proxy"):
        host, _ = _host_from_token(inp.get("url") or "")
        if host is None:
            host = netcheck.normalize_host(inp.get("host") or "")
        return "net:" + (host or "")
    return "%s:%s" % (tool, json.dumps(inp, sort_keys=True, default=str))


def decide(action, settings, state):
    decision = _decide(action, settings, state)
    decision.row = _deciding_row(decision)
    return decision


def _deciding_row(decision):
    rows = decision.rows
    if not rows:
        return ""
    want = decision.verdict
    if want == "allow" and any(v == "ask" for (_r, _t, v) in rows):
        want = "ask"  # allowed through an approve-for-run key or a net pass
    pool = [r for (r, _t, v) in rows if v == want] or [r for (r, _t, _v) in rows]
    return sorted(pool, key=_row_sort_key, reverse=True)[0]


def _decide(action, settings, state):
    matches = classify(action, settings)
    hosts = []
    taint_sources = []
    for m in matches:
        h = m.meta.get("host")
        if h and h not in hosts:
            hosts.append(h)
        if m.row in ("2", "16", "17"):
            taint_sources.append("row %s (%s)" % (m.row, ROWS[m.row].title))
    approval_key = _approval_key(action, settings)
    mode = state.mode

    if state.stopped:
        return Decision("block", [], "operator stopped the run", approval_key,
                        hosts, taint_sources)

    if not matches:
        return Decision("allow", [], "no policy rule matched", approval_key,
                        hosts, taint_sources)

    row_entries = []
    for m in matches:
        row = ROWS[m.row]
        v = getattr(row, mode)
        if m.row in state.overrides and v == "block":
            v = "ask"
        if m.row == "9":
            v = _row9_verdict(mode, m.meta, settings, state)
        row_entries.append((m.row, row.title, v, m))

    # Strictest wins. Block first.
    blockers = [e for e in row_entries if e[2] == "block"]
    if blockers:
        row_id, title, _v, m = _pick_strictest(blockers)
        reason = _reason(row_id, title, mode, "block", m, action)
        return Decision("block", _rows_out(row_entries), reason, approval_key,
                        hosts, taint_sources)

    askers = [e for e in row_entries if e[2] == "ask"]
    if askers:
        # approve-for-run key already granted?
        if approval_key in state.approved_keys:
            return Decision("allow", _rows_out(row_entries),
                            "approved earlier for this run", approval_key,
                            hosts, taint_sources)
        # proxy net pass?
        if action.source in ("proxy-mitm", "proxy-stdlib"):
            for h in hosts:
                if h in state.net_passes and state.net_passes[h] > state.now():
                    return Decision("allow", _rows_out(row_entries),
                                    "network pass for %s" % h, approval_key,
                                    hosts, taint_sources)
        row_id, title, _v, m = _pick_strictest(askers)
        reason = _reason(row_id, title, mode, "ask", m, action)
        return Decision("ask", _rows_out(row_entries), reason, approval_key,
                        hosts, taint_sources)

    return Decision("allow", _rows_out(row_entries), "allowed by the mode table",
                    approval_key, hosts, taint_sources)


def _rows_out(row_entries):
    return [(rid, title, v) for (rid, title, v, _m) in row_entries]


def _row_sort_key(row_id):
    base = re.match(r"(\d+)", row_id)
    n = int(base.group(1)) if base else 0
    return (n, row_id)


def _pick_strictest(entries):
    return sorted(entries, key=lambda e: _row_sort_key(e[0]), reverse=True)[0]


def _reason(row_id, title, mode, verdict, match, action):
    glyph = {"block": "⛔", "ask": "❓", "allow": "✅"}[verdict]
    detail = match.detail or ""
    segment = match.meta.get("segment") or ""
    if not segment and _canon_tool(action.tool) == "bash":
        segment = (action.input or {}).get("command") or ""
    segment = " ".join(str(segment).split())
    where = ""
    if detail:
        where = ": %s" % _short(detail)
        if segment and segment != detail:
            where += " in '%s'" % _short(segment, 120)
    elif segment:
        where = ": '%s'" % _short(segment, 120)
    return "row %s (%s) is %s in %s mode%s" % (row_id, title, glyph, mode, where)


# ---------------------------------------------------------------------------
# State mutations (spec 5.5 / 5.6)
# ---------------------------------------------------------------------------


def record_approval(state, decision, for_run=False):
    if for_run and decision.approval_key:
        state.approved_keys.add(decision.approval_key)
    for h in decision.hosts:
        state.net_passes[h] = state.now() + 30


def mark_taint(state, reason):
    if not state.tainted or reason not in state.taint_reasons:
        state.tainted = True
        state.taint_reasons.append(reason)


def scan_tool_output(state, text):
    hits = netcheck.find_secrets(text or "")
    if hits:
        mark_taint(state, "secret in tool output: %s" % ", ".join(hits))
    return hits


def apply_override(state, row, confirm):
    row = str(row)
    if confirm != "YES":
        return False
    if row not in ROWS:
        return False
    r = ROWS[row]
    if "block" not in (r.plan, r.default, r.auto):
        return False
    state.overrides.add(row)
    return True


def set_mode(state, mode):
    if mode not in MODES:
        raise ValueError("unknown mode: %r (expected one of %s)"
                         % (mode, ", ".join(MODES)))
    state.mode = mode
    return mode


# ---------------------------------------------------------------------------
# Legacy wrapper (keeps the starter gateway/proxy/agent importable until a
# later feature rewires them). ask -> 'pending'.
# ---------------------------------------------------------------------------

WORKSPACE = os.path.join(HARNESS_ROOT, "demo-files")
ALLOWED_HOSTS = {"api.example.com"}


def evaluate(tool, args):
    """-> (verdict, reason): 'allow' | 'block' | 'pending'."""
    args = args or {}
    settings = Settings()
    state = RunState(mode="default")
    source = "tool"
    if tool in ("http_proxy", "http_post", "net"):
        source = "proxy-stdlib"
        if tool == "http_post":
            args = dict(args)
            args.setdefault("method", "POST")
    action = Action(source=source, tool=tool, input=args)
    decision = decide(action, settings, state)
    verdict = {"allow": "allow", "block": "block", "ask": "pending"}[decision.verdict]
    return verdict, decision.reason
