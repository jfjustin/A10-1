"""Turn a tool call or a network request into findings.

A finding is either an always-on rule hit (G1–G5, always blocked) or a row of
the mode table (rows 1–15, verdict depends on the mode). The engine combines
them; this module only classifies.
"""
from __future__ import annotations

import fnmatch
import glob as globlib
import ipaddress
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .config import Policy
from .shell import SHELLS, Segment, split_command

# ── tool groups (OpenHarness tool names) ────────────────────────────────────
READ_TOOLS = {"read_file": "path", "glob": "root", "grep": "root", "lsp": "file_path"}
WRITE_TOOLS = {"write_file": "path", "edit_file": "path", "notebook_edit": "path"}
HOUSEKEEPING = {"todo_write", "brief", "sleep", "skill", "tool_search", "ask_user_question",
                "enter_plan_mode", "exit_plan_mode", "task_list", "task_get", "task_output",
                "cron_list"}
SUBAGENT_TOOLS = {"agent", "team_create", "team_delete", "send_message", "task_create",
                  "task_stop", "task_update"}
SCHEDULED_TOOLS = {"cron_create", "cron_toggle", "remote_trigger"}
MCP_TOOLS = {"list_mcp_resources", "read_mcp_resource", "mcp_auth"}

# ── shell command groups ────────────────────────────────────────────────────
READ_ONLY_CMDS = {
    "ls", "cat", "pwd", "wc", "head", "tail", "grep", "egrep", "fgrep", "rg", "stat", "file",
    "tree", "which", "whoami", "date", "echo", "printf", "du", "df", "less", "more", "sort",
    "uniq", "cut", "diff", "basename", "dirname", "realpath", "readlink", "true", "false",
    "test", "[", "id", "uname", "hostname", "type", "jq", "nl", "tr", "column", "__SUBST__",
}
GIT_READ_ONLY = {"status", "diff", "log", "show", "blame", "ls-files", "rev-parse",
                 "describe", "shortlog"}
FIND_WRITES = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls"}
NET_CMDS = {"curl", "wget", "http", "https", "xh"}
RAW_NET_CMDS = {"nc", "ncat", "netcat", "socat", "telnet"}
COPY_NET_CMDS = {"scp", "rsync", "sftp", "ssh"}
INTERPRETERS = SHELLS | {"python", "python3", "perl", "ruby", "node", "php"}
CURL_ARG_OPTS = {"-o", "--output", "-H", "--header", "-d", "--data", "--data-raw",
                 "--data-binary", "--data-urlencode", "--json", "-X", "--request", "-u", "--user",
                 "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar",
                 "-w", "--write-out", "-m", "--max-time", "-x", "--proxy", "-F", "--form",
                 "-T", "--upload-file", "--connect-timeout", "-K", "--config", "-r", "--range",
                 "-O", "--output-document", "--post-data", "--post-file", "--header", "-P"}
CURL_UPLOAD_OPTS = ("-F", "--form", "-T", "--upload-file", "--post-file")
CURL_DATA_OPTS = ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--json",
                  "--post-data")
HARNESS_PROC = re.compile(r"mitm|gateway|run_agent|harness", re.I)
HOST_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?(?:/.*)?$|^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/.*)?$")
REMOTE_SPEC = re.compile(r"^(?:[^/@:\s]+@)?([A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\]):")


@dataclass
class Finding:
    rule: str | int          # "G1".."G5" or a mode-table row number
    reason: str


@dataclass
class Analysis:
    guard: Finding | None = None
    rows: list[Finding] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)

    def hit(self, rule: str, reason: str):
        if self.guard is None:
            self.guard = Finding(rule, reason)

    def row(self, n: int, reason: str):
        self.rows.append(Finding(n, reason))


@dataclass
class Context:
    policy: Policy
    protected_pids: set[int] = field(default_factory=set)


# ── path helpers ────────────────────────────────────────────────────────────
def _abs(path: str, cwd: str) -> str:
    p = os.path.expanduser(os.path.expandvars(path))
    return os.path.normpath(p if os.path.isabs(p) else os.path.join(cwd, p))


def _real(path: str) -> str:
    try:
        return os.path.realpath(path)
    except OSError:
        return path


def under(path: str, root: str | os.PathLike) -> bool:
    root = str(root).rstrip(os.sep) or os.sep
    return path == root or path.startswith(root + os.sep)


def _variants(path: str, cwd: str) -> list[str]:
    """The path as written, its real path, and any glob matches."""
    a = _abs(path, cwd)
    out = {a, _real(a)}
    if any(ch in a for ch in "*?["):
        for m in globlib.glob(a, recursive=True)[:200]:
            out |= {m, _real(m)}
    return list(out)


def sensitive_match(path: str, patterns: list[str]) -> str | None:
    for pat in patterns:
        if pat.startswith("**/"):
            tail = pat[3:]
            if any(fnmatch.fnmatch(part, tail) for part in path.split(os.sep)):
                return pat
            continue
        exp = os.path.normpath(os.path.expanduser(pat))
        if exp.endswith(os.sep + "*"):
            if under(path, exp[:-2]):
                return pat
        elif path == exp or fnmatch.fnmatch(path, exp):
            return pat
    return None


def _is_harness(path: str, ctx: Context) -> bool:
    if under(path, ctx.policy.workspace):
        return False
    return any(under(path, str(h)) for h in ctx.policy.harness_paths)


def _path_like(tok: str) -> str | None:
    """Pull a path out of a shell token, or None if it doesn't look like one."""
    if "://" in tok or not tok:
        return None
    if tok.startswith("-"):
        if "=" not in tok:
            return None
        tok = tok.split("=", 1)[1]
    tok = tok.lstrip("@")
    if tok.startswith(("/", "~", "./", "../", "$HOME", ".")) or "/" in tok:
        return tok
    return None


# ── host helpers ────────────────────────────────────────────────────────────
def host_matches(host: str, domains: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for d in domains:
        d = d.lower()
        if fnmatch.fnmatch(host, d) or host == d or host.endswith("." + d):
            return True
    return False


def _ip(host: str):
    h = host.strip("[]")
    try:
        if re.fullmatch(r"\d+", h):
            return ipaddress.ip_address(int(h))
        if re.fullmatch(r"0x[0-9a-fA-F]+", h):
            return ipaddress.ip_address(int(h, 16))
        return ipaddress.ip_address(h)
    except ValueError:
        return None


def internal_host(host: str, port: int | None, policy: Policy) -> str | None:
    """G4: return a reason if host is internal (cloud metadata, private, loopback)."""
    h = host.lower().strip("[]").rstrip(".")
    ollama = port == policy.ollama_port
    if h == "localhost" or h.endswith(".localhost"):
        return None if ollama else "localhost"
    if h.endswith(".internal"):
        return "*.internal host"
    ip = _ip(h)
    if ip is None:
        return None
    if str(ip) == "169.254.169.254":
        return "cloud metadata address"
    if ip.is_loopback:
        return None if ollama else "localhost"
    if ip.is_private or ip.is_link_local or ip.is_unspecified or ip.is_reserved:
        return f"internal address {ip}"
    return None


def is_ollama(host: str, port: int | None, policy: Policy) -> bool:
    h = host.lower().strip("[]")
    ip = _ip(h)
    local = h == "localhost" or (ip is not None and ip.is_loopback)
    return local and port == policy.ollama_port


def split_url(url: str) -> tuple[str, int | None]:
    parts = urlsplit(url if "://" in url else "http://" + url)
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return (parts.hostname or ""), port


def has_secret(text: str, policy: Policy) -> bool:
    return any(p.search(text) for p in policy.secret_patterns)


def _net_row(a: Analysis, host: str, port: int | None, ctx: Context, what: str):
    p = ctx.policy
    if not host:
        return
    a.hosts.add(host)
    why = internal_host(host, port, p)
    if why:
        a.hit("G4", f"{what} to {why} ({host})")
    elif host_matches(host, p.llm_hosts) or is_ollama(host, port, p):
        a.row(10, f"{what} to LLM provider {host}")
    elif host_matches(host, p.allowed_domains):
        a.row(8, f"{what} to allowlisted host {host}")
    else:
        a.row(9, f"{what} to unknown host {host}")


# ── tool analysis ───────────────────────────────────────────────────────────
def analyze_tool(name: str, tool_input: dict, ctx: Context) -> Analysis:
    a = Analysis()
    p = ctx.policy
    ws = str(p.workspace)
    tool_input = tool_input or {}

    if name in HOUSEKEEPING:
        a.row(15, f"{name} has no side effects")
    elif name in READ_TOOLS or name in WRITE_TOOLS:
        writing = name in WRITE_TOOLS
        field_name = (WRITE_TOOLS if writing else READ_TOOLS)[name]
        raw = tool_input.get(field_name) or ws
        paths = [raw]
        pattern = tool_input.get("pattern") if name == "glob" else tool_input.get("file_glob")
        if isinstance(pattern, str) and pattern.startswith(("/", "~")):
            paths.append(pattern)
        _check_paths(a, paths, ws, ctx, writing=writing, tool=name)
    elif name == "bash":
        analyze_shell(a, str(tool_input.get("command", "")), tool_input.get("cwd") or ws, ctx)
    elif name == "web_fetch":
        url = str(tool_input.get("url", ""))
        host, port = split_url(url)
        if has_secret(url, p):
            a.hit("G3", "secret pattern in an outbound URL")
        _net_row(a, host, port, ctx, "web_fetch")
    elif name == "web_search":
        if has_secret(str(tool_input.get("query", "")), p):
            a.hit("G3", "secret pattern in a search query")
        url = tool_input.get("search_url")
        if url:
            host, port = split_url(str(url))
            _net_row(a, host, port, ctx, "web_search")
        else:
            a.row(9, "web_search to the default search engine")
    elif name == "config":
        action = str(tool_input.get("action", "show"))
        key = str(tool_input.get("key") or "")
        if action == "set" and re.search(r"hook|permission", key, re.I):
            a.hit("G5", f"config tool changing {key}")
        elif action == "show":
            a.row(15, "config show is read-only")
        else:
            a.row(14, f"config {action} {key}")
    elif name in SUBAGENT_TOOLS:
        a.row(11, f"{name} starts or drives another agent")
    elif name in SCHEDULED_TOOLS:
        a.row(12, f"{name} would keep running after STOP")
    elif name.startswith("mcp__") or name in MCP_TOOLS:
        a.row(13, f"MCP tool {name}")
    else:
        a.row(14, f"unknown tool {name}")
    return a


def _check_paths(a: Analysis, paths: list[str], cwd: str, ctx: Context, *, writing: bool, tool: str):
    p = ctx.policy
    for raw in paths:
        for path in _variants(str(raw), cwd):
            pat = sensitive_match(path, p.sensitive_paths)
            if pat:
                a.hit("G1", f"{tool} touches sensitive path {raw} ({pat})")
            if writing and _is_harness(path, ctx):
                a.hit("G5", f"{tool} writes to the harness: {raw}")
        inside = all(under(v, p.workspace) for v in _variants(str(raw), cwd))
        if writing:
            a.row(3 if inside else 4, f"{tool} {'inside' if inside else 'outside'} the workspace: {raw}")
        else:
            a.row(1 if inside else 2, f"{tool} {'inside' if inside else 'outside'} the workspace: {raw}")


# ── shell analysis ──────────────────────────────────────────────────────────
def _git_sub(args: list[str]) -> tuple[str, list[str]]:
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in ("-C", "-c") else 1
    return (args[i], args[i + 1:]) if i < len(args) else ("", [])


def destructive(seg: Segment) -> str | None:
    cmd, args = seg.cmd, seg.args
    if cmd in {"rm", "rmdir", "unlink", "shred", "dd", "sudo", "doas", "su", "shutdown",
               "reboot", "halt", "poweroff"} or cmd.startswith("mkfs"):
        return cmd
    if cmd in {"chmod", "chown"} and any(x == "--recursive" or re.fullmatch(r"-[A-Za-z]*R[A-Za-z]*", x) for x in args):
        return f"{cmd} -R"
    if cmd == "find" and "-delete" in args:
        return "find -delete"
    if cmd == "git":
        sub, rest = _git_sub(args)
        if sub == "push" and any(x in ("-f", "--force", "--force-with-lease", "--mirror")
                                 or x.startswith("--force") or (x.startswith("+") and len(x) > 1) for x in rest):
            return "git push --force"
        if sub == "reset" and "--hard" in rest:
            return "git reset --hard"
        if sub == "clean" and any(re.fullmatch(r"-[A-Za-z]*f[A-Za-z]*", x) or x == "--force" for x in rest):
            return "git clean -f"
    return None


def _package_install(seg: Segment) -> bool:
    cmd, args = seg.cmd, seg.args
    first = next((x for x in args if not x.startswith("-")), "")
    if cmd in {"pip", "pip3", "pipx", "gem", "cargo", "brew", "apt", "apt-get", "conda", "mamba"}:
        return first in {"install", "run"}
    if cmd in {"python", "python3"} and args[:2] == ["-m", "pip"]:
        return "install" in args
    if cmd == "uv":
        return first in {"add", "pip", "tool"} and ("install" in args or first == "add")
    if cmd in {"npm", "pnpm", "bun"}:
        return first in {"install", "i", "add", "ci"} or (cmd == "pnpm" and first == "")
    if cmd == "yarn":
        return first in {"add", "install", ""}
    if cmd in {"npx", "bunx", "uvx"}:
        return True
    if cmd == "go":
        return first in {"install", "get"}
    if cmd == "poetry":
        return first in {"add", "install"}
    return False


def _read_only(seg: Segment) -> bool:
    if [t for t in seg.write_targets if not t.startswith("/dev/")]:
        return False
    if seg.cmd == "find":
        return not any(x in FIND_WRITES for x in seg.args)
    if seg.cmd == "git":
        sub, rest = _git_sub(seg.args)
        if sub == "branch":
            return all(x in {"-a", "-r", "-v", "-vv", "--list", "-l", "--show-current"} for x in rest)
        if sub == "remote":
            return all(x == "-v" for x in rest)
        return sub in GIT_READ_ONLY
    if seg.cmd in {"sort"} and any(x.startswith("-o") or x.startswith("--output") for x in seg.args):
        return False
    return seg.cmd in READ_ONLY_CMDS


def _url_args(seg: Segment) -> list[str]:
    # curl -O takes no value; wget -O / -P do.
    takes_value = CURL_ARG_OPTS if seg.cmd == "wget" else CURL_ARG_OPTS - {"-O", "-P"}
    urls, skip = [], False
    for tok in seg.args:
        if skip:
            skip = False
            continue
        if tok in takes_value:
            skip = True
            continue
        if tok.startswith("-"):
            continue
        if "://" in tok or HOST_RE.match(tok):
            urls.append(tok)
    return urls


def _opt_values(args: list[str], opts: tuple[str, ...]) -> list[str]:
    vals = []
    for i, tok in enumerate(args):
        for o in opts:
            if tok == o and i + 1 < len(args):
                vals.append(args[i + 1])
            elif tok.startswith(o + "=") or (len(o) == 2 and tok.startswith(o) and len(tok) > 2 and not o.startswith("--")):
                vals.append(tok.split("=", 1)[1] if "=" in tok else tok[2:])
    return vals


def analyze_shell(a: Analysis, command: str, cwd: str, ctx: Context):
    p = ctx.policy
    ws = str(p.workspace)
    cwd = _abs(cwd, ws)
    segments = split_command(command)
    if not segments:
        a.row(5, "empty command")
        return

    for i, seg in enumerate(segments):
        label = seg.text if len(seg.text) < 80 else seg.text[:77] + "..."

        # G2: destructive commands, in every part of the command
        why = destructive(seg)
        if why:
            a.hit("G2", f"destructive command `{why}` in: {label}")
        if seg.sep == "|" and seg.cmd in INTERPRETERS and i > 0 and segments[i - 1].cmd in NET_CMDS:
            a.hit("G2", f"download piped into a shell: {segments[i - 1].cmd} … | {seg.cmd}")

        # G5: killing the gateway or proxy
        if seg.cmd in {"kill", "pkill", "killall"}:
            pids = {int(x) for x in seg.args if x.isdigit()}
            if pids & ctx.protected_pids or any(HARNESS_PROC.search(x) for x in seg.args if not x.startswith("-")):
                a.hit("G5", f"{seg.cmd} aimed at the gateway or mitmproxy")

        # G1 / G5: paths mentioned anywhere in the command
        tokens = seg.args + seg.write_targets + seg.read_targets
        outside = []
        for tok in tokens:
            raw = _path_like(tok)
            if raw is None:
                continue
            for path in _variants(raw, cwd):
                pat = sensitive_match(path, p.sensitive_paths)
                if pat:
                    a.hit("G1", f"sensitive path {raw} ({pat}) in: {label}")
                if _is_harness(path, ctx):
                    a.hit("G5", f"command touches the harness ({raw})")
            if not all(under(v, ws) for v in _variants(raw, cwd)) and not raw.startswith("/dev/"):
                outside.append(raw)

        # Network: G3 exfiltration, G4 internal addresses, rows 8/9
        is_net = seg.cmd in NET_CMDS | RAW_NET_CMDS | COPY_NET_CMDS
        if is_net and has_secret(seg.text, p):
            a.hit("G3", f"secret pattern in an outbound command: {seg.cmd}")
        if seg.cmd in NET_CMDS:
            uploads = _opt_values(seg.args, CURL_UPLOAD_OPTS)
            data_files = [v for v in _opt_values(seg.args, CURL_DATA_OPTS) if v.startswith("@")]
            writes_file = any(x in ("-o", "-O", "--output", "--remote-name", "--output-document") or
                              re.fullmatch(r"-[A-Za-z]*O[A-Za-z]*", x) for x in seg.args) or bool(seg.write_targets)
            for url in _url_args(seg):
                host, port = split_url(url)
                if (uploads or data_files) and not host_matches(host, p.allowed_domains):
                    a.hit("G3", f"upload with {seg.cmd} to non-allowlisted host {host}")
                _net_row(a, host, port, ctx, seg.cmd)
            if uploads or data_files or writes_file:
                a.row(6, f"{seg.cmd} that uploads or writes files")
            for f in uploads + data_files:
                f = f.lstrip("@").split(";")[0].split("=", 1)[-1].lstrip("@")
                for path in _variants(f, cwd):
                    if sensitive_match(path, p.sensitive_paths):
                        a.hit("G1", f"uploading sensitive file {f}")
            continue
        if seg.cmd in RAW_NET_CMDS or seg.cmd in COPY_NET_CMDS:
            hosts = []
            if seg.cmd in RAW_NET_CMDS or seg.cmd == "ssh":
                hosts = [next((x for x in seg.args if not x.startswith("-")), "")]
                hosts = [h.split("@")[-1] for h in hosts if h]
            for tok in seg.args:
                m = REMOTE_SPEC.match(tok)
                if m and "://" not in tok:
                    hosts.append(m.group(1))
            for host in hosts:
                host = host.strip("[]")
                why = internal_host(host, None, p)
                if why:
                    a.hit("G4", f"{seg.cmd} to {why} ({host})")
                elif not host_matches(host, p.allowed_domains):
                    a.hit("G3", f"{seg.cmd} to non-allowlisted host {host}")
                a.hosts.add(host)
            a.row(6, f"{seg.cmd} opens a raw connection")
            continue
        # URLs passed to anything else (python script.py http://169.254.169.254 ...)
        for url in [t for t in seg.args if "://" in t]:
            host, port = split_url(url)
            why = internal_host(host, port, p)
            if why:
                a.hit("G4", f"{why} ({host}) in: {label}")

        if _package_install(seg):
            a.row(7, f"package install: {label}")
        elif _read_only(seg):
            if outside or not under(cwd, ws):
                a.row(2, f"read-only command outside the workspace: {label}")
            else:
                a.row(5, f"read-only command: {label}")
        else:
            a.row(6, f"shell command: {label}")
            if outside or not under(cwd, ws):
                a.row(4, f"shell command touching paths outside the workspace: {', '.join(outside) or cwd}")
