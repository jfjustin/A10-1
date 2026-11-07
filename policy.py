"""Policy engine for the A10 Agent Harness (Prompt 2).

Every tool call from the CLI agent is judged here before it runs, and every
outbound request the network proxy sees is judged here too. A block always
carries a human-readable reason -- never a silent failure. Rules are
deliberately small and explainable to judges in one sentence each.

Verdicts: 'allow' | 'block' | 'pending' (pause for operator approval).
"""
import os
import re

# The agent may only write inside this directory (the demo workspace).
WORKSPACE = os.path.abspath(os.path.join(os.path.dirname(__file__), "demo-files"))

# Outbound hosts the demo agent may reach. 127.0.0.1 is local services only
# (the gateway itself + its stub API); api.example.com is the demo API.
ALLOWED_HOSTS = {"api.example.com", "127.0.0.1"}

# Shell verbs that are destructive by nature -- blocked regardless of target.
BLOCKED_SHELL_VERBS = {"rm", "rmdir", "dd", "mkfs", "shutdown", "reboot"}

# Uploads (curl -d / --data / POST with a body) are risky, not forbidden:
# pause them for operator approval instead of blocking outright.
UPLOAD_FLAGS = {"-d", "--data", "--data-binary", "--data-ascii", "--data-raw"}


def _is_inside_workspace(path):
    if not path:
        return False
    return os.path.abspath(path).startswith(WORKSPACE + os.sep)


def _hosts_in_command(cmd):
    hosts = []
    for token in cmd.split():
        m = re.match(r"https?://([^/:]+)", token)
        if m:
            hosts.append(m.group(1))
    return hosts


def evaluate(tool, args):
    """-> (verdict, reason): verdict is 'allow', 'block' or 'pending'."""
    args = args or {}

    if tool == "shell":
        cmd = (args.get("command") or "").strip()
        tokens = cmd.split()
        verb = tokens[0] if tokens else ""
        if verb in BLOCKED_SHELL_VERBS:
            return "block", f"destructive shell command '{verb}' is never allowed"
        # Any URL in the command must be allowlisted (checked before the
        # upload rule, so an exfil curl is blocked, not paused).
        for host in _hosts_in_command(cmd):
            if host not in ALLOWED_HOSTS:
                return "block", f"outbound call to non-allowlisted host '{host}'"
        if "curl" in tokens or "wget" in tokens:
            if UPLOAD_FLAGS & set(tokens):
                return "pending", "data upload needs operator approval"
            return "allow", "outbound call to allowlisted host (re-checked at the proxy)"
        return "allow", "shell command within policy"

    if tool == "file_read":
        path = args.get("path", "")
        if not _is_inside_workspace(path):
            return "block", f"read outside workspace: {path}"
        return "allow", "read inside workspace"

    if tool == "file_write":
        path = args.get("path", "")
        if not _is_inside_workspace(path):
            return "block", f"write outside workspace: {path}"
        return "allow", "write inside workspace"

    if tool == "http_get":
        host = args.get("host", "")
        if host not in ALLOWED_HOSTS:
            return "block", f"outbound call to non-allowlisted host '{host}'"
        return "allow", f"host '{host}' is allowlisted"

    if tool == "http_post":
        host = args.get("host", "")
        if host not in ALLOWED_HOSTS:
            return "block", f"outbound call to non-allowlisted host '{host}'"
        return "pending", "POST upload needs operator approval"

    if tool == "http_proxy":
        # The network proxy asks the gateway about every outbound request.
        host = args.get("host", "")
        if host not in ALLOWED_HOSTS:
            return "block", f"proxy: non-allowlisted host '{host}'"
        return "allow", f"proxy: host '{host}' is allowlisted"

    return "block", f"unknown tool '{tool}' -- deny by default"
