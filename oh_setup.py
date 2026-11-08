"""OpenHarness (`oh`) integration for the A10 Agent Harness (Prompt 2).

`harness.py oh` uses this module to put oh under the gateway without touching
the user's own oh configuration:

  prepare_config_dir()  builds A10_HOME/oh-config/ and returns
                        {"OPENHARNESS_CONFIG_DIR": <that dir>} for oh's env.
                        settings.json (0600) is the user's settings with the
                        gateway's pre_tool_use / post_tool_use HTTP hooks
                        placed first (priority 1000); every other entry of the
                        user's config dir (credentials.json, data/, logs/, ...)
                        is symlinked, never copied. Nothing is ever written to
                        the user's dir.
  provider_hosts()      the LLM provider host of oh's active profile, which
                        the policy allows as row 10 (and nothing else).

CLI (generates docker/oh-settings.json for the Docker layout):
  python3 oh_setup.py --print-hooks --gateway-url http://gateway:8000 \\
      > docker/oh-settings.json

Facts about oh this relies on (read from github.com/HKUDS/OpenHarness): oh
loads settings only from $OPENHARNESS_CONFIG_DIR/settings.json (default
~/.openharness/settings.json); an http hook POSTs {"event", "payload"} and,
with block_on_failure, a non-2xx answer blocks the tool and the response text
becomes the tool error; the hook timeout is capped at 600 s.

Stdlib only.
"""
import argparse
import json
import os
import sys
from urllib.parse import urlsplit

DEFAULT_PROFILE = "claude-api"
OLLAMA_HOST = "localhost:11434"
HOOK_PRIORITY = 1000
PRE_TIMEOUT = 600     # oh's hook cap; the gateway answers within --approval-wait
POST_TIMEOUT = 10
SETTINGS_NAME = "settings.json"
CONFIG_SUBDIR = "oh-config"

# Built-in oh profiles (name -> provider) used when settings.json does not
# define the active profile itself.
BUILTIN_PROFILES = {
    "claude-api": {"provider": "anthropic"},
    "claude-subscription": {"provider": "anthropic_claude"},
    "openai-compatible": {"provider": "openai"},
    "codex": {"provider": "openai_codex"},
}

# Provider -> host when the profile has no base_url.
PROVIDER_HOSTS = {
    "anthropic": "api.anthropic.com",
    "anthropic_claude": "api.anthropic.com",
    "openai": "api.openai.com",
    "openai_codex": "chatgpt.com",
    "copilot": "api.githubcopilot.com",
    "github_copilot": "api.githubcopilot.com",
    "ollama": OLLAMA_HOST,
}

# Top-level keys of an older "flat" settings.json (no profiles section).
FLAT_KEYS = ("provider", "api_format", "base_url", "auth_source", "model",
             "default_model")


def user_config_dir(env=None):
    """The user's oh config dir: $OPENHARNESS_CONFIG_DIR or ~/.openharness."""
    env = os.environ if env is None else env
    path = env.get("OPENHARNESS_CONFIG_DIR") or "~/.openharness"
    return os.path.abspath(os.path.expanduser(path))


def load_user_settings(user_dir):
    """The user's settings.json as a dict; {} when missing or unreadable."""
    try:
        with open(os.path.join(user_dir, SETTINGS_NAME)) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def active_profile(settings, env=None):
    """-> (profile_name, profile_dict).

    Name: $OPENHARNESS_PROFILE, then settings["active_profile"], then
    'claude-api'. A profile of that name in settings["profiles"] wins.
    Otherwise flat top-level keys (provider and/or base_url, an older settings
    layout) are used on top of the built-in profile, unless the env override
    is set. Otherwise the built-in profile of that name ({} when unknown).
    """
    env = os.environ if env is None else env
    settings = settings if isinstance(settings, dict) else {}
    profiles = settings.get("profiles")
    profiles = profiles if isinstance(profiles, dict) else {}
    override = str(env.get("OPENHARNESS_PROFILE") or "").strip()
    name = (override or str(settings.get("active_profile") or "").strip()
            or DEFAULT_PROFILE)
    if isinstance(profiles.get(name), dict):
        return name, dict(profiles[name])
    builtin = dict(BUILTIN_PROFILES.get(name, {}))
    flat = {k: settings[k] for k in FLAT_KEYS if settings.get(k)}
    if not override and (flat.get("provider") or flat.get("base_url")):
        builtin.update(flat)
    return name, builtin


def _host_of(base_url):
    """host[:port] of a base_url (port only when explicit), lowercase."""
    u = str(base_url).strip()
    if "://" not in u:
        u = "https://" + u
    parts = urlsplit(u)
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return ""
    if ":" in host:  # IPv6 literal
        host = "[%s]" % host
    try:
        port = parts.port
    except ValueError:
        port = None
    return "%s:%d" % (host, port) if port else host


def provider_hosts(settings, env=None):
    """Hosts for row 10: only the active profile's LLM provider.

    base_url set -> its host[:port] (e.g. 'localhost:11434' for
    http://localhost:11434/v1). Otherwise the provider's default host:
    anthropic / anthropic_claude -> api.anthropic.com, openai ->
    api.openai.com, ollama -> localhost:11434.

    Unconfirmed defaults (spec section 7: check with a live oh run): the Codex
    subscription profile (openai_codex) -> chatgpt.com and Copilot ->
    api.githubcopilot.com. The Claude subscription bridge is assumed to call
    api.anthropic.com. Pass --provider-host to override.
    """
    name, prof = active_profile(settings, env)
    base_url = prof.get("base_url")
    if base_url:
        host = _host_of(base_url)
        return {host} if host else set()
    provider = str(prof.get("provider") or "").strip().lower()
    hint = (provider + " " + name).lower()
    if "ollama" in hint:
        return {OLLAMA_HOST}
    if "copilot" in hint:
        return {PROVIDER_HOSTS["copilot"]}
    host = PROVIDER_HOSTS.get(provider)
    if host is None and not provider:
        host = PROVIDER_HOSTS.get(BUILTIN_PROFILES.get(name, {}).get("provider"))
    return {host} if host else set()


def hook_settings(gateway_url):
    """The gateway's oh hooks: {"pre_tool_use": [...], "post_tool_use": [...]}."""
    url = gateway_url.rstrip("/") + "/hooks/oh"
    return {
        "pre_tool_use": [{"type": "http", "url": url,
                          "timeout_seconds": PRE_TIMEOUT,
                          "block_on_failure": True,
                          "priority": HOOK_PRIORITY}],
        "post_tool_use": [{"type": "http", "url": url,
                           "timeout_seconds": POST_TIMEOUT,
                           "block_on_failure": False,
                           "priority": HOOK_PRIORITY}],
    }


def merged_settings(user_settings, gateway_url):
    """User settings with our hooks first in each event list; the user's
    other hooks (and any other hook events) are kept in their order."""
    out = json.loads(json.dumps(user_settings or {}))  # deep copy
    hooks = out.get("hooks")
    hooks = dict(hooks) if isinstance(hooks, dict) else {}
    for event, ours in hook_settings(gateway_url).items():
        theirs = hooks.get(event)
        theirs = [h for h in theirs if h not in ours] if isinstance(
            theirs, list) else []
        hooks[event] = ours + theirs
    out["hooks"] = hooks
    return out


def _write_private(path, text):
    """Write `text` to `path` with mode 0600, replacing (not following) an
    existing file or symlink."""
    tmp = path + ".tmp"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _sync_links(user_dir, out_dir):
    """Symlink every entry of user_dir except settings.json into out_dir.
    Returns the names linked. Real files in out_dir (e.g. ones oh created in
    an earlier run) are left alone; links that no longer have a source in
    user_dir are removed."""
    linked = []
    names = []
    if os.path.isdir(user_dir):
        names = sorted(n for n in os.listdir(user_dir) if n != SETTINGS_NAME)
    for name in names:
        src = os.path.join(user_dir, name)
        dst = os.path.join(out_dir, name)
        if os.path.islink(dst):
            if os.readlink(dst) == src:
                linked.append(name)
                continue
            os.unlink(dst)
        elif os.path.lexists(dst):
            continue  # a real entry of ours; never clobber it
        os.symlink(src, dst)
        linked.append(name)
    real_user = os.path.realpath(user_dir)
    for name in os.listdir(out_dir):
        dst = os.path.join(out_dir, name)
        if name in names or not os.path.islink(dst):
            continue
        target = os.readlink(dst)
        if (os.path.dirname(target) in (user_dir, real_user)
                and not os.path.lexists(target)):
            os.unlink(dst)
    return linked


def prepare_config_dir(a10_home, gateway_url, user_dir=None, env=None):
    """Create A10_HOME/oh-config for oh and return
    {"OPENHARNESS_CONFIG_DIR": path}. Idempotent; reads but never writes the
    user's config dir."""
    user_dir = os.path.abspath(user_dir or user_config_dir(env))
    out_dir = os.path.join(os.path.abspath(a10_home), CONFIG_SUBDIR)
    if os.path.realpath(user_dir) == os.path.realpath(out_dir):
        raise ValueError("OPENHARNESS_CONFIG_DIR already points at the "
                         "harness config dir %s; unset it first" % out_dir)
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    os.chmod(out_dir, 0o700)
    settings = merged_settings(load_user_settings(user_dir), gateway_url)
    _write_private(os.path.join(out_dir, SETTINGS_NAME),
                   json.dumps(settings, indent=2) + "\n")
    _sync_links(user_dir, out_dir)
    return {"OPENHARNESS_CONFIG_DIR": out_dir}


def hooks_json(gateway_url):
    """settings.json text holding only the gateway's hooks."""
    return json.dumps({"hooks": hook_settings(gateway_url)}, indent=2) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Print oh settings.json with the A10 gateway hooks")
    p.add_argument("--print-hooks", action="store_true",
                   help='print {"hooks": ...} as JSON on stdout')
    p.add_argument("--gateway-url", default="http://127.0.0.1:8000",
                   help="gateway base URL the hooks call (default %(default)s)")
    args = p.parse_args(argv)
    if not args.print_hooks:
        p.print_usage(sys.stderr)
        print("nothing to do: pass --print-hooks", file=sys.stderr)
        return 2
    sys.stdout.write(hooks_json(args.gateway_url))
    return 0


if __name__ == "__main__":
    sys.exit(main())
