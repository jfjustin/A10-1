"""OpenHarness (`oh`) integration for the A10 Agent Harness (Prompt 2).

`harness.py oh` uses this module to put oh under the gateway without touching
the user's own oh configuration:

  prepare_config_dir()  builds A10_HOME/oh-config/ and returns
                        {"OPENHARNESS_CONFIG_DIR": <that dir>} for oh's env.
                        settings.json (0600) is the user's settings with the
                        gateway's pre_tool_use / post_tool_use HTTP hooks
                        placed first in each list; every other entry of the
                        user's config dir (credentials.json, data/, logs/, ...)
                        is symlinked, never copied. Nothing is ever written to
                        the user's dir.
  provider_hosts()      the LLM provider host of oh's active profile, which
                        the policy allows as row 10 (and nothing else).

CLI (generates docker/oh-settings.json for the Docker layout):
  python3 oh_setup.py --print-hooks --gateway-url http://gateway:8000 \\
      > docker/oh-settings.json

Facts about oh this relies on, checked against the installed openharness-ai
0.1.9 source (paths relative to site-packages/openharness/):
  - oh reads settings only from $OPENHARNESS_CONFIG_DIR/settings.json
    (default ~/.openharness/settings.json): config/paths.py get_config_dir().
  - Hook entries are pydantic models (hooks/schemas.py HttpHookDefinition:
    type "http", url, headers, timeout_seconds 1..600, matcher,
    block_on_failure). Unknown keys such as our "priority" are ignored; hooks
    run in list order (hooks/loader.py), every matching hook runs, and any
    blocking result blocks (hooks/types.py AggregatedHookResult).
  - An http hook POSTs {"event", "payload"} with httpx (trust_env, so
    NO_PROXY applies). A non-2xx answer with block_on_failure blocks the
    tool, and the response text becomes the tool error the model sees
    (hooks/executor.py _run_http_hook, engine/query.py _execute_tool_call).
  - The active profile and the API host oh calls: see active_profile() and
    provider_hosts().

Stdlib only.
"""
import argparse
import json
import os
import sys
from pathlib import PurePosixPath
from urllib.parse import urlsplit

DEFAULT_PROFILE = "claude-api"
HOOK_PRIORITY = 1000  # ignored by oh 0.1.9 (list order counts); kept for
#                       oh versions that sort hooks by priority
PRE_TIMEOUT = 600     # oh's hook cap; the gateway answers within --approval-wait
POST_TIMEOUT = 10
SETTINGS_NAME = "settings.json"
CONFIG_SUBDIR = "oh-config"

# oh 0.1.9's built-in profile catalog (config/settings.py
# default_provider_profiles): name -> provider, api_format, base_url.
# There is no built-in Ollama profile: Ollama is an OpenAI-compatible profile
# with base_url http://localhost:11434/v1 (api/registry.py).
BUILTIN_PROFILES = {
    "claude-api": {"provider": "anthropic", "api_format": "anthropic"},
    "claude-subscription": {"provider": "anthropic_claude",
                            "api_format": "anthropic"},
    "openai-compatible": {"provider": "openai", "api_format": "openai"},
    "codex": {"provider": "openai_codex", "api_format": "openai"},
    "copilot": {"provider": "copilot", "api_format": "copilot"},
    "moonshot": {"provider": "moonshot", "api_format": "openai",
                 "base_url": "https://api.moonshot.cn/v1"},
    "gemini": {"provider": "gemini", "api_format": "openai",
               "base_url": "https://generativelanguage.googleapis.com/v1beta/openai"},
    "minimax": {"provider": "minimax", "api_format": "openai",
                "base_url": "https://api.minimax.io/v1"},
    "nvidia": {"provider": "nvidia", "api_format": "openai",
               "base_url": "https://integrate.api.nvidia.com/v1"},
    "qwen": {"provider": "dashscope", "api_format": "openai",
             "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1"},
    "modelscope": {"provider": "modelscope", "api_format": "openai",
                   "base_url": "https://api-inference.modelscope.cn/v1"},
}

# Default API hosts of oh's clients when the profile has no base_url.
ANTHROPIC_HOST = "api.anthropic.com"   # anthropic SDK (ANTHROPIC_BASE_URL)
OPENAI_HOST = "api.openai.com"         # openai SDK (OPENAI_BASE_URL)
CODEX_HOST = "chatgpt.com"             # api/codex_client.py DEFAULT_CODEX_BASE_URL
COPILOT_HOST = "api.githubcopilot.com"  # api/copilot_auth.py COPILOT_DEFAULT_API_BASE


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


def _text(value):
    return value.strip() if isinstance(value, str) else ""


def _slug(value):
    """oh's _slugify_profile_name."""
    cleaned = "".join(ch.lower() if ch.isalnum() else "-"
                      for ch in value).strip("-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned or "custom"


def _flat_profile(settings):
    """oh's _profile_from_flat_settings: (name, profile) from the top-level
    provider / api_format / base_url keys (api_format defaults to
    'anthropic' as in oh's Settings model)."""
    provider = _text(settings.get("provider"))
    fmt = _text(settings.get("api_format")) or "anthropic"
    base_url = _text(settings.get("base_url")) or None
    if provider == "openai_codex":
        name = "codex"
    elif provider == "anthropic_claude":
        name = "claude-subscription"
    elif provider == "copilot" or fmt == "copilot":
        name = "copilot"
    elif provider == "openai" and not base_url:
        name = "openai-compatible"
    elif provider == "anthropic" and not base_url:
        name = DEFAULT_PROFILE
    elif base_url:
        name = _slug(PurePosixPath(base_url).name or base_url)
    elif provider:
        name = _slug(provider)
    else:
        name = DEFAULT_PROFILE
    builtin = BUILTIN_PROFILES.get(name)
    if (builtin and provider in ("", builtin["provider"])
            and builtin["api_format"] == fmt
            and builtin.get("base_url") == base_url):
        return name, dict(builtin)
    if not provider:
        provider = {"copilot": "copilot", "openai": "openai"}.get(fmt,
                                                                  "anthropic")
    return name, {"provider": provider, "api_format": fmt,
                  "base_url": base_url}


def active_profile(settings):
    """-> (profile_name, profile_dict), resolved the way oh 0.1.9 does it
    (config/settings.py load_settings and Settings.resolve_profile).

    With both "active_profile" and "profiles" in settings.json: the named
    profile from the user's profiles merged over the built-in catalog (a
    user profile without base_url inherits the built-in one's), default
    'claude-api'. When either key is missing, or the name is unknown, oh
    ignores active_profile and infers the profile from the flat top-level
    keys (default 'claude-api'). oh reads no environment variable to pick a
    profile, so neither does this.
    """
    settings = settings if isinstance(settings, dict) else {}
    profiles = settings.get("profiles")
    if "active_profile" in settings and isinstance(profiles, dict):
        merged = {n: dict(p) for n, p in BUILTIN_PROFILES.items()}
        for n, p in profiles.items():
            if not isinstance(p, dict):
                continue
            p = dict(p)
            builtin_url = BUILTIN_PROFILES.get(n, {}).get("base_url")
            if p.get("base_url") is None and builtin_url:
                p["base_url"] = builtin_url
            merged[n] = p
        name = _text(settings.get("active_profile")) or DEFAULT_PROFILE
        if name in merged:
            return name, merged[name]
    return _flat_profile(settings)


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
    """Hosts for row 10: only the API host oh's active profile calls.

    Mirrors oh 0.1.9's client choice (ui/runtime.py
    _resolve_api_client_from_settings):
      api_format 'copilot'      -> api.githubcopilot.com (oh ignores the
                                   profile's base_url; GitHub Enterprise uses
                                   copilot-api.<domain>, not detected)
      base_url set              -> its host[:port] (Ollama:
                                   http://localhost:11434/v1 -> localhost:11434)
      provider 'openai_codex'   -> chatgpt.com
      api_format 'openai'       -> $OPENAI_BASE_URL's host, else api.openai.com
      anything else (Anthropic) -> $ANTHROPIC_BASE_URL's host, else
                                   api.anthropic.com (also the Claude
                                   subscription)
    The two *_BASE_URL variables are read by the anthropic / openai SDKs when
    oh passes no base_url. Not detected: oh's --base-url flag, and the Claude
    subscription's token refresh at platform.claude.com. Pass --provider-host
    to override.
    """
    env = os.environ if env is None else env
    _, prof = active_profile(settings)
    provider = _text(prof.get("provider"))
    fmt = _text(prof.get("api_format"))
    base_url = _text(prof.get("base_url"))
    if fmt == "copilot":
        return {COPILOT_HOST}
    if not base_url and provider == "openai_codex":
        return {CODEX_HOST}
    if not base_url:
        if provider != "anthropic_claude" and fmt in ("openai", "openai_compat"):
            base_url, default = _text(env.get("OPENAI_BASE_URL")), OPENAI_HOST
        else:
            base_url = _text(env.get("ANTHROPIC_BASE_URL"))
            default = ANTHROPIC_HOST
        if not base_url:
            return {default}
    host = _host_of(base_url)
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
