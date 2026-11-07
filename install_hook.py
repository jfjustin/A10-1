"""Install (or remove) the gateway as OpenHarness's pre_tool_use hook.

    python install_hook.py             # add the hook to ~/.openharness/settings.json
    python install_hook.py --uninstall

Writes a backup next to the settings file first. Subagents started with oh's
`agent` tool run `oh --task-worker`, which loads the same settings file, so they
go through the hook too.

The hook timeout is the approval timeout plus a margin, so oh waits for the
operator instead of giving up first. block_on_failure is on: if the gateway is
down or times out, the tool call is blocked.
"""
from __future__ import annotations

import argparse
import json
import shutil
import time

from harness.config import load_policy, oh_config_dir


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--policy", default=None)
    args = ap.parse_args(argv)
    policy = load_policy(args.policy)

    path = oh_config_dir() / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    settings = json.loads(path.read_text()) if path.exists() else {}
    if path.exists():
        backup = path.with_name(f"settings.json.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup)
        print(f"backup: {backup}")

    url = policy.gateway_url + "/hook"
    hooks = settings.setdefault("hooks", {})
    pre = [h for h in hooks.get("pre_tool_use", []) if not str(h.get("url", "")).endswith("/hook")
           or not str(h.get("url", "")).startswith(policy.gateway_url)]
    if not args.uninstall:
        pre.insert(0, {
            "type": "http",
            "url": url,
            "timeout_seconds": int(policy.approval_timeout_seconds) + 15,
            "block_on_failure": True,
            "priority": 1000,
        })
    hooks["pre_tool_use"] = pre
    if not pre:
        hooks.pop("pre_tool_use")
    path.write_text(json.dumps(settings, indent=2) + "\n")
    print(("removed" if args.uninstall else "installed") + f" pre_tool_use hook -> {url} in {path}")


if __name__ == "__main__":
    main()
