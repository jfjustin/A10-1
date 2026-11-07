"""Load policy.json and resolve the paths the gateway protects."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

HARNESS_DIR = Path(__file__).resolve().parent.parent
STATE_DIR = HARNESS_DIR / "state"
DEFAULT_POLICY = HARNESS_DIR / "policy.json"
MODES = ("plan", "default", "auto")


def oh_config_dir() -> Path:
    """Same lookup as openharness.config.paths.get_config_dir()."""
    env = os.environ.get("OPENHARNESS_CONFIG_DIR")
    return Path(env).expanduser() if env else Path.home() / ".openharness"


@dataclass
class Policy:
    mode: str = "default"
    workspace: Path = HARNESS_DIR / "sandbox"
    gateway_host: str = "127.0.0.1"
    gateway_port: int = 8765
    proxy_port: int = 8080
    approval_timeout_seconds: float = 60
    host_pass_seconds: float = 30
    block_on_failure: bool = True
    allowed_domains: list[str] = field(default_factory=list)
    llm_hosts: list[str] = field(default_factory=list)
    ollama_port: int = 11434
    sensitive_paths: list[str] = field(default_factory=list)
    secret_patterns: list[re.Pattern] = field(default_factory=list)
    state_dir: Path = STATE_DIR

    # Files the agent must never write (G5). Filled in by load_policy().
    harness_paths: list[Path] = field(default_factory=list)

    @property
    def audit_path(self) -> Path:
        return self.state_dir / "audit.jsonl"

    @property
    def token_path(self) -> Path:
        return self.state_dir / "operator.token"

    @property
    def gateway_url(self) -> str:
        return f"http://{self.gateway_host}:{self.gateway_port}"


def load_policy(path: str | os.PathLike | None = None, **overrides) -> Policy:
    path = Path(path or os.environ.get("HARNESS_POLICY") or DEFAULT_POLICY)
    raw = json.loads(path.read_text()) if path.exists() else {}
    raw.update({k: v for k, v in overrides.items() if v is not None})

    ws = Path(raw.pop("workspace", "./sandbox")).expanduser()
    if not ws.is_absolute():
        ws = path.parent / ws
    patterns = [re.compile(p) for p in raw.pop("secret_patterns", [])]
    state_dir = Path(raw.pop("state_dir", STATE_DIR))

    p = Policy(workspace=Path(os.path.realpath(ws)), secret_patterns=patterns,
               state_dir=state_dir, **{k: v for k, v in raw.items() if k in Policy.__dataclass_fields__})
    if p.mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {p.mode!r}")
    if HARNESS_DIR == p.workspace or p.workspace in HARNESS_DIR.parents:
        raise ValueError("the workspace must not contain the harness itself; "
                         "point it at a sandbox folder")

    oh_dir = oh_config_dir()
    p.harness_paths = [
        oh_dir / "settings.json",           # where the pre_tool_use hook lives
        Path.home() / ".openharness" / "settings.json",
        Path(os.path.realpath(state_dir)),  # audit log, operator token, session file
        HARNESS_DIR,                        # gateway code and policy.json
    ]
    # The operator token is also a sensitive path (G1), so it can't even be read.
    p.sensitive_paths = list(p.sensitive_paths) + [str(p.token_path)]
    return p
