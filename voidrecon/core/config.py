"""Layered configuration.

Precedence (lowest to highest): built-in defaults -> packaged
``configs/default.yaml`` -> user config file (``--config``) -> environment
variables (``VOIDRECON_*``) -> explicit CLI overrides. API keys are read from the
environment so they never have to live in a file.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

DEFAULTS: dict[str, Any] = {
    "general": {
        "output_dir": "runs",
        "log_level": "info",
        "user_agent": "VoidRecon/0.2 (+https://github.com/CypherNova1337/VoidRecon)",
        "wildcard_apex": True,   # a bare apex in scope covers subdomains
        "sqlite": True,          # append each run to <output_base>/voidrecon.db
    },
    "opsec": {
        # Passive is always allowed. Active interaction is off unless explicitly
        # enabled — this keeps VoidRecon quiet and lawful by default.
        "allow_active": False,
        # Aggressive mode: maximum-coverage recon. Enables active mode, every
        # opt-in module, and heavier throughput. Requires explicit confirmation.
        "aggressive": False,
        "max_concurrency": 20,
        "requests_per_second": 8.0,
        "jitter": 0.3,               # +/- fraction randomly added to delays
        "timeout": 20.0,
        "retries": 2,
        "rotate_user_agents": True,
        "respect_out_of_scope": True,
    },
    "http": {
        "verify_tls": True,
        "follow_redirects": True,
        "max_redirects": 5,
    },
    "auth": {
        # Authenticated-session material sent on every active request. Lets the
        # crawler, API discovery, fuzzer, etc. reach behind a login.
        "headers": {},   # e.g. {"Authorization": "Bearer <token>"}
        "cookies": {},   # e.g. {"session": "<value>"}
        # Optional scripted browser login run once at start; captured cookies are
        # merged into 'cookies'. Requires Playwright.
        "login": {},     # {url, username, password, [username_selector, password_selector,
                         #  submit_selector, success_text]}
    },
    "dns": {
        # Trusted resolvers for all DNS modules. Empty -> bundled list (dns-helix).
        "resolvers": [],
    },
    "oob": {
        # Out-of-band interaction domain (e.g. an interactsh domain you control).
        # Enables blind SSRF testing: VoidRecon injects callbacks; you watch the listener.
        "domain": None,
    },
    "modules": {
        # Per-module enable flags and options are merged in here.
        "disabled": [],
        # Force-enable opt-in modules by name. "*" enables every opt-in module
        # (set automatically by aggressive mode). --only also folds names in here.
        "enabled": [],
    },
    "sources": {
        # Optional API keys/endpoints for richer passive sources. All optional.
        # Prefer env vars: VOIDRECON_SOURCES_<NAME>.
        "github_token": None,
        "shodan_api_key": None,
        "securitytrails_api_key": None,
        "virustotal_api_key": None,
        "censys_api_id": None,
        "censys_api_secret": None,
    },
    "intel": {
        "llm_enabled": False,
        "llm_provider": "none",      # none | openai | anthropic | ollama | openai_compatible
        "llm_model": "",
        "llm_base_url": "",          # for ollama / openai_compatible
        "llm_api_key_env": "VOIDRECON_LLM_API_KEY",
        "llm_max_assets": 60,        # cap what we ask the model to reason about
    },
    "reporting": {
        "formats": ["json", "markdown", "html"],
    },
    "notify": {
        # Optional completion notifications. Any/all channels may be set.
        "webhook": None,            # Slack or Discord webhook (env: VOIDRECON_NOTIFY_WEBHOOK)
        "telegram_token": None,     # Telegram bot token (env: VOIDRECON_NOTIFY_TELEGRAM_TOKEN)
        "telegram_chat_id": None,   # Telegram chat id  (env: VOIDRECON_NOTIFY_TELEGRAM_CHAT_ID)
        "min_severity": "high",     # only ping if a finding at/above this severity exists
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _load_yaml(path: Path) -> dict:
    if yaml is None:
        raise RuntimeError("PyYAML is required to read config files. Install with: pip install pyyaml")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config at {path} must be a mapping at the top level.")
    return data


def _apply_env(cfg: dict) -> dict:
    """Fold VOIDRECON_* env vars in. Keys map by section, e.g.
    VOIDRECON_SOURCES_GITHUB_TOKEN -> cfg['sources']['github_token']."""
    for env_key, value in os.environ.items():
        if not env_key.startswith("VOIDRECON_"):
            continue
        parts = env_key[len("VOIDRECON_"):].lower().split("_", 1)
        if len(parts) != 2:
            continue
        section, key = parts
        if section in cfg and isinstance(cfg[section], dict):
            cfg[section][key] = _coerce(value)
    return cfg


def _coerce(value: str) -> Any:
    low = value.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


class Config:
    """Dotted-path access over the merged config dict."""

    def __init__(self, data: dict[str, Any]):
        self._data = data

    @classmethod
    def load(cls, config_path: str | Path | None = None, overrides: dict | None = None) -> "Config":
        cfg = copy.deepcopy(DEFAULTS)
        packaged = Path(__file__).resolve().parents[2] / "configs" / "default.yaml"
        if packaged.exists():
            try:
                cfg = _deep_merge(cfg, _load_yaml(packaged))
            except Exception:
                pass
        # Persistent user config (written by `voidrecon setup`).
        try:
            user_cfg = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
            user_cfg = user_cfg / "voidrecon" / "config.yaml"
            if user_cfg.exists():
                cfg = _deep_merge(cfg, _load_yaml(user_cfg))
        except Exception:
            pass
        if config_path:
            p = Path(config_path)
            if not p.exists():
                raise FileNotFoundError(f"Config file not found: {p}")
            cfg = _deep_merge(cfg, _load_yaml(p))
        cfg = _apply_env(cfg)
        if overrides:
            cfg = _deep_merge(cfg, overrides)
        return cls(cfg)

    def get(self, path: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    def set(self, path: str, value: Any) -> None:
        parts = path.split(".")
        node = self._data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    def section(self, name: str) -> dict:
        return self.get(name, {}) or {}

    @property
    def data(self) -> dict:
        return self._data
