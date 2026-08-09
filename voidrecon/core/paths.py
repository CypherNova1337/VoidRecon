"""User-writable paths for VoidRecon (config, cached datasets)."""

from __future__ import annotations

import os
from pathlib import Path


def user_data_dir() -> Path:
    """Return VoidRecon's per-user data directory, creating it if needed."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    path = Path(base) / "voidrecon"
    path.mkdir(parents=True, exist_ok=True)
    return path


def user_cve_dataset() -> Path:
    """Path to the user's (auto-refreshed) CVE signature dataset override."""
    return user_data_dir() / "cve_signatures.json"
