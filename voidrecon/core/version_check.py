"""Lightweight "is a newer version available?" check.

Fetches the version declared on the project's default branch and compares it to
what's running. It only *notifies* — it never updates on its own. The result is
cached for a day so it costs nothing on repeat runs, the network call is
best-effort with a short timeout, and it can be disabled with ``--no-update-check``
or ``VOIDRECON_NO_UPDATE_CHECK=1``.
"""

from __future__ import annotations

import json
import os
import re
import time

from voidrecon.core.paths import user_data_dir
from voidrecon.utils.versions import is_newer
from voidrecon.version import __version__

_REPO = "CypherNova1337/VoidRecon"
# Branch that carries releases. Override with VOIDRECON_UPDATE_BRANCH if needed.
DEFAULT_BRANCH = "main"


def update_branch() -> str:
    return os.environ.get("VOIDRECON_UPDATE_BRANCH", DEFAULT_BRANCH)


def _raw_version_url() -> str:
    return f"https://raw.githubusercontent.com/{_REPO}/{update_branch()}/voidrecon/version.py"


_CACHE_TTL = 86400  # 24h
_VER_RE = re.compile(r'__version__\s*=\s*["\']([0-9]+(?:\.[0-9]+)*)["\']')


def _cache_file():
    return user_data_dir() / "version_check.json"


def _read_cache() -> dict | None:
    try:
        data = json.loads(_cache_file().read_text(encoding="utf-8"))
        if time.time() - data.get("ts", 0) < _CACHE_TTL:
            return data
    except Exception:
        pass
    return None


def _write_cache(latest: str) -> None:
    try:
        _cache_file().write_text(json.dumps({"latest": latest, "ts": time.time()}), encoding="utf-8")
    except Exception:
        pass


def fetch_latest(timeout: float = 3.0) -> str | None:
    """Return the latest published version string, or None (best-effort, cached)."""
    cached = _read_cache()
    if cached:
        return cached.get("latest")
    try:
        import httpx

        resp = httpx.get(_raw_version_url(), timeout=timeout, follow_redirects=True)
        if resp.status_code == 200:
            m = _VER_RE.search(resp.text)
            if m:
                _write_cache(m.group(1))
                return m.group(1)
    except Exception:
        pass
    return None


def check(current: str = __version__) -> str | None:
    """Return the newer version string if an update is available, else None."""
    if os.environ.get("VOIDRECON_NO_UPDATE_CHECK"):
        return None
    latest = fetch_latest()
    if latest and is_newer(latest, current):
        return latest
    return None
