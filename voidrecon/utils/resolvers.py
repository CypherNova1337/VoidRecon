"""Trusted DNS resolver list loading.

Using a curated set of fast, reliable public resolvers (rather than whatever the
host is configured with) makes resolution and brute-forcing both faster and more
consistent. The default list is bundled (sourced from CypherNova1337/dns-helix);
override with ``dns.resolvers`` in config (a path or an inline list).
"""

from __future__ import annotations

import os

try:
    from importlib.resources import files as _res_files
except Exception:  # pragma: no cover
    _res_files = None

_CACHE: list[str] | None = None


def load_resolvers(config=None) -> list[str]:
    """Return resolver IPs from config override or the bundled list."""
    if config is not None:
        override = config.get("dns.resolvers")
        if isinstance(override, list) and override:
            return [str(x).strip() for x in override if str(x).strip()]
        if isinstance(override, str) and os.path.exists(override):
            with open(override, encoding="utf-8") as fh:
                return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    resolvers: list[str] = []
    if _res_files is not None:
        try:
            raw = _res_files("voidrecon.data").joinpath("resolvers.txt").read_text(encoding="utf-8")
            resolvers = [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.startswith("#")]
        except Exception:
            resolvers = []
    _CACHE = resolvers
    return resolvers


def apply_resolvers(resolver, config=None) -> None:
    """Point a dnspython resolver at the trusted list (best-effort)."""
    ips = load_resolvers(config)
    if ips:
        try:
            resolver.nameservers = ips
        except Exception:
            pass
