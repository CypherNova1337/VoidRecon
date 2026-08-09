"""Bug-bounty program scope import.

Turns a program URL into structured scope so you don't hand-copy asset lists.
The reliable path is the platform's own API (HackerOne today, via credentials in
the environment); without credentials VoidRecon falls back to best-effort parsing
of whatever the URL returns (a HackerOne-style ``structured_scopes`` JSON, a
generic ``{"include": [...], "exclude": [...]}`` document, or a plain list of
hosts). When it can't extract scope it says so and points you at ``--scope-file``.

Nothing here probes the target — it only reads the program's own scope
definition, and it never widens scope silently: results are reported so the
operator sees exactly what was imported.

Credentials (optional, HackerOne):
    VOIDRECON_SOURCES_HACKERONE_USERNAME
    VOIDRECON_SOURCES_HACKERONE_TOKEN
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from voidrecon.core.logging import get_logger

log = get_logger("program")

# HackerOne asset types we treat as web/host scope.
_H1_HOST_TYPES = {"URL", "WILDCARD", "DOMAIN"}
_H1_NET_TYPES = {"CIDR", "IP_ADDRESS"}


@dataclass
class ImportedScope:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    platform: str = "unknown"
    handle: str | None = None
    note: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.include or self.exclude)


def detect_platform(url: str) -> tuple[str, str | None]:
    host = (urlparse(url).hostname or "").lower()
    path = urlparse(url).path.strip("/")
    handle = path.split("/")[0] if path else None
    if "hackerone.com" in host:
        return "hackerone", handle
    if "bugcrowd.com" in host:
        return "bugcrowd", handle
    if "intigriti.com" in host:
        return "intigriti", handle
    if "yeswehack.com" in host:
        return "yeswehack", handle
    return "generic", handle


async def import_program_scope(url: str, *, timeout: float = 20.0) -> ImportedScope:
    platform, handle = detect_platform(url)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                 headers={"Accept": "application/json"}) as client:
        if platform == "hackerone" and handle:
            scope = await _hackerone(client, handle)
            if scope.ok:
                return scope
        return await _generic(client, url, platform, handle)


async def _hackerone(client: httpx.AsyncClient, handle: str) -> ImportedScope:
    scope = ImportedScope(platform="hackerone", handle=handle)
    user = os.environ.get("VOIDRECON_SOURCES_HACKERONE_USERNAME")
    token = os.environ.get("VOIDRECON_SOURCES_HACKERONE_TOKEN")
    if not (user and token):
        scope.note = ("HackerOne API needs VOIDRECON_SOURCES_HACKERONE_USERNAME + "
                      "VOIDRECON_SOURCES_HACKERONE_TOKEN for reliable scope import")
        return scope
    url = f"https://api.hackerone.com/v1/hackers/programs/{handle}/structured_scopes"
    page = url
    try:
        while page:
            resp = await client.get(page, auth=(user, token),
                                    headers={"Accept": "application/json"})
            if resp.status_code != 200:
                scope.note = f"HackerOne API returned {resp.status_code}"
                return scope
            data = resp.json()
            for row in data.get("data", []):
                _apply_h1_row(scope, row.get("attributes", {}))
            page = (data.get("links") or {}).get("next")
    except Exception as exc:  # noqa: BLE001
        scope.note = f"HackerOne API error: {exc}"
    return scope


def _apply_h1_row(scope: ImportedScope, attrs: dict) -> None:
    ident = (attrs.get("asset_identifier") or "").strip()
    atype = (attrs.get("asset_type") or "").upper()
    if not ident:
        return
    if atype not in _H1_HOST_TYPES | _H1_NET_TYPES:
        return
    if attrs.get("eligible_for_submission", True):
        scope.include.append(ident)
    else:
        scope.exclude.append(ident)


async def _generic(client: httpx.AsyncClient, url: str, platform: str, handle: str | None) -> ImportedScope:
    """Best-effort: parse whatever the URL returns."""
    scope = ImportedScope(platform=platform, handle=handle)
    try:
        resp = await client.get(url)
    except Exception as exc:  # noqa: BLE001
        scope.note = f"could not fetch program URL: {exc}"
        return scope
    if resp.status_code != 200:
        scope.note = f"program URL returned {resp.status_code}"
        return scope

    text = resp.text
    # 1) JSON documents.
    try:
        data = resp.json()
        _parse_json_scope(scope, data)
        if scope.ok:
            return scope
    except Exception:
        pass

    # 2) Plain host list (one per line).
    hosts = []
    for line in text.splitlines():
        line = line.strip()
        if re.fullmatch(r"[*.]?[A-Za-z0-9.\-*]+\.[A-Za-z]{2,}", line):
            hosts.append(line)
    if hosts:
        scope.include = hosts
        scope.note = "parsed plain host list from URL"
        return scope

    scope.note = ("could not extract structured scope automatically — "
                  "use --scope-file with the program's in/out-of-scope entries")
    return scope


def _parse_json_scope(scope: ImportedScope, data) -> None:
    if isinstance(data, dict) and ("include" in data or "exclude" in data):
        scope.include = list(data.get("include", []))
        scope.exclude = list(data.get("exclude", []))
        scope.note = "parsed include/exclude JSON"
        return
    # HackerOne-style structured_scopes embedded/exported as JSON.
    rows = data.get("data") if isinstance(data, dict) else (data if isinstance(data, list) else None)
    if isinstance(rows, list):
        for row in rows:
            attrs = row.get("attributes", row) if isinstance(row, dict) else {}
            _apply_h1_row(scope, attrs)
        if scope.ok:
            scope.note = "parsed structured_scopes JSON"
