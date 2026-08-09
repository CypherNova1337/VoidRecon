"""RunContext — the shared state handed to every module.

A single :class:`RunContext` is created per engagement. It carries the config,
the scope engine, the datastore, a shared HTTP client, the external-tool
registry, and helpers to emit assets/findings with automatic scope tagging.
Modules never construct their own HTTP client or touch the store directly for
scope decisions — they go through the context so policy is enforced in one place.
"""

from __future__ import annotations

import time
from pathlib import Path

from voidrecon.core.config import Config
from voidrecon.core.http import HttpClient
from voidrecon.core.logging import get_logger
from voidrecon.core.models import Asset, AssetKind, Confidence, Finding, ScopeState
from voidrecon.core.scope import Scope
from voidrecon.core.store import DataStore
from voidrecon.core.tools import ToolRegistry
from voidrecon.utils import net
from voidrecon.utils.text import slugify


class RunContext:
    def __init__(self, config: Config, scope: Scope, *, run_id: str | None = None):
        self.config = config
        self.scope = scope
        self.store = DataStore()
        self.tools = ToolRegistry()
        self.log = get_logger("engine")
        self.started_at = time.time()
        self.run_id = run_id or self._make_run_id()
        self.output_dir = Path(config.get("general.output_dir", "runs")) / self.run_id
        self._http: HttpClient | None = None

    def _make_run_id(self) -> str:
        seed = self.scope.seeds[0] if self.scope.seeds else "target"
        return f"{slugify(seed)}-{time.strftime('%Y%m%d-%H%M%S')}"

    # ---- shared services --------------------------------------------------
    @property
    def http(self) -> HttpClient:
        if self._http is None:
            opsec = self.config.section("opsec")
            httpc = self.config.section("http")
            self._http = HttpClient(
                user_agent=self.config.get("general.user_agent", "VoidRecon/0.1"),
                rate=float(opsec.get("requests_per_second", 8.0)),
                jitter=float(opsec.get("jitter", 0.0)),
                concurrency=int(opsec.get("max_concurrency", 20)),
                timeout=float(opsec.get("timeout", 20.0)),
                retries=int(opsec.get("retries", 2)),
                verify_tls=bool(httpc.get("verify_tls", True)),
                follow_redirects=bool(httpc.get("follow_redirects", True)),
                max_redirects=int(httpc.get("max_redirects", 5)),
                rotate_user_agents=bool(opsec.get("rotate_user_agents", True)),
            )
        return self._http

    @property
    def active_allowed(self) -> bool:
        return bool(self.config.get("opsec.allow_active", False))

    def can_touch(self, value: str) -> bool:
        """True only if active mode is on AND the asset is positively in scope."""
        if not self.active_allowed:
            return False
        return self.scope.allows_active(value)

    def source_key(self, name: str) -> str | None:
        return self.config.get(f"sources.{name}")

    # ---- emitting results (with scope tagging) ----------------------------
    def add_asset(
        self,
        kind: AssetKind,
        value: str,
        *,
        source: str,
        confidence: Confidence = Confidence.LIKELY,
        tags: set[str] | None = None,
        **attrs,
    ) -> Asset | None:
        value = value.strip()
        if not value:
            return None
        if kind in (AssetKind.DOMAIN, AssetKind.SUBDOMAIN, AssetKind.URL, AssetKind.ENDPOINT):
            host = net.normalize_host(value) if kind != AssetKind.URL else (net.host_from_url(value) or value)
            scope_state = self.scope.classify_host(host)
        elif kind in (AssetKind.IP,):
            scope_state = self.scope.classify_ip(value)
        else:
            scope_state = ScopeState.UNKNOWN

        asset = Asset(
            kind=kind,
            value=value,
            sources={source},
            tags=tags or set(),
            attrs=dict(attrs),
            scope_state=scope_state,
            confidence=confidence,
        )
        if scope_state == ScopeState.OUT_OF_SCOPE:
            asset.tags.add("out_of_scope")
        return self.store.add_asset(asset)

    def add_finding(
        self,
        title: str,
        *,
        module: str,
        severity=None,
        asset: str | None = None,
        description: str = "",
        confidence: Confidence = Confidence.LIKELY,
        evidence: dict | None = None,
        references: list[str] | None = None,
        tags: set[str] | None = None,
    ) -> Finding:
        from voidrecon.core.models import Severity

        finding = Finding(
            title=title,
            severity=severity or Severity.INFO,
            confidence=confidence,
            asset=asset,
            module=module,
            description=description,
            evidence=evidence or {},
            references=references or [],
            tags=tags or set(),
        )
        return self.store.add_finding(finding)

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
