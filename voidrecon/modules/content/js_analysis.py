"""JavaScript analysis — secrets and hidden endpoints.

Modern apps ship their attack surface to the browser. Bundled JavaScript is full
of API base URLs, undocumented routes, feature flags, and — far too often — live
credentials. This module collects JS referenced by discovered web assets, then
mines each file for secret patterns and endpoint strings.

Active and scope-gated: it only fetches JS from in-scope hosts and only when
``opsec.allow_active`` is set. Findings from secret patterns are always treated as
*candidates* to verify by hand — never as confirmed, exploitable credentials.
"""

from __future__ import annotations

import asyncio
import re

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net
from voidrecon.utils.text import find_secrets

_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
_ENDPOINT_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{2,120}?)["'`]""")
_URL_RE = re.compile(r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,200}""")


@register
class JsAnalysis(Module):
    name = "js_analysis"
    phase = Phase.CONTENT
    active = True
    description = "Mine JavaScript for secrets and hidden endpoints"
    depends_on = ("http_probe",)

    async def run(self, ctx: RunContext) -> None:
        js_urls = await self._collect_js_urls(ctx)
        if not js_urls:
            self.log.info("no in-scope JavaScript to analyse")
            return
        self.log.info("analysing %d JavaScript files", len(js_urls))
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        async def worker(url):
            async with sem:
                await self._analyse(ctx, url)

        await asyncio.gather(*(worker(u) for u in js_urls))

    async def _collect_js_urls(self, ctx: RunContext) -> set[str]:
        js: set[str] = set()
        # 1) Direct .js references already known (archives / endpoints).
        for asset in ctx.store.assets(kind=AssetKind.URL) + ctx.store.assets(kind=AssetKind.ENDPOINT):
            if asset.value.split("?")[0].endswith(".js"):
                host = net.host_from_url(asset.value)
                if host and ctx.can_touch(host):
                    js.add(asset.value)
        # 2) Parse <script src> from probed web pages.
        for asset in ctx.store.assets():
            page = asset.attrs.get("http_url")
            if not page or "web" not in asset.tags:
                continue
            if not ctx.can_touch(asset.value):
                continue
            html = await ctx.http.get_text(page)
            if not html:
                continue
            for m in _SCRIPT_SRC_RE.finditer(html):
                src = m.group(1)
                full = self._absolutise(page, src)
                if full and full.split("?")[0].endswith(".js"):
                    host = net.host_from_url(full)
                    if host and ctx.can_touch(host):
                        js.add(full)
        return js

    def _absolutise(self, base: str, src: str) -> str | None:
        from urllib.parse import urljoin

        try:
            return urljoin(base, src)
        except Exception:
            return None

    async def _analyse(self, ctx: RunContext, url: str) -> None:
        body = await ctx.http.get_text(url)
        if not body:
            return
        # Secrets
        secrets = find_secrets(body)
        if secrets:
            host = net.host_from_url(url)
            asset = None
            for kind in (AssetKind.SUBDOMAIN, AssetKind.DOMAIN):
                asset = ctx.store.get_asset(kind, host) if host else None
                if asset:
                    break
            if asset:
                asset.attrs["secrets_found"] = True
            labels = sorted({label for label, _ in secrets})
            ctx.add_finding(
                f"Possible secrets in JavaScript: {url}",
                module=self.name,
                severity=Severity.HIGH,
                confidence=Confidence.TENTATIVE,
                asset=host,
                description=(
                    "Secret-like strings were found in a JavaScript bundle. Verify each by "
                    "hand — many are public keys, sample values, or false positives. Never "
                    "use discovered credentials beyond confirming validity within scope."
                ),
                evidence={"url": url, "types": labels, "samples": [s for _, s in secrets][:10]},
                tags={"secret", "js"},
            )
        # Endpoints
        endpoints = set(_ENDPOINT_RE.findall(body)[:300])
        for path in endpoints:
            if len(path) > 3 and not path.startswith("//"):
                ctx.add_asset(
                    AssetKind.ENDPOINT, path, source=self.name,
                    confidence=Confidence.TENTATIVE, from_js=url,
                )
