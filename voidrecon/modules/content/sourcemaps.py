"""JavaScript source-map extraction.

When a site ships ``.map`` files (or references them via ``sourceMappingURL``),
the original, un-minified source — file tree, internal module paths, comments,
and sometimes secrets — is recoverable. This module locates source maps for
discovered JavaScript, parses the ``sources``/``sourcesContent`` fields, and
surfaces the disclosed paths and any secrets. Uses the ``sourcemapper`` binary
when installed. Active and scope-gated.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net
from voidrecon.utils.text import find_secrets

_SM_URL_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")


@register
class SourceMaps(Module):
    name = "sourcemaps"
    phase = Phase.CONTENT
    active = True
    description = "Recover source from exposed JavaScript source maps (.map)"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in

    async def run(self, ctx: RunContext) -> None:
        js_urls = await self._collect_js(ctx)
        if not js_urls:
            self.log.info("no in-scope JavaScript for source-map extraction")
            return
        self.log.info("checking %d JS files for source maps", len(js_urls))
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        found = 0

        async def worker(url):
            nonlocal found
            async with sem:
                found += await self._process(ctx, url)

        await asyncio.gather(*(worker(u) for u in js_urls))
        self.log.info("recovered %d source map(s)", found)

    async def _collect_js(self, ctx: RunContext) -> set[str]:
        js: set[str] = set()
        for asset in ctx.store.assets(kind=AssetKind.URL) + ctx.store.assets(kind=AssetKind.ENDPOINT):
            u = asset.value.split("?")[0]
            if u.endswith(".js"):
                host = net.host_from_url(asset.value)
                if host and ctx.can_touch(host):
                    js.add(asset.value)
        return js

    async def _process(self, ctx: RunContext, js_url: str) -> int:
        # 1) explicit sourceMappingURL comment; 2) conventional <js>.map
        map_url = js_url + ".map"
        body = await ctx.http.get_text(js_url)
        if body:
            m = _SM_URL_RE.search(body[-2000:])
            if m and not m.group(1).startswith("data:"):
                map_url = urljoin(js_url, m.group(1))
        host = net.host_from_url(map_url)
        if not host or not ctx.can_touch(host):
            return 0
        data = await ctx.http.get_json(map_url)
        if not isinstance(data, dict) or "sources" not in data:
            return 0
        sources = [s for s in data.get("sources", []) if isinstance(s, str)]
        contents = data.get("sourcesContent") or []
        # Record disclosed source paths as endpoints/structure.
        for src in sources[:300]:
            clean = src.replace("webpack://", "").lstrip("./")
            if clean and not clean.startswith(("node_modules", "..")):
                ctx.add_asset(AssetKind.ENDPOINT, f"{urlparse(map_url).scheme}://{host}/{clean.lstrip('/')}",
                              source=self.name, confidence=Confidence.TENTATIVE, from_sourcemap=map_url)
        # Mine the recovered source for secrets.
        secrets = []
        for blob in contents:
            if isinstance(blob, str):
                secrets.extend(find_secrets(blob))
        sev = Severity.HIGH if secrets else Severity.MEDIUM
        ctx.add_finding(
            f"Exposed source map: {map_url}",
            module=self.name, severity=sev, confidence=Confidence.CONFIRMED, asset=host,
            description=("A JavaScript source map is publicly reachable, disclosing original source "
                         "(file structure, internal paths"
                         + (", and secret-like strings" if secrets else "") + "). Review it."),
            evidence={"map": map_url, "source_files": len(sources),
                      "secret_types": sorted({s[0] for s in secrets})[:10]},
            tags={"sourcemap", "exposure"},
        )
        return 1
