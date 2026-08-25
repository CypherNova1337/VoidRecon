"""Historical URL harvesting from web archives.

The Wayback Machine remembers URLs, parameters, and endpoints that were removed,
renamed, or never meant to stay public — old admin panels, deprecated API
versions, parameterised endpoints ripe for testing. This module pulls the CDX
index for each seed and extracts hosts, URLs, and parameterised endpoints, all
without sending a single request to the target.
"""

from __future__ import annotations

from urllib.parse import urlparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.core.tools import run_tool
from voidrecon.utils import net

_INTERESTING_EXT = (".json", ".xml", ".config", ".bak", ".sql", ".env", ".yml",
                    ".yaml", ".zip", ".tar", ".gz", ".log", ".old", ".txt")


@register
class Wayback(Module):
    name = "wayback"
    phase = Phase.PASSIVE
    active = False
    description = "Historical URLs/endpoints from web archives (CDX)"

    async def run(self, ctx: RunContext) -> None:
        prior = self._prior_endpoints(ctx)
        for seed in ctx.scope.seeds:
            urls = await self._cdx(ctx, seed)
            if ctx.tools.first_available("gau", "waybackurls"):
                urls |= await self._tool(ctx, seed)
            self._ingest(ctx, seed, urls, prior)
            self.log.info("archives: %d unique URLs for %s", len(urls), seed)

    def _prior_endpoints(self, ctx: RunContext) -> set[str]:
        """Endpoint values recorded in this target's most recent previous run, for
        delta mode — so a repeat scan surfaces what's *new* instead of the same
        thousands of URLs every time."""
        from voidrecon.core import history
        from voidrecon.utils.text import slugify

        try:
            base = ctx.output_dir.parent
            slug = slugify(ctx.scope.seeds[0]) if ctx.scope.seeds else None
            runs = history.find_runs(base, target=slug)
            if not runs:
                return set()
            data = history.load_run(runs[-1])   # newest completed prior run
        except Exception:
            return set()
        out: set[str] = set()
        for a in data.get("store", {}).get("assets", []):
            if a.get("kind") == "endpoint":
                out.add(a.get("value", ""))
        return out

    async def _cdx(self, ctx: RunContext, apex: str) -> set[str]:
        # The archive CDX index is large and slow — give it room, and record
        # whether we actually reached it so an empty result is explainable.
        o = await ctx.http.fetch(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{apex}/*",
                "output": "text",
                "fl": "original",
                "collapse": "urlkey",
                "limit": "50000",
            },
            want="text", timeout=60.0,
        )
        urls = {line.strip() for line in (o.text or "").splitlines() if line.strip()}
        ctx.note_source("wayback", apex, o, len(urls))
        return urls

    async def _tool(self, ctx: RunContext, apex: str) -> set[str]:
        tool = ctx.tools.first_available("gau", "waybackurls")
        if not tool:
            return set()
        result = await run_tool(tool, [apex], timeout=180)
        return set(result.lines()) if result.ok else set()

    def _ingest(self, ctx: RunContext, apex: str, urls: set[str], prior: set[str]) -> None:
        hosts: set[str] = set()
        interesting = 0
        new_endpoints: list[str] = []
        for url in urls:
            parsed = urlparse(url if "://" in url else "//" + url, scheme="http")
            host = net.normalize_host(parsed.hostname or "")
            if host and net.is_subdomain_of(host, apex):
                hosts.add(host)
            # Endpoints worth flagging: parameterised or sensitive extensions.
            path = (parsed.path or "").lower()
            if parsed.query or path.endswith(_INTERESTING_EXT):
                interesting += 1
                if interesting <= 500:  # cap stored endpoints per run
                    is_new = bool(prior) and url not in prior
                    a = ctx.add_asset(
                        AssetKind.ENDPOINT, url, source=self.name,
                        confidence=Confidence.TENTATIVE,
                        has_params=bool(parsed.query),
                    )
                    if is_new:
                        new_endpoints.append(url)
                        if a is not None:
                            a.tags.add("new-since-last")
        for host in hosts:
            kind = AssetKind.DOMAIN if host == apex else AssetKind.SUBDOMAIN
            ctx.add_asset(kind, host, source=self.name, confidence=Confidence.TENTATIVE)

        # Delta mode: if we have a prior run, surface what's NEW as its own lead —
        # fresh archive endpoints are the ones worth testing first on a repeat scan.
        if prior and new_endpoints:
            self.log.info("archives: %d endpoint(s) NEW since last run for %s", len(new_endpoints), apex)
            ctx.add_finding(
                f"{len(new_endpoints)} new archived endpoint(s) since last run — {apex}",
                module=self.name, severity=Severity.LOW, confidence=Confidence.TENTATIVE,
                asset=apex,
                description=("These parameterised/sensitive endpoints appear in the web archives "
                             "but were not seen in the previous run — new surface to test first."),
                evidence={"count": len(new_endpoints), "sample": new_endpoints[:25]},
                tags={"delta", "new-endpoints"},
            )
