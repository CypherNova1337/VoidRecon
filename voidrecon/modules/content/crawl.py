"""Web crawling (extension point).

Deep crawling — following links, forms, and XHR to build a complete endpoint and
parameter map — is a large capability planned for a dedicated build-out. The
interface is defined here and wired into the CONTENT phase so it participates in
scheduling today; when a best-in-class crawler (``katana``, ``gospider``) is
installed, VoidRecon drives it now and ingests the results. The native crawler
will land in a future release.

Active and scope-gated.
"""

from __future__ import annotations

from urllib.parse import urlparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.core.tools import run_tool
from voidrecon.utils import net


@register
class Crawl(Module):
    name = "crawl"
    phase = Phase.CONTENT
    active = True
    description = "Crawl web assets for links, endpoints, and parameters"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in until the native crawler ships

    async def run(self, ctx: RunContext) -> None:
        tool = ctx.tools.first_available("katana", "gospider")
        seeds = [
            a.attrs["http_url"]
            for a in ctx.store.assets()
            if a.attrs.get("http_url") and "web" in a.tags and ctx.can_touch(a.value)
        ]
        if not seeds:
            self.log.info("no in-scope web assets to crawl")
            return
        if not tool:
            self.log.info(
                "native crawler not yet implemented; install 'katana' or 'gospider' to crawl now "
                "(%d seed URLs ready)", len(seeds)
            )
            return
        await self._crawl_with_tool(ctx, tool, seeds)

    async def _crawl_with_tool(self, ctx: RunContext, tool: str, seeds: list[str]) -> None:
        stdin = "\n".join(seeds)
        if tool == "katana":
            args = ["-silent", "-jc", "-d", "2", "-list", "-"]
            result = await run_tool("katana", args, stdin=stdin, timeout=600)
        else:  # gospider
            args = ["-q", "-d", "2", "-S", "-"]
            result = await run_tool("gospider", args, stdin=stdin, timeout=600)
        if not result.ok:
            self.log.warning("%s crawl failed", tool)
            return
        count = 0
        for line in result.lines():
            url = line.strip()
            if "://" not in url:
                continue
            host = net.host_from_url(url)
            if not host or not ctx.scope.is_related(host):
                continue
            parsed = urlparse(url)
            ctx.add_asset(
                AssetKind.ENDPOINT, url, source=self.name,
                confidence=Confidence.LIKELY, has_params=bool(parsed.query),
            )
            count += 1
        self.log.info("%s crawl added %d endpoints", tool, count)
