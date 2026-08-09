"""Web crawling — native BFS crawler with form & parameter mapping.

Builds an endpoint and parameter map the way an attacker enumerates an app:
breadth-first from every live in-scope page, following same-scope links, and
harvesting the things that become test cases — query parameters, form actions and
their input names, and paths disclosed by ``robots.txt`` / ``sitemap.xml`` (which
operators read precisely because they list the paths someone wanted hidden).

When ``katana`` or ``gospider`` is installed it is used for speed and JS-aware
crawling; otherwise the native crawler runs. Active and scope-gated throughout.
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from urllib.parse import urljoin, urlparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.core.tools import run_tool
from voidrecon.utils import net

_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#\s]+)["']""", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_METHOD_RE = re.compile(r"""method\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r"""<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)

_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css",
             ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".pdf", ".zip")


@register
class Crawl(Module):
    name = "crawl"
    phase = Phase.CONTENT
    active = True
    description = "Crawl web assets for links, endpoints, forms, and parameters"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in: crawling is chattier than probing

    async def run(self, ctx: RunContext) -> None:
        seeds = [
            a.attrs["http_url"]
            for a in ctx.store.assets()
            if a.attrs.get("http_url") and "web" in a.tags and ctx.can_touch(a.value)
        ]
        if not seeds:
            self.log.info("no in-scope web assets to crawl")
            return

        tool = ctx.tools.first_available("katana", "gospider")
        if tool:
            await self._crawl_with_tool(ctx, tool, seeds)
            return

        await self._native_crawl(ctx, seeds)

    # ---- native crawler ---------------------------------------------------
    async def _native_crawl(self, ctx: RunContext, seeds: list[str]) -> None:
        aggressive = bool(ctx.config.get("opsec.aggressive"))
        max_depth = int(ctx.config.get("modules.crawl.depth", 3 if aggressive else 2))
        max_pages = int(ctx.config.get("modules.crawl.max_pages", 600 if aggressive else 250))

        seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque()
        for s in seeds:
            queue.append((s, 0))
            seen.add(s.split("#")[0])
        # Seed robots/sitemap for each distinct host.
        await self._seed_robots_sitemap(ctx, seeds, queue, seen)

        endpoints = 0
        forms = 0
        pages = 0
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        while queue and pages < max_pages:
            batch = [queue.popleft() for _ in range(min(len(queue), 25))]

            async def fetch(url_depth):
                url, depth = url_depth
                async with sem:
                    return url, depth, await ctx.http.get_text(url)

            for url, depth, html in await asyncio.gather(*(fetch(ud) for ud in batch)):
                pages += 1
                if not html:
                    continue
                e, f = self._extract(ctx, url, html, depth, max_depth, seen, queue)
                endpoints += e
                forms += f
                if pages >= max_pages:
                    break

        self.log.info("native crawl: %d pages, +%d endpoints, +%d forms", pages, endpoints, forms)

    async def _seed_robots_sitemap(self, ctx, seeds, queue, seen) -> None:
        hosts = {f"{urlparse(s).scheme}://{urlparse(s).netloc}" for s in seeds}
        for origin in hosts:
            robots = await ctx.http.get_text(urljoin(origin, "/robots.txt"))
            if robots:
                for line in robots.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            full = urljoin(origin, path.split("*")[0])
                            self._maybe_queue(ctx, full, 1, seen, queue)
                    elif line.lower().startswith("sitemap:"):
                        sm = line.split(":", 1)[1].strip()
                        await self._ingest_sitemap(ctx, sm, seen, queue)
            await self._ingest_sitemap(ctx, urljoin(origin, "/sitemap.xml"), seen, queue)

    async def _ingest_sitemap(self, ctx, url, seen, queue) -> None:
        xml = await ctx.http.get_text(url)
        if not xml:
            return
        for loc in _SITEMAP_LOC_RE.findall(xml)[:2000]:
            loc = loc.strip()
            if loc.endswith(".xml"):  # nested sitemap
                continue
            self._maybe_queue(ctx, loc, 1, seen, queue)

    def _extract(self, ctx, base, html, depth, max_depth, seen, queue) -> tuple[int, int]:
        endpoints = 0
        forms = 0
        # Links
        for m in _LINK_RE.finditer(html):
            raw = m.group(1)
            if raw.startswith(("mailto:", "javascript:", "tel:", "data:")):
                continue
            full = urljoin(base, raw)
            host = net.host_from_url(full)
            if not host or not ctx.scope.is_related(host):
                continue
            parsed = urlparse(full)
            if parsed.query:
                ctx.add_asset(AssetKind.ENDPOINT, full, source=self.name,
                              confidence=Confidence.LIKELY, has_params=True)
                endpoints += 1
            if depth < max_depth and not full.lower().split("?")[0].endswith(_SKIP_EXT):
                if ctx.can_touch(host):
                    self._maybe_queue(ctx, full, depth + 1, seen, queue)
        # Forms
        for fm in _FORM_RE.finditer(html):
            block = fm.group(0)
            action = _ACTION_RE.search(block)
            method = _METHOD_RE.search(block)
            inputs = _INPUT_NAME_RE.findall(block)
            action_url = urljoin(base, action.group(1)) if action and action.group(1) else base
            host = net.host_from_url(action_url)
            if not host or not ctx.scope.is_related(host):
                continue
            ctx.add_asset(
                AssetKind.ENDPOINT, action_url, source=self.name, confidence=Confidence.LIKELY,
                is_form=True, method=(method.group(1).upper() if method else "GET"),
                params=sorted(set(inputs)),
            )
            forms += 1
        return endpoints, forms

    def _maybe_queue(self, ctx, url, depth, seen, queue) -> None:
        key = url.split("#")[0]
        if key in seen:
            return
        host = net.host_from_url(url)
        if not host or not ctx.can_touch(host):
            return
        seen.add(key)
        queue.append((url, depth))

    # ---- external tool ----------------------------------------------------
    async def _crawl_with_tool(self, ctx: RunContext, tool: str, seeds: list[str]) -> None:
        stdin = "\n".join(seeds)
        depth = "3" if ctx.config.get("opsec.aggressive") else "2"
        if tool == "katana":
            args = ["-silent", "-jc", "-d", depth, "-list", "-"]
            result = await run_tool("katana", args, stdin=stdin, timeout=600)
        else:  # gospider
            args = ["-q", "-d", depth, "-S", "-"]
            result = await run_tool("gospider", args, stdin=stdin, timeout=600)
        if not result.ok:
            self.log.warning("%s crawl failed; falling back to native crawler", tool)
            await self._native_crawl(ctx, seeds)
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
            ctx.add_asset(AssetKind.ENDPOINT, url, source=self.name,
                          confidence=Confidence.LIKELY, has_params=bool(parsed.query))
            count += 1
        self.log.info("%s crawl added %d endpoints", tool, count)
