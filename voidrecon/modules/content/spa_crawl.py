"""SPA-aware crawling via headless Chromium.

Single-page apps build their real attack surface at runtime: the endpoints an app
actually calls live in XHR/fetch traffic and dynamically injected scripts, not in
the initial HTML the static crawler sees. This module loads each in-scope web
origin in headless Chromium, records every network request the page makes, and
harvests the same-scope endpoints (with their query parameters) from that live
traffic.

Requires Playwright (``pip install -e ".[screenshots]"``). Active, scope-gated,
and opt-in. Falls back silently when no browser backend is present.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net
from voidrecon.utils.browser import HAS_PLAYWRIGHT, launch_chromium

if HAS_PLAYWRIGHT:
    from playwright.async_api import async_playwright  # type: ignore


@register
class SpaCrawl(Module):
    name = "spa_crawl"
    phase = Phase.CONTENT
    active = True
    description = "Headless-browser crawl capturing XHR/fetch endpoints (SPA-aware)"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in: drives a real browser, heavier

    async def run(self, ctx: RunContext) -> None:
        if not HAS_PLAYWRIGHT:
            self.log.info("Playwright not installed — skipping SPA crawl (pip install playwright)")
            return
        origins = self._origins(ctx)
        if not origins:
            self.log.info("no in-scope web origins for SPA crawl")
            return
        max_origins = int(ctx.config.get("modules.spa_crawl.max_origins", 40))
        origins = origins[:max_origins]

        timeout = float(ctx.config.get("opsec.timeout", 20.0)) * 1000
        endpoints = 0
        async with async_playwright() as pw:
            try:
                browser = await launch_chromium(pw)
            except Exception as exc:  # noqa: BLE001
                self.log.warning("could not launch Chromium: %s", exc)
                return
            sem = asyncio.Semaphore(min(int(ctx.config.get("opsec.max_concurrency", 20)), 5))

            async def visit(origin):
                nonlocal endpoints
                async with sem:
                    endpoints += await self._visit(ctx, browser, origin, timeout)

            await asyncio.gather(*(visit(o) for o in origins))
            await browser.close()
        self.log.info("SPA crawl over %d origins; +%d live endpoints", len(origins), endpoints)

    def _origins(self, ctx: RunContext) -> list[str]:
        seen, out = set(), []
        for a in ctx.store.assets():
            url = a.attrs.get("http_url")
            if not url or "web" not in a.tags or not ctx.can_touch(a.value):
                continue
            p = urlparse(url)
            origin = f"{p.scheme}://{p.netloc}"
            if origin not in seen:
                seen.add(origin)
                out.append(url)
        return out

    async def _visit(self, ctx: RunContext, browser, url: str, timeout: float) -> int:
        captured: set[str] = set()
        context = await browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=ctx.auth_headers or None,
        )
        page = await context.new_page()

        def on_request(request):
            try:
                captured.add(request.url)
            except Exception:
                pass

        page.on("request", on_request)
        try:
            await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            # Give XHR/fetch a moment to fire.
            try:
                await page.wait_for_load_state("networkidle", timeout=min(timeout, 8000))
            except Exception:
                pass
        except Exception as exc:  # noqa: BLE001
            self.log.debug("spa_crawl navigation failed for %s: %s", url, exc)
        finally:
            await context.close()

        added = 0
        for req_url in captured:
            host = net.host_from_url(req_url)
            if not host or not ctx.scope.is_related(host):
                continue
            parsed = urlparse(req_url)
            if parsed.scheme not in ("http", "https"):
                continue
            asset = ctx.add_asset(
                AssetKind.ENDPOINT, req_url, source=self.name,
                confidence=Confidence.CONFIRMED, has_params=bool(parsed.query), via="xhr",
            )
            if asset:
                added += 1
        return added
