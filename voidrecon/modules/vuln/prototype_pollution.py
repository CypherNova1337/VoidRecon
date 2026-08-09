"""Client-side prototype-pollution detection.

Loads each in-scope web page in a real browser with a ``__proto__[...]`` payload
in the query string and hash, then checks whether ``Object.prototype`` actually
got polluted. Because it uses a live JS engine, a positive is a genuine confirmed
client-side prototype-pollution sink — not a guess. Requires Playwright; active,
scope-gated, opt-in.
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import Confidence, Severity
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils.browser import HAS_PLAYWRIGHT, launch_chromium

if HAS_PLAYWRIGHT:
    from playwright.async_api import async_playwright  # type: ignore

_MARKER = "vrpp"
_PAYLOADS = [
    "__proto__[{m}]=polluted",
    "__proto__.{m}=polluted",
    "constructor[prototype][{m}]=polluted",
]


@register
class PrototypePollution(Module):
    name = "prototype_pollution"
    phase = Phase.VULN
    active = True
    description = "Detect client-side prototype pollution in a real browser"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in; needs a browser

    async def run(self, ctx: RunContext) -> None:
        if not HAS_PLAYWRIGHT:
            self.log.info("Playwright not installed — skipping prototype-pollution check")
            return
        origins = []
        seen = set()
        for a in ctx.store.assets():
            u = a.attrs.get("http_url")
            if u and "web" in a.tags and ctx.can_touch(a.value) and u not in seen:
                seen.add(u)
                origins.append(u)
        if not origins:
            self.log.info("no in-scope web assets for prototype-pollution testing")
            return
        cap = int(ctx.config.get("modules.prototype_pollution.max_targets", 40))
        origins = origins[:cap]
        timeout = float(ctx.config.get("opsec.timeout", 20.0)) * 1000
        found = 0
        async with async_playwright() as pw:
            try:
                browser = await launch_chromium(pw)
            except Exception as exc:  # noqa: BLE001
                self.log.warning("could not launch Chromium: %s", exc)
                return
            sem = asyncio.Semaphore(min(int(ctx.config.get("opsec.max_concurrency", 20)), 5))

            async def worker(url):
                nonlocal found
                async with sem:
                    if await self._test(ctx, browser, url, timeout):
                        found += 1

            await asyncio.gather(*(worker(u) for u in origins))
            await browser.close()
        self.log.info("prototype-pollution testing complete: %d confirmed", found)

    async def _test(self, ctx: RunContext, browser, url: str, timeout: float) -> bool:
        for payload in _PAYLOADS:
            frag = payload.format(m=_MARKER)
            sep = "&" if "?" in url else "?"
            target = f"{url}{sep}{frag}#{frag}"
            context = await browser.new_context(ignore_https_errors=True,
                                                extra_http_headers=ctx.auth_headers or None)
            page = await context.new_page()
            try:
                await page.goto(target, timeout=timeout, wait_until="domcontentloaded")
                try:
                    await page.wait_for_load_state("networkidle", timeout=min(timeout, 6000))
                except Exception:
                    pass
                polluted = await page.evaluate(f"() => window.Object.prototype.{_MARKER} || null")
            except Exception:
                polluted = None
            finally:
                await context.close()
            if polluted == "polluted":
                ctx.add_finding(
                    f"Client-side prototype pollution: {url}",
                    module=self.name, severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                    asset=url,
                    description=("A __proto__ payload in the URL polluted Object.prototype in the browser. "
                                 "Depending on gadgets present this can escalate to DOM XSS or logic abuse."),
                    evidence={"url": target, "payload": frag}, tags={"prototype-pollution", "xss"},
                )
                return True
        return False
