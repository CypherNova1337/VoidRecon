"""Screenshotting and visual triage.

A wall of screenshots is how an operator triages hundreds of hosts in minutes —
login portals, default install pages, error screens, and abandoned apps announce
themselves visually far faster than by status code. This module renders each live
in-scope web asset to a PNG and records the path on the asset so the HTML report
can build a visual gallery.

Uses Playwright (headless Chromium) when the Python package is available, or the
``gowitness`` binary as a fallback. Active and scope-gated; skips cleanly if
neither backend is present.
"""

from __future__ import annotations

import asyncio
import glob
import os

from voidrecon.core.context import RunContext
from voidrecon.core.module import Module, Phase, register
from voidrecon.core.tools import run_tool
from voidrecon.utils.text import slugify


def _find_chromium() -> str | None:
    """Locate a Chromium executable, tolerating Playwright version/browser drift.

    Managed environments often ship a cached browser whose build number differs
    from the installed Playwright package. When the default launch can't find its
    expected binary we fall back to whatever Chromium is on disk.
    """
    explicit = os.environ.get("VOIDRECON_CHROMIUM") or os.environ.get("CHROMIUM_PATH")
    if explicit and os.path.exists(explicit):
        return explicit
    roots = [os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers"), "/opt/pw-browsers"]
    patterns = ["chromium-*/chrome-linux/chrome", "chromium_headless_shell-*/chrome-linux/headless_shell"]
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for pat in patterns:
            hits = sorted(glob.glob(os.path.join(root, pat)))
            if hits:
                return hits[-1]
    return None

try:
    from playwright.async_api import async_playwright  # type: ignore

    _HAS_PLAYWRIGHT = True
except Exception:  # pragma: no cover
    _HAS_PLAYWRIGHT = False


@register
class Screenshot(Module):
    name = "screenshot"
    phase = Phase.CONTENT
    active = True
    description = "Capture screenshots of live web assets for visual triage"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in: needs a browser and is slower

    async def run(self, ctx: RunContext) -> None:
        targets = [
            a for a in ctx.store.assets()
            if a.attrs.get("http_url") and "web" in a.tags and ctx.can_touch(a.value)
        ]
        if not targets:
            self.log.info("no in-scope web assets to screenshot")
            return

        outdir = ctx.output_dir / "screenshots"
        outdir.mkdir(parents=True, exist_ok=True)

        if _HAS_PLAYWRIGHT:
            await self._with_playwright(ctx, targets, outdir)
        elif ctx.tools.has("gowitness"):
            await self._with_gowitness(ctx, targets, outdir)
        else:
            self.log.info(
                "no screenshot backend available — `pip install playwright` "
                "or install the `gowitness` binary to enable visual triage"
            )

    async def _with_playwright(self, ctx: RunContext, targets, outdir) -> None:
        timeout = float(ctx.config.get("opsec.timeout", 20.0)) * 1000
        captured = 0
        # Honour standard proxy env vars so screenshots work behind a corporate
        # proxy (Chromium does not read these automatically).
        proxy_url = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
                     or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
                     or os.environ.get("ALL_PROXY") or os.environ.get("all_proxy"))
        proxy = {"server": proxy_url} if proxy_url else None
        launch_args = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(headless=True, args=launch_args, proxy=proxy)
            except Exception as exc:  # noqa: BLE001 - browser build drift
                exe = _find_chromium()
                if not exe:
                    self.log.warning("could not launch Chromium and none found on disk: %s", exc)
                    return
                self.log.info("using cached Chromium at %s", exe)
                browser = await pw.chromium.launch(
                    headless=True, args=launch_args, executable_path=exe, proxy=proxy
                )
            sem = asyncio.Semaphore(min(int(ctx.config.get("opsec.max_concurrency", 20)), 6))

            async def shoot(asset):
                nonlocal captured
                async with sem:
                    url = asset.attrs["http_url"]
                    path = outdir / f"{slugify(asset.value)}.png"
                    context = await browser.new_context(ignore_https_errors=True)
                    page = await context.new_page()
                    try:
                        await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
                        await page.screenshot(path=str(path), full_page=False)
                        asset.attrs["screenshot"] = str(path.relative_to(ctx.output_dir))
                        captured += 1
                    except Exception as exc:  # noqa: BLE001
                        self.log.debug("screenshot failed for %s: %s", url, exc)
                    finally:
                        await context.close()

            await asyncio.gather(*(shoot(a) for a in targets))
            await browser.close()
        self.log.info("captured %d screenshots (playwright) -> %s", captured, outdir)

    async def _with_gowitness(self, ctx: RunContext, targets, outdir) -> None:
        urls = "\n".join(a.attrs["http_url"] for a in targets)
        result = await run_tool(
            "gowitness",
            ["scan", "file", "-f", "-", "--screenshot-path", str(outdir)],
            stdin=urls,
            timeout=900,
        )
        if result.ok:
            self.log.info("gowitness screenshots written to %s", outdir)
        else:
            self.log.warning("gowitness failed: %s", result.stderr[:200])
