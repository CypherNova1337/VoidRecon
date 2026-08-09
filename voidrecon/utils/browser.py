"""Shared headless-browser helpers.

Both the screenshot module and the SPA crawler drive headless Chromium via
Playwright. This module centralises the two things that are fiddly in managed
environments: locating a usable Chromium binary when the installed Playwright's
expected build differs from what's cached on disk, and honouring proxy env vars
(Chromium does not read ``HTTPS_PROXY`` on its own).
"""

from __future__ import annotations

import glob
import os

try:
    from playwright.async_api import async_playwright  # noqa: F401

    HAS_PLAYWRIGHT = True
except Exception:  # pragma: no cover
    HAS_PLAYWRIGHT = False

LAUNCH_ARGS = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]


def find_chromium() -> str | None:
    """Locate a Chromium executable, tolerating Playwright/browser build drift."""
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


def proxy_from_env() -> dict | None:
    url = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
           or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
           or os.environ.get("ALL_PROXY") or os.environ.get("all_proxy"))
    return {"server": url} if url else None


async def launch_chromium(pw):
    """Launch headless Chromium, falling back to a cached binary on build drift.

    Returns the launched browser, or raises the original error if no browser can
    be located at all.
    """
    proxy = proxy_from_env()
    try:
        return await pw.chromium.launch(headless=True, args=LAUNCH_ARGS, proxy=proxy)
    except Exception:
        exe = find_chromium()
        if not exe:
            raise
        return await pw.chromium.launch(headless=True, args=LAUNCH_ARGS, proxy=proxy, executable_path=exe)
