"""Authenticated login automation.

Drives a headless browser through a login form once, at the start of a run, and
captures the resulting session cookies. Those cookies are injected into the HTTP
client (and the browser modules), so the crawler, fuzzer, parameter discovery,
and analysis all operate as an authenticated user — which is where the highest-
impact bugs (IDOR, broken access control, privileged functionality) live.

Because it just navigates and submits a form, it also handles many OAuth-backed
logins: whatever cookies the flow ends up setting are captured. Configure via the
``auth.login`` section or the ``--login-*`` flags.
"""

from __future__ import annotations

from voidrecon.core.logging import get_logger
from voidrecon.utils.browser import HAS_PLAYWRIGHT, launch_chromium

log = get_logger("login")

_USER_SELECTORS = ["input[name=username]", "input[name=email]", "input[type=email]",
                   "input[name=user]", "input[name=login]", "#username", "#email", "#user"]
_PASS_SELECTORS = ["input[type=password]", "input[name=password]", "#password", "#pass"]
_SUBMIT_SELECTORS = ["button[type=submit]", "input[type=submit]", "button[name=login]",
                     "button:has-text('Log in')", "button:has-text('Sign in')", "button"]

if HAS_PLAYWRIGHT:
    from playwright.async_api import async_playwright  # type: ignore


async def _fill_first(page, selectors, value) -> bool:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if await loc.count() > 0:
                await loc.fill(value, timeout=5000)
                return True
        except Exception:
            continue
    return False


async def _click_first(page, selectors) -> bool:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if await loc.count() > 0:
                await loc.click(timeout=5000)
                return True
        except Exception:
            continue
    return False


async def perform_login(config) -> dict:
    """Return a ``{name: value}`` cookie dict for the authenticated session, or {}."""
    cfg = (config.section("auth") or {}).get("login") or {}
    url = cfg.get("url")
    user = cfg.get("username")
    password = cfg.get("password")
    if not (url and user and password):
        return {}
    if not HAS_PLAYWRIGHT:
        log.warning("auth.login configured but Playwright is not installed — skipping login")
        return {}

    user_sel = ([cfg["username_selector"]] if cfg.get("username_selector") else []) + _USER_SELECTORS
    pass_sel = ([cfg["password_selector"]] if cfg.get("password_selector") else []) + _PASS_SELECTORS
    submit_sel = ([cfg["submit_selector"]] if cfg.get("submit_selector") else []) + _SUBMIT_SELECTORS
    success_text = cfg.get("success_text")
    timeout = float(config.get("opsec.timeout", 20.0)) * 1000

    try:
        async with async_playwright() as pw:
            browser = await launch_chromium(pw)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            if not await _fill_first(page, user_sel, user):
                log.warning("login: could not find a username field")
            await _fill_first(page, pass_sel, password)
            await _click_first(page, submit_sel)
            try:
                await page.wait_for_load_state("networkidle", timeout=min(timeout, 10000))
            except Exception:
                pass
            ok = True
            if success_text:
                body = await page.content()
                ok = success_text in body
            cookies = {c["name"]: c["value"] for c in await context.cookies()}
            await browser.close()
        if not cookies:
            log.warning("login completed but no cookies were set")
            return {}
        if not ok:
            log.warning("login success_text not found — cookies captured anyway (%d)", len(cookies))
        log.info("authenticated login captured %d cookie(s)", len(cookies))
        return cookies
    except Exception as exc:  # noqa: BLE001
        log.warning("login automation failed: %s", exc)
        return {}
