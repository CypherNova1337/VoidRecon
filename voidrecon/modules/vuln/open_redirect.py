"""Open-redirect testing.

Redirect parameters that send the browser wherever the value points are a classic
bug (phishing, OAuth token theft, SSRF stepping-stone). This module takes
endpoints whose parameters look redirect-related, swaps in a canary destination,
and checks whether the server actually redirects off-site to it — confirming the
open redirect rather than just flagging the parameter. Active, scope-gated,
opt-in; it only ever redirects to a harmless canary host.
"""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_url", "redirect_uri", "redirect_to", "next", "next_page",
    "dest", "destination", "return", "returnto", "return_to", "return_url", "returnurl",
    "go", "goto", "out", "target", "to", "continue", "checkout_url", "forward", "from_url",
    "rurl", "redir", "link", "u", "r",
}
_CANARY_HOST = "voidrecon-canary.example"
_CANARY = f"https://{_CANARY_HOST}/"


@register
class OpenRedirect(Module):
    name = "open_redirect"
    phase = Phase.VULN
    active = True
    description = "Confirm open redirects by testing redirect-style parameters with a canary"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in: sends crafted requests

    async def run(self, ctx: RunContext) -> None:
        targets = self._targets(ctx)
        if not targets:
            self.log.info("no redirect-style parameterised endpoints to test")
            return
        cap = int(ctx.config.get("modules.open_redirect.max_targets", 200))
        targets = targets[:cap]
        self.log.info("testing %d redirect parameter(s) for open redirect", len(targets))
        timeout = float(ctx.config.get("opsec.timeout", 20.0))
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        found = 0

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=timeout) as client:
            async def worker(item):
                nonlocal found
                async with sem:
                    if await self._test(ctx, client, *item):
                        found += 1

            await asyncio.gather(*(worker(t) for t in targets))
        self.log.info("open-redirect testing complete: %d confirmed", found)

    def _targets(self, ctx: RunContext):
        """Return (url, param) pairs worth testing."""
        out, seen = [], set()
        for a in ctx.store.assets(kind=AssetKind.URL) + ctx.store.assets(kind=AssetKind.ENDPOINT):
            parsed = urlparse(a.value)
            if not parsed.query:
                continue
            host = parsed.hostname
            if not host or not ctx.can_touch(host):
                continue
            for p in parse_qs(parsed.query):
                if p.lower() in _REDIRECT_PARAMS:
                    key = (a.value.split("?")[0], p)
                    if key not in seen:
                        seen.add(key)
                        out.append((a.value, p))
        return out

    async def _test(self, ctx: RunContext, client, url: str, param: str) -> bool:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [_CANARY]
        new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        await ctx.http._limiter.acquire()
        try:
            resp = await client.get(new_url, headers={"User-Agent": "VoidRecon"})
        except Exception:
            return False
        location = resp.headers.get("location", "")
        confirmed = resp.status_code in (301, 302, 303, 307, 308) and _CANARY_HOST in location
        # Also catch meta-refresh / JS redirects to the canary in-body.
        if not confirmed and _CANARY_HOST in resp.text[:5000] and "refresh" in resp.text[:5000].lower():
            confirmed = True
        if confirmed:
            ctx.add_finding(
                f"Open redirect: {url} (parameter '{param}')",
                module=self.name, severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED,
                asset=parsed.hostname,
                description=("The parameter redirects the browser to an attacker-controlled host. "
                             "Useful for phishing and, against OAuth flows, token theft."),
                evidence={"url": url, "param": param, "location": location or "(in-body redirect)"},
                tags={"open-redirect"},
            )
            return True
        return False
