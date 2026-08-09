"""SSRF probing (out-of-band + in-band signals).

Server-side request forgery is usually blind, so real confirmation needs an
out-of-band listener. Given an OOB domain you control (``oob.domain`` — e.g. an
interactsh domain), this module injects a unique callback URL into every
SSRF-shaped parameter and reports the tokens dispatched, so a hit on your listener
maps straight back to the vulnerable parameter. It also flags in-band signals
(fetched-content reflection, SSRF-typical errors). Benign callbacks only. Active,
scope-gated, opt-in.
"""

from __future__ import annotations

import asyncio
import random
import string
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_SSRF_PARAMS = {
    "url", "uri", "dest", "destination", "redirect", "redirect_uri", "path", "continue",
    "domain", "callback", "feed", "host", "port", "to", "out", "view", "dir", "show",
    "navigation", "open", "file", "document", "folder", "proxy", "load", "import",
    "endpoint", "image_url", "img_url", "src", "next", "data", "reference", "site", "target",
}
_SSRF_ERRORS = ["connection refused", "could not resolve host", "failed to connect",
                "no route to host", "invalid url", "connection timed out", "name or service not known"]


@register
class SsrfProbe(Module):
    name = "ssrf_probe"
    phase = Phase.VULN
    active = True
    description = "Blind SSRF testing via OOB callbacks (needs oob.domain) + in-band signals"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in

    async def run(self, ctx: RunContext) -> None:
        oob = ctx.config.get("oob.domain")
        targets = self._targets(ctx)
        if not targets:
            self.log.info("no SSRF-shaped parameters to test")
            return
        if not oob:
            self.log.info("no oob.domain set — SSRF is blind without a listener; "
                          "set oob.domain (e.g. an interactsh domain) to enable OOB testing")
        cap = int(ctx.config.get("modules.ssrf_probe.max_targets", 200))
        targets = targets[:cap]
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        dispatched: list[dict] = []

        async def worker(item):
            async with sem:
                await self._probe(ctx, *item, oob, dispatched)

        await asyncio.gather(*(worker(t) for t in targets))
        if dispatched and oob:
            ctx.add_finding(
                f"SSRF OOB callbacks dispatched ({len(dispatched)}) — check your listener at {oob}",
                module=self.name, severity=Severity.INFO, confidence=Confidence.TENTATIVE,
                description=("Unique callback URLs were injected into SSRF-shaped parameters. Any hit on "
                             "your OOB listener confirms SSRF; match the subdomain token back to the "
                             "parameter below."),
                evidence={"oob_domain": oob, "callbacks": dispatched[:100]},
                tags={"ssrf", "oob"},
            )
        self.log.info("SSRF probing dispatched %d callback(s)", len(dispatched))

    def _targets(self, ctx: RunContext):
        out, seen = [], set()
        for a in ctx.store.assets(kind=AssetKind.URL) + ctx.store.assets(kind=AssetKind.ENDPOINT):
            parsed = urlparse(a.value)
            if not parsed.query:
                continue
            host = parsed.hostname
            if not host or not ctx.can_touch(host):
                continue
            for p in parse_qs(parsed.query):
                if p.lower() in _SSRF_PARAMS:
                    key = (a.value.split("?")[0], p)
                    if key not in seen:
                        seen.add(key)
                        out.append((a.value, p))
        return out

    def _mutate(self, url, param, value):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async def _probe(self, ctx, url, param, oob, dispatched):
        token = "vr" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        callback = f"http://{token}.{oob}/" if oob else "http://voidrecon-canary.example/"
        resp = await ctx.http.get(self._mutate(url, param, callback))
        if oob:
            dispatched.append({"token": token, "url": url, "param": param})
        if resp is not None:
            low = resp.text[:5000].lower()
            for sig in _SSRF_ERRORS:
                if sig in low:
                    ctx.add_finding(
                        f"SSRF in-band signal: {url} (parameter '{param}')",
                        module=self.name, severity=Severity.MEDIUM, confidence=Confidence.TENTATIVE,
                        asset=urlparse(url).hostname,
                        description="The server produced a network-fetch error when given a URL parameter — "
                                    "it is making server-side requests. Test for SSRF to internal targets.",
                        evidence={"url": url, "param": param, "signal": sig}, tags={"ssrf"})
                    break
