"""Deeper injection-point probing (candidates, not exploitation).

Safely tests parameterised endpoints for several high-value injection classes and
reports *candidates* to verify by hand:

* **SSTI** — inject template arithmetic with an improbable product and look for the
  evaluated result reflected back.
* **CRLF / header injection** — inject an encoded newline + marker header and check
  whether it appears in the response headers.
* **Reflected XSS context** — inject a marker with HTML metacharacters and check
  whether it comes back unencoded (i.e. lands in an HTML sink).
* **Web cache deception** — request a dynamic path with an appended static
  extension and see if it still returns the dynamic body with a cacheable response.

All payloads are benign markers. Active, scope-gated, opt-in.
"""

from __future__ import annotations

import asyncio
import random
import string
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

def build_ssti_payloads():
    # Improbable product so a coincidental match in the page is unlikely.
    a, b = random.randint(1000, 9999), random.randint(1000, 9999)
    expect = str(a * b)
    payloads = ["{{%d*%d}}" % (a, b), "${%d*%d}" % (a, b), "#{%d*%d}" % (a, b),
                "<%%= %d*%d %%>" % (a, b)]
    return payloads, expect


def crlf_detected(headers: dict, marker: str) -> bool:
    return any(marker.lower() == k.lower() for k in headers)


@register
class InjectionProbe(Module):
    name = "injection_probe"
    phase = Phase.VULN
    active = True
    description = "Probe endpoints for SSTI / CRLF / reflected-XSS / cache-deception candidates"
    depends_on = ("http_probe",)
    enabled_by_default = False  # opt-in: sends crafted (benign) payloads

    async def run(self, ctx: RunContext) -> None:
        targets = self._targets(ctx)
        if not targets:
            self.log.info("no parameterised endpoints for injection probing")
            return
        cap = int(ctx.config.get("modules.injection_probe.max_targets", 200))
        targets = targets[:cap]
        self.log.info("injection-probing %d parameter(s)", len(targets))
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))
        found = 0

        async def worker(item):
            nonlocal found
            async with sem:
                found += await self._probe(ctx, *item)

        await asyncio.gather(*(worker(t) for t in targets))
        # Cache-deception is per-path, not per-param.
        await self._cache_deception(ctx)
        self.log.info("injection probing complete: %d candidate(s)", found)

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
                key = (a.value.split("?")[0], p)
                if key not in seen:
                    seen.add(key)
                    out.append((a.value, p))
        return out

    def _mutate(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    async def _probe(self, ctx: RunContext, url: str, param: str) -> int:
        found = 0
        found += await self._ssti(ctx, url, param)
        found += await self._xss(ctx, url, param)
        found += await self._crlf(ctx, url, param)
        return found

    async def _ssti(self, ctx: RunContext, url: str, param: str) -> int:
        payloads, expect = build_ssti_payloads()
        for payload in payloads:
            resp = await ctx.http.get(self._mutate(url, param, payload))
            if resp is not None and expect in resp.text and payload not in resp.text:
                ctx.add_finding(
                    f"SSTI candidate: {url} (parameter '{param}')",
                    module=self.name, severity=Severity.HIGH, confidence=Confidence.TENTATIVE,
                    asset=urlparse(url).hostname,
                    description=("A template-arithmetic payload was evaluated server-side (the product "
                                 "was reflected). Strong server-side template injection candidate — verify."),
                    evidence={"url": url, "param": param, "payload": payload, "expected": expect},
                    tags={"ssti", "injection"},
                )
                return 1
        return 0

    async def _xss(self, ctx: RunContext, url: str, param: str) -> int:
        marker = "vr" + "".join(random.choices(string.ascii_lowercase, k=5))
        payload = f'{marker}"><svg/onload=1>'
        resp = await ctx.http.get(self._mutate(url, param, payload))
        if resp is not None and f'{marker}"><svg' in resp.text:
            ctx.add_finding(
                f"Reflected XSS candidate: {url} (parameter '{param}')",
                module=self.name, severity=Severity.MEDIUM, confidence=Confidence.TENTATIVE,
                asset=urlparse(url).hostname,
                description=("HTML metacharacters were reflected unencoded into the response — the input "
                             "reaches an HTML sink. Confirm the execution context before reporting."),
                evidence={"url": url, "param": param, "marker": marker},
                tags={"xss", "injection"},
            )
            return 1
        return 0

    async def _crlf(self, ctx: RunContext, url: str, param: str) -> int:
        marker = "x-voidrecon-" + "".join(random.choices(string.ascii_lowercase, k=5))
        payload = f"test%0d%0a{marker}%3a%20injected"
        resp = await ctx.http.get(self._mutate(url, param, payload))
        if resp is not None and crlf_detected(dict(resp.headers), marker):
            ctx.add_finding(
                f"CRLF / header injection candidate: {url} (parameter '{param}')",
                module=self.name, severity=Severity.MEDIUM, confidence=Confidence.LIKELY,
                asset=urlparse(url).hostname,
                description="An injected CRLF sequence produced a new response header — header/response splitting.",
                evidence={"url": url, "param": param, "injected_header": marker},
                tags={"crlf", "injection"},
            )
            return 1
        return 0

    async def _cache_deception(self, ctx: RunContext) -> int:
        # Compare a dynamic path with a static-looking variant; a cacheable dynamic
        # body is a web-cache-deception candidate.
        found = 0
        origins = [(a.value, a.attrs["http_url"]) for a in ctx.store.assets()
                   if a.attrs.get("http_url") and "web" in a.tags and ctx.can_touch(a.value)]
        for host, url in origins[:20]:
            variant = url.rstrip("/") + f"/{''.join(random.choices(string.ascii_lowercase, k=6))}.css"
            r = await ctx.http.get(variant)
            if r is None or r.status_code != 200:
                continue
            cc = (r.headers.get("cache-control", "") + " " + r.headers.get("x-cache", "")).lower()
            ctype = r.headers.get("content-type", "").lower()
            if ("public" in cc or "max-age" in cc or "hit" in cc) and "text/html" in ctype:
                found += 1
                ctx.add_finding(
                    f"Web-cache-deception candidate: {host}",
                    module=self.name, severity=Severity.LOW, confidence=Confidence.TENTATIVE, asset=host,
                    description=("A static-looking URL returned cacheable HTML — if authenticated pages are "
                                 "cached this way, a cache-deception attack may expose other users' content."),
                    evidence={"url": variant, "cache_control": r.headers.get("cache-control"),
                              "content_type": ctype},
                    tags={"cache-deception"},
                )
        return found
