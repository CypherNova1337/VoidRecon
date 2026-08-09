"""Virtual-host discovery.

One IP often serves many sites, and not all of them resolve publicly — internal
apps, staging copies, and admin panels frequently hide behind a Host header on an
otherwise ordinary web server. This module baselines each in-scope web IP with a
bogus Host, then replays candidate hostnames (the subdomains already discovered,
plus the brute wordlist in aggressive mode) and flags any whose response diverges
from the baseline — a virtual host bound to that IP.

Active and scope-gated; opt-in.
"""

from __future__ import annotations

import asyncio
import random
import re
import string

import httpx

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence, Severity
from voidrecon.core.module import Module, Phase, register

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _signature(status: int, length: int, title: str | None) -> tuple:
    # Bucket length so trivial dynamic differences don't count as a new vhost.
    return (status, length // 256, (title or "").strip().lower())


@register
class Vhost(Module):
    name = "vhost"
    phase = Phase.CONTENT
    active = True
    description = "Discover hidden virtual hosts via Host-header fuzzing on web IPs"
    depends_on = ("dns_resolve", "http_probe")
    enabled_by_default = False  # opt-in

    async def run(self, ctx: RunContext) -> None:
        # IPs that serve web content (resolved from in-scope web hosts).
        web_ips: set[str] = set()
        for a in ctx.store.assets():
            if "web" in a.tags and ctx.can_touch(a.value):
                web_ips.update(a.attrs.get("resolved_ips") or [])
        web_ips = {ip for ip in web_ips if ctx.scope.classify_ip(ip).value != "out_of_scope"}
        if not web_ips:
            self.log.info("no in-scope web IPs for vhost discovery")
            return

        candidates = self._candidates(ctx)
        if not candidates:
            return
        self.log.info("vhost discovery: %d candidates across %d IP(s)", len(candidates), len(web_ips))
        timeout = float(ctx.config.get("opsec.timeout", 20.0))
        sem = asyncio.Semaphore(min(int(ctx.config.get("opsec.max_concurrency", 20)), 20))
        found = 0

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=timeout) as client:
            for ip in web_ips:
                found += await self._scan_ip(ctx, client, ip, candidates, sem)
        self.log.info("vhost discovery complete: %d hidden vhost(s)", found)

    def _candidates(self, ctx: RunContext) -> list[str]:
        names = {a.value for a in ctx.store.assets(kind=AssetKind.SUBDOMAIN)}
        if ctx.config.get("opsec.aggressive"):
            try:
                from importlib.resources import files
                raw = files("voidrecon.data").joinpath("subdomains.txt").read_text()
                for seed in ctx.scope.seeds:
                    for w in raw.splitlines():
                        w = w.strip()
                        if w and not w.startswith("#"):
                            names.add(f"{w}.{seed}")
            except Exception:
                pass
        cap = int(ctx.config.get("modules.vhost.max_candidates", 2000))
        return list(names)[:cap]

    async def _scan_ip(self, ctx, client, ip, candidates, sem) -> int:
        scheme = "https"
        baseline = await self._probe(ctx, client, ip, scheme,
                                     "".join(random.choices(string.ascii_lowercase, k=12)) + ".invalid")
        if baseline is None:
            scheme = "http"
            baseline = await self._probe(ctx, client, ip, scheme,
                                         "".join(random.choices(string.ascii_lowercase, k=12)) + ".invalid")
        if baseline is None:
            return 0
        found = 0

        async def test(host):
            nonlocal found
            async with sem:
                sig = await self._probe(ctx, client, ip, scheme, host)
                if sig is not None and sig != baseline and sig[0] not in (400, 421):
                    ctx.add_finding(
                        f"Virtual host {host} served by {ip}",
                        module=self.name, severity=Severity.INFO, confidence=Confidence.LIKELY,
                        asset=host,
                        description=("This IP serves a distinct response for the Host header — a virtual "
                                     "host that may not resolve publicly (internal/staging surface)."),
                        evidence={"ip": ip, "host": host, "status": sig[0]},
                        tags={"vhost"},
                    )
                    a = ctx.add_asset(AssetKind.SUBDOMAIN, host, source=self.name,
                                      confidence=Confidence.LIKELY, vhost_ip=ip)
                    if a:
                        a.tags.add("vhost")
                    found += 1

        await asyncio.gather(*(test(h) for h in candidates))
        return found

    async def _probe(self, ctx, client, ip, scheme, host):
        await ctx.http._limiter.acquire()
        try:
            resp = await client.get(f"{scheme}://{ip}/", headers={"Host": host, "User-Agent": "VoidRecon"})
        except Exception:
            return None
        m = _TITLE_RE.search(resp.text)
        return _signature(resp.status_code, len(resp.content), m.group(1) if m else None)
