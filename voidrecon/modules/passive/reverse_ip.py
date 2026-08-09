"""Reverse-IP hosting lookup.

A single IP frequently hosts many sites. Asking "what else lives on this address?"
turns a discovered IP into a list of co-hosted domains — sibling properties on
shared hosting, or (on dedicated infrastructure) more of the same organisation.
Uses HackerTarget's keyless reverse-IP dataset. Fully passive (third-party data).
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register
from voidrecon.utils import net


@register
class ReverseIp(Module):
    name = "reverse_ip"
    phase = Phase.PASSIVE
    active = False
    description = "Find domains co-hosted on discovered IPs (reverse-IP lookup)"
    depends_on = ("dns_resolve",)
    enabled_by_default = False  # opt-in: one third-party query per IP (rate-limited)

    async def run(self, ctx: RunContext) -> None:
        # Only IPs that in-scope hosts actually resolve to (avoid CDN noise).
        ips: set[str] = set()
        for a in ctx.store.assets(kind=AssetKind.SUBDOMAIN) + ctx.store.assets(kind=AssetKind.DOMAIN):
            if ctx.scope.is_related(a.value):
                ips.update(a.attrs.get("resolved_ips") or [])
        ips = {ip for ip in ips if ctx.scope.classify_ip(ip).value != "out_of_scope"}
        cap = int(ctx.config.get("modules.reverse_ip.max_ips", 50))
        ips = list(ips)[:cap]
        if not ips:
            self.log.info("no in-scope IPs for reverse-IP lookup")
            return
        sem = asyncio.Semaphore(min(int(ctx.config.get("opsec.max_concurrency", 20)), 5))
        total = 0

        async def worker(ip):
            nonlocal total
            async with sem:
                total += await self._lookup(ctx, ip)

        await asyncio.gather(*(worker(ip) for ip in ips))
        self.log.info("reverse-IP lookup over %d IPs; +%d co-hosted domains", len(ips), total)

    async def _lookup(self, ctx: RunContext, ip: str) -> int:
        text = await ctx.http.get_text("https://api.hackertarget.com/reverseiplookup/", params={"q": ip})
        if not text or "error" in text.lower() or "no records" in text.lower() or "api count" in text.lower():
            return 0
        added = 0
        for line in text.splitlines():
            host = net.normalize_host(line.strip())
            if not host or not net.is_domain(host):
                continue
            related = ctx.scope.is_related(host)
            kind = AssetKind.SUBDOMAIN if related else AssetKind.DOMAIN
            a = ctx.add_asset(kind, host, source=self.name, confidence=Confidence.TENTATIVE,
                              cohosted_ip=ip)
            if a:
                a.tags.add("reverse-ip")
                added += 1
        return added
