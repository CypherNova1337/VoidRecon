"""DNS resolution of discovered hostnames.

Turns names into infrastructure: A/AAAA records (IP assets), CNAME chains (which
feed subdomain-takeover correlation), and a liveness signal that prunes the noise
of passive sources down to hosts that actually exist. Resolution goes through
recursive resolvers, not the target, so it stays passive; it is placed in its own
RESOLVE phase so later active modules only ever touch things that resolve.
"""

from __future__ import annotations

import asyncio

from voidrecon.core.context import RunContext
from voidrecon.core.models import AssetKind, Confidence
from voidrecon.core.module import Module, Phase, register

try:
    import dns.asyncresolver
    import dns.resolver

    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False


@register
class DnsResolve(Module):
    name = "dns_resolve"
    phase = Phase.RESOLVE
    active = False
    description = "Resolve discovered hostnames to IPs + CNAMEs"
    depends_on = ("crtsh", "passive_subs", "wayback")

    async def run(self, ctx: RunContext) -> None:
        if not _HAS_DNS:
            self.log.warning("dnspython not installed — skipping resolution (pip install dnspython)")
            return
        hosts = [
            a for a in ctx.store.assets()
            if a.kind in (AssetKind.SUBDOMAIN, AssetKind.DOMAIN)
        ]
        if not hosts:
            return

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0
        resolver.timeout = 5.0
        sem = asyncio.Semaphore(int(ctx.config.get("opsec.max_concurrency", 20)))

        async def worker(asset):
            async with sem:
                await self._resolve_one(ctx, resolver, asset)

        await asyncio.gather(*(worker(a) for a in hosts))
        live = sum(1 for a in hosts if a.attrs.get("resolved_ips"))
        self.log.info("resolved %d/%d hosts to live IPs", live, len(hosts))

    async def _resolve_one(self, ctx: RunContext, resolver, asset) -> None:
        host = asset.value
        ips: list[str] = []
        cname = None
        try:
            answer = await resolver.resolve(host, "A")
            ips = [r.address for r in answer]
        except Exception:
            pass
        try:
            cans = await resolver.resolve(host, "CNAME")
            if cans:
                cname = str(cans[0].target).rstrip(".")
        except Exception:
            pass

        if ips:
            asset.attrs["resolved_ips"] = ips
            asset.confidence = Confidence.CONFIRMED
            asset.tags.add("live")
            for ip in ips:
                ctx.add_asset(AssetKind.IP, ip, source=self.name, resolved_from=host)
        if cname:
            asset.attrs["cname"] = cname
        if not ips and cname:
            # Resolves to a CNAME but no address — classic dangling-record signal.
            asset.tags.add("dangling-candidate")
